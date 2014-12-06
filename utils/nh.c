/*
 * nh.c
 *
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stdbool.h>
#include <getopt.h>

#include <sys/types.h>
#include <sys/socket.h>
#if defined(__linux__)
#include <asm/types.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_ether.h>

#include <net/if.h>
#include <netinet/ether.h>
#elif defined(__FreeBSD__)
#include <net/if.h>
#endif
#include <net/ethernet.h>

#include "vr_types.h"
#include "vr_message.h"
#include "vr_nexthop.h"
#include "vr_genetlink.h"
#include "vr_os.h"
#include "nl_util.h"

static nh_set;
static struct nl_client *cl;
static int8_t src_mac[6], dst_mac[6];
static uint32_t nh_id, if_id, vrf_id ;
static uint16_t flags;
static struct in_addr sip, dip;
static uint16_t sport, dport;
static int command;
static int type;
static bool dump_pending = false;
static int dump_marker = -1;
static int comp_nh[10];
static int lbl[10];
static int comp_nh_ind = 0;
static int lbl_ind = 0;

char *
nh_type(uint32_t type)
{
    switch(type) {
       case NH_DEAD:
           return "Dead";
       case NH_RCV:
           return "Receieve";
       case NH_ENCAP:
           return "Encap";
       case NH_TUNNEL:
           return "Tunnel";
       case NH_DISCARD:
           return "Drop";
       case NH_RESOLVE:
           return "Resolve";
       case NH_COMPOSITE:
           return "Composite";
       case NH_VRF_TRANSLATE:
           return "Vrf_Translate";
       default:
           return "Invalid";
    }
}

char *
nh_flags(uint16_t flags, uint8_t type, char *ptr)
{
    int i;
    uint32_t mask;
    if (!flags) {
        strcpy(ptr, "None");
        return ptr;
    }


    strcpy(ptr,"");
    for(i = 0, mask = 1; (i < 18); i++, mask = mask << 1) {
        switch(flags & mask) {
        case NH_FLAG_VALID:
            strcat(ptr, "Valid, ");
            break;

        case NH_FLAG_POLICY_ENABLED:
            strcat(ptr, "Policy, ");
            break;
        
        case NH_FLAG_RELAXED_POLICY:
            strcat(ptr, "Policy(R), ");
            break;

        case NH_FLAG_TUNNEL_GRE:
            if (type == NH_TUNNEL)
                strcat(ptr, "MPLSoGRE, ");
            break;

        case NH_FLAG_TUNNEL_UDP_MPLS:
            if (type == NH_TUNNEL)
                strcat(ptr, "MPLSoUDP, ");
            break;

        case NH_FLAG_TUNNEL_UDP:
            if (type == NH_TUNNEL)
                strcat(ptr, "Udp, ");
            break;

        case NH_FLAG_COMPOSITE_L2:
            if (type == NH_COMPOSITE)
                strcat(ptr, "L2, ");
            break;

        case NH_FLAG_COMPOSITE_ECMP:
            if (type == NH_COMPOSITE)
                strcat(ptr, "Ecmp, ");
            break;

        case NH_FLAG_COMPOSITE_FABRIC:
            if (type == NH_COMPOSITE)
                strcat(ptr, "Fabric, ");
            break;

        case NH_FLAG_COMPOSITE_EVPN:
            if (type == NH_COMPOSITE)
                strcat(ptr, "Evpn, ");
            break;
        case NH_FLAG_COMPOSITE_TOR:
            if (type == NH_COMPOSITE)
                strcat(ptr, "Tor, ");
            break;

        case NH_FLAG_COMPOSITE_ENCAP:
            if (type == NH_COMPOSITE)
                strcat(ptr, "Encap, ");
            break;

        case NH_FLAG_MCAST:
            strcat(ptr, "Multicast, ");
            break;

        case NH_FLAG_ENCAP_L2:
            if (type == NH_ENCAP)
                strcat(ptr, "L2, ");
            break;

        case NH_FLAG_TUNNEL_VXLAN:
                strcat(ptr, "Vxlan, ");
            break;
        }
    }
    return ptr;
}

void
vr_nexthop_req_process(void *s_req)
{
    unsigned int i;
    struct in_addr a;
    char flags_mem[500];
    char fam[100];

    vr_nexthop_req *req = (vr_nexthop_req *)(s_req);

    if (req->nhr_family == AF_INET)
        strcpy(fam, "AF_INET");
    else if (req->nhr_family == AF_BRIDGE)
        strcpy(fam, "AF_BRIDGE");
    else if (req->nhr_family == AF_UNSPEC)
        strcpy(fam, "AF_UNSPEC");
    else 
        strcpy(fam, "N/A");

    printf("Id:%03d  Type:%-8s  Fmly:%8s  Flags:%s  Rid:%d  Ref_cnt:%d\n", 
                req->nhr_id, nh_type(req->nhr_type), fam,
                nh_flags(req->nhr_flags, req->nhr_type, flags_mem), req->nhr_rid, req->nhr_ref_cnt);

    if (req->nhr_type == NH_RCV)
        printf("\tOif:%d\n", req->nhr_encap_oif_id);

    if (req->nhr_type == NH_ENCAP) {
        printf("\tEncapFmly:%04x Oif:%d Len:%d Data:", req->nhr_encap_family, req->nhr_encap_oif_id, req->nhr_encap_size);
        for (i = 0; i< req->nhr_encap_size; i++) {
            printf("%02x ", (unsigned char)req->nhr_encap[i]);
        }
        printf("\n");
    }

    if (req->nhr_type == NH_TUNNEL) {
        printf("\tOif:%d Len:%d Flags %s Data:", req->nhr_encap_oif_id,
                req->nhr_encap_size, nh_flags(req->nhr_flags, req->nhr_type, flags_mem));
        for (i = 0; i< req->nhr_encap_size; i++) {
            printf("%02x ", (unsigned char)req->nhr_encap[i]);
        }
        printf("\n\tVrf:%d", req->nhr_vrf);
        a.s_addr = req->nhr_tun_sip;
        printf("  Sip:%s", inet_ntoa(a));
        a.s_addr = req->nhr_tun_dip;
        printf("  Dip:%s\n", inet_ntoa(a));

        if (req->nhr_flags & NH_FLAG_TUNNEL_UDP) {
            printf("        Sport:%d Dport:%d\n", ntohs(req->nhr_tun_sport), 
                                                  ntohs(req->nhr_tun_dport));
        }
    }

    if (req->nhr_type == NH_VRF_TRANSLATE) {
        printf("\tVrf:%d\n", req->nhr_vrf);
    }

    if (req->nhr_type == NH_COMPOSITE) {
        printf("\tSub NH(label):");
        for (i = 0; i < req->nhr_nh_list_size; i++) {
            printf(" %d", req->nhr_nh_list[i]);
            if (req->nhr_label_list[i] >= 0)
                printf("(%d)", req->nhr_label_list[i]);
        }
        printf("\n");
    }

    if (command == 3)
        dump_marker = req->nhr_id;

    printf("\n");
}

void
vr_response_process(void *s)
{
   vr_response *resp = (vr_response *)s;
    if (resp->resp_code < 0) {
        printf("Error %s in kernel operation\n", strerror(-resp->resp_code));
    } else {
        if (command == 3) {
            if (resp->resp_code & VR_MESSAGE_DUMP_INCOMPLETE)
                dump_pending = true;
            else
                dump_pending = false;
        }
    }

    return;
}

int 
vr_nh_op(int opt, int mode, uint32_t nh_id, uint32_t if_id, uint32_t vrf_id, 
        int8_t *dst, int8_t  *src, struct in_addr sip, struct in_addr dip, uint16_t flags)
{
    vr_nexthop_req nh_req;
    char *buf;
    int ret, error, attr_len;
    struct nl_response *resp;
    int i;

op_retry:

    bzero(&nh_req, sizeof(nh_req));

    if (opt == 1) {
        nh_req.h_op = SANDESH_OP_ADD;
        nh_req.nhr_flags = flags;
        nh_req.nhr_encap_oif_id = if_id;
        nh_req.nhr_encap_size = 0;
#if defined(__linux__)
        nh_req.nhr_encap_family = ETH_P_ARP;
#elif defined(__FreeBSD__)
    nh_req.nhr_encap_family = ETHERTYPE_ARP;
#endif
        nh_req.nhr_vrf = vrf_id;
        nh_req.nhr_tun_sip = sip.s_addr;
        nh_req.nhr_tun_dip = dip.s_addr;
        nh_req.nhr_tun_sport = htons(sport);
        nh_req.nhr_tun_dport = htons(dport);
        nh_req.nhr_nh_list_size = 0;
        if ((mode == NH_TUNNEL) || 
                ((mode == NH_ENCAP) && !(flags & NH_FLAG_ENCAP_L2))) {
            nh_req.nhr_encap_size = 14;
            buf = calloc(1, nh_req.nhr_encap_size);
            memcpy(buf, dst, 6);
            memcpy(buf+6, src, 6);
            buf[12] = 0x08;
            nh_req.nhr_encap = (int8_t *)buf;
        }

        if (mode == NH_COMPOSITE) {
            nh_req.nhr_nh_list_size = comp_nh_ind;
            nh_req.nhr_label_list_size = comp_nh_ind;
            nh_req.nhr_nh_list = calloc(comp_nh_ind, sizeof(uint32_t));
            nh_req.nhr_label_list = calloc(comp_nh_ind, sizeof(uint32_t));
            for (i = 0; i < comp_nh_ind; i++) {
                nh_req.nhr_nh_list[i] = comp_nh[i];
                if (i < lbl_ind)
                    nh_req.nhr_label_list[i] = lbl[i];
                else
                    nh_req.nhr_label_list[i] = 0;
            }
        }

    } else if (opt == 2) {
        nh_req.h_op = SANDESH_OP_DELETE;
    } else if (opt == 3) {
        nh_req.h_op = SANDESH_OP_DUMP;
        nh_req.nhr_marker = dump_marker;
    } else if (opt == 4) {
        nh_req.h_op = SANDESH_OP_GET;
    }

    nh_req.nhr_id = nh_id;
    nh_req.nhr_rid = 0;

    if ((mode == NH_ENCAP) && (flags & NH_FLAG_ENCAP_L2)) 
        nh_req.nhr_family = AF_BRIDGE;
    else
        nh_req.nhr_family = AF_INET;

    nh_req.nhr_type = mode;
    /* nlmsg header */
    ret = nl_build_nlh(cl, cl->cl_genl_family_id, NLM_F_REQUEST);
    if (ret) {
        return ret;
    }

    /* Generic nlmsg header */
    ret = nl_build_genlh(cl, SANDESH_REQUEST, 0);
    if (ret) {
        return ret;
    }

    attr_len = nl_get_attr_hdr_size();
     
    error = 0;
    ret = sandesh_encode(&nh_req, "vr_nexthop_req", vr_find_sandesh_info, 
                             (nl_get_buf_ptr(cl) + attr_len),
                             (nl_get_buf_len(cl) - attr_len), &error);

    if ((ret <= 0) || error) {
        return ret;
    }

    /* Add sandesh attribute */
    nl_build_attr(cl, ret, NL_ATTR_VR_MESSAGE_PROTOCOL);
    nl_update_nlh(cl);

    /* Send the request to kernel */
    ret = nl_sendmsg(cl);
    while ((ret = nl_recvmsg(cl)) > 0) {
        resp = nl_parse_reply(cl);
        if (resp->nl_op == SANDESH_REQUEST) {
            sandesh_decode(resp->nl_data, resp->nl_len, vr_find_sandesh_info, &ret);
        }
    }

    if (dump_pending)
        goto op_retry;

    return 0;

}
void
cmd_usage()
{
    printf("Usage: [--create <nhid> create nexthop\n"
           "       [--delete <nhid> delete nexthop\n"
           "       [--vrf <vrf_id> ]\n"
           "       [--pol NH with policy]\n"
           "       [--rpol NH with relaxed policy]\n"
           "       [--type <type> type of the tunnel 1 - rcv, 2 - encap, 3 - tunnel, 4 - resolve, 5 - discard, 6 - Composite, 7 - Vxlan VRF] \n"
           "                [RCV_NH options]\n"
           "                    [--oif <if_id> out going interface index]\n"
           "                [ENCAP_NH optionsi - default L3]\n"
           "                    [--el2 encap L2 ]\n"
           "                        [--oif <if_id> out going interface index]\n"
           "                    [--mc multicast nh]\n"
           "                    [--smac <xx:xx:xx:xx:xx:xx> source mac ]\n"
           "                    [--dmac <xx:xx:xx:xx:xx:xx> destination mac ]\n"
           "                    [--oif = out going interface index]\n"
           "                [TUNNEL_NH options - default Gre]\n"
           "                    [--oif <if_id> out going interface index]\n"
           "                    [--smac <xx:xx:xx:xx:xx:xx> source mac ]\n"
           "                    [--dmac <xx:xx:xx:xx:xx:xx> destination mac ]\n"
           "                    [--sip <x.x.x.x> source ip of tunnel] \n"
           "                    [--dip <x.x.x.x> destination ip of tunnel ]\n"
           "                    [--udp Udptunnel ]\n"
           "                        [--sport <port> source port of udp tunnel]\n"
           "                        [--dport <port> destination port of udp tunnel]\n"
           "                    [--vxlan Vxlan Tunnel]\n"
           "                        [--sport <port> source port of vxlan tunnel]\n"
           "                        [--dport <port> destination port of vxlan tunnel]\n"
           "                [RESOLVE_NH options]\n"
           "                [DISCARD_NH options]\n"
           "                [COMPOSITE_NH options]\n"
           "                    [--cni <nh_id> composite nexthop member id]\n"
           "                    [--cl2 composite l2 nexhop]\n"
           "                    [--cfa composit fabric ]\n"
           "                    [--cen composit encap ]\n"
           "                    [--cevpn composit evpn ]\n"
           "                        [--lbl <lbl> label for composit fabric ]\n"
           "                    [--tor composit tor ]\n"
           "                        [--lbl <lbl> label for composit fabric ]\n"
           "                [VxlanVRF options]\n");

    exit(-EINVAL);
}

void
usage()
{
    printf("Usage: nh --list\n"
           "       nh --get <nh_id>\n"
           "       nh --help\n\n"
           "--list Lists All Nexthops\n"
           "--get  <nh_id> Displays nexthop corresponding to <nh_id>\n"
           "--help Displays this help message\n\n");

    exit(-EINVAL);
}

enum opt_index {
    OIF_OPT_IND,
    SMAC_OPT_IND,
    DMAC_OPT_IND,
    VRF_OPT_IND,
    TYPE_OPT_IND,
    SIP_OPT_IND,
    DIP_OPT_IND,
    POL_OPT_IND,
    RPOL_OPT_IND,
    SPORT_OPT_IND,
    DPORT_OPT_IND,
    UDP_OPT_IND,
    VXLAN_OPT_IND,
    CNI_OPT_IND,
    CL2_OPT_IND,
    CFA_OPT_IND,
    MC_OPT_IND,
    EL2_OPT_IND,
    CEN_OPT_IND,
    CEVPN_OPT_IND,
    TOR_OPT_IND,
    LBL_OPT_IND,
    LST_OPT_IND,
    GET_OPT_IND,
    CRT_OPT_IND,
    DEL_OPT_IND,
    CMD_OPT_IND,
    HLP_OPT_IND,
    MAX_OPT_IND
};

int opt[MAX_OPT_IND], zero_opt[MAX_OPT_IND];
bool opt_set(int ind)
{
    if (ind < 0 || ind >= MAX_OPT_IND)
        return false;
    if (opt[ind]) {
        opt[ind] = 0;
        return true;
    }
    return false;
}
static struct option long_options[] = {
    [OIF_OPT_IND]       = {"oif",   required_argument,  &opt[OIF_OPT_IND],      1},
    [SMAC_OPT_IND]      = {"smac",  required_argument,  &opt[SMAC_OPT_IND],     1},
    [DMAC_OPT_IND]      = {"dmac",  required_argument,  &opt[DMAC_OPT_IND],     1},
    [VRF_OPT_IND]       = {"vrf",   required_argument,  &opt[VRF_OPT_IND],      1},
    [TYPE_OPT_IND]      = {"type",  required_argument,  &opt[TYPE_OPT_IND],     1},
    [SIP_OPT_IND]       = {"sip",   required_argument,  &opt[SIP_OPT_IND],      1},
    [DIP_OPT_IND]       = {"dip",   required_argument,  &opt[DIP_OPT_IND],      1},
    [POL_OPT_IND]       = {"pol",   no_argument,        &opt[POL_OPT_IND],      1},
    [RPOL_OPT_IND]      = {"rpol",  no_argument,        &opt[RPOL_OPT_IND],     1},
    [SPORT_OPT_IND]     = {"sport", required_argument,  &opt[SPORT_OPT_IND],    1},
    [DPORT_OPT_IND]     = {"dport", required_argument,  &opt[DPORT_OPT_IND],    1},
    [UDP_OPT_IND]       = {"udp",   no_argument,        &opt[UDP_OPT_IND],      1},
    [VXLAN_OPT_IND]     = {"vxlan", no_argument,        &opt[VXLAN_OPT_IND],    1},
    [CNI_OPT_IND]       = {"cni",   required_argument,  &opt[CNI_OPT_IND],      1},
    [CL2_OPT_IND]       = {"cl2",   no_argument,        &opt[CL2_OPT_IND],      1},
    [CFA_OPT_IND]       = {"cfa",   no_argument,        &opt[CFA_OPT_IND],      1},
    [MC_OPT_IND]        = {"mc",    no_argument,        &opt[MC_OPT_IND],       1},
    [EL2_OPT_IND]       = {"el2",   no_argument,        &opt[EL2_OPT_IND],      1},
    [CEN_OPT_IND]       = {"cen",   no_argument,        &opt[CEN_OPT_IND],      1},
    [CEVPN_OPT_IND]     = {"cevpn", no_argument,        &opt[CEVPN_OPT_IND],    1},
    [TOR_OPT_IND]       = {"tor",   no_argument,        &opt[TOR_OPT_IND],    1},
    [LBL_OPT_IND]       = {"lbl",   required_argument,  &opt[LBL_OPT_IND],      1},
    [LST_OPT_IND]       = {"list",  no_argument,        &opt[LST_OPT_IND],      1},
    [GET_OPT_IND]       = {"get",   required_argument,  &opt[GET_OPT_IND],      1},
    [CRT_OPT_IND]       = {"create", required_argument, &opt[CRT_OPT_IND],      1},
    [DEL_OPT_IND]       = {"delete", required_argument, &opt[DEL_OPT_IND],      1},
    [CMD_OPT_IND]       = {"cmd",   no_argument,        &opt[CMD_OPT_IND],      1},
    [HLP_OPT_IND]       = {"help",  no_argument,        &opt[HLP_OPT_IND],      1},
    [MAX_OPT_IND]       = { NULL,   0,                  0,                      0}
};

static void
parse_long_opts(int ind, char *opt_arg)
{
    int errno;
    struct ether_addr *mac;

    errno = 0;
    switch(ind) {
        case CMD_OPT_IND:
            cmd_usage();
        case HLP_OPT_IND:
            usage();
        case GET_OPT_IND:
        case CRT_OPT_IND:
        case DEL_OPT_IND:
            nh_id = strtoul(opt_arg, NULL, 0);
            if (errno)
                usage();
            nh_set = 1;
            break;
        case OIF_OPT_IND:
            if_id = strtoul(opt_arg, NULL, 0);
            if (errno) 
                usage();
            break;
        case SMAC_OPT_IND:
            mac = ether_aton(opt_arg);
            if (mac)
                memcpy(src_mac, mac, sizeof(src_mac));
            else
                cmd_usage();
            break;
        case DMAC_OPT_IND:
            mac = ether_aton(opt_arg);
            if (mac)
                memcpy(dst_mac, mac, sizeof(dst_mac));
            else
                cmd_usage();
            break;
        case VRF_OPT_IND:
            vrf_id = strtoul(opt_arg, NULL, 0);
            if (errno) 
                usage();
            break;
        case TYPE_OPT_IND:
            type = strtoul(opt_arg, NULL, 0);
            if (errno) 
                usage();
            break;
        case SIP_OPT_IND:
            inet_aton(opt_arg, &sip);
            break;
        case DIP_OPT_IND:
            inet_aton(opt_arg, &dip);
            break;
        case SPORT_OPT_IND:
            sport = strtoul(opt_arg, NULL, 0);
            if (errno) 
                usage();
            break;
        case CNI_OPT_IND:
            comp_nh[comp_nh_ind++] = strtoul(opt_arg, NULL, 0);
            if (errno)
                usage();
            break;
        case LBL_OPT_IND:
            lbl[lbl_ind++] = strtoul(opt_arg, NULL, 0);
            if (errno)
                usage();
        case DPORT_OPT_IND:
            dport = strtoul(opt_arg, NULL, 0);
            if (errno) 
                usage();
    }
}

static void
validate_options()
{
    if (opt_set(CRT_OPT_IND))
        command = 1;
    else if (opt_set(DEL_OPT_IND))
        command = 2;
    else if (opt_set(GET_OPT_IND))
        command = 4;
    else if (opt_set(LST_OPT_IND))
        command = 3;
    else
        usage();


    switch (command) {
        case 1:
            if (!nh_set)
                cmd_usage();

            flags |= NH_FLAG_VALID;
            opt_set(TYPE_OPT_IND);
            opt_set(VRF_OPT_IND);

            if (opt_set(MC_OPT_IND))
                flags |= NH_FLAG_MCAST;

            if (opt_set(POL_OPT_IND))
                flags |= NH_FLAG_POLICY_ENABLED;

            if (opt_set(RPOL_OPT_IND))
                flags |= NH_FLAG_RELAXED_POLICY;


            if (type == NH_RCV) {
                if (!opt_set(OIF_OPT_IND))
                    cmd_usage();
                if (memcmp(opt, zero_opt, sizeof(opt)))
                    cmd_usage();
            } else if (type == NH_ENCAP) {
                if (!opt_set(OIF_OPT_IND)) 
                    cmd_usage();

                if (!opt_set(EL2_OPT_IND)) {
                    if (!opt_set(SMAC_OPT_IND) || !opt_set(DMAC_OPT_IND))
                        cmd_usage();
                } else
                    flags |= NH_FLAG_ENCAP_L2;

                if (memcmp(opt, zero_opt, sizeof(opt)))
                    cmd_usage();

            } else if (type == NH_TUNNEL) {
                if (!opt_set(OIF_OPT_IND) || !opt_set(SMAC_OPT_IND) ||
                        !opt_set(DMAC_OPT_IND) || !opt_set(SIP_OPT_IND) ||
                        !opt_set(DIP_OPT_IND)) {
                    cmd_usage();
                }

                if (opt_set(UDP_OPT_IND)) {
                    flags |= NH_FLAG_TUNNEL_UDP;
                    if (!opt_set(SPORT_OPT_IND) || !opt_set(DPORT_OPT_IND))
                        cmd_usage();
                } else if (opt_set(VXLAN_OPT_IND)) {
                    flags |= NH_FLAG_TUNNEL_VXLAN;
                    if (!opt_set(SPORT_OPT_IND) || !opt_set(DPORT_OPT_IND))
                        cmd_usage();
                } else {
                    flags |= NH_FLAG_TUNNEL_GRE;
                }

                if (memcmp(opt, zero_opt, sizeof(opt)))
                    cmd_usage();
            } else if (type == NH_RESOLVE) {
                if (memcmp(opt, zero_opt, sizeof(opt)))
                    cmd_usage();
            } else if (type == NH_DISCARD) {
                if (memcmp(opt, zero_opt, sizeof(opt)))
                    cmd_usage();
            } else if (type == NH_COMPOSITE) {
                if (!opt_set(CNI_OPT_IND))
                    cmd_usage();

                if (opt_set(CL2_OPT_IND))
                    flags |= NH_FLAG_COMPOSITE_L2;
                if (opt_set(CFA_OPT_IND))
                    flags |= NH_FLAG_COMPOSITE_FABRIC;
                if (opt_set(CEN_OPT_IND))
                    flags |= NH_FLAG_COMPOSITE_ENCAP;
                if (opt_set(CEVPN_OPT_IND))
                    flags |= NH_FLAG_COMPOSITE_EVPN;
                if (opt_set(TOR_OPT_IND))
                    flags |= NH_FLAG_COMPOSITE_TOR;
                opt_set(LBL_OPT_IND);
                if (memcmp(opt, zero_opt, sizeof(opt)))
                    cmd_usage();
            } else if (type != NH_VRF_TRANSLATE) {
                cmd_usage();
            }
            break;

        case 2:
            if (!nh_set)
                cmd_usage();
            if (memcmp(opt, zero_opt, sizeof(opt)))
                    cmd_usage();
            break;

        case 3:
            if (memcmp(opt, zero_opt, sizeof(opt)))
                    usage();
            break;
        case 4:
            if (memcmp(opt, zero_opt, sizeof(opt)))
                    usage();
            break;

    }
}


int main(int argc, char *argv[])
{
   int ret;
    int opt;
    int ind;

    cl = nl_register_client();
    if (!cl) {
        exit(1);
    }

    ret = nl_socket(cl, NETLINK_GENERIC);    
    if (ret <= 0) {
       exit(1);
    }

    if (vrouter_get_family_id(cl) <= 0) {
        return 0;
    }

    while ((opt = getopt_long(argc, argv, "",
                                        long_options, &ind)) >= 0) {
        switch(opt) {
            case 0:
                parse_long_opts(ind, optarg);
                break;

            default:
                usage();
        }

    }

    validate_options();

    vr_nh_op(command, type, nh_id, if_id, vrf_id, dst_mac,
            src_mac, sip, dip, flags);


    return 0;
}
