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

#include <net/if.h>

#if defined(__linux__) || defined(_WIN32)
#include <netinet/ether.h>
#elif defined(__FreeBSD__)
#include <net/ethernet.h>
#endif

#include "vr_types.h"
#include "vr_nexthop.h"
#include "vr_os.h"
#include "nl_util.h"

static int8_t src_mac[6], dst_mac[6];
static uint16_t sport, dport;
static uint32_t nh_id, if_id, vrf_id, flags;
static int nh_set, command, type, dump_marker = -1;

static bool dump_pending = false;
static int comp_nh[32], lbl[32];
static int comp_nh_ind = 0, lbl_ind = 0;

static struct in_addr sip, dip;
static struct nl_client *cl;

static int
vr_nh_op(struct nl_client *cl, int command, int type, uint32_t nh_id,
        uint32_t if_id, uint32_t vrf_id, int8_t *dst, int8_t  *src,
        struct in_addr sip, struct in_addr dip, uint32_t flags);

char *
nh_type(uint32_t type)
{
    switch (type) {
    case NH_DEAD:
        return "Dead";

    case NH_RCV:
        return "Receive";

    case NH_L2_RCV:
        return "L2 Receive";

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

    return NULL;
}

char *
nh_ecmp_config_hash_str(uint8_t hash, char *ptr)
{
    int i;

    strcpy(ptr,"");
    hash = hash & ((1 << NH_ECMP_CONFIG_HASH_BITS) - 1);
    for (i = 0; i < NH_ECMP_CONFIG_HASH_BITS; i++) {
        switch (hash & (1 << i)) {
        case 0:
            break;
        case NH_ECMP_CONFIG_HASH_PROTO:
            strcat(ptr, "Proto,");
            break;
        case NH_ECMP_CONFIG_HASH_SRC_IP:
            strcat(ptr, "SrcIP,");
            break;
        case NH_ECMP_CONFIG_HASH_SRC_PORT:
            strcat(ptr, "SrcPort,");
            break;
        case NH_ECMP_CONFIG_HASH_DST_IP:
            strcat(ptr, "DstIp,");
            break;
        case NH_ECMP_CONFIG_HASH_DST_PORT:
            strcat(ptr, "DstPort");
            break;
        default:
            strcat(ptr, "Invalid,");
            break;
        }
    }

    return ptr;
}

char *
nh_flags(uint32_t flags, uint8_t type, char *ptr)
{
    int i;
    uint32_t mask;

    if (!flags) {
        strcpy(ptr, "None");
        return ptr;
    }


    strcpy(ptr,"");
    for (i = 0, mask = 1; (i < 32); i++, mask = mask << 1) {
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

        case NH_FLAG_FLOW_LOOKUP:
            strcat(ptr, "Flow Lookup, ");
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

        case NH_FLAG_ROUTE_LOOKUP:
            strcat(ptr, "RouteLookup, ");
            break;

        case NH_FLAG_TUNNEL_VXLAN:
            strcat(ptr, "Vxlan, ");
            break;

        case NH_FLAG_UNKNOWN_UC_FLOOD:
            strcat(ptr, "Unicast Flood, ");
            break;

        case NH_FLAG_TUNNEL_SIP_COPY:
            strcat(ptr, "Copy SIP, ");
            break;

        case NH_FLAG_TUNNEL_PBB:
            strcat(ptr, "Pbb, ");
            break;

        case NH_FLAG_INDIRECT:
            strcat(ptr, "Indirect, ");
            break;

        case NH_FLAG_ETREE_ROOT:
            strcat(ptr, "Etree Root, ");
            break;

        case NH_FLAG_MAC_LEARN:
            strcat(ptr, "Mac Learn, ");
            break;

        case NH_FLAG_L2_CONTROL_DATA:
            strcat(ptr, "Evpn Control Word, ");
            break;
        }
    }

    return ptr;
}

static void
nh_print_newline_header(void)
{
    printf("\n%14c", ' ');
    return;
}

static void
nexthop_req_process(void *s_req)
{
    unsigned int i, printed = 0;
    struct in_addr a;
    char flags_mem[500];
    char fam[100];
    char in6_dst[INET6_ADDRSTRLEN] = { 0 };

    vr_nexthop_req *req = (vr_nexthop_req *)(s_req);

    if (req->nhr_family == AF_INET)
        strcpy(fam, "AF_INET");
    else if (req->nhr_family == AF_INET6)
        strcpy(fam, "AF_INET6");
    else if (req->nhr_family == AF_BRIDGE)
        strcpy(fam, "AF_BRIDGE");
    else if (req->nhr_family == AF_UNSPEC)
        strcpy(fam, "AF_UNSPEC");
    else
        strcpy(fam, "N/A");

    printf("Id:%-9d  Type:%-13s  Fmly:%8s  Rid:%d  Ref_cnt:%-10d Vrf:%d",
                req->nhr_id, nh_type(req->nhr_type), fam,
                req->nhr_rid, req->nhr_ref_cnt, req->nhr_vrf);
    nh_print_newline_header();
    printf("Flags:%s",
            nh_flags(req->nhr_flags, req->nhr_type, flags_mem));

    if ((req->nhr_flags & NH_FLAG_INDIRECT) && (req->nhr_nh_list_size)) {
        i = -1;
        if (req->nhr_label_list_size)
            i = req->nhr_label_list[0];
        nh_print_newline_header();
        printf("Direct NH(label): %d(%d)", req->nhr_nh_list[0], i);
    }

    if (req->nhr_type == NH_RCV) {
        nh_print_newline_header();
        printf("Oif:%d", req->nhr_encap_oif_id);
    } else if (req->nhr_type == NH_ENCAP) {
        nh_print_newline_header();
        printf("EncapFmly:%04x Oif:%d Len:%d",
                req->nhr_encap_family, req->nhr_encap_oif_id, req->nhr_encap_size);
        nh_print_newline_header();
        printf("Encap Data: ");
        for (i = 0; i< req->nhr_encap_size; i++) {
            printf("%02x ", (unsigned char)req->nhr_encap[i]);
        }
    } else if (req->nhr_type == NH_TUNNEL) {
        nh_print_newline_header();
        if (!(req->nhr_flags & NH_FLAG_TUNNEL_PBB)) {
            printf("Oif:%d Len:%d Data:", req->nhr_encap_oif_id, req->nhr_encap_size);
            for (i = 0; i< req->nhr_encap_size; i++) {
                printf("%02x ", (unsigned char)req->nhr_encap[i]);
            }
            nh_print_newline_header();
        }
        if (!(req->nhr_flags & NH_FLAG_TUNNEL_PBB)) {
            if (req->nhr_family == AF_INET) {
                a.s_addr = req->nhr_tun_sip;
                printf("Sip:%s", inet_ntoa(a));
                a.s_addr = req->nhr_tun_dip;
                printf(" Dip:%s", inet_ntoa(a));
            } else if (req->nhr_family == AF_INET6) {
                printf("Sip: %s",
                    inet_ntop(AF_INET6, (struct in6_addr *)req->nhr_tun_sip6,
                    in6_dst, sizeof(in6_dst)));
                printf(" Dip: %s",
                    inet_ntop(AF_INET6, (struct in6_addr *)req->nhr_tun_dip6,
                    in6_dst, sizeof(in6_dst)));
            }
        }

        if (req->nhr_flags & NH_FLAG_TUNNEL_UDP) {
            nh_print_newline_header();
            printf("Sport:%d Dport:%d\n", ntohs(req->nhr_tun_sport),
                                                  ntohs(req->nhr_tun_dport));
        }

        if (req->nhr_flags & NH_FLAG_TUNNEL_PBB) {
            i = -1;
            if (req->nhr_label_list_size)
                i = req->nhr_label_list[0];
            printf("Bmac:"MAC_FORMAT " Label:%d",
                    MAC_VALUE((uint8_t *)req->nhr_pbb_mac), i);
        }
    } else if (req->nhr_type == NH_VRF_TRANSLATE) {
        nh_print_newline_header();
        printf("Vrf:%d", req->nhr_vrf);
    } else if (req->nhr_type == NH_COMPOSITE) {
        if (req->nhr_flags & NH_FLAG_COMPOSITE_ECMP) {
            if (req->nhr_ecmp_config_hash) {
                nh_print_newline_header();
                nh_ecmp_config_hash_str(req->nhr_ecmp_config_hash, flags_mem);
                printf("Valid Hash Key Parameters: %s", flags_mem);
            }
        }
        nh_print_newline_header();
        printf("Sub NH(label):");
        for (i = 0; i < req->nhr_nh_list_size; i++) {
            if (printed > 60) {
                nh_print_newline_header();
                printf("%14c", ' ');
                printed = 0;
            }
            printed += printf(" %d", req->nhr_nh_list[i]);
            if (req->nhr_label_list[i] >= 0)
                printed += printf("(%d)", req->nhr_label_list[i]);
        }

        if (req->nhr_nh_count &&
                (req->nhr_nh_count - req->nhr_nh_list_size)) {
            printf(" and %u more components...\n",
                    req->nhr_nh_count - req->nhr_nh_list_size);
        }
    }

    if (command == SANDESH_OP_DUMP) {
        dump_marker = req->nhr_id;
    }

    printf("\n\n");
    if (command == SANDESH_OP_GET) {
        if (req->nhr_type == NH_COMPOSITE) {
            for (i = 0; i < req->nhr_nh_list_size; i++) {
                // Skip expanding sub-nh for -1 index
                if (req->nhr_nh_list[i] == -1)
                    continue;
                vr_nh_op(cl, command, type, req->nhr_nh_list[i], if_id, vrf_id,
                            dst_mac, src_mac, sip, dip, flags);
            }
        }

        if ((req->nhr_flags & NH_FLAG_INDIRECT) && (req->nhr_nh_list_size)) {
            vr_nh_op(cl, command, type, req->nhr_nh_list[0], if_id, vrf_id,
                         dst_mac, src_mac, sip, dip, flags);
        }
    }
}

static void
response_process(void *s)
{
    vr_response_common_process((vr_response *)s, &dump_pending);
    return;
}

static void
nh_fill_nl_callbacks()
{
    nl_cb.vr_response_process = response_process;
    nl_cb.vr_nexthop_req_process = nexthop_req_process;
}

static int
vr_nh_op(struct nl_client *cl, int command, int type, uint32_t nh_id,
        uint32_t if_id, uint32_t vrf_id, int8_t *dst, int8_t  *src,
        struct in_addr sip, struct in_addr dip, uint32_t flags)
{
    int ret;
    bool dump = false;

op_retry:
    switch (command) {
    case SANDESH_OP_ADD:
        if (flags & NH_FLAG_TUNNEL_PBB) {
            ret = vr_send_pbb_tunnel_add(cl, 0, nh_id, flags,
                    vrf_id, dst, comp_nh[0], lbl[0]);
        } else if ((type == NH_ENCAP) || (type == NH_TUNNEL)) {
            ret = vr_send_nexthop_encap_tunnel_add(cl, 0, type, nh_id,
                    flags, vrf_id, if_id, src, dst, sip, dip, sport, dport);
        } else if (type == NH_COMPOSITE) {
            ret = vr_send_nexthop_composite_add(cl, 0, nh_id, flags, vrf_id,
                    comp_nh_ind, comp_nh, lbl);
        } else {
            ret = vr_send_nexthop_add(cl, 0, type, nh_id, flags, vrf_id, if_id);
        }

        break;

    case SANDESH_OP_DEL:
        ret = vr_send_nexthop_delete(cl, 0, nh_id);
        break;

    case SANDESH_OP_DUMP:
        dump = true;
        ret = vr_send_nexthop_dump(cl, 0, dump_marker);
       break;

    case SANDESH_OP_GET:
        ret = vr_send_nexthop_get(cl, 0, nh_id);
        break;

    default:
        ret = -EINVAL;
    }

    if (ret < 0)
        return ret;

    ret = vr_recvmsg(cl, dump);
    if (ret <= 0)
        return ret;

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
           "       [--root NH is an Etree Root]\n"
           "       [--rlkup Force Route Lookup]\n"
           "       [--type <type> type of the tunnel 1 - rcv, 2 - encap \n"
           "                       3 - tunnel, 4 - resolve, 5 - discard, 6 - Composite\n"
           "                       7 - VRF Translate, 8 - L2 Rcv NH] \n"
           "                [RCV_NH options]\n"
           "                    [--oif <if_id> out going interface index]\n"
           "                [L2RCV_NH options]\n"
           "                    [--oif <if_id> out going interface index]\n"
           "                [ENCAP_NH optionsi - default L3]\n"
           "                    [--el2 encap L2 ]\n"
           "                        [--oif <if_id> out going interface index]\n"
           "                    [--mc multicast nh]\n"
           "                    [--smac <xx:xx:xx:xx:xx:xx> source mac ]\n"
           "                    [--dmac <xx:xx:xx:xx:xx:xx> destination mac ]\n"
           "                    [--oif = out going interface index]\n"
           "                [TUNNEL_NH options - default Gre]\n"
           "                    [--pbb PBB tunnel options]\n"
           "                        [--cni <nh_id> direct nh member id]\n"
           "                        [--lbl <lbl> Evpn label for PBB tunnel]\n"
           "                        [--dmac <xx:xx:xx:xx:xx:xx> destination Bmac]\n"
           "                        [--ind indirect flag]\n"
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
           "                [VRF Translate options]\n"
           "                    [--vxlan Vxlan VRF Translation]\n"
           "                    [--uucf Unknown Unicast Flood]\n");
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
    RLKUP_OPT_IND,
    LBL_OPT_IND,
    UUCF_OPT_IND,
    LST_OPT_IND,
    GET_OPT_IND,
    CRT_OPT_IND,
    DEL_OPT_IND,
    CMD_OPT_IND,
    IND_OPT_IND,
    PBB_OPT_IND,
    ROOT_OPT_IND,
    ML_OPT_IND,
    HLP_OPT_IND,
    MAX_OPT_IND
};

static int opt[MAX_OPT_IND], zero_opt[MAX_OPT_IND];

static bool
opt_set(int ind)
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
    [TOR_OPT_IND]       = {"tor",   no_argument,        &opt[TOR_OPT_IND],      1},
    [RLKUP_OPT_IND]     = {"rlkup", no_argument,        &opt[RLKUP_OPT_IND],    1},
    [LBL_OPT_IND]       = {"lbl",   required_argument,  &opt[LBL_OPT_IND],      1},
    [UUCF_OPT_IND]      = {"uucf",  no_argument,        &opt[UUCF_OPT_IND],     1},
    [LST_OPT_IND]       = {"list",  no_argument,        &opt[LST_OPT_IND],      1},
    [GET_OPT_IND]       = {"get",   required_argument,  &opt[GET_OPT_IND],      1},
    [CRT_OPT_IND]       = {"create", required_argument, &opt[CRT_OPT_IND],      1},
    [DEL_OPT_IND]       = {"delete", required_argument, &opt[DEL_OPT_IND],      1},
    [CMD_OPT_IND]       = {"cmd",   no_argument,        &opt[CMD_OPT_IND],      1},
    [IND_OPT_IND]       = {"ind",   no_argument,        &opt[IND_OPT_IND],      1},
    [PBB_OPT_IND]       = {"pbb",   no_argument,        &opt[PBB_OPT_IND],      1},
    [ROOT_OPT_IND]      = {"root",  no_argument,        &opt[ROOT_OPT_IND],     1},
    [ML_OPT_IND]        = {"ml",    no_argument,        &opt[ML_OPT_IND],       1},
    [HLP_OPT_IND]       = {"help",  no_argument,        &opt[HLP_OPT_IND],      1},
    [MAX_OPT_IND]       = { NULL,   0,                  0,                      0}
};

static void
parse_long_opts(int ind, char *opt_arg)
{
    int errno;
    struct ether_addr *mac;

    errno = 0;
    switch (ind) {
    case CMD_OPT_IND:
        cmd_usage();
        break;

    case HLP_OPT_IND:
        usage();
        break;

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
        break;

    case DPORT_OPT_IND:
        dport = strtoul(opt_arg, NULL, 0);
        if (errno)
            usage();
        break;
    }

    return;
}

static void
validate_options(void)
{
    if (opt_set(CRT_OPT_IND)) {
        command = SANDESH_OP_ADD;
    } else if (opt_set(DEL_OPT_IND)) {
        command = SANDESH_OP_DEL;
    } else if (opt_set(GET_OPT_IND)) {
        command = SANDESH_OP_GET;
    } else if (opt_set(LST_OPT_IND)) {
        command = SANDESH_OP_DUMP;
    } else {
        usage();
        return;
    }


    switch (command) {
    case SANDESH_OP_ADD:
        if (!nh_set)
            cmd_usage();

        flags |= NH_FLAG_VALID;
        if (!opt_set(TYPE_OPT_IND))
            cmd_usage();

         if(!opt_set(VRF_OPT_IND))
            cmd_usage();

        if (opt_set(MC_OPT_IND))
            flags |= NH_FLAG_MCAST;

        if (opt_set(POL_OPT_IND))
            flags |= NH_FLAG_POLICY_ENABLED;

        if (opt_set(IND_OPT_IND))
            flags |= NH_FLAG_INDIRECT;

        if (opt_set(RPOL_OPT_IND))
            flags |= NH_FLAG_RELAXED_POLICY;

        if (opt_set(RLKUP_OPT_IND))
            flags |= NH_FLAG_ROUTE_LOOKUP;

        if (opt_set(ML_OPT_IND))
            flags |= NH_FLAG_MAC_LEARN;

        if (opt_set(ROOT_OPT_IND))
            flags |= NH_FLAG_ETREE_ROOT;

        if (type == NH_RCV) {
            if (!opt_set(OIF_OPT_IND))
                cmd_usage();

            if (memcmp(opt, zero_opt, sizeof(opt)))
                cmd_usage();
        } else if (type == NH_L2_RCV) {
            if (memcmp(opt, zero_opt, sizeof(opt)))
                cmd_usage();
        } else if (type == NH_ENCAP) {
            if (!opt_set(OIF_OPT_IND))
                cmd_usage();

            if (!opt_set(EL2_OPT_IND)) {
                if (!opt_set(SMAC_OPT_IND) || !opt_set(DMAC_OPT_IND))
                    cmd_usage();

                if (memcmp(opt, zero_opt, sizeof(opt)))
                    cmd_usage();
            } else {
                flags |= NH_FLAG_ENCAP_L2;
            }

        } else if (type == NH_TUNNEL) {

            if (opt_set(PBB_OPT_IND)) {
                if (!opt_set(CNI_OPT_IND)) {
                    cmd_usage();
                }

                if (comp_nh_ind != 1)
                    cmd_usage();

                if (!opt_set(LBL_OPT_IND) || !opt_set(DMAC_OPT_IND))
                    cmd_usage();

                flags |= NH_FLAG_TUNNEL_PBB;

            } else if (!opt_set(OIF_OPT_IND) || !opt_set(SMAC_OPT_IND) ||
                    !opt_set(DMAC_OPT_IND) || !opt_set(SIP_OPT_IND) ||
                    !opt_set(DIP_OPT_IND)) {
                cmd_usage();
            }

            if (opt_set(UDP_OPT_IND)) {
                if (!opt_set(SPORT_OPT_IND) || !opt_set(DPORT_OPT_IND))
                    flags |= NH_FLAG_TUNNEL_UDP_MPLS;
                else
                    flags |= NH_FLAG_TUNNEL_UDP;
            } else if (opt_set(VXLAN_OPT_IND)) {
                flags |= NH_FLAG_TUNNEL_VXLAN;
                if (!opt_set(SPORT_OPT_IND) || !opt_set(DPORT_OPT_IND))
                    cmd_usage();
            }

            if (!(flags & (NH_FLAG_TUNNEL_UDP_MPLS | NH_FLAG_TUNNEL_UDP |
                        NH_FLAG_TUNNEL_VXLAN | NH_FLAG_TUNNEL_PBB)))
                flags |= NH_FLAG_TUNNEL_GRE;

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

            if (opt_set(CEVPN_OPT_IND)) {
                flags |= NH_FLAG_COMPOSITE_EVPN;

                if (!opt_set(LBL_OPT_IND))
                    cmd_usage();
            }

            if (opt_set(TOR_OPT_IND)) {
                flags |= NH_FLAG_COMPOSITE_TOR;

                if (!opt_set(LBL_OPT_IND))
                    cmd_usage();
            }

            if (memcmp(opt, zero_opt, sizeof(opt)))
                cmd_usage();

        } else if (type == NH_VRF_TRANSLATE) {
            if (opt_set(UUCF_OPT_IND))
                flags |= NH_FLAG_UNKNOWN_UC_FLOOD;
        } else {
            cmd_usage();
        }

        break;

    case SANDESH_OP_DEL:
        if (!nh_set)
            cmd_usage();

        if (memcmp(opt, zero_opt, sizeof(opt)))
            cmd_usage();
        break;

    case SANDESH_OP_DUMP:
    case SANDESH_OP_GET:
        if (memcmp(opt, zero_opt, sizeof(opt)))
            usage();
        break;
    }

    return;
}


int
main(int argc, char *argv[])
{
    int opt, ind;

    nh_fill_nl_callbacks();

    while ((opt = getopt_long(argc, argv, "",
                    long_options, &ind)) >= 0) {
        switch (opt) {
        case 0:
            parse_long_opts(ind, optarg);
            break;

        default:
            usage();
        }
    }

    validate_options();

    cl = vr_get_nl_client(VR_NETLINK_PROTO_DEFAULT);
    if (!cl) {
        exit(1);
    }

    vr_nh_op(cl, command, type, nh_id, if_id, vrf_id, dst_mac,
            src_mac, sip, dip, flags);

    return 0;
}
