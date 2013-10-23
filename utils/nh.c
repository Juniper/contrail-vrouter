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
#include <malloc.h>
#include <stdbool.h>
#include <getopt.h>

#include <asm/types.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <asm/types.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_ether.h>

#include <net/if.h>
#include <netinet/ether.h>

#include "vr_types.h"
#include "vr_message.h"
#include "vr_nexthop.h"
#include "vr_genetlink.h"
#include "nl_util.h"

static struct nl_client *cl;
static char src_mac[50], dst_mac[50];
static int smac_set, dmac_set;
static uint32_t nh_id, if_id, vrf_id ;
static int nh_set, oif_set, dvrf_set;
static uint16_t flags;
static int pol_set;
static struct in_addr sip, dip;
static int sip_set, dip_set;
static uint16_t sport, dport;
static int sport_set, dport_set;
static int command;
static int udp_set;
static int vxlan_set;
static int type, type_set;
static bool dump_pending = false;
static int dump_marker = -1;
static int comp_nh[10];
static int lbl[10];
static int comp_nh_ind = 0;
static int lbl_ind = 0;
static int cni_set;
static int cmp_set;
static int cl3_set;
static int cl2_set;
static int cfa_set;
static int mcast_set;
static int el2_set;
static int lbl_set;

static int 
str_to_encap(char *str, char *mac)
{
    int i;
    char ch;
    unsigned int val;
    int len;

    i = 0;
    len = 0;
    while(str[i] != 0) {
      
       val = 0; 
       ch = str[i];
       if (ch >= '0' && ch <= '9') 
           val = ch - '0';
       if (ch >= 'a' && ch <= 'f')
           val = (ch - 'a') + 10;
  
       if (str[i+1] != 0) { 
           val *= 16;

           ch = str[i+1];
           if (ch >= '0' && ch <= '9') 
               val += (ch - '0');
           if (ch >= 'a' && ch <= 'f')
               val += ((ch - 'a') + 10);
       } else {
           break;
       }

       mac[len++] = val;
       i += 2;
    }

    return len;
}


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
       case NH_VXLAN_VRF:
           return "Vxlan Vrf";
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
    for(i = 1, mask = 1; (i < 16); i++, mask = mask << 1) { 
        switch(flags & mask) {
        case NH_FLAG_VALID:
            strcat(ptr, "Valid, ");
            break;

        case NH_FLAG_POLICY_ENABLED:
            strcat(ptr, "Policy, ");
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

        case NH_FLAG_COMPOSITE_L3:
            if (type == NH_COMPOSITE)
                strcat(ptr, "L3, ");
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

        case NH_FLAG_COMPOSITE_MULTI_PROTO:
            if (type == NH_COMPOSITE)
                strcat(ptr, "Multi Proto, ");
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

    if (req->nhr_type == NH_VXLAN_VRF) {
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
        char *dst, char *src, struct in_addr sip, struct in_addr dip, uint32_t flags)
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
        nh_req.nhr_encap_family = ETH_P_ARP;
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
            str_to_encap(dst, buf);
            str_to_encap(src, buf+6);
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
                    nh_req.nhr_label_list[i] = (i + 100);

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
    else if ((mode == NH_COMPOSITE) && (flags &
                NH_FLAG_COMPOSITE_MULTI_PROTO))
        nh_req.nhr_family = AF_UNSPEC;
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
usage()
{
    printf("Usage: b - bulk dump\n"
           "       c - create\n"
           "       d - delete\n"
           "       g - get\n"
           "       [--nh = nhop_index ]\n"
           "       [--oif = out going interface index]\n"
           "       [--smac = source mac ]\n"
           "       [--dmac = destination ]\n"
           "       [--type = type of the tunnel 1 - rcv, 2 - encap, 3 - tunnel, 4 - resolve, 5 - discard, 6 - Composite, 7 - Vxlan VRF] \n"
           "       [--sip = x.x.x.x source ip of tunnel] \n"
           "       [--dip = x.x.x.x destination ip of tunnel ]\n"
           "       [--sport = src_port of udp tunnel]\n"
           "       [--dport = dsr_port of udp tunnel]\n"
           "       [--dip = x.x.x.x destination ip of tunnel ]\n"
           "       [--vrf = vrf_id]\n"
           "       [--pol = policy flag on interface ]\n"
           "       [--cni = composite nexthop member id]\n"
           "       [--cl3 = composite l3 nexhop]\n"
           "       [--cl2 = composite l2 nexhop]\n"
           "       [--cmp = composit multiprotocol ]\n"
           "       [--udp = udp tunnel ]\n"
           "       [--vxlan = vxlan tunnel ]\n"
           "       [--el2 = encap L2 ]\n"
           "       [--cfa = composit fabric ]\n"
           "       [--lbl = ilabel for composit fabric ]\n"
           "       [--mc = multicast nh]\n");
    exit(-EINVAL);
                      

}

enum opt_index {
    NH_OPT_IND,
    OIF_OPT_IND,
    SMAC_OPT_IND,
    DMAC_OPT_IND,
    DVRF_OPT_IND,
    TYPE_OPT_IND,
    SIP_OPT_IND,
    DIP_OPT_IND,
    POL_OPT_IND,
    SPORT_OPT_IND,
    DPORT_OPT_IND,
    UDP_OPT_IND,
    VXLAN_OPT_IND,
    CNI_OPT_IND,
    CMP_OPT_IND,
    CL3_OPT_IND,
    CL2_OPT_IND,
    CFA_OPT_IND,
    MC_OPT_IND,
    EL2_OPT_IND,
    LBL_OPT_IND,
    MAX_OPT_IND
};

static struct option long_options[] = {
    [NH_OPT_IND]    =   {"nh", required_argument, &nh_set, 1},
    [OIF_OPT_IND]    = {"oif", required_argument, &oif_set, 1},
    [SMAC_OPT_IND]    = {"smac", required_argument, &smac_set, 1},
    [DMAC_OPT_IND]    = {"dmac", required_argument, &dmac_set, 1},
    [DVRF_OPT_IND]    = {"dvrf", required_argument, &dvrf_set, 1},
    [TYPE_OPT_IND]  = {"type", required_argument, &type_set, 1},
    [SIP_OPT_IND]  = {"sip", required_argument, &sip_set, 1},
    [DIP_OPT_IND]  = {"dip", required_argument, &dip_set, 1},
    [POL_OPT_IND]  = {"pol", no_argument, &pol_set, 1},
    [SPORT_OPT_IND]  = {"sport", required_argument, &sport_set, 1},
    [DPORT_OPT_IND]  = {"dport", required_argument, &dport_set, 1},
    [UDP_OPT_IND]  = {"udp", no_argument, &udp_set, 1},
    [VXLAN_OPT_IND]  = {"vxlan", no_argument, &vxlan_set, 1},
    [CNI_OPT_IND]  = {"cni", required_argument, &cni_set, 1},
    [CMP_OPT_IND]  = {"cmp", no_argument, &cmp_set, 1},
    [CL3_OPT_IND]  = {"cl3", no_argument, &cl3_set, 1},
    [CL2_OPT_IND]  = {"cl2", no_argument, &cl2_set, 1},
    [CFA_OPT_IND]  = {"cfa", no_argument, &cfa_set, 1},
    [MC_OPT_IND]  = {"mc", no_argument, &mcast_set, 1},
    [EL2_OPT_IND]  = {"el2", no_argument, &el2_set, 1},
    [LBL_OPT_IND] = {"lbl", required_argument, &lbl_set, 1},
    [MAX_OPT_IND]     = { NULL,  0,                 0        , 0}
};

static void
parse_long_opts(int ind, char *opt_arg)
{
    int errno;

    errno = 0;
    switch(ind) {
        case NH_OPT_IND:
            nh_id = strtoul(opt_arg, NULL, 0);
            if (errno) 
                usage();
            break;

        case OIF_OPT_IND:
            if_id = strtoul(opt_arg, NULL, 0);
            if (errno) 
                usage();
            break;
        case SMAC_OPT_IND:
            strcpy(src_mac, opt_arg);
            break;
        case DMAC_OPT_IND:
            strcpy(dst_mac, opt_arg);
            break;
        case DVRF_OPT_IND:
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

    switch (command) {
        case 1:
            if (!nh_set) {
                usage();
            }

            if (type == NH_RCV) {
                if (oif_set || smac_set || dmac_set || dvrf_set || 
                            sip_set || dip_set || pol_set || 
                            sport_set || dport_set || udp_set ||
                            vxlan_set) {
                    usage();
                }
            } else if (type == NH_ENCAP) {
                
                if (el2_set && (!oif_set || smac_set || dmac_set || sip_set ||
                        dip_set || sport_set || dport_set || udp_set ||
                        vxlan_set)) 
                    usage();

                    if (!el2_set && (!oif_set || !smac_set || !dmac_set || sip_set ||
                        dip_set || sport_set || dport_set || udp_set ||
                        vxlan_set)) {
                    usage();
                }
            } else if (type == NH_TUNNEL) {
                if (!oif_set || !smac_set || !dmac_set || !sip_set ||
                        !dip_set) {
                    usage();
                }

                if ((udp_set && (!sport_set || !dport_set)) || 
                        (!udp_set && (dport_set || sport_set))) {
                    usage();

                }

            } else if (type == NH_RESOLVE) {
                if (oif_set || smac_set || dmac_set || dvrf_set || 
                            sip_set || dip_set || pol_set || 
                            sport_set || dport_set || udp_set ||
                            vxlan_set) {
                    usage();
                }
            } else if (type == NH_DISCARD) {
                if (oif_set || smac_set || dmac_set || dvrf_set || 
                            sip_set || dip_set || pol_set || 
                            sport_set || dport_set || udp_set ||
                            vxlan_set) {
                    usage();
                }
            } else if (type == NH_COMPOSITE) {
                if (!cni_set || oif_set || smac_set || 
                            dmac_set || dvrf_set || sip_set || dip_set || 
                            pol_set || sport_set || dport_set || udp_set
                            || vxlan_set) {
                        usage();
                 }
            } else if (type != NH_VXLAN_VRF) {
                usage();
            }
            break;

        case 2:
            if (!nh_set || oif_set || smac_set || dmac_set || dvrf_set || 
                            sip_set || dip_set || pol_set || 
                            sport_set || dport_set || udp_set ||
                            vxlan_set) {
                    usage();
            }
            break;

        case 3:
            if (nh_set || oif_set || smac_set || dmac_set || dvrf_set || 
                            sip_set || dip_set || pol_set || 
                            sport_set || dport_set || udp_set ||
                            vxlan_set) {
                    usage();
            }
            break;
        case 4:
            if (!nh_set || oif_set || smac_set || dmac_set || dvrf_set || 
                            sip_set || dip_set || pol_set || 
                            sport_set || dport_set || udp_set ||
                            vxlan_set) {
                    usage();
            }
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

    while ((opt = getopt_long(argc, argv, "bcdg",
                                        long_options, &ind)) >= 0) {
        switch(opt) {
            case 'c':
                command = 1;
                break;
            case 'd':
                command = 2;
                break;
            case 'b':
                command = 3;
                break;
            case 'g':
                command = 4;
                break;
            case 0:
                parse_long_opts(ind, optarg);
                break;

            default:
                usage();
        }

    }

    validate_options();

    if (command == 1) {
        flags = NH_FLAG_VALID;

        if (mcast_set)
            flags |= NH_FLAG_MCAST;

        if (type == NH_TUNNEL) {
            if (udp_set)
                flags |= NH_FLAG_TUNNEL_UDP;
            else if (vxlan_set)
                flags |= NH_FLAG_TUNNEL_VXLAN;
            else
                flags |= NH_FLAG_TUNNEL_GRE;
        }

        if (type == NH_COMPOSITE) {
            if (cl3_set)
                flags |= NH_FLAG_COMPOSITE_L3;
            if (cl2_set)
                flags |= NH_FLAG_COMPOSITE_L2;
            if (cfa_set)
                flags |= NH_FLAG_COMPOSITE_FABRIC;
            if (cmp_set)
                flags |= NH_FLAG_COMPOSITE_MULTI_PROTO;
        }

        if (type == NH_ENCAP) {
            if (el2_set)
                flags |= NH_FLAG_ENCAP_L2;
        }

    }

    vr_nh_op(command, type, nh_id, if_id, vrf_id, dst_mac,
            src_mac, sip, dip, flags);


    return 0;
}
