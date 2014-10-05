/*
 *  rt.c
 *
 *  Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
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
#include <net/ethernet.h>
#endif

#include "vr_types.h"
#include "vr_nexthop.h"
#include "vr_genetlink.h"
#include "nl_util.h"
#include "vr_mpls.h"
#include "vr_defs.h"
#include "vr_route.h"
#include "vr_bridge.h"
#include "vr_os.h"

static struct nl_client *cl;
static int resp_code;
static vr_route_req rt_req;
static uint8_t rt_prefix[16], rt_src[16], rt_marker[16];
static bool cmd_proxy_set = false;

static int cmd_set, dump_set;
static int family_set, help_set;
static int table_set;

static int cmd_prefix_set;
static int cmd_dst_mac_set;

static int cmd_vrf_id = -1, cmd_family_id;
static int cmd_op = -1;

static int cmd_nh_id = -1;
static uint8_t cmd_prefix[16], cmd_src[16];
static uint32_t cmd_plen = 0;
static int32_t cmd_label;
static int cmd_rt_type = RT_UCAST;
static uint32_t cmd_replace_plen = 100;
static char cmd_dst_mac[6];
static void Usage(void);
static void usage_internal(void);

#define INET_FAMILY_STRING      "inet"
#define BRIDGE_FAMILY_STRING    "bridge"
#define INET6_FAMILY_STRING      "inet6"

#define UCST_TABLE_STRING       "ucst"
#define MCST_TABLE_STRING       "mcst"

static int
table_string_to_id(char *tname)
{
    if (!strncmp(tname, UCST_TABLE_STRING, strlen(UCST_TABLE_STRING)))
        return RT_UCAST;
    else if (!strncmp(tname, MCST_TABLE_STRING, strlen(MCST_TABLE_STRING)))
        return RT_MCAST;
    return -1;
}
static int
family_string_to_id(char *fname)
{
    if (!strncmp(fname, INET_FAMILY_STRING, strlen(INET_FAMILY_STRING)))
        return AF_INET;
    else if (!strncmp(fname, BRIDGE_FAMILY_STRING, strlen(BRIDGE_FAMILY_STRING)))
        return AF_BRIDGE;
    else if (!strncmp(fname, INET6_FAMILY_STRING, strlen(INET6_FAMILY_STRING)))
        return AF_INET6;

    return -1;
}

void
vr_route_req_process(void *s_req)
{
    int ret = 0, i;
    int8_t addr[16];
    char flags[4];
    vr_route_req *rt = (vr_route_req *)s_req;

    if (!rt_req.rtr_prefix) {
        rt_req.rtr_prefix = rt_prefix;
        rt_req.rtr_marker = rt_marker;
        rt_req.rtr_src    = rt_src;
            
    }
    rt_req.rtr_prefix_size = rt_req.rtr_marker_size = rt_req.rtr_src_size = 0;


    if (rt->rtr_prefix_size) {
        memcpy(rt_req.rtr_prefix, rt->rtr_prefix, RT_IP_ADDR_SIZE(rt->rtr_family));
        memcpy(rt_req.rtr_marker, rt->rtr_prefix, RT_IP_ADDR_SIZE(rt->rtr_family));
        rt_req.rtr_prefix_size = rt_req.rtr_marker_size = RT_IP_ADDR_SIZE(rt->rtr_family);
    } else {
        memset(rt_req.rtr_prefix, 0, 16);
        memset(rt_req.rtr_marker, 0, 16);
    }
        
    if (rt->rtr_src_size) {
        memcpy(rt_req.rtr_src, rt->rtr_src, RT_IP_ADDR_SIZE(rt->rtr_family));
        rt_req.rtr_src_size = RT_IP_ADDR_SIZE(rt->rtr_family);
    } else {
        memset(rt_req.rtr_src, 0, 16);
    }

    rt_req.rtr_prefix_len = rt->rtr_prefix_len;
    rt_req.rtr_rt_type = rt->rtr_rt_type;
    if (rt->rtr_mac) {
        if (!rt_req.rtr_mac) {
            rt_req.rtr_mac_size = 6;
            rt_req.rtr_mac = calloc(1, 6);
        }
        memcpy(rt_req.rtr_mac, rt->rtr_mac, 6);
    }
    rt_req.rtr_vrf_id = rt->rtr_vrf_id;

    if ((rt->rtr_family == AF_INET) ||
        (rt->rtr_family == AF_INET6)) {
        if (rt->rtr_rt_type == RT_UCAST) {
            
            if (rt->rtr_prefix_size) {
                inet_ntop(rt->rtr_family, rt->rtr_prefix, addr, 16);
                ret = printf("%s/%-2d", addr, rt->rtr_prefix_len);
            }
            for (i = ret; i < 21; i++)
                printf(" ");

            printf("  ");
            printf("%4d", rt->rtr_replace_plen);

            for (i = 0; i < 8; i++)
                printf(" ");

            bzero(flags, sizeof(flags));
            if (rt->rtr_label_flags & VR_RT_LABEL_VALID_FLAG)
                strcat(flags, "L");
            if (rt->rtr_label_flags & VR_RT_HOSTED_FLAG)
                strcat(flags, "H");

            printf("%5s", flags);

            for (i = 0; i < 8; i++)
                printf(" ");

            if (rt->rtr_label_flags & VR_RT_LABEL_VALID_FLAG)
                printf("%5d", rt->rtr_label);
            else
                printf("%5c", '-');

            for (i = 0; i < 8; i++)
                printf(" ");

            printf("%7d", rt->rtr_nh_id);
            printf("\n");
        } else { 
            if (rt->rtr_src_size)
                inet_ntop(rt->rtr_family, rt->rtr_src, addr, 16);
            ret = printf("%s,", addr);
            if (rt->rtr_prefix_size)
                inet_ntop(rt->rtr_family, rt->rtr_prefix, addr, 16);
            ret += printf("%s", addr);
            for (i = ret; i < 33; i++)
                printf(" ");
            printf(" ");
            printf("%7d", rt->rtr_nh_id);
            printf("\n");
        }
    } else {
        ret = printf("%s", ether_ntoa((struct ether_addr *)(rt->rtr_mac)));
        for(i = ret; i < 21; i++)
            printf(" ");

        ret = printf("%5d", rt->rtr_vrf_id);
        for(i = ret; i < 12; i++)
            printf(" ");
        if (rt->rtr_label_flags & VR_RT_LABEL_VALID_FLAG)
            ret = printf("%5d", rt->rtr_label);
        else
            ret = printf("%5c", '-');
        for(i = ret; i < 12; i++)
            printf(" ");
        printf("%7d\n",rt->rtr_nh_id);
    }

    return;
}

void
vr_response_process(void *s)
{
    vr_response *rt_resp;

    rt_resp = (vr_response *)s;
    resp_code = rt_resp->resp_code;

    if (rt_resp->resp_code < 0)
        printf("Error %s in kernel operation\n", strerror(rt_resp->resp_code));

    return;
}


static vr_route_req *
vr_build_route_request(unsigned int op, int family, int8_t *prefix, 
        unsigned int p_len, unsigned int nh_id, unsigned int vrf, int label, 
        unsigned int rt_type, int8_t *src, char *eth, uint32_t replace_plen)
{
    int i;
    char buf[64];
    rt_req.rtr_family = family;
    rt_req.rtr_vrf_id = vrf;
    rt_req.rtr_rid = 0;
    rt_req.h_op = op;

    if (!rt_req.rtr_prefix) {
        rt_req.rtr_prefix = rt_prefix;
        rt_req.rtr_marker = rt_marker;
        rt_req.rtr_src    = rt_src;
    }
    rt_req.rtr_prefix_size = rt_req.rtr_marker_size = rt_req.rtr_src_size = 0;

    switch (rt_req.h_op) {
    case SANDESH_OP_DUMP:
        if (prefix) {
            memcpy(rt_req.rtr_prefix, prefix, RT_IP_ADDR_SIZE(family));
            memcpy(rt_req.rtr_marker, prefix, RT_IP_ADDR_SIZE(family));
            rt_req.rtr_marker_size = rt_req.rtr_prefix_size = RT_IP_ADDR_SIZE(family);
        } else {
            memset(rt_req.rtr_prefix, 0, 16);
            memset(rt_req.rtr_marker, 0, 16);
        }
        if (src) {
            memcpy(rt_req.rtr_src, src, RT_IP_ADDR_SIZE(family));
            rt_req.rtr_src_size = RT_IP_ADDR_SIZE(family);
        } else {
            memset(rt_req.rtr_src, 0, 16);
        }

        rt_req.rtr_marker_plen = p_len;
        rt_req.rtr_rt_type = rt_type;
        rt_req.rtr_vrf_id = vrf;
        if (!rt_req.rtr_mac) {
            rt_req.rtr_mac_size = 6;
            rt_req.rtr_mac = calloc(1, 6);
        }
        memcpy(rt_req.rtr_mac, eth, 6);
        break;

    default:
        rt_req.rtr_nh_id = nh_id;
        if (cmd_prefix_set) {
            memcpy(rt_req.rtr_prefix, prefix, RT_IP_ADDR_SIZE(family));
            rt_req.rtr_prefix_size = RT_IP_ADDR_SIZE(family);

            inet_ntop(family, rt_req.rtr_prefix, buf, sizeof(buf));
            printf ("Adding prefix %s \n Prefix: ", buf);
            for (i=0; i< RT_IP_ADDR_SIZE(family); i++) {
                 printf("%x:", prefix[i]);
            }
            printf ("\n");
        } else {
            rt_req.rtr_prefix = NULL;
        }
            
        rt_req.rtr_prefix_len = p_len;
        rt_req.rtr_label_flags = 0;
        rt_req.rtr_rt_type = rt_type;
        rt_req.rtr_replace_plen = replace_plen;

        if (cmd_proxy_set)
            rt_req.rtr_label_flags |= VR_RT_HOSTED_FLAG;

        if ((family == AF_INET) ||
            (family == AF_INET6)) {
            if (rt_type == RT_UCAST) {
                *rt_req.rtr_src = 0;
            } else {
                memcpy(rt_req.rtr_src, src, RT_IP_ADDR_SIZE(family));
                rt_req.rtr_src_size = RT_IP_ADDR_SIZE(family);
            }
            if (label != -1) {
                rt_req.rtr_label = label;
                rt_req.rtr_label_flags |= VR_RT_LABEL_VALID_FLAG;
            }
        } else {
            rt_req.rtr_mac = calloc(1,6);
            rt_req.rtr_mac_size = 6;
            memcpy(rt_req.rtr_mac, eth, 6); 
            if (label != -1) {
                rt_req.rtr_label = label;
                rt_req.rtr_label_flags |= VR_RT_LABEL_VALID_FLAG;
            }
        }
        break;
    }

    return &rt_req;
}

static int
vr_build_netlink_request(vr_route_req *req)
{
    int ret, error = 0, attr_len;

    /* nlmsg header */
    ret = nl_build_nlh(cl, cl->cl_genl_family_id, NLM_F_REQUEST);
    if (ret)
        return ret;

    /* Generic nlmsg header */
    ret = nl_build_genlh(cl, SANDESH_REQUEST, 0);
    if (ret)
        return ret;

    attr_len = nl_get_attr_hdr_size();
    ret = sandesh_encode(req, "vr_route_req", vr_find_sandesh_info, 
                             (nl_get_buf_ptr(cl) + attr_len),
                             (nl_get_buf_len(cl) - attr_len), &error);

    if ((ret <= 0) || error)
        return -1;

    /* Add sandesh attribute */
    nl_build_attr(cl, ret, NL_ATTR_VR_MESSAGE_PROTOCOL);
    nl_update_nlh(cl);

    return 0;
}

static int
vr_send_one_message(void)
{
    int ret;
    struct nl_response *resp;

    ret = nl_sendmsg(cl);
    if (ret <= 0)
        return 0;

    while ((ret = nl_recvmsg(cl)) > 0) {
        resp = nl_parse_reply(cl);
        if (resp->nl_op == SANDESH_REQUEST)
            sandesh_decode(resp->nl_data, resp->nl_len, vr_find_sandesh_info, &ret);
    }

    return resp_code;
}

static void
vr_route_dump(void)
{
    while (vr_send_one_message() != 0) {
        vr_build_route_request(SANDESH_OP_DUMP, rt_req.rtr_family, rt_req.rtr_marker,
                rt_req.rtr_marker_plen, 0, rt_req.rtr_vrf_id, 0, 
                rt_req.rtr_rt_type, rt_req.rtr_src, (char *)rt_req.rtr_mac, 0);
        vr_build_netlink_request(&rt_req);
    }

    return;
}

static void
vr_do_route_op(int op)
{
    if (op == SANDESH_OP_DUMP)
        vr_route_dump();
    else
        vr_send_one_message();

    return;
}

static int 
vr_route_op(void)
{
    vr_route_req *req;
    int ret;

    req = vr_build_route_request(cmd_op, cmd_family_id, cmd_prefix, cmd_plen,
            cmd_nh_id, cmd_vrf_id, cmd_label, cmd_rt_type,
            cmd_src, cmd_dst_mac, cmd_replace_plen);
    if (!req)
        return -errno;

    if (cmd_op == SANDESH_OP_DUMP) {
        if ((cmd_family_id == AF_INET) || (cmd_family_id == AF_INET6)) {
            if (cmd_rt_type == RT_UCAST) {
                printf("Kernel IP routing table %d/%d/unicast\n", req->rtr_rid, cmd_vrf_id);
                printf("Destination	        PPL        Flags        Label        Nexthop\n");
            } else {
                printf("Kernel IP routing table %d/%d/multicast\n", req->rtr_rid, cmd_vrf_id);
                printf("(Src,Group)                       Nexthop\n");
            }
        } else {
                printf("Kernel L2 Bridge table %d/%d\n", req->rtr_rid, cmd_vrf_id);
                printf("DestMac                 Vrf    Label/VNID     Nexthop\n");
        }
    }

    ret = vr_build_netlink_request(req);
    if (ret < 0)
        return ret;

    vr_do_route_op(cmd_op);

    return 0;
}

static void
usage_internal()
{
    printf("Usage: c - create\n"
           "       d - delete\n"
           "       b - dump\n"
           "       n <nhop_id> \n"
           "       p <prefix in dotted decimal form> \n"
           "       P <do proxy arp for this route> \n"
           "       l <prefix_length>\n"
           "       t <label/vnid>\n"
           "       f <family 0 - AF_INET 1 - AF_BRIDGE 2 - AF_INET6 >\n"
           "       e <mac address in : format>\n"
           "       r <replacement route preifx length for delete>\n"
           "       v <vrfid>\n");

    exit(1);
}

static void
validate_options(void)
{
    unsigned int set = dump_set + family_set + cmd_set + help_set;

    if (cmd_op < 0)
        goto usage;

    switch (cmd_op) {
    case SANDESH_OP_DUMP:
        if (cmd_vrf_id < 0)
            goto usage;

        if (set > 1 && !family_set)
            goto usage;

        if (cmd_family_id == AF_BRIDGE &&
                cmd_rt_type == RT_MCAST) {
            printf("There is no separate multicast table\n");
            Usage();
        }

        break;

    case SANDESH_OP_DELETE:
        if ((cmd_family_id == AF_INET) || (cmd_family_id == AF_INET6)) {
            if (cmd_rt_type == RT_UCAST) {
                if ((cmd_replace_plen < 0 || 
                    ( cmd_replace_plen > (RT_IP_ADDR_SIZE(cmd_family_id)*4)))) {
                    goto usage_internal;
                }

                if (!cmd_prefix_set || cmd_plen < 0 || cmd_nh_id  < 0 || cmd_vrf_id < 0)
                    goto usage_internal;
            }
        } else if (cmd_family_id == AF_BRIDGE) {
            if (!cmd_dst_mac_set || cmd_vrf_id < 0)
                goto usage_internal;
        }

        break;

    case SANDESH_OP_ADD:
        if ((cmd_family_id == AF_INET) || (cmd_family_id == AF_INET6)) {
            if (cmd_rt_type == RT_UCAST) {
                if (!cmd_prefix_set || cmd_plen < 0 || cmd_nh_id  < 0 || cmd_vrf_id < 0)
                    goto usage_internal;
            }
        } else if (cmd_family_id == AF_BRIDGE) {
            if (!cmd_dst_mac_set || cmd_vrf_id < 0 || cmd_nh_id < 0)
                goto usage_internal;
        }

        break;

    default:
        goto usage_internal;
    }

    return;

usage:
    Usage();
    return;

usage_internal:
    usage_internal();
    return;
}

enum opt_flow_index {
    COMMAND_OPT_INDEX,
    DUMP_OPT_INDEX,
    FAMILY_OPT_INDEX,
    HELP_OPT_INDEX,
    TABLE_OPT_INDEX,
    MAX_OPT_INDEX,
};

static struct option long_options[] = {
    [COMMAND_OPT_INDEX]   = {"cmd",    no_argument,       &cmd_set,    1},
    [DUMP_OPT_INDEX]      = {"dump",   required_argument, &dump_set,   1},
    [FAMILY_OPT_INDEX]    = {"family", required_argument, &family_set, 1},
    [HELP_OPT_INDEX]      = {"help",   no_argument,       &help_set,   1},
    [TABLE_OPT_INDEX]     = {"table",  required_argument, &table_set,  1},
    [MAX_OPT_INDEX]       = { NULL,    0,                 0,           0},
};

static void
Usage(void)
{
    printf("Usage:   rt --dump <vrf_id> [--family <inet|bridge>][--table <ucst|mcst>\n");
    printf("         rt --help\n");
    printf("\n");
    printf("--dump   Dumps the routing table corresponding to vrf_id\n");
    printf("--family Optional family specification to --dump command\n");
    printf("         Specification should be one of \"inet\" or \"bridge\"\n");
    printf("--table  Specify the type of the table to dump. Valid only for inet\n");
    printf("         Type can be one of \"ucst\" or \"mcst\"\n");
    printf("--help   Prints this help message\n");

    exit(1);
}

static void
parse_long_opts(int opt_flow_index, char *opt_arg)
{
    errno = 0;
    switch (opt_flow_index) {
    case COMMAND_OPT_INDEX:
        usage_internal();
        break;

    case DUMP_OPT_INDEX:
        cmd_op = SANDESH_OP_DUMP;
        cmd_vrf_id = strtoul(opt_arg, NULL, 0);
        if (errno)
            Usage();
        break;

    case FAMILY_OPT_INDEX:
        cmd_family_id = family_string_to_id(opt_arg);
        if (cmd_family_id != AF_INET &&
                cmd_family_id != AF_BRIDGE &&
                cmd_family_id != AF_INET6)
            Usage();
        break;

    case TABLE_OPT_INDEX:
        cmd_rt_type = table_string_to_id(opt_arg);
        if (cmd_rt_type != RT_UCAST &&
                cmd_rt_type != RT_MCAST)
            Usage();
        break;

    case HELP_OPT_INDEX:
    default:
        Usage();
    }

    return;
}

int main(int argc, char *argv[])
{
    int ret;
    int opt;
    int option_index;
    struct ether_addr *cmd_eth;

    cmd_nh_id = -255;
    cmd_label = -1;
    cmd_family_id = AF_INET;

    while ((opt = getopt_long(argc, argv, "cdbmPn:p:l:v:t:s:e:f:r:",
                    long_options, &option_index)) >= 0) { 
            switch (opt) {
            case 'c':
                if (cmd_op >= 0) {
                    usage_internal();
                }
                cmd_op = SANDESH_OP_ADD;
                break;

            case 'd':
                if (cmd_op >= 0) {
                    usage_internal();
                }
                cmd_op = SANDESH_OP_DELETE;
                break;

            case 'b':
                if (cmd_op >= 0) {
                    usage_internal();
                }
                cmd_op = SANDESH_OP_DUMP;
                break;

            case 'v':
                cmd_vrf_id = atoi(optarg);
                break;      

            case 'n':
                cmd_nh_id = atoi(optarg);
                break;

            case 'p':
                /* 
                 * Try parsing for AF_INET first, if not try AF_INET6
                 */
                if (!inet_pton(AF_INET, optarg, cmd_prefix))
                    inet_pton(AF_INET6, optarg, cmd_prefix);
                cmd_prefix_set = 1;
                break;

            case 'l':
                cmd_plen = atoi(optarg);
                break;

            case 'r':
                cmd_replace_plen = atoi(optarg);
                break;

            case 't':
                cmd_label = atoi(optarg);
                break;

            case 's':
                /* 
                 * Try parsing for AF_INET first, if not try AF_INET6
                 */
                if (!inet_pton(AF_INET, optarg, cmd_src))
                    inet_pton(AF_INET6, optarg, cmd_src);
                break;

            case 'm':
                cmd_rt_type = RT_MCAST;
                break;

            case 'f':
                cmd_family_id = atoi(optarg);
                if (cmd_family_id == 0) {
                    cmd_family_id = AF_INET;
                } else if (cmd_family_id == 1) {
                    cmd_family_id = AF_BRIDGE;
                    cmd_rt_type = RT_UCAST;
                } else {
                    cmd_family_id = AF_INET6;
                }

                break;

            case 'e':
                cmd_eth = ether_aton(optarg);
                if (cmd_eth)
                    memcpy(cmd_dst_mac, cmd_eth, 6);
                cmd_dst_mac_set = 1;
                break;

            case 'P':
                cmd_proxy_set = true;
                break;

            case 0:
                parse_long_opts(option_index, optarg);
                break;

            case '?':
            default:
                Usage();
                break;
        }
    }

    validate_options();

    cl = nl_register_client();
    if (!cl) {
        printf("nl_register_client failed\n");
        exit(1);
    }

    ret = nl_socket(cl, NETLINK_GENERIC);    
    if (ret <= 0) {
        printf("nl_socket failed\n");
        exit(1);
    }

    if (vrouter_get_family_id(cl) <= 0) {
        printf("Unable to get vrouter family id\n");
        return -1;
    }

    vr_route_op();

    return 0;
}
