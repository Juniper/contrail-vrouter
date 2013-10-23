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
#include <malloc.h>
#include <stdbool.h>

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
#include "vr_nexthop.h"
#include "vr_genetlink.h"
#include "nl_util.h"
#include "vr_mpls.h"
#include "vr_defs.h"
#include "vr_route.h"
#include "vr_bridge.h"

static struct nl_client *cl;
static int resp_code;
static vr_route_req rt_req;
static bool proxy_set = false;

void
vr_route_req_process(void *s_req)
{
    int ret, i;
    struct in_addr addr;
    vr_route_req *rt = (vr_route_req *)s_req;

    rt_req.rtr_marker = rt->rtr_prefix;
    rt_req.rtr_marker_plen = rt->rtr_prefix_len;
    rt_req.rtr_prefix = rt->rtr_prefix;
    rt_req.rtr_prefix_len = rt->rtr_prefix_len;
    rt_req.rtr_src = rt->rtr_src;
    rt_req.rtr_rt_type = rt->rtr_rt_type;
    if (rt->rtr_mac) {
        if (!rt_req.rtr_mac) {
            rt_req.rtr_mac_size = 6;
            rt_req.rtr_mac = calloc(1, 6);
        }
        memcpy(rt_req.rtr_mac, rt->rtr_mac, 6);
    }
    rt_req.rtr_vrf_id = rt->rtr_vrf_id;

    if (rt->rtr_family == AF_INET) {
        if (rt->rtr_rt_type == RT_UCAST) {
            addr.s_addr = htonl(rt->rtr_prefix);
            ret = printf("%s/%-2d	%-2d", inet_ntoa(addr), rt->rtr_prefix_len, rt->rtr_replace_plen);

            for (i = ret; i < 20; i++)
                printf(" ");
            printf("%5d        ", rt->rtr_label_flags);
            if (rt->rtr_label_flags & VR_RT_LABEL_VALID_FLAG)
                printf("%5d        ", rt->rtr_label);
            else
                printf("%5c        ", '-');
            printf("%7d", rt->rtr_nh_id);
            printf("\n");
        } else {
            addr.s_addr = htonl(rt->rtr_src);
            printf("%s, ", inet_ntoa(addr));
            addr.s_addr = htonl(rt->rtr_prefix);
            printf("%s    ", inet_ntoa(addr));
            printf("%8d", rt->rtr_nh_id);
            printf("\n");
        }
    } else {
        printf("%12s %5d", ether_ntoa((struct ether_addr *)(rt->rtr_mac)), rt->rtr_vrf_id);
        if (rt->rtr_label_flags & VR_RT_LABEL_VALID_FLAG)
            printf("%5d        ", rt->rtr_label);
        else
            printf("%5c        ", '-');
        printf("%3d \n",rt->rtr_nh_id); 
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
vr_build_route_request(unsigned int op, int family, unsigned int prefix, unsigned int p_len,
        unsigned int nh_id, unsigned int vrf, int label, 
        unsigned int rt_type, unsigned int src, char *eth, uint32_t replace_plen)
{
    rt_req.rtr_family = family;
    rt_req.rtr_vrf_id = vrf;
    rt_req.rtr_rid = 0;
    rt_req.h_op = op;

    switch (rt_req.h_op) {
    case SANDESH_OP_DUMP:
        rt_req.rtr_marker = prefix;
        rt_req.rtr_marker_plen = p_len;
        rt_req.rtr_src = src;
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
        rt_req.rtr_prefix = ntohl(prefix);
        rt_req.rtr_prefix_len = p_len;
        rt_req.rtr_label_flags = 0;
        rt_req.rtr_rt_type = rt_type;
        rt_req.rtr_replace_plen = replace_plen;

        if (proxy_set)
            rt_req.rtr_label_flags |= VR_RT_HOSTED_FLAG;

        if (family == AF_INET) {
            if (rt_type == RT_UCAST) {
                rt_req.rtr_src = 0;
            } else {
                rt_req.rtr_src = src;
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
vr_route_op(int opt, int family, uint32_t prefix, uint32_t len, 
                uint32_t nh_id, uint32_t vrf_id, int32_t label, 
                uint32_t rt_type, uint32_t src, char *eth, uint32_t replace_plen)
{
    vr_route_req *req;
    int ret;

    req = vr_build_route_request(opt, family, prefix, len, nh_id,
            vrf_id, label, rt_type, src, eth, replace_plen);
    if (!req)
        return -errno;

    if (opt == SANDESH_OP_DUMP) {
        if (family == AF_INET) {
            if (rt_type == RT_UCAST) {
                printf("Kernel IP routing table %d/%d/unicast\n", req->rtr_rid, vrf_id);
                printf("Destination	PrefixLen         Flags        Label          Nexthop\n");
            } else {
                printf("Kernel IP routing table %d/%d/multicast\n", req->rtr_rid, vrf_id);
                printf("(Src,Group)             Nexthop\n");
            }
        } else {
                printf("Kernel L2 Bridge table %d\n", req->rtr_rid);
                printf("DestMac Vrf Label/VNID          Nexthop\n");
        }
    }

    ret = vr_build_netlink_request(req);
    if (ret < 0)
        return ret;

    vr_do_route_op(opt);

    return 0;
}

void
usage()
{
    printf("Usage: c - create\n"
           "       d - delete\n"
           "       b - dummp\n"
           "       n <nhop_id> \n"
           "       p <prefix in dotted decimal form> \n"
           "       P <do proxy arp for this route> \n"
           "       l <prefix_length>\n"
           "       t <label/vnid>\n"
           "       f <family 0 - AF_INET 1 - AF_BRIDGE>\n"
           "       e <mac address in : format>\n"
           "       r <replacement route preifx length for delete>\n"
           "       v <vrfid>\n");
}

int main(int argc, char *argv[])
{
    int ret;
    int opt;
    int op = 0;
    int nh_id, vrf_id;
    uint32_t prefix = 0, plen = 0, src = 0xffffffff;
    int32_t label;
    int rt_type = RT_UCAST;
    struct ether_addr *eth;
    char dst_mac[6] = {0,0,0,0,0,0};
    int family;
    uint32_t replace_plen = 100;

    cl = nl_register_client();
    if (!cl) {
        exit(1);
    }

    ret = nl_socket(cl, NETLINK_GENERIC);    
    if (ret <= 0) {
       exit(1);
    }

    if (vrouter_get_family_id(cl) <= 0) {
        return -1;
    }

    vrf_id = 0;
    nh_id = -255;
    label = -1;
    family = -1;

    while ((opt = getopt(argc, argv, "cdbmPn:p:l:v:t:s:e:f:r:")) != -1) {
            switch (opt) {
            case 'c':
                op = SANDESH_OP_ADD;
                break;

            case 'd':
                op = SANDESH_OP_DELETE;
                break;

            case 'b':
                op = SANDESH_OP_DUMP;
                src = 0;
                break;

            case 'v':
                vrf_id = atoi(optarg);
                break;      

            case 'n':
                nh_id = atoi(optarg);
                break;

            case 'p':
                prefix = inet_addr(optarg);
                break;

            case 'l':
                plen = atoi(optarg);
                break;

            case 'r':
                replace_plen = atoi(optarg);
                break;

            case 't':
                label = atoi(optarg);
                break;

            case 's':
                src = inet_addr(optarg);
                break;
            case 'm':
                rt_type = RT_MCAST;
                break;

            case 'f':
                family = atoi(optarg);
                if (family == 0)
                    family = AF_INET;
                else {
                    family = AF_BRIDGE;
                    rt_type = RT_UCAST;
                }

                break;

            case 'e':
                eth = ether_aton(optarg);
                if (eth)
                    memcpy(dst_mac, eth, 6);
                break;

            case 'P':
                proxy_set = true;
                break;

            case '?':
            default:
                usage();
                exit(1);
        }
    }

    if (family == -1) {
        usage();
        exit(1);
    }

    if ((op == SANDESH_OP_DELETE) && (replace_plen < 0 || replace_plen > 32)) {
        usage();
        exit(1);
    }

    vr_route_op(op, family, prefix, plen, nh_id, vrf_id, label, rt_type,
            src, dst_mac, replace_plen);

    return 0;
}
