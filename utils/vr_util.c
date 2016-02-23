/*
 * vr_util.c -- common functions used by utilities in a library form
 *
 * Copyright (c) 2015, Juniper Networks, Inc.
 * All rights reserved
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>

#include <sys/socket.h>
#if defined(__linux__)
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_ether.h>
#elif defined(__FreeBSD__)
#include <net/ethernet.h>
#endif

#include <net/if.h>
#include <netinet/in.h>

#include "vr_types.h"
#include "nl_util.h"
#include "vr_message.h"
#include "vr_genetlink.h"
#include "vr_interface.h"
#include "vr_nexthop.h"
#include "vr_route.h"
#include "vr_bridge.h"
#include "ini_parser.h"

/* Suppress NetLink error messages */
bool vr_ignore_nl_errors = false;

char *
vr_extract_token(char *string, char token_separator)
{
    int ret;
    unsigned int length;

    char *sep;

    /* skip over leading white spaces */
    while ((*string == ' ') && string++);

    /* if there is nothing left after the spaces, return */
    if (!(length = strlen(string))) {
        return NULL;
    }

    /* start searching for the token */
    sep = strchr(string, token_separator);
    if (sep) {
        length = sep - string;
        /* terminate the token with NULL */
        string[sep - string] = '\0';
        length = strlen(string);
    }

    /* remove trailing spaces */
    length -= 1;
    while ((*(string + length) == ' ') && --length);
    *(string + length + 1) = '\0';

    /*
     * reset the separator to space, since a space at the beginning
     * will be snipped
     */
    if (sep && (((sep - string)) != strlen(string)))
        string[sep - string] = ' ';

    return string;
}

bool
vr_valid_ipv6_address(const char *addr)
{
    unsigned int i = 0, j = 0, sep_count = 0;

    /* a '*' is treated as a valid address */
    if (!strncmp(addr, "*", 1) && (strlen(addr) == 1))
        return true;

    while (*(addr + i)) {
        if (isalnum(*(addr + i))) {
            j++;
        } else if (*(addr + i) == ':') {
            j = 0;
            sep_count++;
        } else {
            printf("match: \"%s\" is not a valid ipv6 address format\n", addr);
            return false;
        }

        if ((j > 4) || (sep_count > 7)) {
            printf("match: \"%s\" is not a valid ipv6 address format\n", addr);
            return false;
        }

        i++;
    }

    return true;
}

bool
vr_valid_ipv4_address(const char *addr)
{
    unsigned int i = 0, j = 0, sep_count = 0;

    /* a '*' is treated as a valid address */
    if (!strncmp(addr, "*", 1) && (strlen(addr) == 1))
        return true;

    /* every character should be either a digit or a '.' */
    while (*(addr + i)) {
        if (isdigit(*(addr + i))) {
            j++;
        } else if (i && (*(addr + i) == '.')) {
            j = 0;
            ++sep_count;
        } else {
            printf("match: \"%s\" is not a valid ipv4 address format\n", addr);
            return false;
        }

        if ((j > 3) || (sep_count > 3)) {
            printf("match: \"%s\" is not a valid ipv4 address format\n", addr);
            return false;
        }

        i++;
    }

    if (sep_count != 3) {
        printf("match: \"%s\" is not a valid ipv4 address format\n", addr);
        return false;
    }

    return true;
}

/* send and receive */
int
vr_recvmsg(struct nl_client *cl, bool dump)
{
    int ret = 0;
    bool pending = true;
    struct nl_response *resp;
    struct nlmsghdr *nlh;

    while (pending) {
        if ((ret = nl_recvmsg(cl)) > 0) {
            if (dump) {
                pending = true;
            } else {
                pending = false;
            }

            resp = nl_parse_reply(cl);
            if (resp->nl_op == SANDESH_REQUEST) {
                sandesh_decode(resp->nl_data, resp->nl_len,
                        vr_find_sandesh_info, &ret);
            } else if (resp->nl_type == NL_MSG_TYPE_DONE) {
                pending = false;
            }
        } else {
            return ret;
        }

        nlh = (struct nlmsghdr *)cl->cl_buf;
        if (!nlh || !nlh->nlmsg_flags)
            break;
    }

    return ret;
}

int
vr_sendmsg(struct nl_client *cl, void *request,
        char *request_string)
{
    int ret, error, attr_len;

    /* nlmsg header */
    ret = nl_build_nlh(cl, cl->cl_genl_family_id, NLM_F_REQUEST);
    if (ret)
        return ret;

    /* Generic nlmsg header */
    ret = nl_build_genlh(cl, SANDESH_REQUEST, 0);
    if (ret)
        return ret;

    attr_len = nl_get_attr_hdr_size();
    ret = sandesh_encode(request, request_string, vr_find_sandesh_info,
                             (nl_get_buf_ptr(cl) + attr_len),
                             (nl_get_buf_len(cl) - attr_len), &error);
    if (ret <= 0)
        return ret;

    /* Add sandesh attribute */
    nl_build_attr(cl, ret, NL_ATTR_VR_MESSAGE_PROTOCOL);
    nl_update_nlh(cl);

    return nl_sendmsg(cl);
}

struct nl_client *
vr_get_nl_client(unsigned int proto)
{
    int ret;
    unsigned int sock_proto = proto;
    struct nl_client *cl;

    cl = nl_register_client();
    if (!cl)
        return NULL;

    parse_ini_file();

    if (proto == VR_NETLINK_PROTO_DEFAULT)
        sock_proto = get_protocol();

    ret = nl_socket(cl, get_domain(), get_type(), sock_proto);
    if (ret <= 0)
        goto fail;

    ret = nl_connect(cl, get_ip(), get_port());
    if (ret < 0)
        goto fail;

    if ((proto == VR_NETLINK_PROTO_DEFAULT) &&
            (vrouter_get_family_id(cl) <= 0))
        goto fail;

    return cl;

fail:
    if (cl)
        nl_free_client(cl);

    return NULL;
}

int
vr_response_common_process(vr_response *resp, bool *dump_pending)
{
    int ret = 0;

    if (dump_pending)
        *dump_pending = false;

    if (resp->resp_code < 0) {
        if (!vr_ignore_nl_errors) {
            printf("vRouter(Response): %s (%d)\n", strerror(-resp->resp_code),
                    -resp->resp_code);
        }
        ret = resp->resp_code;
    } else {
        if ((resp->resp_code & VR_MESSAGE_DUMP_INCOMPLETE) &&
                dump_pending)
            *dump_pending = true;
    }

    return ret;
}

/* dropstats start */
int
vr_send_drop_stats_get(struct nl_client *cl, unsigned int router_id,
        int core)
{
    vr_drop_stats_req req;

    memset(&req, 0, sizeof(req));
    req.h_op = SANDESH_OP_GET;
    req.vds_rid = router_id;
    req.vds_core = core;

    return vr_sendmsg(cl, &req, "vr_drop_stats_req");
}
/* dropstats end */

/* Interface start */
int
vr_send_interface_dump(struct nl_client *cl, unsigned int router_id,
        int marker, int core)
{
    vr_interface_req req;

    memset(&req, 0, sizeof(req));
    req.h_op = SANDESH_OP_DUMP;
    req.vifr_rid = router_id;
    req.vifr_marker = marker;
    req.vifr_core = core;
    return vr_sendmsg(cl, &req, "vr_interface_req");
}

int
vr_send_interface_get(struct nl_client *cl, unsigned int router_id,
        int vif_index, int os_index, int core)
{
    vr_interface_req req;

    memset(&req, 0, sizeof(req));

    req.h_op = SANDESH_OP_GET;
    req.vifr_rid = router_id;
    req.vifr_os_idx = os_index;
    req.vifr_idx = vif_index;
    req.vifr_core = core;

    return vr_sendmsg(cl, &req, "vr_interface_req");
}

int
vr_send_interface_delete(struct nl_client *cl, unsigned int router_id,
        char *vif_name, int vif_index)
{
    vr_interface_req req;

    memset(&req, 0, sizeof(req));

    req.h_op = SANDESH_OP_DELETE;
    req.vifr_rid = router_id;
    req.vifr_name = vif_name;
    req.vifr_idx = vif_index;

    return vr_sendmsg(cl, &req, "vr_interface_req");
}

int
vr_send_interface_add(struct nl_client *cl, int router_id, char *vif_name,
        int os_index, int vif_index, int vif_xconnect_index, int vif_type,
        unsigned int vrf, unsigned int flags, int8_t *vif_mac, int8_t vif_transport)
{
    int platform;
    vr_interface_req req;

    platform = get_platform();
    memset(&req, 0, sizeof(req));

    req.h_op = SANDESH_OP_ADD;
    if (vif_name)
        req.vifr_name = vif_name;
    if (vif_mac) {
        req.vifr_mac_size = 6;
        req.vifr_mac = vif_mac;
    }
    req.vifr_vrf = vrf;

    if (os_index > 0)
        req.vifr_os_idx = os_index;

    req.vifr_idx = vif_index;
    req.vifr_rid = router_id;
    req.vifr_type = vif_type;
    req.vifr_flags = flags;
    req.vifr_transport = vif_transport;

    if (vif_type == VIF_TYPE_HOST) {
        req.vifr_cross_connect_idx = vif_xconnect_index;
    }

    return vr_sendmsg(cl, &req, "vr_interface_req");
}

/* interface end */


int
vr_send_mem_stats_get(struct nl_client *cl, unsigned int router_id)
{
    vr_mem_stats_req req;

    memset(&req, 0, sizeof(req));
    req.h_op = SANDESH_OP_GET;
    req.vms_rid = router_id;

    return vr_sendmsg(cl, &req, "vr_mem_stats_req");
}

/* mirror start */
int
vr_send_mirror_dump(struct nl_client *cl, unsigned int router_id,
        int marker)
{
    vr_mirror_req req;

    req.h_op = SANDESH_OP_DUMP;
    req.mirr_rid = router_id;
    req.mirr_marker = marker;

    return vr_sendmsg(cl, &req, "vr_mirror_req");
}

int
vr_send_mirror_get(struct nl_client *cl, unsigned int router_id,
        unsigned int mirror_index)
{
    vr_mirror_req req;

    req.h_op = SANDESH_OP_GET;
    req.mirr_rid = router_id;
    req.mirr_index = mirror_index;

    return vr_sendmsg(cl, &req, "vr_mirror_req");
}

int
vr_send_mirror_delete(struct nl_client *cl, unsigned int router_id,
        unsigned int mirror_index)
{
    vr_mirror_req req;

    req.h_op = SANDESH_OP_DELETE;
    req.mirr_rid = router_id;
    req.mirr_index = mirror_index;

    return vr_sendmsg(cl, &req, "vr_mirror_req");
}

int
vr_send_mirror_add(struct nl_client *cl, unsigned int router_id,
        unsigned int mirror_index, int mirror_nh_index,
        unsigned int mirror_flags)
{
    vr_mirror_req req;

    memset(&req, 0, sizeof(req));

    req.h_op = SANDESH_OP_ADD;
    req.mirr_rid = router_id;
    req.mirr_index = mirror_index;
    req.mirr_nhid = mirror_nh_index;
    req.mirr_flags = mirror_flags;

    return vr_sendmsg(cl, &req, "vr_mirror_req");
}
/* mirror end */

int
vr_send_mpls_delete(struct nl_client *cl, unsigned int router_id,
        unsigned int label)
{
    vr_mpls_req req;

    memset(&req, 0, sizeof(req));
    req.h_op = SANDESH_OP_DELETE;
    req.mr_rid = router_id;
    req.mr_label = label;

    return vr_sendmsg(cl, &req, "vr_mpls_req");
}

int
vr_send_mpls_dump(struct nl_client *cl, unsigned int router_id, int marker)
{
    vr_mpls_req req;

    memset(&req, 0, sizeof(req));
    req.h_op = SANDESH_OP_DUMP;
    req.mr_rid = router_id;
    req.mr_marker = marker;

    return vr_sendmsg(cl, &req, "vr_mpls_req");
}

int
vr_send_mpls_get(struct nl_client *cl, unsigned int router_id, unsigned int label)
{
    vr_mpls_req req;

    memset(&req, 0, sizeof(req));
    req.h_op = SANDESH_OP_GET;
    req.mr_rid = router_id;
    req.mr_label = label;

    return vr_sendmsg(cl, &req, "vr_mpls_req");
}

int
vr_send_mpls_add(struct nl_client *cl, unsigned int router_id,
        unsigned int label, unsigned int nh_index)
{
    vr_mpls_req req;

    memset(&req, 0, sizeof(req));
    req.h_op = SANDESH_OP_ADD;
    req.mr_rid = router_id;
    req.mr_label = label;
    req.mr_nhid = nh_index;

    return vr_sendmsg(cl, &req, "vr_mpls_req");
}

int
vr_send_nexthop_delete(struct nl_client *cl, unsigned int router_id,
        unsigned int nh_index)
{
    vr_nexthop_req req;

    memset(&req, 0, sizeof(req));
    req.h_op = SANDESH_OP_DELETE;
    req.nhr_rid = router_id;
    req.nhr_id = nh_index;

    return vr_sendmsg(cl, &req, "vr_nexthop_req");
}

int
vr_send_nexthop_dump(struct nl_client *cl, unsigned int router_id,
        int marker)
{
    vr_nexthop_req req;

    memset(&req, 0, sizeof(req));
    req.h_op = SANDESH_OP_DUMP;
    req.nhr_rid = router_id;
    req.nhr_marker = marker;

    return vr_sendmsg(cl, &req, "vr_nexthop_req");
}

int
vr_send_nexthop_get(struct nl_client *cl, unsigned int router_id,
        unsigned int nh_index)
{
    vr_nexthop_req req;

    memset(&req, 0, sizeof(req));
    req.h_op = SANDESH_OP_GET;
    req.nhr_rid = router_id;
    req.nhr_id = nh_index;

    return vr_sendmsg(cl, &req, "vr_nexthop_req");
}

int
vr_send_nexthop_composite_add(struct nl_client *cl, unsigned int router_id,
        int nh_index, unsigned int flags, int vrf_index,
        unsigned int num_components, unsigned int *component_nh_indices,
        unsigned int *component_labels)
{
    int ret = 0;
    unsigned int i;
    vr_nexthop_req req;

    memset(&req, 0, sizeof(req));
    req.h_op = SANDESH_OP_ADD;
    req.nhr_rid = router_id;
    req.nhr_vrf = vrf_index;
    req.nhr_id = nh_index;
    req.nhr_flags = flags;
    req.nhr_type = NH_COMPOSITE;

    req.nhr_nh_list_size = num_components;
    req.nhr_nh_list = calloc(num_components, sizeof(uint32_t));
    if (!req.nhr_nh_list) {
        ret = -ENOMEM;
        goto fail;
    }

    req.nhr_label_list = calloc(num_components, sizeof(uint32_t));
    if (!req.nhr_label_list) {
        ret = -ENOMEM;
        goto fail;
    }

    req.nhr_label_list_size = num_components;
    for (i = 0; i < num_components; i++) {
        req.nhr_nh_list[i] = component_nh_indices[i];
        req.nhr_label_list[i] = component_labels[i];
    }


    if (flags & NH_FLAG_COMPOSITE_L2)
        req.nhr_family = AF_BRIDGE;
    else
        req.nhr_family = AF_INET;

    ret = vr_sendmsg(cl, &req, "vr_nexthop_req");
fail:
    if (req.nhr_nh_list) {
        free(req.nhr_nh_list);
        req.nhr_nh_list = NULL;
    }

    if (req.nhr_label_list) {
        free(req.nhr_label_list);
        req.nhr_label_list = NULL;
    }

    return ret;
}


int
vr_send_nexthop_encap_tunnel_add(struct nl_client *cl, unsigned int router_id,
        unsigned int type, int nh_index, unsigned int flags, int vrf_index,
        int vif_index, int8_t *smac, int8_t *dmac, struct in_addr sip,
        struct in_addr dip, int sport, int dport)
{
    vr_nexthop_req req;

    memset(&req, 0, sizeof(req));

    req.h_op = SANDESH_OP_ADD;
    req.nhr_rid = router_id;
    req.nhr_vrf = vrf_index;
    req.nhr_id = nh_index;
    req.nhr_flags = flags;
    req.nhr_type = type;

    req.nhr_encap_oif_id = vif_index;
    req.nhr_encap_size = 14;
    req.nhr_encap = malloc(req.nhr_encap_size);
    if (!req.nhr_encap)
        return -ENOMEM;
    memcpy(req.nhr_encap, dmac, 6);
    memcpy(req.nhr_encap + 6, smac, 6);
    *(uint16_t *)(&req.nhr_encap[12]) = htons(0x0800);

#if defined(__linux__)
    req.nhr_encap_family = ETH_P_ARP;
#elif defined(__FreeBSD__)
    req.nhr_encap_family = ETHERTYPE_ARP;
#endif

    if (type == NH_TUNNEL) {
        req.nhr_tun_sip = sip.s_addr;
        req.nhr_tun_dip = dip.s_addr;
        if ((sport >= 0) && (dport >= 0)) {
            req.nhr_tun_sport = htons(sport);
            req.nhr_tun_dport = htons(dport);
        }
    }

    if ((type == NH_ENCAP) && (flags & NH_FLAG_ENCAP_L2))
        req.nhr_family = AF_BRIDGE;
    else
        req.nhr_family = AF_INET;

    return vr_sendmsg(cl, &req, "vr_nexthop_req");
}

int
vr_send_nexthop_add(struct nl_client *cl, unsigned int router_id,
        unsigned int type, int nh_index, unsigned int flags, int vrf_index,
        int vif_index)
{
    vr_nexthop_req req;

    memset(&req, 0, sizeof(req));

    req.h_op = SANDESH_OP_ADD;
    req.nhr_rid = router_id;
    req.nhr_vrf = vrf_index;
    req.nhr_id = nh_index;
    req.nhr_flags = flags;
    req.nhr_type = type;
    req.nhr_encap_oif_id = vif_index;

    return vr_sendmsg(cl, &req, "vr_nexthop_req");
}

int
vr_send_route_dump(struct nl_client *cl, unsigned int router_id, unsigned int vrf,
        unsigned int family, uint8_t *marker, unsigned int marker_plen)
{
    vr_route_req req;

    memset(&req, 0, sizeof(req));
    req.h_op = SANDESH_OP_DUMP;
    req.rtr_rid = router_id;
    req.rtr_vrf_id = vrf;
    req.rtr_family = family;

    if (family == AF_BRIDGE) {
        if (marker_plen != VR_ETHER_ALEN)
            return -EINVAL;
        req.rtr_mac = marker;
        req.rtr_mac_size = VR_ETHER_ALEN;
    } else {
        req.rtr_prefix = marker;
        req.rtr_prefix_size = RT_IP_ADDR_SIZE(family);
        req.rtr_marker = marker;
        req.rtr_marker_size = RT_IP_ADDR_SIZE(family);
        req.rtr_marker_plen = marker_plen;
    }

    return vr_sendmsg(cl, &req, "vr_route_req");
}

static int
vr_send_route_common(struct nl_client *cl, unsigned int op,
        unsigned int router_id, unsigned int vrf, unsigned int family,
        uint8_t *prefix, unsigned int prefix_len, unsigned int nh_index,
        int label, uint8_t *mac, uint32_t replace_len, unsigned int flags)
{
    vr_route_req req;

    memset(&req, 0, sizeof(req));
    req.h_op = op;
    req.rtr_rid = router_id;
    req.rtr_vrf_id = vrf;
    req.rtr_family = family;

    if ((family == AF_INET) || (family == AF_INET6)) {
        req.rtr_prefix = prefix;
        req.rtr_prefix_size = RT_IP_ADDR_SIZE(family);
        req.rtr_prefix_len = prefix_len;
    } else if (family == AF_BRIDGE) {
        req.rtr_index = VR_BE_INVALID_INDEX;
    }

    if (mac) {
        req.rtr_mac = mac;
        req.rtr_mac_size = VR_ETHER_ALEN;
    }

    req.rtr_replace_plen = replace_len;
    req.rtr_label_flags = flags;
    req.rtr_label = label;
    if (label != -1)
        req.rtr_label_flags |= VR_RT_LABEL_VALID_FLAG;

    req.rtr_nh_id = nh_index;

    return vr_sendmsg(cl, &req, "vr_route_req");
}

int
vr_send_route_get(struct nl_client *cl,
        unsigned int router_id, unsigned int vrf, unsigned int family,
        uint8_t *prefix, unsigned int prefix_len, uint8_t *mac)
{
    return vr_send_route_common(cl, SANDESH_OP_GET, router_id, vrf,
            family, prefix, prefix_len, 0, 0, mac, 0, 0);
}

int
vr_send_route_delete(struct nl_client *cl,
        unsigned int router_id, unsigned int vrf, unsigned int family,
        uint8_t *prefix, unsigned int prefix_len, unsigned int nh_index,
        int label, uint8_t *mac, uint32_t replace_len, unsigned int flags)
{
    return vr_send_route_common(cl, SANDESH_OP_DELETE, router_id, vrf,
            family, prefix, prefix_len, nh_index, label,
            mac, replace_len, flags);
}

int
vr_send_route_add(struct nl_client *cl,
        unsigned int router_id, unsigned int vrf, unsigned int family,
        uint8_t *prefix, unsigned int prefix_len, unsigned int nh_index,
        int label, uint8_t *mac, uint32_t replace_len, unsigned int flags)
{
    return vr_send_route_common(cl, SANDESH_OP_ADD, router_id, vrf,
            family, prefix, prefix_len, nh_index, label,
            mac, replace_len,flags);
}

/* vrf assign start */
int
vr_send_vrf_assign_dump(struct nl_client *cl, unsigned int router_id,
        unsigned int vif_index, int marker)
{
    vr_vrf_assign_req req;

    memset(&req, 0, sizeof(req));
    req.h_op = SANDESH_OP_DUMP;
    req.var_rid = router_id;
    req.var_vif_index = vif_index;
    req.var_marker = marker;

    return vr_sendmsg(cl, &req, "vr_vrf_assign_req");
}

int
vr_send_vrf_assign_set(struct nl_client *cl, unsigned int router_id,
        unsigned int vif_index, unsigned int vlan_id, unsigned int vrf_id)
{

    vr_vrf_assign_req req;

    memset(&req, 0, sizeof(req));
    req.h_op = SANDESH_OP_ADD;
    req.var_rid = router_id;
    req.var_vif_index = vif_index;
    req.var_vif_vrf = vrf_id;
    req.var_vlan_id = vlan_id;

    return vr_sendmsg(cl, &req, "vr_vrf_assign_req");
}
/* vrf assign end */

int
vr_send_vrf_stats_dump(struct nl_client *cl, unsigned int router_id, int marker)
{
    vr_vrf_stats_req req;

    memset(&req, 0, sizeof(req));
    req.h_op = SANDESH_OP_DUMP;
    req.vsr_rid = router_id;
    req.vsr_marker = marker;
    req.vsr_family = AF_INET;

    return vr_sendmsg(cl, &req, "vr_vrf_stats_req");
}

int
vr_send_vrf_stats_get(struct nl_client *cl, unsigned int router_id,
        unsigned int vrf)
{
    vr_vrf_stats_req req;

    memset(&req, 0, sizeof(req));
    req.h_op = SANDESH_OP_GET;
    req.vsr_rid = router_id;
    req.vsr_vrf = vrf;
    req.vsr_family = AF_INET;

    return vr_sendmsg(cl, &req, "vr_vrf_stats_req");
}

int
vr_send_vrouter_get(struct nl_client *cl, unsigned int router_id)
{
    vrouter_ops req;

    memset(&req, 0, sizeof(req));
    req.h_op = SANDESH_OP_GET;

    return vr_sendmsg(cl, &req, "vrouter_ops");
}

int
vr_send_vrouter_set_logging(struct nl_client *cl, unsigned int router_id,
        unsigned int log_level, unsigned int *e_log_types, unsigned int e_size,
        unsigned int *d_log_types, unsigned int d_size)
{
    vrouter_ops req;

    memset(&req, 0, sizeof(req));
    req.h_op = SANDESH_OP_ADD;

    if (log_level > 0)
        req.vo_log_level = log_level;

    if (e_log_types && e_size) {
        req.vo_log_type_enable_size = e_size;
        req.vo_log_type_enable = e_log_types;
    }

    if (d_log_types && d_size) {
        req.vo_log_type_disable_size = d_size;
        req.vo_log_type_disable = d_log_types;
    }

    /*
     * We create request to change logging options only. As we do not change
     * vRouter's runtime parameters here, they need to be set to a meaningless
     * value. They cannot be left zeroed, because 0 means 'feature turned off'.
     */
    req.vo_perfr = -1;
    req.vo_perfs = -1;
    req.vo_from_vm_mss_adj = -1;
    req.vo_to_vm_mss_adj = -1;
    req.vo_perfr1 = -1;
    req.vo_perfr2 = -1;
    req.vo_perfr3 = -1;
    req.vo_perfp = -1;
    req.vo_perfq1 = -1;
    req.vo_perfq2 = -1;
    req.vo_perfq3 = -1;
    req.vo_udp_coff = -1;
    req.vo_flow_hold_limit = -1;
    req.vo_mudp = -1;

    return vr_sendmsg(cl, &req, "vrouter_ops");
}

int
vr_send_vrouter_set_runtime_opts(struct nl_client *cl, unsigned int router_id,
        int perfr, int perfs, int from_vm_mss_adj, int to_vm_mss_adj,
        int perfr1, int perfr2, int perfr3, int perfp, int perfq1,
        int perfq2, int perfq3, int udp_coff, int flow_hold_limit,
        int mudp)
{
    vrouter_ops req;

    memset(&req, 0, sizeof(req));
    req.h_op = SANDESH_OP_ADD;

    /*
     * vRouter runtime options. Adjustable by sysctl as well.
     *
     * No real validation is required, as sysctl does not perform any.
     * Variables are only tested to be -1 ('do not change'),
     * 0 ('feature turned off'), or non-zero ('feature turned on').
     */
    req.vo_perfr = perfr;
    req.vo_perfs = perfs;
    req.vo_from_vm_mss_adj = from_vm_mss_adj;
    req.vo_to_vm_mss_adj = to_vm_mss_adj;
    req.vo_perfr1 = perfr1;
    req.vo_perfr2 = perfr2;
    req.vo_perfr3 = perfr3;
    req.vo_perfp = perfp;
    req.vo_perfq1 = perfq1;
    req.vo_perfq2 = perfq2;
    req.vo_perfq3 = perfq3;
    req.vo_udp_coff = udp_coff;
    req.vo_flow_hold_limit = flow_hold_limit;
    req.vo_mudp = mudp;

    /*
     * We create request to change runtime (sysctl) options only. Log level
     * fields can be left zeroed, because only non-zero values are meaningful
     * in this case.
     */

    return vr_sendmsg(cl, &req, "vrouter_ops");
}

int
vr_send_vxlan_delete(struct nl_client *cl, unsigned int router_id,
        unsigned int vnid)
{
    vr_vxlan_req req;

    memset(&req, 0, sizeof(req));
    req.h_op = SANDESH_OP_DELETE;
    req.vxlanr_vnid = vnid;

    return vr_sendmsg(cl, &req, "vr_vxlan_req");
}

int
vr_send_vxlan_dump(struct nl_client *cl, unsigned int router_id,
        int marker)
{
    vr_vxlan_req req;

    memset(&req, 0, sizeof(req));
    req.h_op = SANDESH_OP_DUMP;
    req.vxlanr_vnid = marker;

    return vr_sendmsg(cl, &req, "vr_vxlan_req");
}

int
vr_send_vxlan_get(struct nl_client *cl, unsigned int router_id,
        unsigned int vnid)
{
    vr_vxlan_req req;

    memset(&req, 0, sizeof(req));
    req.h_op = SANDESH_OP_GET;
    req.vxlanr_vnid = vnid;

    return vr_sendmsg(cl, &req, "vr_vxlan_req");
}

int
vr_send_vxlan_add(struct nl_client *cl, unsigned int router_id,
        unsigned int vnid, unsigned int nh_index)
{
    vr_vxlan_req req;

    memset(&req, 0, sizeof(req));
    req.h_op = SANDESH_OP_ADD;
    req.vxlanr_vnid = vnid;
    req.vxlanr_nhid = nh_index;

    return vr_sendmsg(cl, &req, "vr_vxlan_req");
}

