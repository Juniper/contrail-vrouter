/*
 * vr_util.c -- common functions used by utilities in a library form
 *
 * Copyright (c) 2015, Juniper Networks, Inc.
 * All rights reserved
 */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <ctype.h>
#include <inttypes.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/mman.h>
#if defined(__linux__)
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_ether.h>
#include <linux/dcbnl.h>
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
#include "vr_packet.h"
#include "vr_nexthop.h"
#include "vr_route.h"
#include "vr_bridge.h"
#include "vr_mem.h"
#include "ini_parser.h"

/* Suppress NetLink error messages */
bool vr_ignore_nl_errors = false;
char *vr_socket_dir = VR_DEF_SOCKET_DIR;
uint16_t vr_netlink_port = VR_DEF_NETLINK_PORT;

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

bool
vr_valid_mac_address(const char *mac)
{
    uint8_t null_mac[VR_ETHER_ALEN] = { 0 };

    if (!mac || !memcmp(mac, null_mac, VR_ETHER_ALEN))
        return false;

    return true;
}

char *
vr_proto_string(unsigned short proto)
{
    switch (proto) {
    case VR_IP_PROTO_TCP:
        return "TCP";
        break;

    case VR_IP_PROTO_UDP:
        return "UDP";
        break;

    case VR_IP_PROTO_ICMP:
        return "ICMP";
        break;

    case VR_IP_PROTO_SCTP:
        return "SCTP";
        break;

    case VR_IP_PROTO_ICMP6:
        return "ICMPv6";
        break;


    default:
        return "UNKNOWN";
    }

    return "UNKNOWN";
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
vr_get_nl_client(int proto)
{
    int ret;
    int sock_proto = proto;
    struct nl_client *cl;

    cl = nl_register_client();
    if (!cl)
        return NULL;

#ifndef _WIN32
    /* Do not use ini file if we are in a test mode. */
    if (proto == VR_NETLINK_PROTO_TEST) {
        ret = nl_socket(cl, AF_INET, SOCK_STREAM, 0);
        if (ret <= 0)
            goto fail;

        ret = nl_connect(cl, get_ip(), vr_netlink_port);
        if (ret < 0)
            goto fail;

        return cl;
    }

    parse_ini_file();

    if (proto == VR_NETLINK_PROTO_DEFAULT)
        sock_proto = get_protocol();

    ret = nl_socket(cl, get_domain(), get_type(), sock_proto);
    if (ret <= 0)
        goto fail;

    ret = nl_connect(cl, get_ip(), get_port());
    if (ret < 0)
        goto fail;
#else
    DWORD access_flags = GENERIC_READ | GENERIC_WRITE;
    DWORD attrs = OPEN_EXISTING;

    cl->cl_win_pipe = CreateFile(KSYNC_PATH, access_flags, 0, NULL, attrs, 0, NULL);
    if (cl->cl_win_pipe == INVALID_HANDLE_VALUE)
        goto fail;

    cl->cl_recvmsg = win_nl_client_recvmsg;
#endif

    if ((proto == VR_NETLINK_PROTO_DEFAULT) &&
            (vrouter_get_family_id(cl) <= 0))
        goto fail;

    return cl;

fail:
    if (cl)
        nl_free_client(cl);

    return NULL;
}

#ifndef _WIN32
// TODO(Windows): Implement general memory mapping mechanism
void *
vr_table_map(int major, unsigned int table,
        char *table_path, size_t size)
{
    int fd, ret;
    uint16_t dev;

    void *mem;
    char *path;
    const char *platform = read_string(DEFAULT_SECTION, PLATFORM_KEY);

    if (major < 0)
        return NULL;

    if (platform && ((strcmp(platform, PLATFORM_DPDK) == 0) ||
                (strcmp(platform, PLATFORM_NIC) == 0))) {
        path = table_path;
    } else {
        switch (table) {
        case VR_MEM_BRIDGE_TABLE_OBJECT:
            path = BRIDGE_TABLE_DEV;
            break;

        case VR_MEM_FLOW_TABLE_OBJECT:
            path = FLOW_TABLE_DEV;
            break;

        default:
            return NULL;
        }

        ret = mknod(path, S_IFCHR | O_RDWR, makedev(major, table));
        if (ret && errno != EEXIST) {
            perror(path);
            return NULL;
        }
    }

    fd = open(path, O_RDONLY | O_SYNC);
    if (fd <= 0) {
        perror(path);
        return NULL;
    }

    mem = mmap(NULL, size, PROT_READ, MAP_SHARED, fd, 0);
    close(fd);

    return mem;
}
#endif

int
vr_send_get_bridge_table_data(struct nl_client *cl)
{
    int ret;
    vr_bridge_table_data req;

    memset(&req, 0, sizeof(req));
    req.btable_op = SANDESH_OP_GET;
    req.btable_rid = 0;

    return vr_sendmsg(cl, &req, "vr_bridge_table_data");
}

int
vr_send_set_dcb_state(struct nl_client *cl, uint8_t *ifname, uint8_t state)
{
#ifdef _WIN32
    // TODO(Windows): Implement for windows
    return -1;
#else
    int ret;

    ret = nl_build_set_dcb_state_msg(cl, ifname, state);
    if (ret < 0)
        return ret;

    ret = nl_dcb_sendmsg(cl, DCB_CMD_SSTATE, NULL);
    if (ret <= 0)
        return ret;

    if (ret != state) {
        printf("vRouter: Set DCB State failed (Req/Resp: %u/%d)\n",
                state, ret);
        return -1;
    }

    return 0;
#endif
}

int
vr_send_get_dcb_state(struct nl_client *cl, uint8_t *ifname)
{
#ifdef _WIN32
    // TODO(Windows): Implement for windows
    return -1;
#else
    int ret;

    ret = nl_build_get_dcb_state_msg(cl, ifname);
    if (ret < 0)
        return ret;

    return nl_dcb_sendmsg(cl, DCB_CMD_GSTATE, NULL);
#endif
}

int
vr_send_set_dcbx(struct nl_client *cl, uint8_t *ifname, uint8_t dcbx)
{
#ifdef _WIN32
    // TODO(Windows): Implement for windows
    return -1;
#else
    int ret;

    ret = nl_build_set_dcbx(cl, ifname, dcbx);
    if (ret < 0)
        return ret;

    ret = nl_dcb_sendmsg(cl, DCB_CMD_SDCBX, NULL);
    if (ret < 0)
        return ret;

    if (ret) {
        printf("vRouter: Set DCBX failed (Req/Resp: %u/%d)\n",
            dcbx, ret);
        return -1;
    }

    return 0;
#endif
}

int
vr_send_get_dcbx(struct nl_client *cl, uint8_t *ifname)
{
#ifdef _WIN32
    // TODO(Windows): Implement for windows
    return -1;
#else
    int ret;

    ret = nl_build_get_dcbx(cl, ifname);
    if (ret < 0)
        return ret;

    return nl_dcb_sendmsg(cl, DCB_CMD_GDCBX, NULL);
#endif
}

int
vr_send_get_priority_config(struct nl_client *cl, uint8_t *ifname,
        struct priority *p)
{
#ifdef _WIN32
    // TODO(Windows): Implement for windows
    return -1;
#else
    int ret;

    ret = nl_build_get_priority_config_msg(cl, ifname);
    if (ret < 0)
        return ret;

    ret = nl_dcb_sendmsg(cl, DCB_CMD_PGTX_GCFG, p);
    if (ret < 0)
        return ret;

    return 0;
#endif
}

int
vr_send_set_priority_config(struct nl_client *cl, uint8_t *ifname,
        struct priority *p)
{
#ifdef _WIN32
    // TODO(Windows): Implement for windows
    return -1;
#else
    int ret;

    ret = nl_build_set_priority_config_msg(cl, ifname, p);
    if (ret < 0)
        return ret;

    ret = nl_dcb_sendmsg(cl, DCB_CMD_PGTX_SCFG, NULL);
    if (ret < 0)
        return ret;

    return 0;
#endif
}

int
vr_send_set_dcb_all(struct nl_client *cl, uint8_t *ifname)
{
#ifdef _WIN32
    // TODO(Windows): Implement for windows
    return -1;
#else
    int ret;

    ret = nl_build_set_dcb_all(cl, ifname);
    if (ret < 0)
        return ret;

    return nl_dcb_sendmsg(cl, DCB_CMD_SET_ALL, NULL);
#endif
}

int
vr_send_get_ieee_ets(struct nl_client *cl, uint8_t *ifname,
        struct priority *p)
{
#ifdef _WIN32
    // TODO(Windows): Implement for windows
    return -1;
#else
    int ret;

    ret = nl_build_get_ieee_ets(cl, ifname, p);
    if (ret < 0)
        return ret;

    return nl_dcb_sendmsg(cl, DCB_CMD_IEEE_GET, p);
#endif
}

int
vr_send_set_ieee_ets(struct nl_client *cl, uint8_t *ifname,
        struct priority *p)
{
#ifdef _WIN32
    // TODO(Windows): Implement for windows
    return -1;
#else
    int ret;

    ret = nl_build_set_ieee_ets(cl, ifname, p);
    if (ret < 0)
        return ret;

    return nl_dcb_sendmsg(cl, DCB_CMD_IEEE_SET, NULL);
#endif
}

void
vr_print_drop_stats(vr_drop_stats_req *stats, int core)
{
    int platform = get_platform();

   if (core != (unsigned)-1)
        printf("Statistics for core %u\n\n", core);

   if (stats->vds_pcpu_stats_failure_status)
       printf("Failed to maintain PerCPU stats for this interface\n\n");

    printf("Invalid IF                    %" PRIu64 "\n",
            stats->vds_invalid_if);
    printf("Trap No IF                    %" PRIu64 "\n",
            stats->vds_trap_no_if);
    printf("IF TX Discard                 %" PRIu64 "\n",
            stats->vds_interface_tx_discard);
    printf("IF Drop                       %" PRIu64 "\n",
            stats->vds_interface_drop);
    printf("IF RX Discard                 %" PRIu64 "\n",
            stats->vds_interface_rx_discard);
    printf("\n");

    printf("Flow Unusable                 %" PRIu64 "\n",
            stats->vds_flow_unusable);
    printf("Flow No Memory                %" PRIu64 "\n",
            stats->vds_flow_no_memory);
    printf("Flow Table Full               %" PRIu64 "\n",
            stats->vds_flow_table_full);
    printf("Flow NAT no rflow             %" PRIu64 "\n",
            stats->vds_flow_nat_no_rflow);
    printf("Flow Action Drop              %" PRIu64 "\n",
            stats->vds_flow_action_drop);
    printf("Flow Action Invalid           %" PRIu64 "\n",
            stats->vds_flow_action_invalid);
    printf("Flow Invalid Protocol         %" PRIu64 "\n",
            stats->vds_flow_invalid_protocol);
    printf("Flow Queue Limit Exceeded     %" PRIu64 "\n",
            stats->vds_flow_queue_limit_exceeded);
    printf("New Flow Drops                %" PRIu64 "\n",
            stats->vds_drop_new_flow);
    printf("Flow Unusable (Eviction)      %" PRIu64 "\n",
            stats->vds_flow_evict);
    printf("\n");

    printf("Original Packet Trapped       %" PRIu64 "\n",
            stats->vds_trap_original);
    printf("\n");

    printf("Discards                      %" PRIu64 "\n",
            stats->vds_discard);
    printf("TTL Exceeded                  %" PRIu64 "\n",
            stats->vds_ttl_exceeded);
    printf("Mcast Clone Fail              %" PRIu64 "\n",
            stats->vds_mcast_clone_fail);
    printf("Cloned Original               %" PRIu64 "\n",
            stats->vds_cloned_original);
    printf("\n");

    printf("Invalid NH                    %" PRIu64 "\n",
            stats->vds_invalid_nh);
    printf("Invalid Label                 %" PRIu64 "\n",
            stats->vds_invalid_label);
    printf("Invalid Protocol              %" PRIu64 "\n",
            stats->vds_invalid_protocol);
    printf("Etree Leaf to Leaf            %" PRIu64 "\n",
            stats->vds_leaf_to_leaf);
    printf("Bmac/ISID Mismatch            %" PRIu64 "\n",
            stats->vds_bmac_isid_mismatch);
    printf("Rewrite Fail                  %" PRIu64 "\n",
            stats->vds_rewrite_fail);
    printf("Invalid Mcast Source          %" PRIu64 "\n",
            stats->vds_invalid_mcast_source);
    printf("Packet Loop                   %" PRIu64 "\n",
            stats->vds_pkt_loop);
    printf("\n");

    printf("Push Fails                    %" PRIu64 "\n",
            stats->vds_push);
    printf("Pull Fails                    %" PRIu64 "\n",
            stats->vds_pull);
    printf("Duplicated                    %" PRIu64 "\n",
            stats->vds_duplicated);
    printf("Head Alloc Fails              %" PRIu64 "\n",
            stats->vds_head_alloc_fail);
    printf("PCOW fails                    %" PRIu64 "\n",
            stats->vds_pcow_fail);
    printf("Invalid Packets               %" PRIu64 "\n",
            stats->vds_invalid_packet);
    printf("\n");

    printf("Misc                          %" PRIu64 "\n",
            stats->vds_misc);
    printf("Nowhere to go                 %" PRIu64 "\n",
            stats->vds_nowhere_to_go);
    printf("Checksum errors               %" PRIu64 "\n",
            stats->vds_cksum_err);
    printf("No Fmd                        %" PRIu64 "\n",
            stats->vds_no_fmd);
    printf("Invalid VNID                  %" PRIu64 "\n",
            stats->vds_invalid_vnid);
    printf("Fragment errors               %" PRIu64 "\n",
            stats->vds_frag_err);
    printf("Invalid Source                %" PRIu64 "\n",
            stats->vds_invalid_source);
    printf("Jumbo Mcast Pkt with DF Bit   %" PRIu64 "\n",
            stats->vds_mcast_df_bit);
    printf("No L2 Route                   %" PRIu64 "\n",
            stats->vds_l2_no_route);

    printf("Memory Failures               %" PRIu64 "\n",
            stats->vds_no_memory);
    printf("Fragment Queueing Failures    %" PRIu64 "\n",
            stats->vds_fragment_queue_fail);

    printf("\n");
    if (platform == DPDK_PLATFORM) {
        printf("VLAN fwd intf failed TX       %" PRIu64 "\n",
                stats->vds_vlan_fwd_tx);
        printf("VLAN fwd intf failed enq      %" PRIu64 "\n",
                stats->vds_vlan_fwd_enq);
    }
    return;
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
uint64_t
vr_sum_drop_stats(vr_drop_stats_req *req)
{
    uint64_t sum = 0;

    sum += req->vds_discard;
    sum += req->vds_pull;
    sum += req->vds_invalid_if;
    sum += req->vds_invalid_arp;
    sum += req->vds_trap_no_if;
    sum += req->vds_nowhere_to_go;
    sum += req->vds_flow_queue_limit_exceeded;
    sum += req->vds_flow_no_memory;
    sum += req->vds_flow_invalid_protocol;
    sum += req->vds_flow_nat_no_rflow;
    sum += req->vds_flow_action_drop;
    sum += req->vds_flow_action_invalid;
    sum += req->vds_flow_unusable;
    sum += req->vds_flow_table_full;
    sum += req->vds_interface_tx_discard;
    sum += req->vds_interface_drop;
    sum += req->vds_duplicated;
    sum += req->vds_push;
    sum += req->vds_ttl_exceeded;
    sum += req->vds_invalid_nh;
    sum += req->vds_invalid_label;
    sum += req->vds_invalid_protocol;
    sum += req->vds_interface_rx_discard;
    sum += req->vds_invalid_mcast_source;
    sum += req->vds_head_alloc_fail;
    sum += req->vds_pcow_fail;
    sum += req->vds_mcast_df_bit;
    sum += req->vds_mcast_clone_fail;
    sum += req->vds_no_memory;
    sum += req->vds_rewrite_fail;
    sum += req->vds_misc;
    sum += req->vds_invalid_packet;
    sum += req->vds_cksum_err;
    sum += req->vds_no_fmd;
    sum += req->vds_cloned_original;
    sum += req->vds_invalid_vnid;
    sum += req->vds_frag_err;
    sum += req->vds_invalid_source;
    sum += req->vds_l2_no_route;
    sum += req->vds_fragment_queue_fail;
    sum += req->vds_vlan_fwd_tx;
    sum += req->vds_vlan_fwd_enq;
    sum += req->vds_drop_new_flow;
    sum += req->vds_trap_original;
    sum += req->vds_pkt_loop;

    return sum;
}

void
vr_drop_stats_req_destroy(vr_drop_stats_req *req)
{
    if (!req)
        return;

    free(req);
    return;
}

vr_drop_stats_req *
vr_drop_stats_req_get_copy(vr_drop_stats_req *src)
{
    vr_drop_stats_req *dst;

    if (!src)
        return NULL;

    dst = malloc(sizeof(*dst));
    if (!dst)
        return NULL;

    *dst = *src;
    return dst;
}

int
vr_send_drop_stats_get(struct nl_client *cl, unsigned int router_id,
        short core)
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
void
vr_interface_req_destroy(vr_interface_req *req)
{
    if (!req)
        return;

    if (req->vifr_name) {
        free(req->vifr_name);
        req->vifr_name = NULL;
    }

    if (req->vifr_queue_ierrors_to_lcore_size &&
            req->vifr_queue_ierrors_to_lcore) {
        free(req->vifr_queue_ierrors_to_lcore);
        req->vifr_queue_ierrors_to_lcore = NULL;
        req->vifr_queue_ierrors_to_lcore_size = 0;
    }


    if (req->vifr_mac && req->vifr_mac_size) {
        free(req->vifr_mac);
        req->vifr_mac = NULL;
        req->vifr_mac_size = 0;
    }

    if (req->vifr_src_mac && req->vifr_src_mac_size) {
        free(req->vifr_src_mac);
        req->vifr_src_mac = NULL;
        req->vifr_src_mac_size = 0;
    }

    if (req->vifr_fat_flow_protocol_port_size &&
            req->vifr_fat_flow_protocol_port) {
        free(req->vifr_fat_flow_protocol_port);
        req->vifr_fat_flow_protocol_port = NULL;
        req->vifr_fat_flow_protocol_port_size = 0;
    }

    free(req);
    return;
}


vr_interface_req *
vr_interface_req_get_copy(vr_interface_req *src)
{
    vr_interface_req *dst;

    dst = malloc(sizeof(*dst));
    if (!dst)
        return NULL;

    *dst = *src;
    dst->vifr_name = NULL;
    dst->vifr_queue_ierrors_to_lcore_size = 0;
    dst->vifr_queue_ierrors_to_lcore = NULL;
    dst->vifr_mac_size = 0;
    dst->vifr_mac = NULL;
    dst->vifr_src_mac_size = 0;
    dst->vifr_src_mac = NULL;
    dst->vifr_fat_flow_protocol_port_size = 0;
    dst->vifr_fat_flow_protocol_port = NULL;

    if (src->vifr_name) {
        dst->vifr_name = malloc(strlen(src->vifr_name) + 1);
        if (!dst->vifr_name)
            goto free_vif;
        memcpy(dst->vifr_name, src->vifr_name, strlen(src->vifr_name) + 1);
    }

    if (src->vifr_queue_ierrors_to_lcore_size &&
            src->vifr_queue_ierrors_to_lcore) {
        dst->vifr_queue_ierrors_to_lcore =
            malloc(src->vifr_queue_ierrors_to_lcore_size * sizeof(uint64_t));
        if (!dst->vifr_queue_ierrors_to_lcore)
            goto free_vif;

        memcpy(dst->vifr_queue_ierrors_to_lcore,
                src->vifr_queue_ierrors_to_lcore,
                src->vifr_queue_ierrors_to_lcore_size);
        dst->vifr_queue_ierrors_to_lcore_size =
            src->vifr_queue_ierrors_to_lcore_size;
    }

    if (src->vifr_mac && src->vifr_mac_size) {
        dst->vifr_mac = malloc(src->vifr_mac_size);
        if (!dst->vifr_mac)
            goto free_vif;

        memcpy(dst->vifr_mac, src->vifr_mac, src->vifr_mac_size);
        dst->vifr_mac_size = src->vifr_mac_size;
    }

    if (src->vifr_src_mac && src->vifr_src_mac_size) {
        dst->vifr_src_mac = malloc(src->vifr_src_mac_size);
        if (!dst->vifr_src_mac)
            goto free_vif;

        memcpy(dst->vifr_src_mac, src->vifr_src_mac, src->vifr_src_mac_size);
        dst->vifr_src_mac_size = src->vifr_src_mac_size;
    }


    if (src->vifr_fat_flow_protocol_port_size &&
            src->vifr_fat_flow_protocol_port) {
        dst->vifr_fat_flow_protocol_port =
            malloc(src->vifr_fat_flow_protocol_port_size * sizeof(uint32_t));
        if (!dst->vifr_fat_flow_protocol_port)
            goto free_vif;

        memcpy(dst->vifr_fat_flow_protocol_port,
                src->vifr_fat_flow_protocol_port,
                src->vifr_fat_flow_protocol_port_size);
        dst->vifr_fat_flow_protocol_port_size =
            src->vifr_fat_flow_protocol_port_size;
    }

    return dst;

free_vif:
    vr_interface_req_destroy(dst);
    dst = NULL;
    return NULL;
}

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
        int vif_index, int os_index, int core, int get_drops)
{
    vr_interface_req req;

    memset(&req, 0, sizeof(req));

    req.h_op = SANDESH_OP_GET;
    req.vifr_rid = router_id;
    req.vifr_os_idx = os_index;
    req.vifr_idx = vif_index;
    req.vifr_core = core;
    if (get_drops)
        req.vifr_flags |= VIF_FLAG_GET_DROP_STATS;

    return vr_sendmsg(cl, &req, "vr_interface_req");
}

int
vr_send_interface_delete(struct nl_client *cl, unsigned int router_id,
        char *vif_name, int vif_index)
{
    vr_interface_req req;

    memset(&req, 0, sizeof(req));

    req.h_op = SANDESH_OP_DEL;
    req.vifr_rid = router_id;
    req.vifr_name = vif_name;
    req.vifr_idx = vif_index;

    return vr_sendmsg(cl, &req, "vr_interface_req");
}

int
vr_send_interface_add(struct nl_client *cl, int router_id, char *vif_name,
        int os_index, int vif_index, int vif_xconnect_index, int vif_type,
        unsigned int vrf, unsigned int flags, int8_t *vif_mac, int8_t vif_transport,
        const char *guid)
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

#ifdef _WIN32
    if (guid == NULL) {
        NET_LUID system_luid;
        GUID system_guid;
        ConvertInterfaceNameToLuidA(req.vifr_name, &system_luid);
        ConvertInterfaceLuidToGuid(&system_luid, &system_guid);
        req.vifr_if_guid = (uint8_t*)&system_guid;
        req.vifr_if_guid_size = sizeof(system_guid);
    } else {
        req.vifr_if_guid = (uint8_t*)guid;
        req.vifr_if_guid_size = strlen(guid);
    }
#endif

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
void
vr_mirror_req_destroy(vr_mirror_req *req)
{
    if (!req)
        return;

    free(req);

    return;
}

vr_mirror_req *
vr_mirror_req_get_copy(vr_mirror_req *req)
{
    vr_mirror_req *dst;

    if (!req)
        return NULL;

    dst = malloc(sizeof(*req));
    if (!dst)
        return NULL;

    *dst = *req;

    return dst;
}

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

    req.h_op = SANDESH_OP_DEL;
    req.mirr_rid = router_id;
    req.mirr_index = mirror_index;

    return vr_sendmsg(cl, &req, "vr_mirror_req");
}

int
vr_send_mirror_add(struct nl_client *cl, unsigned int router_id,
        unsigned int mirror_index, int mirror_nh_index,
        unsigned int mirror_flags, int vni_id)
{
    vr_mirror_req req;

    memset(&req, 0, sizeof(req));

    req.h_op = SANDESH_OP_ADD;
    req.mirr_rid = router_id;
    req.mirr_index = mirror_index;
    req.mirr_nhid = mirror_nh_index;
    req.mirr_flags = mirror_flags;
    req.mirr_vni = vni_id;

    return vr_sendmsg(cl, &req, "vr_mirror_req");
}
/* mirror end */

int
vr_send_mpls_delete(struct nl_client *cl, unsigned int router_id,
        unsigned int label)
{
    vr_mpls_req req;

    memset(&req, 0, sizeof(req));
    req.h_op = SANDESH_OP_DEL;
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

char *
vr_nexthop_type_string(vr_nexthop_req *nh)
{
    switch (nh->nhr_type) {
    case NH_DEAD:
        return "DEAD";
        break;

    case NH_RCV:
        return "RECEIVE";
        break;

    case NH_ENCAP:
        return "ENCAP";
        break;

    case NH_TUNNEL:
        return "TUNNEL";
        break;

    case NH_RESOLVE:
        return "RESOLVE";
        break;

    case NH_DISCARD:
        return "DISCARD";
        break;

    case NH_COMPOSITE:
        return "COMPOSITE";
        break;

    case NH_VRF_TRANSLATE:
        return "VRF_TRANSLATE";
        break;

    case NH_L2_RCV:
        return "L2_RECEIVE";
        break;

     default:
        return "NONE";
    }

    return "NONE";
}


bool
vr_nexthop_req_has_vif(vr_nexthop_req *req)
{
    switch (req->nhr_type) {
    case NH_ENCAP:
    case NH_TUNNEL:
    case NH_RCV:
    case NH_L2_RCV:
        return true;
        break;

    case NH_COMPOSITE:
    default:
        return false;
        break;
    }

    return false;
}

void
vr_nexthop_req_destroy(vr_nexthop_req *req)
{
    if (!req)
        return;

    if (req->nhr_encap_size && req->nhr_encap) {
        free(req->nhr_encap);
        req->nhr_encap = NULL;
        req->nhr_encap_size = 0;
    }

    if (req->nhr_nh_list_size && req->nhr_nh_list) {
        free(req->nhr_nh_list);
        req->nhr_nh_list = NULL;
        req->nhr_nh_list_size = 0;
    }

    if (req->nhr_label_list_size && req->nhr_label_list) {
        free(req->nhr_label_list);
        req->nhr_label_list = NULL;
        req->nhr_label_list_size = 0;
    }

    if (req->nhr_tun_sip6_size && req->nhr_tun_sip6) {
        free(req->nhr_tun_sip6);
        req->nhr_tun_sip6 = NULL;
        req->nhr_tun_sip6_size = 0;
    }

    if (req->nhr_tun_dip6_size && req->nhr_tun_dip6) {
        free(req->nhr_tun_dip6);
        req->nhr_tun_dip6 = NULL;
        req->nhr_tun_dip6_size = 0;
    }

    free(req);

    return;
}

vr_nexthop_req *
vr_nexthop_req_get_copy(vr_nexthop_req *src)
{
    vr_nexthop_req *dst;

    dst = calloc(sizeof(vr_nexthop_req), 1);
    if (!dst)
        return NULL;

    /* first copy the in-built members */
    *dst = *src;

    dst->nhr_encap = NULL;
    dst->nhr_encap_size = 0;
    dst->nhr_nh_list = NULL;
    dst->nhr_nh_list_size = 0;
    dst->nhr_label_list = NULL;
    dst->nhr_label_list_size = 0;
    dst->nhr_tun_sip6 = NULL;
    dst->nhr_tun_sip6_size = 0;
    dst->nhr_tun_dip6 = NULL;
    dst->nhr_tun_dip6_size = 0;

    /* ...and then the list elements */
    if (src->nhr_encap_size && src->nhr_encap) {
        dst->nhr_encap = malloc(src->nhr_encap_size);
        if (!dst->nhr_encap)
            goto free_nh;
        memcpy(dst->nhr_encap, src->nhr_encap, src->nhr_encap_size);
        dst->nhr_encap_size = src->nhr_encap_size;
    }

    /* component nexthop list */
    if (src->nhr_nh_list_size && src->nhr_nh_list) {
        dst->nhr_nh_list = malloc(src->nhr_nh_list_size * sizeof(uint32_t));
        if (!src->nhr_nh_list)
            goto free_nh;
        memcpy(dst->nhr_nh_list, src->nhr_nh_list,
                src->nhr_nh_list_size * sizeof(uint32_t));
        dst->nhr_nh_list_size = src->nhr_nh_list_size;
    }

    /* label list */
    if (src->nhr_label_list_size && src->nhr_label_list) {
        dst->nhr_label_list = malloc(src->nhr_label_list_size * sizeof(uint32_t));
        if (!src->nhr_label_list)
            goto free_nh;
        memcpy(dst->nhr_label_list, src->nhr_label_list,
                src->nhr_label_list_size * sizeof(uint32_t));
        dst->nhr_label_list_size = src->nhr_label_list_size;
    }

    /* ipv6 tunnel source */
    if (src->nhr_tun_sip6_size && src->nhr_tun_sip6) {
        dst->nhr_tun_sip6 = malloc(src->nhr_tun_sip6_size);
        if (!src->nhr_tun_sip6)
            goto free_nh;
        memcpy(dst->nhr_tun_sip6, src->nhr_tun_sip6, src->nhr_tun_sip6_size);
        dst->nhr_tun_sip6_size = src->nhr_tun_sip6_size;
    }

    /* ipv6 tunnel destination */
    if (src->nhr_tun_dip6_size && src->nhr_tun_dip6) {
        dst->nhr_tun_dip6 = malloc(src->nhr_tun_dip6_size);
        if (!src->nhr_tun_dip6)
            goto free_nh;
        memcpy(dst->nhr_tun_dip6, src->nhr_tun_dip6, src->nhr_tun_dip6_size);
        dst->nhr_tun_dip6_size = src->nhr_tun_dip6_size;
    }

    return dst;

free_nh:
    vr_nexthop_req_destroy(dst);
    return NULL;
}

int
vr_send_nexthop_delete(struct nl_client *cl, unsigned int router_id,
        unsigned int nh_index)
{
    vr_nexthop_req req;

    memset(&req, 0, sizeof(req));
    req.h_op = SANDESH_OP_DEL;
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
vr_send_pbb_tunnel_add(struct nl_client *cl, unsigned int router_id, int
        nh_index, unsigned int flags, int vrf_index, int8_t *bmac,
        unsigned int direct_nh_id, unsigned int direct_label)
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
    req.nhr_type = NH_TUNNEL;

    req.nhr_nh_list_size = 1;
    req.nhr_nh_list = calloc(1, sizeof(uint32_t));
    if (!req.nhr_nh_list) {
        ret = -ENOMEM;
        goto fail;
    }

    req.nhr_label_list = calloc(1, sizeof(uint32_t));
    if (!req.nhr_label_list) {
        ret = -ENOMEM;
        goto fail;
    }

    req.nhr_pbb_mac_size = VR_ETHER_ALEN;
    req.nhr_pbb_mac = calloc(VR_ETHER_ALEN, sizeof(uint8_t));
    if (!req.nhr_pbb_mac) {
        ret = -ENOMEM;
        goto fail;
    }
    VR_MAC_COPY(req.nhr_pbb_mac, bmac);

    req.nhr_label_list_size = 1;
    req.nhr_nh_list[0] = direct_nh_id;
    req.nhr_label_list[0] = direct_label;
    req.nhr_family = AF_BRIDGE;

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

void
vr_route_req_destroy(vr_route_req *req)
{
    if (!req)
        return;

    if (req->rtr_prefix_size && req->rtr_prefix) {
        free(req->rtr_prefix);
        req->rtr_prefix = NULL;
        req->rtr_prefix_size = 0;
    }

    if (req->rtr_mac_size && req->rtr_mac) {
        free(req->rtr_mac);
        req->rtr_mac = NULL;
        req->rtr_mac_size = 0;
    }

    free(req);
    return;
}

void
address_mask(uint8_t *addr, uint8_t plen, unsigned int family)
{
   int i;
    uint8_t address_bits;
    uint8_t mask[VR_IP6_ADDRESS_LEN];

    if (family == AF_INET) {
        address_bits = VR_IP_ADDRESS_LEN * 8;
    } else {
        address_bits = VR_IP6_ADDRESS_LEN * 8;
    }

    memset(mask, 0xFF, sizeof(mask));
    for (i = address_bits - 1; i >= plen; i--) {
        mask[i / 8] ^= (1 << (7 - (i % 8)));
    }

    for (i = 0; i < (address_bits / 8); i++) {
        addr[i] &= mask[i];
    }

    return;
}

vr_route_req *
vr_route_req_get_copy(vr_route_req *src)
{
    vr_route_req *dst;

    dst = malloc(sizeof(*dst));
    if (!dst)
        return NULL;

    *dst = *src;

    dst->rtr_prefix_size = 0;
    dst->rtr_prefix = NULL;

    dst->rtr_marker_size = 0;
    dst->rtr_marker = NULL;

    dst->rtr_mac_size = 0;
    dst->rtr_mac = NULL;

    if (src->rtr_prefix_size && src->rtr_prefix) {
        dst->rtr_prefix = malloc(src->rtr_prefix_size);
        if (!dst->rtr_prefix)
            goto free_rtr_req;
        memcpy(dst->rtr_prefix, src->rtr_prefix, src->rtr_prefix_size);
    }

    if (src->rtr_mac_size && src->rtr_mac) {
        dst->rtr_mac = malloc(src->rtr_mac_size);
        if (!dst->rtr_mac)
            goto free_rtr_req;
        memcpy(dst->rtr_mac, src->rtr_mac, src->rtr_mac_size);
    }

    return dst;

free_rtr_req:
    vr_route_req_destroy(dst);
    return NULL;
}

int
vr_send_route_dump(struct nl_client *cl, unsigned int router_id, unsigned int vrf,
        unsigned int family, uint8_t *marker)
{
    vr_route_req req;

    memset(&req, 0, sizeof(req));
    req.h_op = SANDESH_OP_DUMP;
    req.rtr_rid = router_id;
    req.rtr_vrf_id = vrf;
    req.rtr_family = family;

    if (family == AF_BRIDGE) {
        req.rtr_mac = marker;
        req.rtr_mac_size = VR_ETHER_ALEN;
    } else {
        req.rtr_prefix = marker;
        req.rtr_prefix_size = RT_IP_ADDR_SIZE(family);
        req.rtr_marker = marker;
        req.rtr_marker_size = RT_IP_ADDR_SIZE(family);
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
    return vr_send_route_common(cl, SANDESH_OP_DEL, router_id, vrf,
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
        int mudp, int btokens, int binterval, int bstep,
        unsigned int priority_tagging)
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
    req.vo_burst_tokens = btokens;
    req.vo_burst_interval = binterval;
    req.vo_burst_step = bstep;
    req.vo_priority_tagging = priority_tagging;

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
    req.h_op = SANDESH_OP_DEL;
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

int
vr_send_fc_map_get(struct nl_client *cl, unsigned int router_id,
        uint8_t fc_map_id)
{
    vr_fc_map_req req;
    int16_t id = fc_map_id;

    memset(&req, 0, sizeof(req));
    req.h_op = SANDESH_OP_GET;
    req.fmr_rid = router_id;
    req.fmr_id = &id;
    req.fmr_id_size = 1;

    return vr_sendmsg(cl, &req, "vr_fc_map_req");
}

int
vr_send_fc_map_dump(struct nl_client *cl, unsigned int router_id,
        int marker)
{
    vr_fc_map_req req;

    memset(&req, 0, sizeof(req));
    req.h_op = SANDESH_OP_DUMP;
    req.fmr_rid = router_id;
    req.fmr_marker = marker;

    return vr_sendmsg(cl, &req, "vr_fc_map_req");
}

int
vr_send_fc_map_delete(struct nl_client *cl, unsigned int router_id,
        uint8_t fc_id)
{
    vr_fc_map_req req;
    int16_t id = fc_id;

    memset(&req, 0, sizeof(req));
    req.h_op = SANDESH_OP_DEL;
    req.fmr_rid = router_id;
    req.fmr_id = &id;
    req.fmr_id_size = 1;

    return vr_sendmsg(cl, &req, "vr_fc_map_req");
}

int
vr_send_fc_map_add(struct nl_client *cl, unsigned int router_id,
        int16_t *fc_id, uint8_t fc_id_size,
        uint8_t *dscp, uint8_t *mpls_qos, uint8_t *dotonep, uint8_t *queue)
{
    vr_fc_map_req req;

    memset(&req, 0, sizeof(req));
    req.fmr_rid = router_id;

    req.fmr_id = fc_id;
    req.fmr_id_size = fc_id_size;
    req.fmr_dscp = dscp;
    req.fmr_dscp_size = fc_id_size;
    req.fmr_mpls_qos = mpls_qos;
    req.fmr_mpls_qos_size = fc_id_size;
    req.fmr_dotonep = dotonep;
    req.fmr_dotonep_size = fc_id_size;
    req.fmr_queue_id = queue;
    req.fmr_queue_id_size = fc_id_size;

    return vr_sendmsg(cl, &req, "vr_fc_map_req");
}

int
vr_send_qos_map_get(struct nl_client *cl, unsigned int router_id,
        unsigned int qos_map_id)
{
    vr_qos_map_req req;

    memset(&req, 0, sizeof(req));
    req.h_op = SANDESH_OP_GET;
    req.qmr_rid = router_id;
    req.qmr_id = qos_map_id;

    return vr_sendmsg(cl, &req, "vr_qos_map_req");
}


int
vr_send_qos_map_dump(struct nl_client *cl, unsigned int router_id,
        int marker)
{
    vr_qos_map_req req;

    memset(&req, 0, sizeof(req));
    req.h_op = SANDESH_OP_DUMP;
    req.qmr_rid = router_id;
    req.qmr_marker = marker;

    return vr_sendmsg(cl, &req, "vr_qos_map_req");
}

int
vr_send_qos_map_delete(struct nl_client *cl, unsigned int router_id,
        unsigned int qos_map_id)
{
    vr_qos_map_req req;

    memset(&req, 0, sizeof(req));
    req.h_op = SANDESH_OP_DEL;
    req.qmr_rid = router_id;
    req.qmr_id = qos_map_id;

    return vr_sendmsg(cl, &req, "vr_qos_map_req");
}

int
vr_send_qos_map_add(struct nl_client *cl, unsigned int router_id,
        unsigned int qos_id,
        uint8_t *dscp, uint8_t num_dscp, uint8_t *dscp_fc_id,
        uint8_t *mpls_qos, uint8_t num_mpls_qos, uint8_t *mpls_qos_fc_id,
        uint8_t *dotonep, uint8_t num_dotonep, uint8_t *dotonep_fc_id)
{
    vr_qos_map_req req;

    memset(&req, 0, sizeof(req));
    req.h_op = SANDESH_OP_ADD;
    req.qmr_rid = router_id;
    req.qmr_id = qos_id;

    if (num_dscp) {
        req.qmr_dscp = dscp;
        req.qmr_dscp_size = num_dscp;
        req.qmr_dscp_fc_id = dscp_fc_id;
        req.qmr_dscp_fc_id_size = num_dscp;
    }

    if (num_mpls_qos) {
        req.qmr_mpls_qos = mpls_qos;
        req.qmr_mpls_qos_size = num_mpls_qos;
        req.qmr_mpls_qos_fc_id = mpls_qos_fc_id;
        req.qmr_mpls_qos_fc_id_size = num_mpls_qos;
    }

    if (num_dotonep) {
        req.qmr_dotonep = dotonep;
        req.qmr_dotonep_size = num_dotonep;
        req.qmr_dotonep_fc_id = dotonep_fc_id;
        req.qmr_dotonep_fc_id_size = num_dotonep;
    }

    return vr_sendmsg(cl, &req, "vr_qos_map_req");
}

