/*
 * vrfstats.c -- utility to dump vrf stats
 *
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdbool.h>
#include <getopt.h>

#include "vr_os.h"

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
#include "vr_message.h"
#include "vr_nexthop.h"
#include "vr_genetlink.h"
#include "nl_util.h"
#include "vr_mpls.h"
#include "vr_defs.h"

static struct nl_client *cl;
static int resp_code;
static vr_vrf_stats_req stats_req;
static unsigned int stats_op;
static int vrf = -1;
static int get_set, dump_set;
static int help_set;
static bool dump_pending = false;

void
vr_vrf_stats_req_process(void *s_req)
{
    vr_vrf_stats_req *stats = (vr_vrf_stats_req *)s_req;

    stats_req.vsr_marker = stats->vsr_vrf;
    printf("Vrf: %d\n", stats->vsr_vrf);
    printf("Discards %" PRIu64 ", Resolves %" PRIu64 ", Receives %" PRIu64 "\n",
            stats->vsr_discards, stats->vsr_resolves, stats->vsr_receives);
    printf("Ecmp Composites %" PRIu64 ", L2 Mcast Composites %" PRIu64
            ", Fabric Composites %" PRIu64 ", Encap Composites %" PRIu64
            ", Evpn Composites %" PRIu64 "\n", stats->vsr_ecmp_composites,
            stats->vsr_l2_mcast_composites, stats->vsr_fabric_composites,
            stats->vsr_encap_composites, stats->vsr_evpn_composites);
    printf("Udp Tunnels %" PRIu64 ", Udp Mpls Tunnels %" PRIu64 
            ", Gre Mpls Tunnels %" PRIu64 "\n", stats->vsr_udp_tunnels,
            stats->vsr_udp_mpls_tunnels, stats->vsr_gre_mpls_tunnels);
    printf("L2 Encaps %" PRIu64 ", Encaps %" PRIu64 "\n",
            stats->vsr_l2_encaps, stats->vsr_encaps);
    printf("GROs %" PRIu64 ", Diags %" PRIu64 "\n",
            stats->vsr_gros, stats->vsr_diags);

    printf("\n");
    return;
}

void
vr_response_process(void *s)
{
    vr_response *stats_resp;

    stats_resp = (vr_response *)s;
    resp_code = stats_resp->resp_code;

    if (stats_resp->resp_code < 0) {
        printf("Error %s in kernel operation\n", strerror(stats_resp->resp_code));
        exit(-1);
    } else {
        if (stats_op == SANDESH_OP_DUMP) {
            if (resp_code & VR_MESSAGE_DUMP_INCOMPLETE)
                dump_pending = true;
            else 
                dump_pending = false;
        }
    }

    return;
}


static vr_vrf_stats_req *
vr_build_vrf_stats_request(void)
{
    stats_req.h_op = stats_op;
    stats_req.vsr_rid = 0;
    stats_req.vsr_family = AF_INET;

    switch (stats_req.h_op) {
    case SANDESH_OP_GET:
        stats_req.vsr_vrf = vrf;
        break;

    case SANDESH_OP_DUMP:
        break;

    default:
        return NULL;
    }

    return &stats_req;
}

static int
vr_build_netlink_request(vr_vrf_stats_req *req)
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
    ret = sandesh_encode(req, "vr_vrf_stats_req", vr_find_sandesh_info, 
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
vr_stats_dump(void)
{
    vr_vrf_stats_req *req;

    while (vr_send_one_message() != 0) {
        if (!dump_pending)
            return;
        req = vr_build_vrf_stats_request();
        if (req)
            vr_build_netlink_request(req);
    }

    return;
}

static void
vr_do_stats_op(void)
{
    if (stats_op == SANDESH_OP_DUMP)
        vr_stats_dump();
    else
        vr_send_one_message();

    return;
}

static int 
vr_stats_op(void)
{
    int ret;
    vr_vrf_stats_req *req;

    req = vr_build_vrf_stats_request();
    if (!req)
        return -errno;

    ret = vr_build_netlink_request(req);
    if (ret < 0)
        return ret;

    vr_do_stats_op();

    return 0;
}

enum opt_index {
    GET_OPT_INDEX,
    DUMP_OPT_INDEX,
    HELP_OPT_INDEX,
    MAX_OPT_INDEX
};

static struct option long_options[] = {
    [GET_OPT_INDEX]     =   {"get",     required_argument,  &get_set,       1},
    [DUMP_OPT_INDEX]    =   {"dump",    no_argument,        &dump_set,      1},
    [HELP_OPT_INDEX]    =   {"help",    no_argument,        &help_set,      1},
    [MAX_OPT_INDEX]     =   {"NULL",    0,                  0,              0},
};

static void
Usage()
{
    printf("Usage: vrfstats --get <vrf>\n");
    printf("                --dump\n");
    printf("                --help\n");
    printf("\n");

    printf("--get <vrf>    Displays packet statistics for the vrf <vrf>\n");
    printf("--dump         Displays packet statistics for all vrfs\n");
    printf("--help         Displays this help message\n");

    exit(-EINVAL);
}

static void
parse_long_opts(int opt_index, char *opt_arg)
{
    errno = 0;
    switch (opt_index) {
    case GET_OPT_INDEX:
        vrf = strtol(opt_arg, NULL, 0);
        if (errno)
            Usage();
        stats_op = SANDESH_OP_GET;

        break;

    case DUMP_OPT_INDEX:
        stats_op = SANDESH_OP_DUMP;
        break;

    default:
        break;
    }


    return;
}

static void
validate_options(void)
{
    int options;

    options = get_set + dump_set + help_set;

    if (!options)
        Usage();

    if (options > 1 || help_set)
        Usage();

    return;
}

int
main(int argc, char *argv[])
{
    char opt;
    int ret, option_index;

    while (((opt = getopt_long(argc, argv, "",
                        long_options, &option_index)) >= 0)) {
        switch (opt) {
        case 0:
            parse_long_opts(option_index, optarg);
            break;

        default:
            Usage();
        }
    }

    validate_options();

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

    stats_req.vsr_marker = -1;
    vr_stats_op();

    return 0;
}
