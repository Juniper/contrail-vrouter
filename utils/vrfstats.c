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

#include <net/if.h>

#include "vr_types.h"
#include "vr_nexthop.h"
#include "nl_util.h"
#include "vr_mpls.h"
#include "vr_defs.h"

static struct nl_client *cl;
static unsigned int stats_op;
static int marker = -1;
static int vrf = -1;

static int get_set, dump_set;
static int help_set;
static bool dump_pending = false;

static void
vrf_stats_req_process(void *s_req)
{
    vr_vrf_stats_req *stats = (vr_vrf_stats_req *)s_req;

    marker = stats->vsr_vrf;
    printf("Vrf: %d\n", stats->vsr_vrf);
    printf("Discards %" PRIu64 ", Resolves %" PRIu64 ", Receives %"
            PRIu64 ", L2 Receives %" PRIu64 ", Vrf Translates %" PRIu64
            ", Unknown Unicast Floods %" PRIu64 "\n",
            stats->vsr_discards, stats->vsr_resolves, stats->vsr_receives,
            stats->vsr_l2_receives, stats->vsr_vrf_translates,
            stats->vsr_uuc_floods);
    printf("Ecmp Composites %" PRIu64 ", L2 Mcast Composites %"
            PRIu64 ", Fabric Composites %" PRIu64 ", Encap Composites %" PRIu64
            ", Evpn Composites %" PRIu64 "\n", stats->vsr_ecmp_composites,
            stats->vsr_l2_mcast_composites, stats->vsr_fabric_composites,
            stats->vsr_encap_composites, stats->vsr_evpn_composites);
    printf("Udp Tunnels %" PRIu64 ", Udp Mpls Tunnels %" PRIu64
            ", Gre Mpls Tunnels %" PRIu64 ", Vxlan Tunnels %" PRIu64
            ", Pbb Tunnels %" PRIu64 "\n",
            stats->vsr_udp_tunnels, stats->vsr_udp_mpls_tunnels,
            stats->vsr_gre_mpls_tunnels, stats->vsr_vxlan_tunnels,
            stats->vsr_pbb_tunnels);
    printf("L2 Encaps %" PRIu64 ", Encaps %" PRIu64 "\n",
            stats->vsr_l2_encaps, stats->vsr_encaps);
    printf("GROs %" PRIu64 ", Diags %" PRIu64 "\n",
            stats->vsr_gros, stats->vsr_diags);
    printf("Arp Virtual Proxys %" PRIu64 ", Arp Virtual Stitchs %" PRIu64
           ", Arp Virtual Floods %" PRIu64 ", Arp Physical Stitchs %" PRIu64
           ", Arp Tor Proxys %" PRIu64 ", Arp Physical Floods %" PRIu64 "\n",
            stats->vsr_arp_virtual_proxy, stats->vsr_arp_virtual_stitch,
            stats->vsr_arp_virtual_flood, stats->vsr_arp_physical_stitch,
            stats->vsr_arp_tor_proxy, stats->vsr_arp_physical_flood);

    printf("\n");

    return;
}

static void
response_process(void *s)
{
    vr_response_common_process((vr_response *)s, &dump_pending);
    return;
}

static void
vrfstats_fill_nl_callbacks()
{
    nl_cb.vr_vrf_stats_req_process = vrf_stats_req_process;
    nl_cb.vr_response_process = response_process;
}


static int
vr_stats_op(struct nl_client *cl)
{
    int ret;
    bool dump = false;

op_retry:
    switch (stats_op) {
    case SANDESH_OP_GET:
        ret = vr_send_vrf_stats_get(cl, 0, vrf);
        break;

    case SANDESH_OP_DUMP:
        dump = true;
        ret = vr_send_vrf_stats_dump(cl, 0, marker);
        break;

    default:
        ret = -EINVAL;
        break;
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
    [MAX_OPT_INDEX]     =   {NULL,    0,                  0,              0},
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
        stats_op = SANDESH_OP_GET;

        break;

    case DUMP_OPT_INDEX:
        stats_op = SANDESH_OP_DUMP;
        break;

    case HELP_OPT_INDEX:
    default:
        Usage();
        break;
    }

    if (errno)
        Usage();
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

    vrfstats_fill_nl_callbacks();

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

    cl = vr_get_nl_client(VR_NETLINK_PROTO_DEFAULT);
    if (!cl) {
        exit(1);
    }

    vr_stats_op(cl);

    return 0;
}
