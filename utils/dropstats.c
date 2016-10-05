/*
 * dropstats.c - drop statistics
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

#include <sys/types.h>
#include <sys/socket.h>

#include <net/if.h>

#include "ini_parser.h"
#include "vr_os.h"
#include "vr_types.h"
#include "vr_nexthop.h"
#include "ini_parser.h"
#include "nl_util.h"
#include "ini_parser.h"

static struct nl_client *cl;
static int help_set, intf_set;
static short intf = -1;

void
vr_response_process(void *sresp)
{
    vr_response *resp = (vr_response *)sresp;

    if (resp->resp_code < 0) {
        printf("%s: %s\n", __func__, strerror(-resp->resp_code));
        exit(-1);
    }

    return;
}

void
vr_drop_stats_req_process(void *s_req)
{
    vr_drop_stats_req *stats = (vr_drop_stats_req *)s_req;
    int platform = get_platform();

    if (intf == -1) {
        printf("\nDropstats of all interfaces:\n\n");
    } else {
        printf("\n\nDropstats of VIF %d\n\n", intf);
        if (stats->vds_pcpu_stats_failure_status == 1) {
            printf("PerCPU drop stats are not maintained\n\n");
        }
    }

    printf("Invalid ARPs                  %" PRIu64 "\n",
            stats->vds_invalid_arp);
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
    printf("Rewrite Fail                  %" PRIu64 "\n",
            stats->vds_rewrite_fail);
    printf("Invalid Mcast Source          %" PRIu64 "\n",
            stats->vds_invalid_mcast_source);
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

static int
vr_get_drop_stats(struct nl_client *cl)
{
    int ret;

    ret = vr_send_drop_stats_get(cl, 0, intf);
    if (ret < 0)
        return ret;

    ret = vr_recvmsg(cl, false);
    if (ret <= 0)
        return ret;

    return 0;
}

enum opt_index {
    HELP_OPT_INDEX,
    INTF_OPT_INDEX,
    MAX_OPT_INDEX,
};

static struct option long_options[] = {
    [HELP_OPT_INDEX]    =   {"help",    no_argument,        &help_set,      1},
    [INTF_OPT_INDEX]    =   {"intf",    required_argument,  &intf_set,      1},
    [MAX_OPT_INDEX]     =   {"NULL",    0,                  0,              0},
};

static void
Usage()
{
    printf("Usage: dropstats [--help]\n");
    printf("Usage: dropstats [--intf | -i ] <interface index>\n\n");
    printf("--intf <interface index>\t Show statistics for an interface\n");
    exit(-EINVAL);
}

static void
parse_long_opts(int opt_index, char *opt_arg)
{
    errno = 0;

    switch (opt_index) {
    case INTF_OPT_INDEX:
        intf = (unsigned)strtol(opt_arg, NULL, 0);
        if (errno) {
            printf("Error parsing interface %s: %s (%d)\n", opt_arg,
                    strerror(errno), errno);
            Usage();
        }
        break;

    case HELP_OPT_INDEX:
    default:
        Usage();
    }

    return;
}

int
main(int argc, char *argv[])
{
    char opt;
    int ret, option_index;

    while (((opt = getopt_long(argc, argv, "h:i:",
                        long_options, &option_index)) >= 0)) {
        switch (opt) {
        case 'c':
            intf_set = 1;
            parse_long_opts(INTF_OPT_INDEX, optarg);
            break;

        case 0:
            parse_long_opts(option_index, optarg);
            break;

        case 'h':
        default:
            Usage();
        }
    }

    cl = vr_get_nl_client(VR_NETLINK_PROTO_DEFAULT);
    if (!cl)
        return -1;

    vr_get_drop_stats(cl);

    return 0;
}
