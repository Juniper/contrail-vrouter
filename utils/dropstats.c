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
#include "vr_os.h"

static struct nl_client *cl;
static int resp_code;
static vr_drop_stats_req stats_req;
static int help_set;

void
vr_drop_stats_req_process(void *s_req)
{
    vr_drop_stats_req *stats = (vr_drop_stats_req *)s_req;


    printf("GARP                          %" PRIu64 "\n",
            stats->vds_garp_from_vm);
    printf("ARP notme                     %" PRIu64 "\n",
            stats->vds_arp_not_me);
    printf("Invalid ARPs                  %" PRIu64 "\n",
            stats->vds_invalid_arp);
    printf("\n");

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
    printf("Head Space Reserve Fails      %" PRIu64 "\n",
            stats->vds_head_space_reserve_fail);
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
    } 

    return;
}


static vr_drop_stats_req *
vr_build_drop_stats_request(void)
{
    stats_req.h_op = SANDESH_OP_GET;
    stats_req.vds_rid = 0;

    return &stats_req;
}

static int
vr_build_netlink_request(vr_drop_stats_req *req)
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
    ret = sandesh_encode(req, "vr_drop_stats_req", vr_find_sandesh_info, 
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
vr_drop_stats_op(void)
{
    vr_send_one_message();
    return;
}

static int 
vr_get_drop_stats(void)
{
    int ret;
    vr_drop_stats_req *req;

    req = vr_build_drop_stats_request();
    if (!req)
        return -errno;

    ret = vr_build_netlink_request(req);
    if (ret < 0)
        return ret;

    vr_drop_stats_op();

    return 0;
}

enum opt_index {
    HELP_OPT_INDEX,
    MAX_OPT_INDEX,
};

static struct option long_options[] = {
    [HELP_OPT_INDEX]    =   {"help",    no_argument,        &help_set,      1},
    [MAX_OPT_INDEX]     =   {"NULL",    0,                  0,              0},
};

static void
Usage()
{
    printf("Usage: drop_stats [--help]\n");
    exit(-EINVAL);
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
            break;

        default:
            Usage();
        }
    }

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

    vr_get_drop_stats();

    return 0;
}
