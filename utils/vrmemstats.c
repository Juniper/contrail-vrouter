/*
 * vrmemstats.c - vrouter memory statistics
 *
 * Copyright (c) 2015 Juniper Networks, Inc. All rights reserved.
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
#include "ini_parser.h"

static struct nl_client *cl;
static int resp_code;
static vr_mem_stats_req stats_req;
static int help_set;

void
vr_mem_stats_req_process(void *s_req)
{
    vr_mem_stats_req *stats = (vr_mem_stats_req *)s_req;


    printf("vRouter memory usage statistics\n\n");

    printf("Alloced %lu Freed %lu\n", stats->vms_alloced, stats->vms_freed);
    printf("Outstanding memory/object:\n\n");

    printf("Bridge MAC                      %" PRIu64 "\n",
            stats->vms_bridge_mac_object);
    printf("Btable                          %" PRIu64 "\n",
            stats->vms_btable_object);
    printf("Build Info                      %" PRIu64 "\n",
            stats->vms_build_info_object);
    printf("Defer                           %" PRIu64 "\n",
            stats->vms_defer_object);
    printf("Drop Stats                      %" PRIu64 "\n",
            stats->vms_drop_stats_object);
    printf("Drop Stats Request              %" PRIu64 "\n",
            stats->vms_drop_stats_req_object);
    printf("Flow queue                      %" PRIu64 "\n",
            stats->vms_flow_queue_object);
    printf("Flow Request                    %" PRIu64 "\n",
            stats->vms_flow_req_object);
    printf("Flow Request Path               %" PRIu64 "\n",
            stats->vms_flow_req_path_object);
    printf("Flow Hold Stat                  %" PRIu64 "\n",
            stats->vms_flow_hold_stat_object);
    printf("Flow Link Local                 %" PRIu64 "\n",
            stats->vms_flow_link_local_object);
    printf("Flow Metadata                   %" PRIu64 "\n",
            stats->vms_flow_metadata_object);
    printf("Flow Table Info                 %" PRIu64 "\n",
            stats->vms_flow_table_info_object);
    printf("Fragment Scanner                %" PRIu64 "\n",
            stats->vms_fragment_scanner_object);
    printf("Host Packet Pool                %" PRIu64 "\n",
            stats->vms_hpacket_pool_object);
    printf("Hash Table                      %" PRIu64 "\n",
            stats->vms_htable_object);
    printf("Interface                       %" PRIu64 "\n",
            stats->vms_interface_object);
    printf("Interface MAC                   %" PRIu64 "\n",
            stats->vms_interface_mac_object);
    printf("Interface Request               %" PRIu64 "\n",
            stats->vms_interface_req_object);
    printf("Interface Request MAC           %" PRIu64 "\n",
            stats->vms_interface_req_mac_object);
    printf("Interface Request Name          %" PRIu64 "\n",
            stats->vms_interface_req_name_object);
    printf("Interface Stats                 %" PRIu64 "\n",
            stats->vms_interface_stats_object);
    printf("Interface Table                 %" PRIu64 "\n",
            stats->vms_interface_table_object);
    printf("VRF Table                       %" PRIu64 "\n",
            stats->vms_interface_vrf_table_object);
    printf("Index Table                     %" PRIu64 "\n",
            stats->vms_itable_object);
    printf("Malloc                          %" PRIu64 "\n",
            stats->vms_malloc_object);
    printf("Message                         %" PRIu64 "\n",
            stats->vms_message_object);
    printf("Message Response                %" PRIu64 "\n",
            stats->vms_message_response_object);
    printf("Message Dump                    %" PRIu64 "\n",
            stats->vms_message_dump_object);
    printf("Memory Stats Request            %" PRIu64 "\n",
            stats->vms_mem_stats_req_object);
    printf("Mirror                          %" PRIu64 "\n",
            stats->vms_mirror_object);
    printf("Mirror Table                    %" PRIu64 "\n",
            stats->vms_mirror_table_object);
    printf("Mirror MetMirror Meta           %" PRIu64 "\n",
            stats->vms_mirror_meta_object);
    printf("MTRIE                           %" PRIu64 "\n",
            stats->vms_mtrie_object);
    printf("Mtrie Bucket                    %" PRIu64 "\n",
            stats->vms_mtrie_bucket_object);
    printf("Mtrie Stats                     %" PRIu64 "\n",
            stats->vms_mtrie_stats_object);
    printf("Mtrie Table                     %" PRIu64 "\n",
            stats->vms_mtrie_table_object);
    printf("Nexthop                         %" PRIu64 "\n",
            stats->vms_nexthop_object);
    printf("NextHop Component               %" PRIu64 "\n",
            stats->vms_nexthop_component_object);
    printf("NextHop Request List            %" PRIu64 "\n",
            stats->vms_nexthop_req_list_object);
    printf("NextHop Request Encap           %" PRIu64 "\n",
            stats->vms_nexthop_req_encap_object);
    printf("NextHop Request                 %" PRIu64 "\n",
            stats->vms_nexthop_req_object);
    printf("Route Table                     %" PRIu64 "\n",
            stats->vms_route_table_object);
    printf("Timer                           %" PRIu64 "\n",
            stats->vms_timer_object);
    printf("Usock                           %" PRIu64 "\n",
            stats->vms_usock_object);
    printf("Usock Poll                      %" PRIu64 "\n",
            stats->vms_usock_poll_object);
    printf("Usock Buf                       %" PRIu64 "\n",
            stats->vms_usock_buf_object);
    printf("Usock Iovec                     %" PRIu64 "\n",
            stats->vms_usock_iovec_object);
    printf("Vrouter Request                 %" PRIu64 "\n",
            stats->vms_vrouter_req_object);
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


static vr_mem_stats_req *
vr_build_mem_stats_request(void)
{
    stats_req.h_op = SANDESH_OP_GET;
    stats_req.vms_rid = 0;

    return &stats_req;
}

static int
vr_build_netlink_request(vr_mem_stats_req *req)
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
    ret = sandesh_encode(req, "vr_mem_stats_req", vr_find_sandesh_info,
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

    if((ret = nl_recvmsg(cl)) > 0) {
        resp = nl_parse_reply(cl);
        if (resp->nl_op == SANDESH_REQUEST)
            sandesh_decode(resp->nl_data, resp->nl_len, vr_find_sandesh_info, &ret);
    }

    return resp_code;
}

static void
vr_mem_stats_op(void)
{
    vr_send_one_message();
    return;
}

static int
vr_get_mem_stats(void)
{
    int ret;
    vr_mem_stats_req *req;

    req = vr_build_mem_stats_request();
    if (!req)
        return -errno;

    ret = vr_build_netlink_request(req);
    if (ret < 0)
        return ret;

    vr_mem_stats_op();

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
    printf("Usage: memstats [--help]\n");
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

    parse_ini_file();

    ret = nl_socket(cl, get_domain(), get_type(), get_protocol());
    if (ret <= 0) {
       exit(1);
    }

    ret = nl_connect(cl, get_ip(), get_port());
    if (ret < 0) {
       exit(1);
    }

    if (vrouter_get_family_id(cl) <= 0) {
        return -1;
    }

    vr_get_mem_stats();

    return 0;
}
