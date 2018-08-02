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

#include <net/if.h>

#include "vr_types.h"
#include "vr_nexthop.h"
#include "nl_util.h"
#include "vr_os.h"

static struct nl_client *cl;
static int help_set;

static void
mem_stats_req_process(void *s_req)
{
    vr_mem_stats_req *stats = (vr_mem_stats_req *)s_req;


    printf("vRouter memory usage statistics\n\n");

    printf("Alloced %lu Freed %lu\n", stats->vms_alloced, stats->vms_freed);
    printf("Outstanding memory/object:\n\n");

    printf("Assembler Table                 %" PRIu64 "\n",
            stats->vms_assembler_table_object);
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
    printf("Flow Table Data                 %" PRIu64 "\n",
            stats->vms_flow_table_data_object);
    printf("Flow Table Info                 %" PRIu64 "\n",
            stats->vms_flow_table_info_object);
    printf("Fragment                        %" PRIu64 "\n",
            stats->vms_fragment_object);
    printf("Fragment Queue                  %" PRIu64 "\n",
            stats->vms_fragment_queue_object);
    printf("Fragment Queue Element          %" PRIu64 "\n",
            stats->vms_fragment_queue_element_object);
    printf("Fragment Scanner                %" PRIu64 "\n",
            stats->vms_fragment_scanner_object);
    printf("Host Packet Pool                %" PRIu64 "\n",
            stats->vms_hpacket_pool_object);
    printf("Hash Table                      %" PRIu64 "\n",
            stats->vms_htable_object);
    printf("Interface                       %" PRIu64 "\n",
            stats->vms_interface_object);
    printf("Interface Bridge Lock           %" PRIu64 "\n",
            stats->vms_interface_bridge_lock_object);
    printf("Interface Fat Flow Config       %" PRIu64 "\n",
            stats->vms_interface_fat_flow_config_object);
    printf("Interface MAC                   %" PRIu64 "\n",
            stats->vms_interface_mac_object);
    printf("Interface Mirror Meta Objects   %" PRIu64 "\n",
            stats->vms_interface_mirror_meta_object);
    printf("Interface Request               %" PRIu64 "\n",
            stats->vms_interface_req_object);
    printf("Interface Request MAC           %" PRIu64 "\n",
            stats->vms_interface_req_mac_object);
    printf("Interface Request PBB MAC       %" PRIu64 "\n",
            stats->vms_interface_req_pbb_mac_object);
    printf("Interface Req Bridge ID         %" PRIu64 "\n",
            stats->vms_interface_req_bridge_id_object);
    printf("Interface Mirror Req Meta Objects   %" PRIu64 "\n",
            stats->vms_interface_req_mirror_meta_object);
    printf("Interface Queue                 %" PRIu64 "\n",
            stats->vms_interface_queue_object);
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
    printf("Network Address                 %" PRIu64 "\n",
            stats->vms_network_address_object);
    printf("Nexthop                         %" PRIu64 "\n",
            stats->vms_nexthop_object);
    printf("NextHop Component               %" PRIu64 "\n",
            stats->vms_nexthop_component_object);
    printf("NextHop Request List            %" PRIu64 "\n",
            stats->vms_nexthop_req_list_object);
    printf("NextHop Request Encap           %" PRIu64 "\n",
            stats->vms_nexthop_req_encap_object);
    printf("NextHop Request PBB BMAC        %" PRIu64 "\n",
            stats->vms_nexthop_req_bmac_object);
    printf("NextHop Request                 %" PRIu64 "\n",
            stats->vms_nexthop_req_object);
    printf("Route Table                     %" PRIu64 "\n",
            stats->vms_route_table_object);
    printf("Route Request MAC object        %" PRIu64 "\n",
            stats->vms_route_req_mac_object);
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
    printf("QOS Map Objects                 %" PRIu64 "\n",
            stats->vms_qos_map_object);
    printf("Forwarding Class Objects        %" PRIu64 "\n",
            stats->vms_fc_object);
    printf("Fatflow v4 exclude list object  %" PRIu64 "\n",
            stats->vms_interface_fat_flow_ipv4_exclude_list_object);
    printf("Fatflow v6 exclude list object  %" PRIu64 "\n",
            stats->vms_interface_fat_flow_ipv6_exclude_list_object);
    return;
}

static void
response_process(void *s)
{
    vr_response_common_process((vr_response *)s, NULL);
    return;
}

static void
vrmemstats_fill_nl_callbacks()
{
    nl_cb.vr_mem_stats_req_process = mem_stats_req_process;
    nl_cb.vr_response_process = response_process;
}


static int
vr_get_mem_stats(struct nl_client *cl)
{
    int ret;

    ret = vr_send_mem_stats_get(cl, 0);
    if (ret < 0)
        return ret;

    return vr_recvmsg(cl, false);
}

enum opt_index {
    HELP_OPT_INDEX,
    MAX_OPT_INDEX,
};

static struct option long_options[] = {
    [HELP_OPT_INDEX]    =   {"help",    no_argument,        &help_set,      1},
    [MAX_OPT_INDEX]     =   {NULL,    0,                  0,              0},
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

    vrmemstats_fill_nl_callbacks();

    while (((opt = getopt_long(argc, argv, "",
                        long_options, &option_index)) >= 0)) {
        switch (opt) {
        case 0:
            break;

        default:
            Usage();
        }
    }

    cl = vr_get_nl_client(VR_NETLINK_PROTO_DEFAULT);
    if (!cl) {
        exit(1);
    }

    vr_get_mem_stats(cl);

    return 0;
}
