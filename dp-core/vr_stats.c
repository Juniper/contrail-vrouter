/*
 * vr_stats.c -- catch all stats support. basically for stats which don't
 * go well in any other bucket, for eg: packet drop statistics
 *
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#include <vr_os.h>
#include <vr_types.h>
#include <vr_packet.h>
#include "vr_message.h"
#include "vr_btable.h"

void vr_stats_exit(struct vrouter *, bool);
int vr_stats_init(struct vrouter *);

static void
vr_drop_stats_make_response(vr_drop_stats_req *response, uint64_t *stats)
{
    if (!response || !stats)
        return;

    response->vds_discard += stats[VP_DROP_DISCARD];
    response->vds_pull += stats[VP_DROP_PULL];
    response->vds_invalid_if += stats[VP_DROP_INVALID_IF];
    response->vds_invalid_arp += stats[VP_DROP_INVALID_ARP];
    response->vds_trap_no_if += stats[VP_DROP_TRAP_NO_IF];
    response->vds_nowhere_to_go += stats[VP_DROP_NOWHERE_TO_GO];
    response->vds_flow_queue_limit_exceeded +=
        stats[VP_DROP_FLOW_QUEUE_LIMIT_EXCEEDED];
    response->vds_flow_no_memory += stats[VP_DROP_FLOW_NO_MEMORY];
    response->vds_flow_invalid_protocol +=
        stats[VP_DROP_FLOW_INVALID_PROTOCOL];
    response->vds_flow_nat_no_rflow += stats[VP_DROP_FLOW_NAT_NO_RFLOW];
    response->vds_flow_action_drop += stats[VP_DROP_FLOW_ACTION_DROP];
    response->vds_flow_action_invalid += stats[VP_DROP_FLOW_ACTION_INVALID];
    response->vds_flow_unusable += stats[VP_DROP_FLOW_UNUSABLE];
    response->vds_flow_table_full += stats[VP_DROP_FLOW_TABLE_FULL];
    response->vds_interface_tx_discard += stats[VP_DROP_INTERFACE_TX_DISCARD];
    response->vds_interface_drop += stats[VP_DROP_INTERFACE_DROP];
    response->vds_duplicated += stats[VP_DROP_DUPLICATED];
    response->vds_push += stats[VP_DROP_PUSH];
    response->vds_ttl_exceeded += stats[VP_DROP_TTL_EXCEEDED];
    response->vds_invalid_nh += stats[VP_DROP_INVALID_NH];
    response->vds_invalid_label += stats[VP_DROP_INVALID_LABEL];
    response->vds_invalid_protocol += stats[VP_DROP_INVALID_PROTOCOL];
    response->vds_interface_rx_discard += stats[VP_DROP_INTERFACE_RX_DISCARD];
    response->vds_invalid_mcast_source += stats[VP_DROP_INVALID_MCAST_SOURCE];
    response->vds_pcow_fail += stats[VP_DROP_PCOW_FAIL];
    response->vds_mcast_df_bit += stats[VP_DROP_MCAST_DF_BIT];
    response->vds_mcast_clone_fail += stats[VP_DROP_MCAST_CLONE_FAIL];
    response->vds_no_memory += stats[VP_DROP_NO_MEMORY];
    response->vds_rewrite_fail += stats[VP_DROP_REWRITE_FAIL];
    response->vds_misc += stats[VP_DROP_MISC];
    response->vds_invalid_packet += stats[VP_DROP_INVALID_PACKET];
    response->vds_cksum_err += stats[VP_DROP_CKSUM_ERR];
    response->vds_no_fmd += stats[VP_DROP_NO_FMD];
    response->vds_cloned_original += stats[VP_DROP_CLONED_ORIGINAL];
    response->vds_invalid_vnid += stats[VP_DROP_INVALID_VNID];
    response->vds_frag_err += stats[VP_DROP_FRAGMENTS];
    response->vds_invalid_source += stats[VP_DROP_INVALID_SOURCE];
    response->vds_l2_no_route += stats[VP_DROP_L2_NO_ROUTE];
    response->vds_fragment_queue_fail +=
        stats[VP_DROP_FRAGMENT_QUEUE_FAIL];
    response->vds_vlan_fwd_tx += stats[VP_DROP_VLAN_FWD_TX];
    response->vds_vlan_fwd_enq += stats[VP_DROP_VLAN_FWD_ENQ];
    response->vds_drop_new_flow += stats[VP_DROP_NEW_FLOWS];
    response->vds_flow_evict += stats[VP_DROP_FLOW_EVICT];
    response->vds_trap_original += stats[VP_DROP_TRAP_ORIGINAL];
    response->vds_leaf_to_leaf += stats[VP_DROP_LEAF_TO_LEAF];
    response->vds_bmac_isid_mismatch += stats[VP_DROP_BMAC_ISID_MISMATCH];
    response->vds_pkt_loop += stats[VP_DROP_PKT_LOOP];

    return;
}


void
vr_drop_stats_get_vif_stats(vr_drop_stats_req *response,
                                struct vr_interface *vif)
{
    uint8_t *count;
    int stats_index, cpu;
    uint64_t stats[VP_DROP_MAX];

    if (!vif || !vif->vif_drop_stats)
        return;

    /*
     * Collect all per cpu and full stats of this interface in local
     * stats before adding to response
     */
    for (stats_index = 0; stats_index < VP_DROP_MAX; stats_index++) {
        stats[stats_index] = vif->vif_drop_stats[stats_index];
        if (vif->vif_pcpu_drop_stats) {
            for (cpu = 0; cpu < vr_num_cpus; cpu++) {
                count = vr_btable_get(vif->vif_pcpu_drop_stats,
                            ((cpu * VP_DROP_MAX) + stats_index));
                stats[stats_index] += *count;
            }
        } else {
            response->vds_pcpu_stats_failure_status = 1;
        }
    }

    /* Now add add the stats to response message */
    vr_drop_stats_make_response(response, stats);

    return;
}

static void
vr_drop_stats_get(unsigned int rid, short core)
{
    int ret = 0;
    unsigned int cpu;
    struct vrouter *router = vrouter_get(rid);
    vr_drop_stats_req *response = NULL;

    if (!router && (ret = -ENOENT))
        goto exit_get;

    response = vr_zalloc(sizeof(*response), VR_DROP_STATS_REQ_OBJECT);
    if (!response && (ret = -ENOMEM))
        goto exit_get;

    if (core == -1) {
        /* summed up stats */
        for (cpu = 0; cpu < vr_num_cpus; cpu++) {
            vr_drop_stats_make_response(response, router->vr_pdrop_stats[cpu]);
        }
    } else if (core < vr_num_cpus) {
        /* stats for a specific core */
        vr_drop_stats_make_response(response, router->vr_pdrop_stats[core]);
    }
    /* otherwise the counters will be zeros */

exit_get:
    vr_message_response(VR_DROP_STATS_OBJECT_ID, ret ? NULL : response, ret, false);

    if (response != NULL)
        vr_free(response, VR_DROP_STATS_REQ_OBJECT);

    return;
}

void
vr_drop_stats_req_process(void *s_req)
{
    int ret;
    vr_drop_stats_req *req = (vr_drop_stats_req *)s_req;

    if ((req->h_op != SANDESH_OP_GET) && (ret = -EOPNOTSUPP))
        vr_send_response(ret);

    /* zero vds_core means to sum up all the per-core stats */
    vr_drop_stats_get(req->vds_rid, req->vds_core - 1);
    return;
}

static void
vr_mem_stats_get(void)
{
    int ret = 0;
    unsigned int cpu, i;
    int64_t alloced = 0, freed = 0;

    struct vrouter *router = vrouter_get(0);
    struct vr_malloc_stats *stats_block;
    vr_mem_stats_req *response = NULL;

    if (!router && (ret = -ENOENT))
        goto exit_get;

    response = vr_zalloc(sizeof(*response), VR_MEM_STATS_REQ_OBJECT);
    if (!response && (ret = -ENOMEM))
        goto exit_get;


    for (cpu = 0; cpu < vr_num_cpus; cpu++) {
        stats_block = (struct vr_malloc_stats *)router->vr_malloc_stats[cpu];
        response->vms_assembler_table_object += (stats_block[VR_ASSEMBLER_TABLE_OBJECT].ms_alloc -
                stats_block[VR_ASSEMBLER_TABLE_OBJECT].ms_free);
        response->vms_bridge_mac_object += (stats_block[VR_BRIDGE_MAC_OBJECT].ms_alloc -
                stats_block[VR_BRIDGE_MAC_OBJECT].ms_free);
        response->vms_btable_object += (stats_block[VR_BTABLE_OBJECT].ms_alloc -
                stats_block[VR_BTABLE_OBJECT].ms_free);
        response->vms_build_info_object += (stats_block[VR_BUILD_INFO_OBJECT].ms_alloc -
                stats_block[VR_BUILD_INFO_OBJECT].ms_free);
        response->vms_defer_object += (stats_block[VR_DEFER_OBJECT].ms_alloc -
                stats_block[VR_DEFER_OBJECT].ms_free);
        response->vms_drop_stats_object += (stats_block[VR_DROP_STATS_OBJECT].ms_alloc -
                stats_block[VR_DROP_STATS_OBJECT].ms_free);
        response->vms_drop_stats_req_object += (stats_block[VR_DROP_STATS_REQ_OBJECT].ms_alloc -
                stats_block[VR_DROP_STATS_REQ_OBJECT].ms_free);
        response->vms_flow_queue_object += (stats_block[VR_FLOW_QUEUE_OBJECT].ms_alloc -
                stats_block[VR_FLOW_QUEUE_OBJECT].ms_free);
        response->vms_flow_req_object += (stats_block[VR_FLOW_REQ_OBJECT].ms_alloc -
                stats_block[VR_FLOW_REQ_OBJECT].ms_free);
        response->vms_flow_req_path_object += (stats_block[VR_FLOW_REQ_PATH_OBJECT].ms_alloc -
                stats_block[VR_FLOW_REQ_PATH_OBJECT].ms_free);
        response->vms_flow_hold_stat_object += (stats_block[VR_FLOW_HOLD_STAT_OBJECT].ms_alloc -
                stats_block[VR_FLOW_HOLD_STAT_OBJECT].ms_free);
        response->vms_flow_link_local_object += (stats_block[VR_FLOW_LINK_LOCAL_OBJECT].ms_alloc -
                stats_block[VR_FLOW_LINK_LOCAL_OBJECT].ms_free);
        response->vms_flow_metadata_object += (stats_block[VR_FLOW_METADATA_OBJECT].ms_alloc -
                stats_block[VR_FLOW_METADATA_OBJECT].ms_free);
        response->vms_flow_table_data_object += (stats_block[VR_FLOW_TABLE_DATA_OBJECT].ms_alloc -
                stats_block[VR_FLOW_TABLE_DATA_OBJECT].ms_free);
        response->vms_flow_table_info_object += (stats_block[VR_FLOW_TABLE_INFO_OBJECT].ms_alloc -
                stats_block[VR_FLOW_TABLE_INFO_OBJECT].ms_free);
        response->vms_fragment_object += (stats_block[VR_FRAGMENT_OBJECT].ms_alloc -
                stats_block[VR_FRAGMENT_OBJECT].ms_free);
        response->vms_fragment_queue_object += (stats_block[VR_FRAGMENT_QUEUE_OBJECT].ms_alloc -
                stats_block[VR_FRAGMENT_QUEUE_OBJECT].ms_free);
        response->vms_fragment_queue_element_object += (stats_block[VR_FRAGMENT_QUEUE_ELEMENT_OBJECT].ms_alloc -
                stats_block[VR_FRAGMENT_QUEUE_ELEMENT_OBJECT].ms_free);
        response->vms_fragment_scanner_object += (stats_block[VR_FRAGMENT_SCANNER_OBJECT].ms_alloc -
                stats_block[VR_FRAGMENT_SCANNER_OBJECT].ms_free);
        response->vms_hpacket_pool_object += (stats_block[VR_HPACKET_POOL_OBJECT].ms_alloc -
                stats_block[VR_HPACKET_POOL_OBJECT].ms_free);
        response->vms_htable_object += (stats_block[VR_HTABLE_OBJECT].ms_alloc -
                stats_block[VR_HTABLE_OBJECT].ms_free);
        response->vms_interface_object += (stats_block[VR_INTERFACE_OBJECT].ms_alloc -
                stats_block[VR_INTERFACE_OBJECT].ms_free);
        response->vms_interface_bridge_lock_object +=
            (stats_block[VR_INTERFACE_BRIDGE_LOCK_OBJECT].ms_alloc -
                stats_block[VR_INTERFACE_BRIDGE_LOCK_OBJECT].ms_free);
        response->vms_interface_req_bridge_id_object +=
            (stats_block[VR_INTERFACE_REQ_BRIDGE_ID_OBJECT].ms_alloc -
                stats_block[VR_INTERFACE_REQ_BRIDGE_ID_OBJECT].ms_free);
        response->vms_interface_fat_flow_config_object +=
            (stats_block[VR_INTERFACE_FAT_FLOW_CONFIG_OBJECT].ms_alloc -
                stats_block[VR_INTERFACE_FAT_FLOW_CONFIG_OBJECT].ms_free);
        response->vms_interface_mac_object += (stats_block[VR_INTERFACE_MAC_OBJECT].ms_alloc -
                stats_block[VR_INTERFACE_MAC_OBJECT].ms_free);
        response->vms_interface_queue_object += (stats_block[VR_INTERFACE_QUEUE_OBJECT].ms_alloc -
                stats_block[VR_INTERFACE_QUEUE_OBJECT].ms_free);
        response->vms_interface_req_object += (stats_block[VR_INTERFACE_REQ_OBJECT].ms_alloc -
                stats_block[VR_INTERFACE_REQ_OBJECT].ms_free);
        response->vms_interface_req_mac_object += (stats_block[VR_INTERFACE_REQ_MAC_OBJECT].ms_alloc -
                stats_block[VR_INTERFACE_REQ_MAC_OBJECT].ms_free);
        response->vms_interface_req_name_object += (stats_block[VR_INTERFACE_REQ_NAME_OBJECT].ms_alloc -
                stats_block[VR_INTERFACE_REQ_NAME_OBJECT].ms_free);
        response->vms_interface_req_pbb_mac_object +=
            (stats_block[VR_INTERFACE_REQ_PBB_MAC_OBJECT].ms_alloc -
                stats_block[VR_INTERFACE_REQ_PBB_MAC_OBJECT].ms_free);
        response->vms_interface_stats_object += (stats_block[VR_INTERFACE_STATS_OBJECT].ms_alloc -
                stats_block[VR_INTERFACE_STATS_OBJECT].ms_free);
        response->vms_interface_table_object += (stats_block[VR_INTERFACE_TABLE_OBJECT].ms_alloc -
                stats_block[VR_INTERFACE_TABLE_OBJECT].ms_free);
        response->vms_interface_vrf_table_object += (stats_block[VR_INTERFACE_VRF_TABLE_OBJECT].ms_alloc -
                stats_block[VR_INTERFACE_VRF_TABLE_OBJECT].ms_free);
        response->vms_itable_object += (stats_block[VR_ITABLE_OBJECT].ms_alloc -
                stats_block[VR_ITABLE_OBJECT].ms_free);
        response->vms_malloc_object += (stats_block[VR_MALLOC_OBJECT].ms_alloc -
                stats_block[VR_MALLOC_OBJECT].ms_free);
        response->vms_message_object += (stats_block[VR_MESSAGE_OBJECT].ms_alloc -
                stats_block[VR_MESSAGE_OBJECT].ms_free);
        response->vms_message_response_object += (stats_block[VR_MESSAGE_RESPONSE_OBJECT].ms_alloc -
                stats_block[VR_MESSAGE_RESPONSE_OBJECT].ms_free);
        response->vms_message_dump_object += (stats_block[VR_MESSAGE_DUMP_OBJECT].ms_alloc -
                stats_block[VR_MESSAGE_DUMP_OBJECT].ms_free);
        response->vms_mem_stats_req_object += (stats_block[VR_MEM_STATS_REQ_OBJECT].ms_alloc -
                stats_block[VR_MEM_STATS_REQ_OBJECT].ms_free);
        response->vms_mirror_object += (stats_block[VR_MIRROR_OBJECT].ms_alloc -
                stats_block[VR_MIRROR_OBJECT].ms_free);
        response->vms_mirror_table_object += (stats_block[VR_MIRROR_TABLE_OBJECT].ms_alloc -
                stats_block[VR_MIRROR_TABLE_OBJECT].ms_free);
        response->vms_mirror_meta_object += (stats_block[VR_MIRROR_META_OBJECT].ms_alloc -
                stats_block[VR_MIRROR_META_OBJECT].ms_free);
        response->vms_mtrie_object += (stats_block[VR_MTRIE_OBJECT].ms_alloc -
                stats_block[VR_MTRIE_OBJECT].ms_free);
        response->vms_mtrie_bucket_object += (stats_block[VR_MTRIE_BUCKET_OBJECT].ms_alloc -
                stats_block[VR_MTRIE_BUCKET_OBJECT].ms_free);
        response->vms_mtrie_stats_object += (stats_block[VR_MTRIE_STATS_OBJECT].ms_alloc -
                stats_block[VR_MTRIE_STATS_OBJECT].ms_free);
        response->vms_mtrie_table_object += (stats_block[VR_MTRIE_TABLE_OBJECT].ms_alloc -
                stats_block[VR_MTRIE_TABLE_OBJECT].ms_free);
        response->vms_network_address_object += (stats_block[VR_NETWORK_ADDRESS_OBJECT].ms_alloc -
                stats_block[VR_NETWORK_ADDRESS_OBJECT].ms_free);
        response->vms_nexthop_object += (stats_block[VR_NEXTHOP_OBJECT].ms_alloc -
                stats_block[VR_NEXTHOP_OBJECT].ms_free);
        response->vms_nexthop_component_object += (stats_block[VR_NEXTHOP_COMPONENT_OBJECT].ms_alloc -
                stats_block[VR_NEXTHOP_COMPONENT_OBJECT].ms_free);
        response->vms_nexthop_req_bmac_object +=
            (stats_block[VR_NEXTHOP_REQ_BMAC_OBJECT].ms_alloc -
                stats_block[VR_NEXTHOP_REQ_BMAC_OBJECT].ms_free);
        response->vms_nexthop_req_list_object += (stats_block[VR_NEXTHOP_REQ_LIST_OBJECT].ms_alloc -
                stats_block[VR_NEXTHOP_REQ_LIST_OBJECT].ms_free);
        response->vms_nexthop_req_encap_object += (stats_block[VR_NEXTHOP_REQ_ENCAP_OBJECT].ms_alloc -
                stats_block[VR_NEXTHOP_REQ_ENCAP_OBJECT].ms_free);
        response->vms_nexthop_req_object += (stats_block[VR_NEXTHOP_REQ_OBJECT].ms_alloc -
                stats_block[VR_NEXTHOP_REQ_OBJECT].ms_free);
        response->vms_route_table_object += (stats_block[VR_ROUTE_TABLE_OBJECT].ms_alloc -
                stats_block[VR_ROUTE_TABLE_OBJECT].ms_free);
        response->vms_route_req_mac_object += (stats_block[VR_ROUTE_REQ_MAC_OBJECT].ms_alloc -
                stats_block[VR_ROUTE_REQ_MAC_OBJECT].ms_free);
        response->vms_timer_object += (stats_block[VR_TIMER_OBJECT].ms_alloc -
                stats_block[VR_TIMER_OBJECT].ms_free);
        response->vms_usock_object += (stats_block[VR_USOCK_OBJECT].ms_alloc -
                stats_block[VR_USOCK_OBJECT].ms_free);
        response->vms_usock_poll_object += (stats_block[VR_USOCK_POLL_OBJECT].ms_alloc -
                stats_block[VR_USOCK_POLL_OBJECT].ms_free);
        response->vms_usock_buf_object += (stats_block[VR_USOCK_BUF_OBJECT].ms_alloc -
                stats_block[VR_USOCK_BUF_OBJECT].ms_free);
        response->vms_usock_iovec_object += (stats_block[VR_USOCK_IOVEC_OBJECT].ms_alloc -
                stats_block[VR_USOCK_IOVEC_OBJECT].ms_free);
        response->vms_vrouter_req_object += (stats_block[VR_VROUTER_REQ_OBJECT].ms_alloc -
                stats_block[VR_VROUTER_REQ_OBJECT].ms_free);
        response->vms_qos_map_object += (stats_block[VR_QOS_MAP_OBJECT].ms_alloc -
                stats_block[VR_QOS_MAP_OBJECT].ms_free);
        response->vms_fc_object += (stats_block[VR_FC_OBJECT].ms_alloc -
                stats_block[VR_FC_OBJECT].ms_free);
        response->vms_interface_mirror_meta_object +=
            (stats_block[VR_INTERFACE_MIRROR_META_OBJECT].ms_alloc -
            stats_block[VR_INTERFACE_MIRROR_META_OBJECT].ms_free);
        response->vms_interface_req_mirror_meta_object +=
            (stats_block[VR_INTERFACE_REQ_MIRROR_META_OBJECT].ms_alloc -
            stats_block[VR_INTERFACE_REQ_MIRROR_META_OBJECT].ms_free);
        for (i = 0; i < VR_VROUTER_MAX_OBJECT; i++) {
            alloced += stats_block[i].ms_alloc;
            freed += stats_block[i].ms_free;
        }
    }


    response->vms_alloced = alloced;
    response->vms_freed = freed;

exit_get:
    vr_message_response(VR_MEM_STATS_OBJECT_ID, ret ? NULL : response, ret, false);
    if (response != NULL)
        vr_free(response, VR_MEM_STATS_REQ_OBJECT);

    return;
}

void
vr_mem_stats_req_process(void *s_req)
{
    int ret;
    vr_mem_stats_req *req = (vr_mem_stats_req *)s_req;

    if ((req->h_op != SANDESH_OP_GET) && (ret = -EOPNOTSUPP))
        vr_send_response(ret);

    vr_mem_stats_get();
    return;
}

void
vr_free_stats(unsigned int object)
{
    struct vrouter *router = vrouter_get(0);
    unsigned int cpu;

    cpu = vr_get_cpu();
    if (router->vr_malloc_stats && router->vr_malloc_stats[cpu])
        router->vr_malloc_stats[cpu][object].ms_free++;

    return;
}

void
vr_malloc_stats(unsigned int size, unsigned int object)
{
    struct vrouter *router = vrouter_get(0);
    unsigned int cpu;

    cpu = vr_get_cpu();
    if (router->vr_malloc_stats) {
        if (router->vr_malloc_stats[cpu]) {
            router->vr_malloc_stats[cpu][object].ms_size += size;
            router->vr_malloc_stats[cpu][object].ms_alloc++;
        }
    }

    return;
}

static void
vr_malloc_stats_exit(struct vrouter *router)
{
    unsigned int i;

    if (!router->vr_malloc_stats)
        return;

    for (i = 0; i < vr_num_cpus; i++) {
        if (router->vr_malloc_stats[i]) {
            vr_free(router->vr_malloc_stats[i], VR_MALLOC_OBJECT);
            router->vr_malloc_stats[i] = NULL;
        }
    }

    vr_free(router->vr_malloc_stats, VR_MALLOC_OBJECT);
    router->vr_malloc_stats = NULL;

    return;
}

static int
vr_malloc_stats_init(struct vrouter *router)
{
    unsigned int i, size, cpu, total_size = 0;

    if (router->vr_malloc_stats)
        return 0;

    size = vr_num_cpus * sizeof(void *);
    router->vr_malloc_stats = vr_zalloc(size, VR_MALLOC_OBJECT);
    if (!router->vr_malloc_stats)
        return -ENOMEM;
    total_size += size;

    size = VR_VROUTER_MAX_OBJECT * sizeof(struct vr_malloc_stats);
    /*
     * align the allocation to cache line size so that per-cpu variable
     * do not result in cache thrashing
     */
    if (size % 64) {
        size = size + (64 - (size % 64));
    }

    for (i = 0; i < vr_num_cpus; i++) {
        router->vr_malloc_stats[i] = vr_zalloc(size, VR_MALLOC_OBJECT);
        if (!router->vr_malloc_stats)
            return -ENOMEM;
        total_size += size;
    }

    cpu = vr_get_cpu();
    router->vr_malloc_stats[cpu][VR_MALLOC_OBJECT].ms_alloc = vr_num_cpus + 1;
    router->vr_malloc_stats[cpu][VR_MALLOC_OBJECT].ms_size = total_size;

    return 0;
}

static void
vr_pkt_drop_stats_exit(struct vrouter *router)
{
    unsigned int i;

    if (!router->vr_pdrop_stats)
        return;

    for (i = 0; i < vr_num_cpus; i++) {
        if (!router->vr_pdrop_stats[i])
            break;
        vr_free(router->vr_pdrop_stats[i], VR_DROP_STATS_OBJECT);
        router->vr_pdrop_stats[i] = NULL;
    }

    vr_free(router->vr_pdrop_stats, VR_DROP_STATS_OBJECT);
    router->vr_pdrop_stats = NULL;

    return;
}


static int
vr_pkt_drop_stats_init(struct vrouter *router)
{
    unsigned int i = 0;
    unsigned int size = 0;

    if (router->vr_pdrop_stats)
        return 0;

    size = sizeof(void *) * vr_num_cpus;
    router->vr_pdrop_stats = vr_zalloc(size, VR_DROP_STATS_OBJECT);
    if (!router->vr_pdrop_stats) {
        vr_module_error(-ENOMEM, __FUNCTION__,
                __LINE__, size);
        goto cleanup;
    }

    size = VP_DROP_MAX * sizeof(uint64_t);
    for (i = 0; i < vr_num_cpus; i++) {
        router->vr_pdrop_stats[i] = vr_zalloc(size, VR_DROP_STATS_OBJECT);
        if (!router->vr_pdrop_stats[i]) {
            vr_module_error(-ENOMEM, __FUNCTION__,
                    __LINE__, i);
            goto cleanup;
        }
    }

    return 0;

cleanup:
    vr_pkt_drop_stats_exit(router);
    return -ENOMEM;
}

static void
vr_pkt_drop_stats_reset(struct vrouter *router)
{
    unsigned int i;

    if (!router->vr_pdrop_stats)
        return;

    for (i = 0; i < vr_num_cpus; i++) {
        if (router->vr_pdrop_stats[i])
            memset(router->vr_pdrop_stats[i], 0, VP_DROP_MAX * sizeof(uint64_t));
    }

    return;
}

void
vr_stats_exit(struct vrouter *router, bool soft_reset)
{
    if (soft_reset) {
        vr_pkt_drop_stats_reset(router);
        return;
    }

    vr_pkt_drop_stats_exit(router);
    vr_malloc_stats_exit(router);
    return;
}

int
vr_stats_init(struct vrouter *router)
{
    int ret;

    ret = vr_malloc_stats_init(router);
    if (ret)
        return ret;

    return vr_pkt_drop_stats_init(router);
}
