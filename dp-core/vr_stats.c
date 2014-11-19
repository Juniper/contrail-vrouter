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

void vr_stats_exit(struct vrouter *, bool);
int vr_stats_init(struct vrouter *);

static void
vr_drop_stats_fill_response(vr_drop_stats_req *response,
        struct vr_drop_stats *stats)
{
    response->vds_discard = stats->vds_discard;
    response->vds_pull = stats->vds_pull;
    response->vds_invalid_if = stats->vds_invalid_if;
    response->vds_arp_not_me = stats->vds_arp_not_me;
    response->vds_garp_from_vm = stats->vds_garp_from_vm;
    response->vds_invalid_arp = stats->vds_invalid_arp;
    response->vds_trap_no_if = stats->vds_trap_no_if;
    response->vds_nowhere_to_go = stats->vds_nowhere_to_go;
    response->vds_flow_queue_limit_exceeded =
        stats->vds_flow_queue_limit_exceeded;
    response->vds_flow_no_memory = stats->vds_flow_no_memory;
    response->vds_flow_invalid_protocol = 
        stats->vds_flow_invalid_protocol;
    response->vds_flow_nat_no_rflow = stats->vds_flow_nat_no_rflow;
    response->vds_flow_action_drop = stats->vds_flow_action_drop;
    response->vds_flow_action_invalid = stats->vds_flow_action_invalid;
    response->vds_flow_unusable = stats->vds_flow_unusable;
    response->vds_flow_table_full = stats->vds_flow_table_full;
    response->vds_interface_tx_discard = stats->vds_interface_tx_discard;
    response->vds_interface_drop = stats->vds_interface_drop;
    response->vds_duplicated = stats->vds_duplicated;
    response->vds_push = stats->vds_push;
    response->vds_ttl_exceeded = stats->vds_ttl_exceeded;
    response->vds_invalid_nh = stats->vds_invalid_nh;
    response->vds_invalid_label = stats->vds_invalid_label;
    response->vds_invalid_protocol = stats->vds_invalid_protocol;
    response->vds_interface_rx_discard = stats->vds_interface_rx_discard;
    response->vds_invalid_mcast_source = stats->vds_invalid_mcast_source;
    response->vds_head_alloc_fail = stats->vds_head_alloc_fail;
    response->vds_head_space_reserve_fail = stats->vds_head_space_reserve_fail;
    response->vds_pcow_fail = stats->vds_pcow_fail;
    response->vds_mcast_df_bit = stats->vds_mcast_df_bit;
    response->vds_mcast_clone_fail = stats->vds_mcast_clone_fail;
    response->vds_composite_invalid_interface =
        stats->vds_composite_invalid_interface;
    response->vds_rewrite_fail = stats->vds_rewrite_fail;
    response->vds_misc = stats->vds_misc;
    response->vds_invalid_packet = stats->vds_invalid_packet;
    response->vds_cksum_err = stats->vds_cksum_err;
    response->vds_clone_fail = stats->vds_clone_fail;
    response->vds_no_fmd = stats->vds_no_fmd;
    response->vds_cloned_original =
        stats->vds_cloned_original;
    response->vds_invalid_vnid = stats->vds_invalid_vnid;
    response->vds_frag_err = stats->vds_frag_err;
    response->vds_invalid_source = stats->vds_invalid_source;

    return;
}

static void
vr_drop_stats_get(void)
{
    int ret = 0;
    unsigned int cpu;
    struct vrouter *router = vrouter_get(0);
    vr_drop_stats_req response;
    struct vr_drop_stats *stats_block, *stats = NULL;

    if (!router && (ret = -ENOENT))
        goto exit_get;

    stats = vr_zalloc(sizeof(*stats));
    if (!stats && (ret = -ENOMEM))
        goto exit_get;

    for (cpu = 0; cpu < vr_num_cpus; cpu++) {
        stats_block = (struct vr_drop_stats *)router->vr_pdrop_stats[cpu];
        stats->vds_discard += stats_block->vds_discard;
        stats->vds_pull += stats_block->vds_pull;
        stats->vds_invalid_if += stats_block->vds_invalid_if;
        stats->vds_arp_not_me += stats_block->vds_arp_not_me;
        stats->vds_garp_from_vm += stats_block->vds_garp_from_vm;
        stats->vds_invalid_arp += stats_block->vds_invalid_arp;
        stats->vds_trap_no_if += stats_block->vds_trap_no_if;
        stats->vds_nowhere_to_go += stats_block->vds_nowhere_to_go;
        stats->vds_flow_queue_limit_exceeded += 
            stats_block->vds_flow_queue_limit_exceeded;
        stats->vds_flow_no_memory += stats_block->vds_flow_no_memory;
        stats->vds_flow_invalid_protocol +=
            stats_block->vds_flow_invalid_protocol;
        stats->vds_flow_nat_no_rflow += stats_block->vds_flow_nat_no_rflow;
        stats->vds_flow_action_drop += stats_block->vds_flow_action_drop;
        stats->vds_flow_action_invalid += stats_block->vds_flow_action_invalid;
        stats->vds_flow_unusable += stats_block->vds_flow_unusable;
        stats->vds_flow_table_full += stats_block->vds_flow_table_full;
        stats->vds_interface_tx_discard += stats_block->vds_interface_tx_discard;
        stats->vds_interface_drop += stats_block->vds_interface_drop;
        stats->vds_duplicated += stats_block->vds_duplicated;
        stats->vds_push += stats_block->vds_push;
        stats->vds_ttl_exceeded += stats_block->vds_ttl_exceeded;
        stats->vds_invalid_nh += stats_block->vds_invalid_nh;
        stats->vds_invalid_label += stats_block->vds_invalid_label;
        stats->vds_invalid_protocol += stats_block->vds_invalid_protocol;
        stats->vds_interface_rx_discard += stats_block->vds_interface_rx_discard;
        stats->vds_invalid_mcast_source += stats_block->vds_invalid_mcast_source;
        stats->vds_head_alloc_fail += stats_block->vds_head_alloc_fail;
        stats->vds_head_space_reserve_fail += stats_block->vds_head_space_reserve_fail;
        stats->vds_pcow_fail += stats_block->vds_pcow_fail;
        stats->vds_mcast_df_bit += stats_block->vds_mcast_df_bit;
        stats->vds_mcast_clone_fail += stats_block->vds_mcast_clone_fail;
        stats->vds_composite_invalid_interface +=
            stats_block->vds_composite_invalid_interface;
        stats->vds_rewrite_fail += stats_block->vds_rewrite_fail;
        stats->vds_misc += stats_block->vds_misc;
        stats->vds_invalid_packet += stats_block->vds_invalid_packet;
        stats->vds_cksum_err += stats_block->vds_cksum_err;
        stats->vds_clone_fail += stats_block->vds_clone_fail;
        stats->vds_no_fmd += stats_block->vds_no_fmd;
        stats->vds_cloned_original += stats_block->vds_cloned_original;
        stats->vds_invalid_vnid += stats_block->vds_invalid_vnid;
        stats->vds_frag_err += stats_block->vds_frag_err;
        stats->vds_invalid_source += stats_block->vds_invalid_source;
    }

    vr_drop_stats_fill_response(&response, stats);

exit_get:
    vr_message_response(VR_DROP_STATS_OBJECT_ID, ret ? NULL : &response, ret);
    if (stats != NULL)
        vr_free(stats);
    return;
}

void
vr_drop_stats_req_process(void *s_req)
{
    int ret;
    vr_drop_stats_req *req = (vr_drop_stats_req *)s_req;

    if ((req->h_op != SANDESH_OP_GET) && (ret = -EOPNOTSUPP))
        vr_send_response(ret);
    
    vr_drop_stats_get();
    return;
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
        vr_free(router->vr_pdrop_stats[i]);
        router->vr_pdrop_stats[i] = NULL;
    }

    vr_free(router->vr_pdrop_stats);
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
    router->vr_pdrop_stats = vr_zalloc(size);
    if (!router->vr_pdrop_stats) {
        vr_module_error(-ENOMEM, __FUNCTION__,
                __LINE__, size);
        goto cleanup;
    }

    size = VP_DROP_MAX * sizeof(uint64_t);
    for (i = 0; i < vr_num_cpus; i++) {
        router->vr_pdrop_stats[i] = vr_zalloc(size);
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
    return;
}

int
vr_stats_init(struct vrouter *router)
{
    return vr_pkt_drop_stats_init(router);
}
