/*
 * Copyright (C) 2014 Semihalf.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation version 2.
 *
 * This program is distributed "as is" WITHOUT ANY WARRANTY of any
 * kind, whether express or implied; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * vr_dpdk_ringdev.c -- DPDK ring device
 *
 */
#include <stdio.h>
#include <unistd.h>

#include "vr_dpdk.h"

#include <rte_port_ring.h>
#include <rte_errno.h>

/* Allocates a new ring */
static struct rte_ring *
dpdk_ring_allocate(unsigned host_lcore_id, unsigned vif_idx, unsigned for_lcore_id)
{
    int ret;
    char ring_name[RTE_RING_NAMESIZE];
    struct rte_ring *ring;
    struct vr_dpdk_lcore *host_lcore = vr_dpdk.lcores[host_lcore_id];

    if (host_lcore->lcore_nb_free_rings > 0) {
        /* reuse free ring */
        RTE_LOG(INFO, VROUTER, "\treusing lcore %u TX ring for lcore %u vif %u\n",
            host_lcore_id, for_lcore_id, vif_idx);
        return host_lcore->lcore_free_rings[--host_lcore->lcore_nb_free_rings];
    }

    RTE_LOG(INFO, VROUTER, "\tcreating lcore %u TX ring for lcore %u vif %u\n",
        host_lcore_id, for_lcore_id, vif_idx);
    ret = snprintf(ring_name, sizeof(ring_name), "vr_dpdk_ring_%u_%u_%u",
            host_lcore_id, vif_idx, for_lcore_id);
    if (ret >= sizeof(ring_name)) {
        RTE_LOG(INFO, VROUTER, "\terror creating lcore %u TX ring name\n",
            host_lcore_id);
        return NULL;
    }
    /* create single-producer single-consumer ring */
    ring = rte_ring_create(ring_name, VR_DPDK_TX_RING_SZ,
        rte_lcore_to_socket_id(host_lcore_id), RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (ring == NULL) {
        RTE_LOG(INFO, VROUTER, "\terror creating lcore %u TX ring: %s (%d)\n",
            host_lcore_id, rte_strerror(rte_errno), rte_errno);
        return NULL;
    }
    return ring;
}

/* Free the ring */
static void
dpdk_ring_free(unsigned host_lcore_id, struct rte_ring *ring)
{
    struct vr_dpdk_lcore *host_lcore = vr_dpdk.lcores[host_lcore_id];

    host_lcore->lcore_free_rings[host_lcore->lcore_nb_free_rings++] =
        ring;
}

/* Add the ring to the list of rings to push */
void
dpdk_ring_to_push_add(unsigned lcore_id, struct rte_ring *tx_ring,
    struct vr_dpdk_queue *tx_queue)
{
    struct vr_dpdk_lcore *lcore = vr_dpdk.lcores[lcore_id];
    struct vr_dpdk_ring_to_push *rtp = &lcore->lcore_rings_to_push[0];

    /* find an empty ring to push */
    while (rtp->rtp_tx_ring) rtp++;

    rtp->rtp_tx_ring = tx_ring;
    rtp->rtp_tx_queue = tx_queue;
    rte_wmb();
    lcore->lcore_nb_rings_to_push++;
    RTE_VERIFY(lcore->lcore_nb_rings_to_push < VR_DPDK_MAX_RINGS);
}

/* Remove the ring from the list of rings to push
 * The function is called by the NetLink lcore only.
 */
void
dpdk_ring_to_push_remove(unsigned lcore_id, struct rte_ring *tx_ring)
{
    struct vr_dpdk_lcore *lcore = vr_dpdk.lcores[lcore_id];
    struct vr_dpdk_ring_to_push *rtp = &lcore->lcore_rings_to_push[0];
    struct vr_dpdk_ring_to_push *last_rtp;

    /* find the ring to push */
    while (rtp->rtp_tx_ring != tx_ring) rtp++;

    rtp->rtp_tx_ring = NULL;
    lcore->lcore_nb_rings_to_push--;
    RTE_VERIFY(lcore->lcore_nb_rings_to_push < VR_DPDK_MAX_RINGS);
    rte_wmb();
    /* copy the last element to the empty spot */
    last_rtp = &lcore->lcore_rings_to_push[lcore->lcore_nb_rings_to_push];
    rtp->rtp_tx_queue = last_rtp->rtp_tx_queue;
    rte_wmb();
    rtp->rtp_tx_ring = last_rtp->rtp_tx_ring;
    last_rtp->rtp_tx_ring = NULL;
    last_rtp->rtp_tx_queue = NULL;
}

/* Release ring TX queue
 * The function is called by the NetLink lcore only.
 */
static void
dpdk_ring_tx_queue_release(unsigned lcore_id, struct vr_interface *vif)
{
    struct vr_dpdk_lcore *lcore = vr_dpdk.lcores[lcore_id];
    struct vr_dpdk_queue *tx_queue = &lcore->lcore_tx_queues[vif->vif_idx];
    struct vr_dpdk_queue_params *tx_queue_params
                        = &lcore->lcore_tx_queue_params[vif->vif_idx];

    tx_queue->txq_ops.f_tx = NULL;
    rte_wmb();

    /* remove the ring from the list of rings to push */
    dpdk_ring_to_push_remove(tx_queue_params->qp_ring.host_lcore_id,
            tx_queue_params->qp_ring.ring_p);

    /* deallocate the ring */
    dpdk_ring_free(tx_queue_params->qp_ring.host_lcore_id,
                            tx_queue_params->qp_ring.ring_p);

    /* flush and free the queue */
    if (tx_queue->txq_ops.f_free(tx_queue->q_queue_h)) {
        RTE_LOG(ERR, VROUTER, "\terror freeing lcore %u ring\n", lcore_id);
    }

    /* reset the queue */
    vrouter_put_interface(tx_queue->q_vif);
    memset(tx_queue, 0, sizeof(*tx_queue));
    memset(tx_queue_params, 0, sizeof(*tx_queue_params));
}

/* Init ring TX queue */
struct vr_dpdk_queue *
vr_dpdk_ring_tx_queue_init(unsigned lcore_id, struct vr_interface *vif,
    unsigned host_lcore_id)
{
    struct vr_dpdk_lcore *lcore = vr_dpdk.lcores[lcore_id];
    struct vr_dpdk_lcore *host_lcore = vr_dpdk.lcores[host_lcore_id];
    const unsigned socket_id = rte_lcore_to_socket_id(lcore_id);
    uint8_t port_id;
    unsigned vif_idx = vif->vif_idx;
    struct vr_dpdk_queue *tx_queue = &lcore->lcore_tx_queues[vif_idx];
    struct vr_dpdk_queue_params *tx_queue_params
                = &lcore->lcore_tx_queue_params[vif_idx];
    struct vr_dpdk_queue *host_tx_queue = &host_lcore->lcore_tx_queues[vif_idx];
    struct rte_ring *tx_ring;

    if (vif->vif_type == VIF_TYPE_PHYSICAL) {
        port_id = (((struct vr_dpdk_ethdev *)(vif->vif_os))->ethdev_port_id);
    } else {
        port_id = vif->vif_os_idx;
    }

    /* init queue */
    tx_queue->txq_ops = rte_port_ring_writer_ops;
    tx_queue->q_queue_h = NULL;
    tx_queue->q_vif = vrouter_get_interface(vif->vif_rid, vif_idx);

    /* allocate a ring on the host lcore */
    tx_ring = dpdk_ring_allocate(host_lcore_id, vif_idx, lcore_id);
    if (tx_ring == NULL) {
        RTE_LOG(ERR, VROUTER, "\terror allocating ring for device %" PRIu8 "\n",
            port_id);
        return NULL;
    }

    /* add the ring to the list of rings to push */
    dpdk_ring_to_push_add(host_lcore_id, tx_ring, host_tx_queue);

    /* create the queue */
    struct rte_port_ring_writer_params writer_params = {
        .ring = tx_ring,
        .tx_burst_sz = VR_DPDK_RING_TX_BURST_SZ,
    };
    tx_queue->q_queue_h = tx_queue->txq_ops.f_create(&writer_params,
                                                        socket_id);
    if (tx_queue->q_queue_h == NULL) {
        RTE_LOG(ERR, VROUTER, "\terror creating ring for device %" PRIu8 "\n",
            port_id);
        return NULL;
    }
    /* store queue params */
    tx_queue_params->qp_release_op = &dpdk_ring_tx_queue_release;
    tx_queue_params->qp_ring.ring_p = tx_ring;
    tx_queue_params->qp_ring.host_lcore_id = host_lcore_id;

    return tx_queue;
}

/* Init ring RX queue */
struct vr_dpdk_queue *
vr_dpdk_ring_rx_queue_init(unsigned lcore_id, struct vr_interface *vif,
    unsigned host_lcore_id)
{
    RTE_LOG(ERR, VROUTER, "%s: not implemented\n", __func__);

    return NULL;
}
