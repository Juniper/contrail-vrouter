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

#include "vr_dpdk.h"

#include <rte_malloc.h>
#include <rte_port_ring.h>

/* Allocates a new ring */
struct rte_ring *
vr_dpdk_ring_allocate(unsigned host_lcore_id, char *ring_name,
    unsigned vr_dpdk_tx_ring_sz, unsigned flags)
{
    int ret;
    ssize_t ring_size;
    struct rte_ring *ring;

    ring_size = rte_ring_get_memsize(vr_dpdk_tx_ring_sz);
    if (ring_size == -EINVAL)
        return NULL;

    ring = (struct rte_ring *)rte_malloc_socket(ring_name, ring_size,
        RTE_CACHE_LINE_SIZE,  rte_lcore_to_socket_id(host_lcore_id));
    if (ring == NULL)
        return NULL;

    ret = rte_ring_init(ring, ring_name, vr_dpdk_tx_ring_sz, flags);
    if (ret < 0) {
        rte_free(ring);
        return NULL;
    }

    return ring;
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
    RTE_LOG(INFO, VROUTER, "    lcore %u now has %" PRIu16
        " ring(s) to push\n",
        lcore_id, lcore->lcore_nb_rings_to_push);
    RTE_VERIFY(lcore->lcore_nb_rings_to_push <= VR_DPDK_MAX_RINGS);
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
    RTE_VERIFY(lcore->lcore_nb_rings_to_push <= VR_DPDK_MAX_RINGS);
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
dpdk_ring_tx_queue_release(unsigned lcore_id, unsigned queue_index,
        struct vr_interface *vif)
{
    struct vr_dpdk_lcore *lcore = vr_dpdk.lcores[lcore_id];
    struct vr_dpdk_queue *tx_queue =
        &lcore->lcore_tx_queues[vif->vif_idx][queue_index];
    struct vr_dpdk_queue_params *tx_queue_params
        = &lcore->lcore_tx_queue_params[vif->vif_idx][queue_index];

    tx_queue->txq_ops.f_tx = NULL;
    rte_wmb();

    /* remove the ring from the list of rings to push */
    dpdk_ring_to_push_remove(tx_queue_params->qp_ring.host_lcore_id,
            tx_queue_params->qp_ring.ring_p);

    rte_free(tx_queue_params->qp_ring.ring_p);

    /* flush and free the queue */
    if (tx_queue->txq_ops.f_free(tx_queue->q_queue_h)) {
        RTE_LOG(ERR, VROUTER, "    error freeing lcore %u ring\n", lcore_id);
    }

    /* reset the queue */
    vrouter_put_interface(tx_queue->q_vif);
    memset(tx_queue, 0, sizeof(*tx_queue));
    memset(tx_queue_params, 0, sizeof(*tx_queue_params));
}

/* Init ring TX queue */
struct vr_dpdk_queue *
vr_dpdk_ring_tx_queue_init(unsigned lcore_id, struct vr_interface *vif,
        unsigned int queue_id, unsigned host_lcore_id)
{
    int ret;
    uint8_t port_id;
    unsigned int vif_idx = vif->vif_idx, dpdk_queue_index;
    const unsigned int socket_id = rte_lcore_to_socket_id(lcore_id);

    char ring_name[RTE_RING_NAMESIZE];
    struct rte_ring *tx_ring;
    struct vr_dpdk_lcore *lcore = vr_dpdk.lcores[lcore_id];
    struct vr_dpdk_lcore *host_lcore = vr_dpdk.lcores[host_lcore_id];
    struct vr_dpdk_queue *tx_queue;
    struct vr_dpdk_queue_params *tx_queue_params;
    struct vr_dpdk_queue *host_tx_queue;


    if (lcore->lcore_hw_queue_to_dpdk_index[vif->vif_idx]) {
        dpdk_queue_index =
            lcore->lcore_hw_queue_to_dpdk_index[vif->vif_idx][queue_id];
    } else {
        dpdk_queue_index = 0;
    }

    tx_queue = &lcore->lcore_tx_queues[vif_idx][dpdk_queue_index];
    tx_queue_params = &lcore->lcore_tx_queue_params[vif_idx][dpdk_queue_index];
    host_tx_queue = &host_lcore->lcore_tx_queues[vif_idx][dpdk_queue_index];

    if (vif->vif_type == VIF_TYPE_PHYSICAL) {
        port_id = (((struct vr_dpdk_ethdev *)(vif->vif_os))->ethdev_port_id);
    } else {
        port_id = vif->vif_os_idx;
    }

    /* init queue */
    tx_queue->txq_ops = rte_port_ring_writer_ops;
    tx_queue->q_queue_h = NULL;
    tx_queue->q_vif = vrouter_get_interface(vif->vif_rid, vif_idx);

    ret = snprintf(ring_name, sizeof(ring_name), "vr_dpdk_ring_%u_%u_%u",
        host_lcore_id, vif_idx, lcore_id);
    if (ret >= sizeof(ring_name))
        goto error;

    /* allocate a ring on the host lcore (single-producer single-consumer) */
    tx_ring = vr_dpdk_ring_allocate(host_lcore_id, ring_name,
            VR_DPDK_TX_RING_SZ, RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (tx_ring == NULL)
        goto error;

    /* add the ring to the list of rings to push */
    dpdk_ring_to_push_add(host_lcore_id, tx_ring, host_tx_queue);

    /* create the queue */
    struct rte_port_ring_writer_params writer_params = {
        .ring = tx_ring,
        .tx_burst_sz = VR_DPDK_TX_BURST_SZ,
    };
    tx_queue->q_queue_h = tx_queue->txq_ops.f_create(&writer_params,
                                                        socket_id);
    if (tx_queue->q_queue_h == NULL)
        goto error;

    /* store queue params */
    tx_queue_params->qp_release_op = &dpdk_ring_tx_queue_release;
    tx_queue_params->qp_ring.ring_p = tx_ring;
    tx_queue_params->qp_ring.host_lcore_id = host_lcore_id;

    return tx_queue;

error:
    RTE_LOG(ERR, VROUTER, "    error initializing ring TX queue for device %"
        PRIu8 "\n", port_id);
    return NULL;
}

/* Init ring RX queue */
struct vr_dpdk_queue *
vr_dpdk_ring_rx_queue_init(unsigned lcore_id, struct vr_interface *vif,
    unsigned host_lcore_id)
{
    RTE_LOG(ERR, VROUTER, "%s: not implemented\n", __func__);

    return NULL;
}
