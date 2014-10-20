/*
 * vr_dpdk_virtio.c - implements DPDK forwarding infrastructure for 
 * virtio interfaces. The virtio data structures are setup by the user
 * space vhost server.
 *
 * Copyright (c) 2014 Juniper Networks, Inc. All rights reserved.
 */

#include <stdint.h>

#include "vr_dpdk.h"
#include "vr_dpdk_virtio.h"

vr_dpdk_virtioq_t vr_dpdk_virtio_rxqs[VR_MAX_INTERFACES][RTE_MAX_LCORE];
vr_dpdk_virtioq_t vr_dpdk_virtio_txqs[VR_MAX_INTERFACES][RTE_MAX_LCORE];

struct rte_port_in_ops dpdk_virtio_reader_ops = {
    .f_create = NULL,
    .f_free = NULL,
    .f_rx = NULL,
};

struct rte_port_out_ops dpdk_virtio_writer_ops = {
    .f_create = NULL,
    .f_free = NULL,
    .f_tx = NULL,
    .f_tx_bulk = NULL,
    .f_flush = NULL,
};

/*
 * vr_dpdk_virtio_nrxqs - returns the number of receives queues for a virtio
 * interface.
 */
uint16_t
vr_dpdk_virtio_nrxqs(struct vr_interface *vif)
{
    return 1;
}

/*
 * vr_dpdk_virtio_ntxqs - returns the number of transmit queues for a virtio
 * interface.
 */
uint16_t
vr_dpdk_virtio_ntxqs(struct vr_interface *vif)
{
    return 1;
}

/*
 * vr_dpdk_virtio_rx_queue_init - initializes a virtio RX queue.
 *
 * Returns a pointer to the RX queue on success, NULL otherwise.
 */
struct vr_dpdk_rx_queue *
vr_dpdk_virtio_rx_queue_init(unsigned int lcore_id, struct vr_interface *vif,
                             unsigned int q_id)
{
    struct vr_dpdk_lcore *lcore = vr_dpdk.lcores[lcore_id];
    unsigned vif_idx = vif->vif_idx;
    struct vr_dpdk_rx_queue *rx_queue = &lcore->lcore_rx_queues[vif_idx];

    if (q_id >= vr_dpdk_virtio_nrxqs(vif)) {
        return NULL;
    }

    rx_queue->rxq_ops = dpdk_virtio_reader_ops;
    rx_queue->rxq_queue_h = (void *) &vr_dpdk_virtio_rxqs[vif_idx][q_id];
    rx_queue->rxq_burst_size = VR_DPDK_VIRTIO_RX_BURST_SZ;
    rx_queue->rxq_vif = vif;

    return rx_queue;
}

/*
 * vr_dpdk_virtio_tx_queue_init - initializes a virtio TX queue.
 *
 * Returns a pointer to the TX queue on success, NULL otherwise.
 */
struct vr_dpdk_tx_queue *
vr_dpdk_virtio_tx_queue_init(unsigned int lcore_id, struct vr_interface *vif,
                             unsigned int q_id)
{
    struct vr_dpdk_lcore *lcore = vr_dpdk.lcores[lcore_id];
    unsigned vif_idx = vif->vif_idx;
    struct vr_dpdk_tx_queue *tx_queue = &lcore->lcore_tx_queues[vif_idx];

    if (q_id >= vr_dpdk_virtio_ntxqs(vif)) {
        return NULL;
    }

    tx_queue->txq_ops = dpdk_virtio_writer_ops;
    tx_queue->txq_queue_h = (void *) &vr_dpdk_virtio_txqs[vif_idx][q_id];
    tx_queue->txq_vif = vif;

    return tx_queue;
}

