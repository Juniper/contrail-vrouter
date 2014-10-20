/*
 * vr_dpdk_virtio.h - header for DPDK virtio forwarding infrastructure.
 *
 *
 * Copyright (c) 2014 Juniper Networks, Inc. All rights reserved.
 */

#ifndef __VR_DPDK_VIRTIO_H__
#define __VR_DPDK_VIRTIO_H__

#define VR_DPDK_VIRTIO_RX_BURST_SZ 32

typedef struct vr_dpdk_virtioq {
    int vdv_ready_state;
    int vdv_enabled_state;
} vr_dpdk_virtioq_t;

uint16_t vr_dpdk_virtio_nrxqs(struct vr_interface *vif);
uint16_t vr_dpdk_virtio_ntxqs(struct vr_interface *vif);
struct vr_dpdk_rx_queue *
vr_dpdk_virtio_rx_queue_init(unsigned int lcore_id, struct vr_interface *vif,
                             unsigned int q_id);
struct vr_dpdk_tx_queue *
vr_dpdk_virtio_tx_queue_init(unsigned int lcore_id, struct vr_interface *vif,
                             unsigned int q_id);

#endif /* __VR_DPDK_VIRTIO_H__ */
