/*
 * vr_dpdk_virtio.h - header for DPDK virtio forwarding infrastructure.
 *
 *
 * Copyright (c) 2014 Juniper Networks, Inc. All rights reserved.
 */

#ifndef __VR_DPDK_VIRTIO_H__
#define __VR_DPDK_VIRTIO_H__

/*
 * Burst size for packets from a VM
 */
#define VR_DPDK_VIRTIO_RX_BURST_SZ VR_DPDK_RX_BURST_SZ
/*
 * Burst size for packets to a VM
 */
#define VR_DPDK_VIRTIO_TX_BURST_SZ VR_DPDK_TX_BURST_SZ
/*
 * Maximum number of queues per virtio device
 */
#define VR_DPDK_VIRTIO_MAX_QUEUES 16

#define VR_BUF_VECTOR_MAX 256

typedef enum vq_ready_state {
    VQ_NOT_READY,
    VQ_READY,
} vq_ready_state_t;

/*
 * Structure contains buffer address, length and descriptor index
 * from vring to do scatter RX.
 */
struct vq_buf_vector {
    uint64_t buf_addr;
    uint32_t buf_len;
    uint32_t desc_idx;
};

struct dpdk_virtio_writer;

/* virtio queue */
typedef struct vr_dpdk_virtioq {
    struct vring_desc   *vdv_desc;      /**< Virtqueue descriptor ring. */
    struct vring_avail  *vdv_avail;     /**< Virtqueue available ring. */
    struct vring_used   *vdv_used;      /**< Virtqueue used ring. */
    uint32_t            vdv_size;       /**< Size of descriptor ring. */
    uint32_t            vdv_hlen;       /**< Size of virtio header */

    volatile uint16_t   vdv_last_used_idx;
    volatile uint16_t   vdv_last_used_idx_res;
    uint16_t            vdv_ready_state;
    uint16_t            vdv_vif_idx;

    /* Big and less frequently used fields */
    int                 vdv_callfd; /**< Used to notify the guest (trigger interrupt). */
    int                 vdv_kickfd; /**< Currently unused as polling mode is enabled. */
    uint32_t            (*vdv_send_func)(struct dpdk_virtio_writer *p,
                        struct vr_dpdk_virtioq *vq, struct rte_mbuf **pkts, uint32_t count);
    /* TODO: not used
    int vdv_enabled_state;
    int vdv_zero_copy;
     */
    DPDK_DEBUG_VAR(uint32_t vdv_hash);
} __rte_cache_aligned vr_dpdk_virtioq_t;

int vr_dpdk_virtio_uvh_get_blk_size(int fd, uint64_t *const blksize);
void vr_dpdk_set_vhost_send_func(unsigned int vif_idx, uint32_t mrg);
uint16_t vr_dpdk_virtio_nrxqs(struct vr_interface *vif);
uint16_t vr_dpdk_virtio_ntxqs(struct vr_interface *vif);
struct vr_dpdk_queue *
vr_dpdk_virtio_rx_queue_init(unsigned int lcore_id, struct vr_interface *vif,
                             unsigned int queue_id);
struct vr_dpdk_queue *
vr_dpdk_virtio_tx_queue_init(unsigned int lcore_id, struct vr_interface *vif,
                             unsigned int queue_id);
void
vr_dpdk_virtio_tx_queue_enable_disable(unsigned int vif_id,
                                       unsigned int vif_gen,
                                       unsigned int queue_id,
                                       bool enable);
void
vr_dpdk_virtio_rx_queue_enable_disable(unsigned int vif_id,
                                       unsigned int vif_gen,
                                       unsigned int queue_id,
                                       bool enable);
void
vr_dpdk_virtio_tx_queue_set(void *arg);
void
vr_dpdk_virtio_rx_queue_set(void *arg);
int vr_dpdk_virtio_set_vring_base(unsigned int vif_idx, unsigned int vring_idx,
                                   unsigned int vring_base);
int vr_dpdk_virtio_get_vring_base(unsigned int vif_idx, unsigned int vring_idx,
                                  unsigned int *vring_basep);
int vr_dpdk_virtio_recover_vring_base(unsigned int vif_idx, unsigned int vring_idx);
int vr_dpdk_set_vring_addr(unsigned int vif_idx, unsigned int vring_idx,
                           struct vring_desc *vrucv_desc,
                           struct vring_avail *vrucv_avail,
                           struct vring_used *vrucv_used);
int vr_dpdk_set_ring_num_desc(unsigned int vif_idx, unsigned int vring_idx,
                              unsigned int num_desc);
int vr_dpdk_set_ring_callfd(unsigned int vif_idx, unsigned int vring_idx,
                            int callfd);
int vr_dpdk_set_virtq_ready(unsigned int vif_idx, unsigned int vring_idx,
                            vq_ready_state_t ready);
void vr_dpdk_virtio_set_vif_client(unsigned int idx, void *client);
void *vr_dpdk_virtio_get_vif_client(unsigned int idx);
int vr_dpdk_virtio_stop(unsigned int vif_idx);

void vr_dpdk_virtio_xstats_update(struct vr_interface_stats *stats,
    struct vr_dpdk_queue *queue);

extern struct rte_port_in_ops vr_dpdk_virtio_reader_ops;
extern struct rte_port_out_ops vr_dpdk_virtio_writer_ops;

extern struct vr_dpdk_virtioq vr_dpdk_virtio_rxqs[VR_MAX_INTERFACES][VR_DPDK_VIRTIO_MAX_QUEUES];
extern struct vr_dpdk_virtioq vr_dpdk_virtio_txqs[VR_MAX_INTERFACES][VR_DPDK_VIRTIO_MAX_QUEUES];
#endif /* __VR_DPDK_VIRTIO_H__ */
