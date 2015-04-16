/*
 * vr_dpdk_virtio.c - implements DPDK forwarding infrastructure for
 * virtio interfaces. The virtio data structures are setup by the user
 * space vhost server.
 *
 * Copyright (c) 2014 Juniper Networks, Inc. All rights reserved.
 */

#include <stdint.h>
#include <linux/vhost.h>
#include <linux/virtio_net.h>
#include <sys/eventfd.h>

#include "vr_dpdk.h"
#include "vr_dpdk_virtio.h"
#include "qemu_uvhost.h"
#include "vr_uvhost_client.h"

#include <rte_malloc.h>

void *vr_dpdk_vif_clients[VR_MAX_INTERFACES];
vr_dpdk_virtioq_t vr_dpdk_virtio_rxqs[VR_MAX_INTERFACES][RTE_MAX_LCORE];
vr_dpdk_virtioq_t vr_dpdk_virtio_txqs[VR_MAX_INTERFACES][RTE_MAX_LCORE];

static int dpdk_virtio_from_vm_rx(void *arg, struct rte_mbuf **pkts,
                                  uint32_t max_pkts);
static int dpdk_virtio_to_vm_tx(void *arg, struct rte_mbuf *pkt);
static int dpdk_virtio_to_vm_flush(void *arg);

struct rte_port_in_ops dpdk_virtio_reader_ops = {
    .f_create = NULL,
    .f_free = NULL,
    .f_rx = dpdk_virtio_from_vm_rx,
};

struct rte_port_out_ops dpdk_virtio_writer_ops = {
    .f_create = NULL,
    .f_free = NULL,
    .f_tx = dpdk_virtio_to_vm_tx,
    .f_tx_bulk = NULL, /* TODO: not implemented */
    .f_flush = dpdk_virtio_to_vm_flush,
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
 * dpdk_virtio_rx_queue_release - releases a virtio RX queue.
 *
 * Returns nothing.
 */
static void
dpdk_virtio_rx_queue_release(unsigned lcore_id, struct vr_interface *vif)
{
    struct vr_dpdk_lcore *lcore = vr_dpdk.lcores[lcore_id];
    struct vr_dpdk_queue *rx_queue = &lcore->lcore_rx_queues[vif->vif_idx];
    struct vr_dpdk_queue_params *rx_queue_params
                        = &lcore->lcore_rx_queue_params[vif->vif_idx];
    int fd;

    /* close call FD */
    fd = ((vr_dpdk_virtioq_t *)rx_queue->q_queue_h)->vdv_callfd;
    if (fd > 0) {
        close(fd);
    }
    /* remove the ring from the list of rings to push */
    dpdk_ring_to_push_remove(rx_queue_params->qp_ring.host_lcore_id,
            rx_queue_params->qp_ring.ring_p);

    rte_free(rx_queue_params->qp_ring.ring_p);

    /* reset the queue */
    memset(rx_queue->q_queue_h, 0, sizeof(vr_dpdk_virtioq_t));
    memset(rx_queue, 0, sizeof(*rx_queue));
    memset(rx_queue_params, 0, sizeof(*rx_queue_params));
}

/*
 * vr_dpdk_virtio_rx_queue_init - initializes a virtio RX queue.
 *
 * Returns a pointer to the RX queue on success, NULL otherwise.
 */
struct vr_dpdk_queue *
vr_dpdk_virtio_rx_queue_init(unsigned int lcore_id, struct vr_interface *vif,
                             unsigned int queue_or_lcore_id)
{
    uint16_t queue_id = queue_or_lcore_id;
    struct vr_dpdk_lcore *lcore = vr_dpdk.lcores[lcore_id];
    unsigned int vif_idx = vif->vif_idx;
    struct vr_dpdk_queue *rx_queue = &lcore->lcore_rx_queues[vif_idx];
    char ring_name[64];
    struct vr_dpdk_queue_params *rx_queue_params =
        &lcore->lcore_rx_queue_params[vif_idx];
    int ret;

    RTE_LOG(INFO, VROUTER, "\tcreating lcore %u RX ring for queue %u vif %u\n",
        lcore_id, queue_id, vif_idx);

    if (queue_id >= vr_dpdk_virtio_nrxqs(vif)) {
        return NULL;
    }

    ret = snprintf(ring_name, sizeof(ring_name), "vif_%d_%" PRIu16 "_ring",
        vif_idx, queue_id);
    if (ret >= sizeof(ring_name))
        goto error;

    vr_dpdk_virtio_rxqs[vif_idx][queue_id].vdv_pring =
        vr_dpdk_ring_allocate(lcore_id, ring_name, VR_DPDK_VIRTIO_TX_RING_SZ);
    if (vr_dpdk_virtio_rxqs[vif_idx][queue_id].vdv_pring == NULL)
        goto error;

    vr_dpdk_virtio_rxqs[vif_idx][queue_id].vdv_pring_dst_lcore_id =
        vr_dpdk_phys_lcore_least_used_get();
    if (vr_dpdk_virtio_rxqs[vif_idx][queue_id].vdv_pring_dst_lcore_id ==
        RTE_MAX_LCORE)
        goto error;

    dpdk_ring_to_push_add(
        vr_dpdk_virtio_rxqs[vif_idx][queue_id].vdv_pring_dst_lcore_id,
        vr_dpdk_virtio_rxqs[vif_idx][queue_id].vdv_pring, NULL);

    rx_queue->rxq_ops = dpdk_virtio_reader_ops;
    vr_dpdk_virtio_rxqs[vif_idx][queue_id].vdv_ready_state = VQ_NOT_READY;
    vr_dpdk_virtio_rxqs[vif_idx][queue_id].vdv_zero_copy = 0;
    vr_dpdk_virtio_rxqs[vif_idx][queue_id].vdv_last_used_idx = 0;
    vr_dpdk_virtio_rxqs[vif_idx][queue_id].vdv_vif_idx = vif->vif_idx;
    rx_queue->q_queue_h = (void *) &vr_dpdk_virtio_rxqs[vif_idx][queue_id];
    rx_queue->rxq_burst_size = VR_DPDK_VIRTIO_RX_BURST_SZ;
    rx_queue->q_vif = vif;

    /* store queue params */
    rx_queue_params->qp_release_op = &dpdk_virtio_rx_queue_release;
    rx_queue_params->qp_ring.ring_p =
                vr_dpdk_virtio_rxqs[vif_idx][queue_id].vdv_pring;
    rx_queue_params->qp_ring.host_lcore_id =
        vr_dpdk_virtio_rxqs[vif_idx][queue_id].vdv_pring_dst_lcore_id;

    return rx_queue;

error:
    if (vr_dpdk_virtio_rxqs[vif_idx][queue_id].vdv_pring) {
        rte_free(vr_dpdk_virtio_rxqs[vif_idx][queue_id].vdv_pring);
        vr_dpdk_virtio_rxqs[vif_idx][queue_id].vdv_pring = NULL;
    }
    RTE_LOG(ERR, VROUTER, "\terror creating lcore %u RX ring for queue %u vif %u\n",
        lcore_id, queue_id, vif_idx);
    return NULL;
}

/*
 * dpdk_virtio_tx_queue_release - releases a virtio TX queue.
 *
 * Returns nothing.
 */
static void
dpdk_virtio_tx_queue_release(unsigned lcore_id, struct vr_interface *vif)
{
    struct vr_dpdk_lcore *lcore = vr_dpdk.lcores[lcore_id];
    struct vr_dpdk_queue *tx_queue = &lcore->lcore_tx_queues[vif->vif_idx];
    struct vr_dpdk_queue_params *tx_queue_params
                        = &lcore->lcore_tx_queue_params[vif->vif_idx];
    int fd;

    tx_queue->txq_ops.f_tx = NULL;
    rte_wmb();

    /* close call FD */
    fd = ((vr_dpdk_virtioq_t *)tx_queue->q_queue_h)->vdv_callfd;
    if (fd > 0) {
        close(fd);
    }
    /* reset the queue */
    memset(tx_queue->q_queue_h, 0, sizeof(vr_dpdk_virtioq_t));
    memset(tx_queue, 0, sizeof(*tx_queue));
    memset(tx_queue_params, 0, sizeof(*tx_queue_params));
}

/*
 * vr_dpdk_virtio_tx_queue_init - initializes a virtio TX queue.
 *
 * Returns a pointer to the TX queue on success, NULL otherwise.
 */
struct vr_dpdk_queue *
vr_dpdk_virtio_tx_queue_init(unsigned int lcore_id, struct vr_interface *vif,
                             unsigned int queue_or_lcore_id)
{
    uint16_t queue_id = queue_or_lcore_id;
    struct vr_dpdk_lcore *lcore = vr_dpdk.lcores[lcore_id];
    unsigned int vif_idx = vif->vif_idx;
    struct vr_dpdk_queue *tx_queue = &lcore->lcore_tx_queues[vif_idx];
    struct vr_dpdk_queue_params *tx_queue_params
                = &lcore->lcore_tx_queue_params[vif_idx];

    if (queue_id >= vr_dpdk_virtio_ntxqs(vif)) {
        return NULL;
    }

    tx_queue->txq_ops = dpdk_virtio_writer_ops;
    vr_dpdk_virtio_txqs[vif_idx][queue_id].vdv_ready_state = VQ_NOT_READY;
    vr_dpdk_virtio_txqs[vif_idx][queue_id].vdv_zero_copy = 0;
    vr_dpdk_virtio_txqs[vif_idx][queue_id].vdv_last_used_idx = 0;
    vr_dpdk_virtio_txqs[vif_idx][queue_id].vdv_vif_idx = vif->vif_idx;
    vr_dpdk_virtio_txqs[vif_idx][queue_id].vdv_tx_mbuf_count = 0;
    tx_queue->q_queue_h = (void *) &vr_dpdk_virtio_txqs[vif_idx][queue_id];
    tx_queue->q_vif = vif;

    /* store queue params */
    tx_queue_params->qp_release_op = &dpdk_virtio_tx_queue_release;

    return tx_queue;
}

/*
 * vr_dpdk_guest_phys_to_host_virt - convert a guest physical address
 * to a host virtual address. Uses the guest memory map stored in the
 * vhost client for the guest interface.
 *
 * Returns address on success, NULL otherwise.
 */
static char *
vr_dpdk_guest_phys_to_host_virt(vr_dpdk_virtioq_t *vq, uint64_t paddr)
{
    int i;
    vr_uvh_client_t *vru_cl;
    vr_uvh_client_mem_region_t *reg;

    vru_cl = vr_dpdk_virtio_get_vif_client(vq->vdv_vif_idx);
    if (vru_cl == NULL) {
        return NULL;
    }

    for (i = 0; i < vru_cl->vruc_num_mem_regions; i++) {
        reg = &vru_cl->vruc_mem_regions[i];

        if ((paddr >= reg->vrucmr_phys_addr) &&
                (paddr <= (reg->vrucmr_phys_addr + reg->vrucmr_size))) {
            return ((char *) reg->vrucmr_mmap_addr) +
                        (paddr - reg->vrucmr_phys_addr);
        }
    }

    return NULL;
}

/*
 * vr_dpdk_virtio_get_mempool - get the mempool to use for receiving
 * packets from VMs.
 */
static struct rte_mempool *
vr_dpdk_virtio_get_mempool(void)
{
    return vr_dpdk.virtio_mempool;
}

/*
 * dpdk_virtio_from_vm_rx - receive packets from a virtio client so that
 * the packets can be handed to vrouter for forwarding. the virtio client is
 * usually a VM.
 *
 * Returns the number of packets to be sent to vrouter (0 if there is nothing
 * to do).
 *
 * This is an adaptation of DPDK rte_vhost_dequeue_burst() function.
 * Copyright(c) 2010-2014 Intel Corporation. All rights reserved.
 */
static int
dpdk_virtio_from_vm_rx(void *arg, struct rte_mbuf **pkts, uint32_t count)
{
    struct rte_mbuf *m, *prev;
    vr_dpdk_virtioq_t *vq = (vr_dpdk_virtioq_t *)arg;
    struct vring_desc *desc;
    uint64_t vb_addr = 0;
    uint32_t head[VR_DPDK_VIRTIO_RX_BURST_SZ];
    uint32_t used_idx;
    uint32_t i;
    uint16_t free_entries, entry_success = 0;
    uint16_t avail_idx;

    struct rte_mempool *mbuf_pool = vr_dpdk_virtio_get_mempool();

    if (unlikely(vq->vdv_ready_state == VQ_NOT_READY)) {
        DPDK_UDEBUG(VROUTER, &vq->vdv_hash, "%s: queue %p is not ready\n",
                     __func__, vq);
         return 0;
    }

    avail_idx =  *((volatile uint16_t *)&vq->vdv_avail->idx);

    /* If there are no available buffers then return. */
    if (vq->vdv_last_used_idx == avail_idx)
        return 0;

    /* Prefetch available ring to retrieve head indexes. */
    rte_prefetch0(&vq->vdv_avail->ring[vq->vdv_last_used_idx & (vq->vdv_size - 1)]);

    /*get the number of free entries in the ring*/
    free_entries = (avail_idx - vq->vdv_last_used_idx);

    free_entries = RTE_MIN(free_entries, count);
    /* limit to VR_DPDK_VIRTIO_RX_BURST_SZ */
    free_entries = RTE_MIN(free_entries, VR_DPDK_VIRTIO_RX_BURST_SZ);

    DPDK_UDEBUG(VROUTER, &vq->vdv_hash, "%s: queue %p num_pkts=%u\n",
            __func__, vq, free_entries);

    /* Retrieve all of the head indexes first to avoid caching issues. */
    for (i = 0; i < free_entries; i++)
        head[i] = vq->vdv_avail->ring[(vq->vdv_last_used_idx + i) & (vq->vdv_size - 1)];

    /* Prefetch descriptor index. */
    rte_prefetch0(&vq->vdv_desc[head[entry_success]]);
    rte_prefetch0(&vq->vdv_used->ring[vq->vdv_last_used_idx & (vq->vdv_size - 1)]);

    while (entry_success < free_entries) {
        uint32_t vb_avail, vb_offset;
        uint32_t seg_avail, seg_offset;
        uint32_t cpy_len;
        uint32_t seg_num = 0;
        struct rte_mbuf *cur;
        uint8_t alloc_err = 0;

        desc = &vq->vdv_desc[head[entry_success]];

        /* Discard first buffer as it is the virtio header */
        desc = &vq->vdv_desc[desc->next];

        /* Buffer address translation. */
        vb_addr = (uint64_t)vr_dpdk_guest_phys_to_host_virt(vq, desc->addr);
        /* Prefetch buffer address. */
        rte_prefetch0((void *)(uintptr_t)vb_addr);

        used_idx = vq->vdv_last_used_idx & (vq->vdv_size - 1);

        if (entry_success < (free_entries - 1)) {
            /* Prefetch descriptor index. */
            rte_prefetch0(&vq->vdv_desc[head[entry_success+1]]);
            rte_prefetch0(&vq->vdv_used->ring[(used_idx + 1) & (vq->vdv_size - 1)]);
        }

        /* Update used index buffer information. */
        vq->vdv_used->ring[used_idx].id = head[entry_success];
        vq->vdv_used->ring[used_idx].len = 0;

        vb_offset = 0;
        vb_avail = desc->len;
        /* Allocate an mbuf and populate the structure. */
        m = rte_pktmbuf_alloc(mbuf_pool);
        if (unlikely(m == NULL)) {
            RTE_LOG(ERR, VROUTER,
                "Error allocating mbuf for VM RX\n");
            return entry_success;
        }
        seg_offset = 0;
        seg_avail = m->buf_len - RTE_PKTMBUF_HEADROOM;
        cpy_len = RTE_MIN(vb_avail, seg_avail);

        seg_num++;
        cur = m;
        prev = m;
        while (cpy_len != 0) {
            rte_memcpy((void *)(rte_pktmbuf_mtod(cur, char *) + seg_offset),
                (void *)((uintptr_t)(vb_addr + vb_offset)),
                cpy_len);

            seg_offset += cpy_len;
            vb_offset += cpy_len;
            vb_avail -= cpy_len;
            seg_avail -= cpy_len;

            if (vb_avail != 0) {
                /*
                 * The segment reachs to its end,
                 * while the virtio buffer in TX vring has
                 * more data to be copied.
                 */
                cur->pkt.data_len = seg_offset;
                m->pkt.pkt_len += seg_offset;
                /* Allocate mbuf and populate the structure. */
                cur = rte_pktmbuf_alloc(mbuf_pool);
                if (unlikely(cur == NULL)) {
                    RTE_LOG(ERR, VROUTER,
                        "Error allocating mbuf segment for VM RX\n");
                    rte_pktmbuf_free(m);
                    alloc_err = 1;
                    break;
                }

                seg_num++;
                prev->pkt.next = cur;
                prev = cur;
                seg_offset = 0;
                seg_avail = cur->buf_len - RTE_PKTMBUF_HEADROOM;
            } else {
                if (desc->flags & VRING_DESC_F_NEXT) {
                    /*
                     * There are more virtio buffers in
                     * same vring entry need to be copied.
                     */
                    if (seg_avail == 0) {
                        /*
                         * The current segment hasn't
                         * room to accomodate more
                         * data.
                         */
                        cur->pkt.data_len = seg_offset;
                        m->pkt.pkt_len += seg_offset;
                        /*
                         * Allocate an mbuf and
                         * populate the structure.
                         */
                        cur = rte_pktmbuf_alloc(mbuf_pool);
                        if (unlikely(cur == NULL)) {
                            RTE_LOG(ERR, VROUTER,
                                "Error allocating mbuf segment for VM RX\n");
                            rte_pktmbuf_free(m);
                            alloc_err = 1;
                            break;
                        }
                        seg_num++;
                        prev->pkt.next = cur;
                        prev = cur;
                        seg_offset = 0;
                        seg_avail = cur->buf_len - RTE_PKTMBUF_HEADROOM;
                    }

                    desc = &vq->vdv_desc[desc->next];

                    /* Buffer address translation. */
                    vb_addr = (uint64_t)vr_dpdk_guest_phys_to_host_virt(vq, desc->addr);
                    /* Prefetch buffer address. */
                    rte_prefetch0((void *)(uintptr_t)vb_addr);
                    vb_offset = 0;
                    vb_avail = desc->len;
                } else {
                    /* The whole packet completes. */
                    cur->pkt.data_len = seg_offset;
                    m->pkt.pkt_len += seg_offset;
                    vb_avail = 0;
                }
            }

            cpy_len = RTE_MIN(vb_avail, seg_avail);
        }

        if (unlikely(alloc_err == 1))
            break;

        m->pkt.nb_segs = seg_num;

        pkts[entry_success] = m;
        vq->vdv_last_used_idx++;
        entry_success++;
    }

    rte_compiler_barrier();
    vq->vdv_used->idx += entry_success;
    /* Kick guest if required. */
    if (!(vq->vdv_avail->flags & VRING_AVAIL_F_NO_INTERRUPT))
        eventfd_write((int)vq->vdv_callfd, 1);
    return entry_success;
}


/*
 * dpdk_virtio_to_vm_tx - sends a packet from vrouter to a virtio client. The
 * virtio client is usually a VM.
 *
 * Returns nothing.
 */
static int
dpdk_virtio_to_vm_tx(void *arg, struct rte_mbuf *mbuf)
{
    vr_dpdk_virtioq_t *vq = (vr_dpdk_virtioq_t *) arg;

    if (vq->vdv_ready_state == VQ_NOT_READY) {
        vr_dpdk_pfree(mbuf, VP_DROP_INTERFACE_DROP);
        return -1;
    }

    vq->vdv_tx_mbuf[vq->vdv_tx_mbuf_count++] = mbuf;
    if (vq->vdv_tx_mbuf_count >= VR_DPDK_VIRTIO_TX_BURST_SZ) {
        dpdk_virtio_to_vm_flush(vq);
    }

    return 0;
}

/*
 * dpdk_virtio_to_vm_flush - flushes packets from vrouter to a virtio client.
 * The virtio client is usually a VM.
 *
 * Returns nothing.
 */
static int
dpdk_virtio_to_vm_flush(void *arg)
{
    vr_dpdk_virtioq_t *vq = (vr_dpdk_virtioq_t *) arg;
    uint16_t i;
    uint16_t num_buf_posted, vq_hard_avail_idx, vq_hard_used_idx, num_pkts;
    uint16_t next_desc_idx, next_avail_idx, size;
    struct vring_desc *desc;
    char *buf_addr;
    struct virtio_net_hdr vhdr = {0, 0, 0, 0, 0, 0};

    if (vq->vdv_ready_state == VQ_NOT_READY) {
        return 0;
    }

    if (vq->vdv_tx_mbuf_count == 0) {
        return 0;
    }

    vq_hard_avail_idx = (*((volatile uint16_t *)&vq->vdv_avail->idx));

    /*
     * Unsigned subtraction gives the right result even with wrap around.
     */
    num_buf_posted = vq_hard_avail_idx - vq->vdv_last_used_idx;
    if (num_buf_posted < vq->vdv_tx_mbuf_count) {
        num_pkts = num_buf_posted;
    } else {
        num_pkts = vq->vdv_tx_mbuf_count;
    }

    for (i = 0; i < num_pkts; i++) {
        next_avail_idx = (vq->vdv_last_used_idx + i) &
                             (vq->vdv_size - 1);
        next_desc_idx = vq->vdv_avail->ring[next_avail_idx];

        /*
         * Move the descriptor (single or chain of 2) to the used list. The
         * used index will, however, only be updated at the end of the loop.
         * This needs to be done even if any failures occur below in the loop.
         * Set the descriptor length to 0 for now and update it at the end
         * of the loop if there were no errors.
         */
        vq->vdv_used->ring[next_avail_idx].id = next_desc_idx;
        vq->vdv_used->ring[next_avail_idx].len = 0;

        desc = &vq->vdv_desc[next_desc_idx];
        buf_addr = vr_dpdk_guest_phys_to_host_virt(vq, desc->addr);
        if (buf_addr == NULL) {
            vr_dpdk_pfree(vq->vdv_tx_mbuf[i], VP_DROP_INTERFACE_DROP);
            continue;
        }

        /*
         * No support for checksum offload or GSO at the moment, so zero
         * out the virtio header.
         */
        size = sizeof(vhdr);
        rte_memcpy(buf_addr, &vhdr, size);
        buf_addr += sizeof(vhdr);

        /*
         * If the descriptor has VRING_DESC_F_NEXT set, the virtio_net header
         * and packet data use separate descriptors.
         */
        if (desc->flags & VRING_DESC_F_NEXT) {
            desc->len = sizeof(struct virtio_net_hdr);
            /*
             * TODO: verify that desc->next is sane below.
             */
            desc = &vq->vdv_desc[desc->next];

            buf_addr = vr_dpdk_guest_phys_to_host_virt(vq, desc->addr);
            if (buf_addr == NULL) {
                vr_dpdk_pfree(vq->vdv_tx_mbuf[i], VP_DROP_INTERFACE_DROP);
                continue;
            }

            desc->len = rte_pktmbuf_data_len(vq->vdv_tx_mbuf[i]);
        } else {
            desc->len = sizeof(struct virtio_net_hdr) +
                            rte_pktmbuf_data_len(vq->vdv_tx_mbuf[i]);
        }

        rte_memcpy(buf_addr, vq->vdv_tx_mbuf[i]->pkt.data,
                   rte_pktmbuf_data_len(vq->vdv_tx_mbuf[i]));

        vq->vdv_used->ring[next_avail_idx].len =
            sizeof(struct virtio_net_hdr) +
            rte_pktmbuf_data_len(vq->vdv_tx_mbuf[i]);

        rte_pktmbuf_free(vq->vdv_tx_mbuf[i]);
    }

    /*
     * Free any packets that could not be sent to the VM because it didn't
     * post receive buffers soon enough.
     */
    for (; i < vq->vdv_tx_mbuf_count; i++) {
        vr_dpdk_pfree(vq->vdv_tx_mbuf[i], VP_DROP_INTERFACE_DROP);
    }

    vq->vdv_tx_mbuf_count = 0;

    /*
     * Now update the used index in the vring.
     * TODO - need memory barrier + VM kick here.
     */
    vq->vdv_last_used_idx += num_pkts;
    vq_hard_used_idx = (*((volatile uint16_t *)&vq->vdv_used->idx));
    *((volatile uint16_t *) &vq->vdv_used->idx) = vq_hard_used_idx + num_pkts;

    /*
     * If the VM did not want to be interrupted (i.e if it uses DPDK), do
     * not raise an interrupt. Otherwise, use eventfd to raise an interrupt
     * in the guest.
     */
    if (vq->vdv_avail->flags & VRING_AVAIL_F_NO_INTERRUPT) {
        return 0;
    }

    eventfd_write(vq->vdv_callfd, 1);

    return 0;
}

/*
 * vr_dpdk_virtio_set_vring_base - sets the vring base using data sent by
 * vhost client.
 *
 * Returns 0 on success, -1 otherwise.
 */
int
vr_dpdk_virtio_set_vring_base(unsigned int vif_idx, unsigned int vring_idx,
                               unsigned int vring_base)
{
    vr_dpdk_virtioq_t *vq;

    if ((vif_idx >= VR_MAX_INTERFACES) || (vring_idx >= (2 * RTE_MAX_LCORE))) {
        return -1;
    }

    /*
     * RX rings are even numbered and TX rings are odd numbered from the
     * VM's point of view. From vrouter's point of view, VM's TX ring is
     * vrouter's RX ring and vice versa.
     */
    if (vring_idx & 1) {
        vq = &vr_dpdk_virtio_rxqs[vif_idx][vring_idx/2];
    } else {
        vq = &vr_dpdk_virtio_txqs[vif_idx][vring_idx/2];
    }

    vq->vdv_base_idx = vring_base;
    return 0;
}

/*
 * vr_dpdk_virtio_get_vring_base - gets the vring base for the specified vring
 * sent by the vhost client.
 *
 * Returns 0 on success, -1 otherwise.
 */
int
vr_dpdk_virtio_get_vring_base(unsigned int vif_idx, unsigned int vring_idx,
                               unsigned int *vring_basep)
{
    vr_dpdk_virtioq_t *vq;

    if ((vif_idx >= VR_MAX_INTERFACES) || (vring_idx >= (2 * RTE_MAX_LCORE))) {
        return -1;
    }

    /*
     * RX rings are even numbered and TX rings are odd numbered from the
     * VM's point of view. From vrouter's point of view, VM's TX ring is
     * vrouter's RX ring and vice versa.
     */
    if (vring_idx & 1) {
        vq = &vr_dpdk_virtio_rxqs[vif_idx][vring_idx/2];
    } else {
        vq = &vr_dpdk_virtio_txqs[vif_idx][vring_idx/2];
    }

    *vring_basep = vq->vdv_base_idx;

    /*
     * This is usually called when qemu shuts down a virtio queue. Set the
     * state to indicate that this queue should not be used any more.
     *
     * TODO: need memory barrier and rcu_synchronize here.
     */
    vq->vdv_ready_state = VQ_NOT_READY;
    vq->vdv_last_used_idx = 0;

    return 0;
}

/*
 * vr_dpdk_set_vring_addr - Sets the address of the virtio descruptor and
 * available/used rings based on messages sent by the vhost client.
 *
 * Returns 0 on suucess, -1 otherwise.
 */
int
vr_dpdk_set_vring_addr(unsigned int vif_idx, unsigned int vring_idx,
                       struct vring_desc *vrucv_desc,
                       struct vring_avail *vrucv_avail,
                       struct vring_used *vrucv_used)
{
    vr_dpdk_virtioq_t *vq;

    if ((vif_idx >= VR_MAX_INTERFACES) || (vring_idx >= (2 * RTE_MAX_LCORE))) {
        return -1;
    }

    /*
     * RX rings are even numbered and TX rings are odd numbered from the
     * VM's point of view. From vrouter's point of view, VM's TX ring is
     * vrouter's RX ring and vice versa.
     */
    if (vring_idx & 1) {
        vq = &vr_dpdk_virtio_rxqs[vif_idx][vring_idx/2];
    } else {
        vq = &vr_dpdk_virtio_txqs[vif_idx][vring_idx/2];
    }

    vq->vdv_desc = vrucv_desc;
    vq->vdv_avail = vrucv_avail;
    vq->vdv_used = vrucv_used;

    /*
     * Tell the guest that it need not interrupt vrouter when it updates the
     * available ring (as vrouter is polling it).
     */
    vq->vdv_used->flags |= VRING_USED_F_NO_NOTIFY;

    return 0;
}

/*
 * vr_dpdk_set_ring_num_desc - sets the number of descriptors in a vring
 * based on messages from the vhost client.
 *
 * Returns 0 on success, -1 otherwise.
 */
int
vr_dpdk_set_ring_num_desc(unsigned int vif_idx, unsigned int vring_idx,
                          unsigned int num_desc)
{
    vr_dpdk_virtioq_t *vq;

    if ((vif_idx >= VR_MAX_INTERFACES) || (vring_idx >= (2 * RTE_MAX_LCORE))) {
        return -1;
    }

    /*
     * RX rings are even numbered and TX rings are odd numbered from the
     * VM's point of view. From vrouter's point of view, VM's TX ring is
     * vrouter's RX ring and vice versa.
     */
    if (vring_idx & 1) {
        vq = &vr_dpdk_virtio_rxqs[vif_idx][vring_idx/2];
    } else {
        vq = &vr_dpdk_virtio_txqs[vif_idx][vring_idx/2];
    }

    vq->vdv_size = num_desc;

    return 0;
}

/*
 * vr_dpdk_set_ring_callfd - set the eventd used to raise interrupts in
 * the guest (if required). Returns 0 on success, -1 otherwise.
 */
int
vr_dpdk_set_ring_callfd(unsigned int vif_idx, unsigned int vring_idx,
                        int callfd)
{
    vr_dpdk_virtioq_t *vq;

    if ((vif_idx >= VR_MAX_INTERFACES) || (vring_idx >= (2 * RTE_MAX_LCORE))) {
        return -1;
    }

    /*
     * RX rings are even numbered and TX rings are odd numbered from the
     * VM's point of view. From vrouter's point of view, VM's TX ring is
     * vrouter's RX ring and vice versa.
     */
    if (vring_idx & 1) {
        vq = &vr_dpdk_virtio_rxqs[vif_idx][vring_idx/2];
    } else {
        vq = &vr_dpdk_virtio_txqs[vif_idx][vring_idx/2];
    }

    if (vq->vdv_callfd > 0) {
        close(vq->vdv_callfd);
    }
    vq->vdv_callfd = callfd;

    return 0;
}

/*
 * vr_dpdk_set_virtq_ready - sets the virtio queue ready state to indicate
 * whether forwarding can start on the virtio queue or not.
 *
 * Returns 0 on success, -1 otherwise.
 */
int
vr_dpdk_set_virtq_ready(unsigned int vif_idx, unsigned int vring_idx,
                        vq_ready_state_t ready)
{
    vr_dpdk_virtioq_t *vq;

    if ((vif_idx >= VR_MAX_INTERFACES) || (vring_idx >= (2 * RTE_MAX_LCORE))) {
        return -1;
    }

    /*
     * RX rings are even numbered and TX rings are odd numbered from the
     * VM's point of view. From vrouter's point of view, VM's TX ring is
     * vrouter's RX ring and vice versa.
     */
    if (vring_idx & 1) {
        vq = &vr_dpdk_virtio_rxqs[vif_idx][vring_idx/2];
    } else {
        vq = &vr_dpdk_virtio_txqs[vif_idx][vring_idx/2];
    }

    vq->vdv_ready_state = ready;

    return 0;
}

/*
 * vr_dpdk_virtio_set_vif_client - sets a pointer to per vif state. Currently
 * used to store a pointer to the vhost client structure.
 *
 * Returns nothing.
 */
void
vr_dpdk_virtio_set_vif_client(unsigned int idx, void *client)
{
    if (idx >= VR_MAX_INTERFACES) {
        return;
    }

    vr_dpdk_vif_clients[idx] = client;

    return;
}

/*
 * vr_dpdk_virtio_get_vif_client - returns a pointer to per vif state if it
 * exists, NULL otherwise.
 */
void *
vr_dpdk_virtio_get_vif_client(unsigned int idx)
{
    if (idx >= VR_MAX_INTERFACES) {
        return NULL;
    }

    return vr_dpdk_vif_clients[idx];
}

/*
 * vr_dpdk_virtio_enq_pkts_to_phys_lcore - enqueue packets received on a
 * virtio interface queue onto a ring that will be handled by the lcore
 * assigned to that queue. This lcore will then transmit the packet out the
 * wire if required.
 *
 * Returns nothing.
 */
void
vr_dpdk_virtio_enq_pkts_to_phys_lcore(struct vr_dpdk_queue *rx_queue,
                                      struct vr_packet **pkt_arr,
                                      uint32_t npkts)
{
    vr_dpdk_virtioq_t *vq;
    struct rte_ring *vq_pring;
    int nb_enq;

    vq = (vr_dpdk_virtioq_t *) rx_queue->q_queue_h;
    vq_pring = vq->vdv_pring;

    RTE_LOG(DEBUG, VROUTER, "%s: enqueue %u pakets to ring %p\n",
                __func__, npkts, vq_pring);
    nb_enq = rte_ring_sp_enqueue_burst(vq_pring, (void **) pkt_arr, npkts);
    for ( ; nb_enq < npkts; nb_enq++)
        vr_pfree(pkt_arr[nb_enq], VP_DROP_INTERFACE_DROP);

    return;
}
