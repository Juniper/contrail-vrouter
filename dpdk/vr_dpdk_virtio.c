/*
 * vr_dpdk_virtio.c - implements DPDK forwarding infrastructure for
 * virtio interfaces. The virtio data structures are setup by the user
 * space vhost server.
 *
 * Copyright (c) 2014 Juniper Networks, Inc. All rights reserved.
 */

#include "vr_dpdk.h"
#include "vr_dpdk_virtio.h"
#include "vr_uvhost_client.h"

#include <linux/virtio_net.h>
#include <sys/eventfd.h>

#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <rte_malloc.h>
#include <rte_memcpy.h>

vr_dpdk_uvh_vif_mmap_addr_t vr_dpdk_virtio_uvh_vif_mmap[VR_MAX_INTERFACES];
extern struct vr_interface_stats *vif_get_stats(struct vr_interface *,
        unsigned short);

void *vr_dpdk_vif_clients[VR_MAX_INTERFACES];
vr_dpdk_virtioq_t vr_dpdk_virtio_rxqs[VR_MAX_INTERFACES][VR_DPDK_VIRTIO_MAX_QUEUES];
vr_dpdk_virtioq_t vr_dpdk_virtio_txqs[VR_MAX_INTERFACES][VR_DPDK_VIRTIO_MAX_QUEUES];

static int dpdk_virtio_from_vm_rx(void *port, struct rte_mbuf **pkts,
                                  uint32_t max_pkts);
static int dpdk_virtio_to_vm_tx(void *port, struct rte_mbuf *pkt);
static int dpdk_virtio_to_vm_flush(void *port);
static int dpdk_virtio_writer_stats_read(void *port,
                                            struct rte_port_out_stats *stats,
                                            int clear);
static int dpdk_virtio_reader_stats_read(void *port,
                                            struct rte_port_in_stats *stats,
                                            int clear);

/*
 * Virtio writer
 */
struct dpdk_virtio_writer {
    struct rte_port_out_stats stats;
    /* extra statistics */
    uint64_t nb_syscalls;

    vr_dpdk_virtioq_t *tx_virtioq;
    struct rte_mbuf *tx_buf[VR_DPDK_VIRTIO_TX_BURST_SZ];
    uint32_t tx_buf_count;
};

struct dpdk_virtio_writer_params {
    /* virtio TX queue pointer */
    vr_dpdk_virtioq_t *tx_virtioq;
};

static void *
dpdk_virtio_writer_create(void *params, int socket_id)
{
    struct dpdk_virtio_writer_params *conf =
            (struct dpdk_virtio_writer_params *) params;
    struct dpdk_virtio_writer *port;

    /* Check input parameters */
    if (conf == NULL) {
        RTE_LOG(ERR, PORT, "%s: Invalid input parameters\n", __func__);
        return NULL;
    }

    /* Memory allocation */
    port = rte_zmalloc_socket("PORT", sizeof(*port),
            RTE_CACHE_LINE_SIZE, socket_id);
    if (port == NULL) {
        RTE_LOG(ERR, PORT, "%s: Failed to allocate port\n", __func__);
        return NULL;
    }

    /* Initialization */
    port->tx_virtioq = conf->tx_virtioq;

    return port;
}

static int
dpdk_virtio_writer_free(void *port)
{
    vr_dpdk_virtioq_t *tx_virtioq;

    if (port == NULL) {
        RTE_LOG(ERR, PORT, "%s: port is NULL\n", __func__);
        return -EINVAL;
    }

    tx_virtioq = ((struct dpdk_virtio_writer *)port)->tx_virtioq;

    /* close FDs */
    if (tx_virtioq->vdv_callfd > 0) {
        close(tx_virtioq->vdv_callfd);
    }
    if (tx_virtioq->vdv_kickfd > 0) {
        close(tx_virtioq->vdv_kickfd);
    }

    /* reset the virtio */
    memset(tx_virtioq, 0, sizeof(vr_dpdk_virtioq_t));

    rte_free(port);

    return 0;
}

struct rte_port_out_ops vr_dpdk_virtio_writer_ops = {
    .f_create = dpdk_virtio_writer_create,
    .f_free = dpdk_virtio_writer_free,
    .f_tx = dpdk_virtio_to_vm_tx,
    .f_tx_bulk = NULL, /* TODO: not implemented */
    .f_flush = dpdk_virtio_to_vm_flush,
    .f_stats = dpdk_virtio_writer_stats_read
};

/*
 * Virtio reader
 */
struct dpdk_virtio_reader {
    struct rte_port_in_stats stats;
    /* extra statistics */
    uint64_t nb_syscalls;
    uint64_t nb_nombufs;

    vr_dpdk_virtioq_t *rx_virtioq;
};

struct dpdk_virtio_reader_params {
    /* virtio RX queue pointer */
    vr_dpdk_virtioq_t *rx_virtioq;
};

static void *
dpdk_virtio_reader_create(void *params, int socket_id)
{
    struct dpdk_virtio_reader_params *conf =
            (struct dpdk_virtio_reader_params *) params;
    struct dpdk_virtio_reader *port;

    /* Check input parameters */
    if (conf == NULL) {
        RTE_LOG(ERR, PORT, "%s: Invalid input parameters\n", __func__);
        return NULL;
    }

    /* Memory allocation */
    port = rte_zmalloc_socket("PORT", sizeof(*port),
            RTE_CACHE_LINE_SIZE, socket_id);
    if (port == NULL) {
        RTE_LOG(ERR, PORT, "%s: Failed to allocate port\n", __func__);
        return NULL;
    }

    /* Initialization */
    port->rx_virtioq = conf->rx_virtioq;

    return port;
}

static int
dpdk_virtio_reader_free(void *port)
{
    vr_dpdk_virtioq_t *rx_virtioq;

    if (port == NULL) {
        RTE_LOG(ERR, PORT, "%s: port is NULL\n", __func__);
        return -EINVAL;
    }

    rx_virtioq = ((struct dpdk_virtio_reader *)port)->rx_virtioq;

    /* close FDs */
    if (rx_virtioq->vdv_callfd > 0) {
        close(rx_virtioq->vdv_callfd);
    }
    if (rx_virtioq->vdv_kickfd > 0) {
        close(rx_virtioq->vdv_kickfd);
    }

    /* reset the virtio */
    memset(rx_virtioq, 0, sizeof(vr_dpdk_virtioq_t));

    rte_free(port);

    return 0;
}


struct rte_port_in_ops vr_dpdk_virtio_reader_ops = {
    .f_create = dpdk_virtio_reader_create,
    .f_free = dpdk_virtio_reader_free,
    .f_rx = dpdk_virtio_from_vm_rx,
    .f_stats = dpdk_virtio_reader_stats_read
};

/*
 * vr_dpdk_vrtio_uvh_get_blk_size - set the block size of fd.
 * On error -1 is returned, otherwise 0.
 */
int
vr_dpdk_virtio_uvh_get_blk_size(int fd, uint64_t *const blksize)
{
    struct stat fd_stat;
    int ret;
    memset(&fd_stat, 0, sizeof(stat));

    ret = fstat(fd, &fd_stat);
    if (!ret){
        *blksize = (uint64_t)fd_stat.st_blksize;
    } else {
      RTE_LOG(DEBUG, VROUTER, "Function fstat() failed: %s  %s \n",
              __func__, strerror(errno));
    }

    return ret;
}


/*
 * vr_dpdk_virtio_uvh_vif_munmap - Unmaps every region,
 * which has been allocated via Qemu's file descriptor.
 */
int
vr_dpdk_virtio_uvh_vif_munmap(vr_dpdk_uvh_vif_mmap_addr_t *const vif_mmap_addrs)
{
   uint32_t i = 0;
   int ret = 0;
   vr_dpdk_uvh_mmap_addr_t *vif_data_mmap = NULL;

   for (i = 0; i < vif_mmap_addrs->vu_nregions; i++) {
        if (vif_mmap_addrs->vu_mmap_data[i].unmap_mmap_addr) {
            vif_data_mmap = &(vif_mmap_addrs->vu_mmap_data[i]);
            ret = vr_dpdk_virtio_uvh_vif_region_munmap(vif_data_mmap);
            if (ret) {
                RTE_LOG(INFO, VROUTER,
                        "munmap() failed: %s , memleak: vif_idx_region %d %s\n",
                        strerror(errno), i, __func__);
            }
            memset(vif_data_mmap, 0, sizeof(vr_dpdk_uvh_mmap_addr_t));
        }
    }
    /* Memleak, when vr_dpdk_virtio_uvh_vif fails.
     * At this moment there is no solution to fix memleak when munmap() fails. */
    memset(vif_mmap_addrs, 0, sizeof(vr_dpdk_uvh_vif_mmap_addr_t));
    return 0;
}

/*
 * vr_dpdk_virtio_uvh_vif_region_munmap - deallocates specified region
 *
 */
int
vr_dpdk_virtio_uvh_vif_region_munmap(vr_dpdk_uvh_mmap_addr_t
                                     *const vif_data_mmap)
{
    uint64_t alignment = vif_data_mmap->unmap_blksz;

    /* if return value  == -1, munmap(2) failed for a region and set errno,
     *  still is possible unmap. */
    return (munmap((void *)(uintptr_t)
            RTE_ALIGN_FLOOR(vif_data_mmap->unmap_mmap_addr, alignment),
            RTE_ALIGN_CEIL(vif_data_mmap->unmap_size, alignment))
           );
}

/*
 * vr_dpdk_virtio_nrxqs - returns the number of receives queues for a virtio
 * interface.
 */
uint16_t
vr_dpdk_virtio_nrxqs(struct vr_interface *vif)
{
    return VR_DPDK_VIRTIO_MAX_QUEUES;
}

/*
 * vr_dpdk_virtio_ntxqs - returns the number of transmit queues for a virtio
 * interface.
 */
uint16_t
vr_dpdk_virtio_ntxqs(struct vr_interface *vif)
{
    return VR_DPDK_VIRTIO_MAX_QUEUES;
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
    /* free the queue */
    if (rx_queue->rxq_ops.f_free(rx_queue->q_queue_h)) {
        RTE_LOG(ERR, VROUTER, "    error freeing lcore %u virtio device RX queue\n",
                    lcore_id);
    }

    /* reset the queue */
    vrouter_put_interface(rx_queue->q_vif);
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
    const unsigned int socket_id = rte_lcore_to_socket_id(lcore_id);
    unsigned int vif_idx = vif->vif_idx;
    struct vr_dpdk_queue *rx_queue = &lcore->lcore_rx_queues[vif_idx];
    struct vr_dpdk_queue_params *rx_queue_params =
        &lcore->lcore_rx_queue_params[vif_idx];

    /* Check input parameters */
    if (queue_id >= vr_dpdk_virtio_nrxqs(vif)) {
        RTE_LOG(ERR, VROUTER, "    error creating virtio device %s RX queue %"
            PRIu16 "\n", vif->vif_name, queue_id);
        return NULL;
    }

    /* init queue */
    rx_queue->rxq_ops = vr_dpdk_virtio_reader_ops;
    rx_queue->q_vif = vrouter_get_interface(vif->vif_rid, vif_idx);

    /* init virtio queue */
    vr_dpdk_virtio_rxqs[vif_idx][queue_id].vdv_ready_state = VQ_NOT_READY;
    vr_dpdk_virtio_rxqs[vif_idx][queue_id].vdv_last_used_idx = 0;
    vr_dpdk_virtio_rxqs[vif_idx][queue_id].vdv_last_used_idx_res = 0;
    vr_dpdk_virtio_rxqs[vif_idx][queue_id].vdv_vif_idx = vif->vif_idx;

    /* create the queue */
    struct dpdk_virtio_reader_params reader_params = {
        .rx_virtioq = &vr_dpdk_virtio_rxqs[vif_idx][queue_id],
    };
    rx_queue->q_queue_h = rx_queue->rxq_ops.f_create(&reader_params, socket_id);
    if (rx_queue->q_queue_h == NULL) {
        RTE_LOG(ERR, VROUTER, "    error creating virtio device %s RX queue %"
            PRIu16 "\n", vif->vif_name, queue_id);
        return NULL;
    }

    /* store queue params */
    rx_queue_params->qp_release_op = &dpdk_virtio_rx_queue_release;

    return rx_queue;
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

    tx_queue->txq_ops.f_tx = NULL;
    rte_wmb();

    /* flush and free the queue */
    if (tx_queue->txq_ops.f_free(tx_queue->q_queue_h)) {
        RTE_LOG(ERR, VROUTER, "    error freeing lcore %u virtio device TX queue\n",
                    lcore_id);
    }

    /* reset the queue */
    vrouter_put_interface(tx_queue->q_vif);
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
    const unsigned int socket_id = rte_lcore_to_socket_id(lcore_id);
    unsigned int vif_idx = vif->vif_idx;
    struct vr_dpdk_queue *tx_queue = &lcore->lcore_tx_queues[vif_idx];
    struct vr_dpdk_queue_params *tx_queue_params
                = &lcore->lcore_tx_queue_params[vif_idx];

    /* Check input parameters */
    /* virtio TX is thread safe, so just use one of the rings */
    queue_id = queue_id % vr_dpdk_virtio_ntxqs(vif);

    /* init queue */
    tx_queue->txq_ops = vr_dpdk_virtio_writer_ops;
    tx_queue->q_vif = vrouter_get_interface(vif->vif_rid, vif_idx);

    /* init virtio queue */
    vr_dpdk_virtio_txqs[vif_idx][queue_id].vdv_ready_state = VQ_NOT_READY;
    vr_dpdk_virtio_txqs[vif_idx][queue_id].vdv_last_used_idx = 0;
    vr_dpdk_virtio_txqs[vif_idx][queue_id].vdv_last_used_idx_res = 0;
    vr_dpdk_virtio_txqs[vif_idx][queue_id].vdv_vif_idx = vif->vif_idx;

    /* create the queue */
    struct dpdk_virtio_writer_params writer_params = {
        .tx_virtioq = &vr_dpdk_virtio_txqs[vif_idx][queue_id],
    };
    tx_queue->q_queue_h = tx_queue->txq_ops.f_create(&writer_params, socket_id);
    if (tx_queue->q_queue_h == NULL) {
        RTE_LOG(ERR, VROUTER, "    error creating virtio device %s TX queue %"
            PRIu16 "\n", vif->vif_name, queue_id);
        return NULL;
    }

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
vr_dpdk_guest_phys_to_host_virt(vr_uvh_client_t *vru_cl, uint64_t paddr)
{
    int i;
    vr_uvh_client_mem_region_t *reg;

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

#if DPDK_VIRTIO_READER_STATS_COLLECT == 1

#define DPDK_VIRTIO_READER_STATS_PKTS_IN_ADD(port, val) \
        port->stats.n_pkts_in += val
#define DPDK_VIRTIO_READER_STATS_PKTS_DROP_ADD(port, val) \
        port->stats.n_pkts_drop += val

#else

#define DPDK_VIRTIO_READER_STATS_PKTS_IN_ADD(port, val)
#define DPDK_VIRTIO_READER_STATS_PKTS_DROP_ADD(port, val)

#endif

/*
 * dpdk_virtio_from_vm_rx - receive packets from a virtio client so that
 * the packets can be handed to vrouter for forwarding. the virtio client is
 * usually a VM.
 *
 * Returns the number of packets to be sent to vrouter (0 if there is nothing
 * to do).
 */
static int
dpdk_virtio_from_vm_rx(void *port, struct rte_mbuf **pkts, uint32_t max_pkts)
{
    struct dpdk_virtio_reader *p = (struct dpdk_virtio_reader *)port;
    vr_dpdk_virtioq_t *vq = p->rx_virtioq;
    rte_prefetch0(vq->vdv_avail);
    uint16_t vq_hard_avail_idx, i;
    uint16_t num_pkts, next_desc_idx, next_avail_idx, pkts_sent = 0;
    struct vring_desc *desc;
    char *pkt_addr, *tail_addr;
    struct rte_mbuf *mbuf;
    uint32_t pkt_len;
    uint64_t mbuf_flags;
    vr_uvh_client_t *vru_cl;

    if (unlikely(vq->vdv_ready_state == VQ_NOT_READY)) {
        DPDK_UDEBUG(VROUTER, &vq->vdv_hash, "%s: queue %p is not ready\n",
                __func__, vq);
        return 0;
    }

    vru_cl = vr_dpdk_virtio_get_vif_client(vq->vdv_vif_idx);
    if (unlikely(vru_cl == NULL))
        return 0;

    vq_hard_avail_idx = (*((volatile uint16_t *)&vq->vdv_avail->idx));

    /*
     * Unsigned subtraction gives the right result even with wrap around.
     */
    num_pkts = vq_hard_avail_idx - vq->vdv_last_used_idx;
    if (unlikely(num_pkts == 0)) {
        DPDK_UDEBUG(VROUTER, &vq->vdv_hash, "%s: queue %p has no packets\n",
                    __func__, vq);
        return 0;
    }

    if (unlikely(num_pkts > max_pkts)) {
        num_pkts = max_pkts;
    }

    DPDK_UDEBUG(VROUTER, &vq->vdv_hash, "%s: queue %p num_pkts=%u\n",
            __func__, vq, num_pkts);
    for (i = 0; i < num_pkts; i++) {
        next_avail_idx = (vq->vdv_last_used_idx + i) &
                             (vq->vdv_size - 1);
        next_desc_idx = vq->vdv_avail->ring[next_avail_idx];
        desc = &vq->vdv_desc[next_desc_idx];

        mbuf_flags = 0;
        pkt_addr = vr_dpdk_guest_phys_to_host_virt(vru_cl, desc->addr);
        if (((struct virtio_net_hdr *)pkt_addr)->flags & VIRTIO_NET_HDR_F_NEEDS_CSUM)
            mbuf_flags |= PKT_RX_IP_CKSUM_BAD;

        /*
         * Ignore virtio header in first descriptor as we don't support
         * mergeable receive buffers yet. Before that, move the descriptors
         * (chain of 2) to the used list. The used index will, however, only
         * be updated at the end of the loop.
         */
        vq->vdv_used->ring[next_avail_idx].id = next_desc_idx;
        vq->vdv_used->ring[next_avail_idx].len = 0;
        if (likely(desc->flags & VRING_DESC_F_NEXT)) {
            /*
             * TODO - make sure desc->next is sane
             */
            DPDK_UDEBUG(VROUTER, &vq->vdv_hash, "%s: queue %p pkt %u F_NEXT\n",
                __func__, vq, i);
            desc = &vq->vdv_desc[desc->next];
            pkt_addr = vr_dpdk_guest_phys_to_host_virt(vru_cl, desc->addr);
            pkt_len = desc->len;
        } else {
            DPDK_UDEBUG(VROUTER, &vq->vdv_hash, "%s: queue %p pkt %u no F_NEXT\n",
                __func__, vq, i);
            pkt_addr = vr_dpdk_guest_phys_to_host_virt(vru_cl, desc->addr);
            if (pkt_addr) {
                pkt_addr += sizeof(struct virtio_net_hdr);
                pkt_len = desc->len - sizeof(struct virtio_net_hdr);
            }
        }

        if (likely(pkt_addr != NULL)) {
            DPDK_UDEBUG(VROUTER, &vq->vdv_hash, "%s: queue %p pkt %u addr %p\n",
                __func__, vq, i, pkt_addr);
            /* No need to use a dedicated mempool at the moment, since there is
             * no dedicated lcore to poll virtio interfaces */
            mbuf = rte_pktmbuf_alloc(vr_dpdk.rss_mempool);
            DPDK_UDEBUG(VROUTER, &vq->vdv_hash, "%s: queue %p pkt %u mbuf %p\n",
                __func__, vq, i, mbuf);
            if (unlikely(mbuf == NULL)) {
                p->nb_nombufs++;
                break;
            }

            mbuf->data_len = pkt_len;
            mbuf->pkt_len = pkt_len;
            mbuf->ol_flags = mbuf_flags;

            rte_memcpy(rte_pktmbuf_mtod(mbuf, void *), pkt_addr, pkt_len);

            /* gather mbuf from several vring buffers (fixes FreeBSD) */
            while (unlikely(desc->flags & VRING_DESC_F_NEXT)) {
                desc = &vq->vdv_desc[desc->next];
                pkt_addr = vr_dpdk_guest_phys_to_host_virt(vru_cl, desc->addr);
                pkt_len = desc->len;

                tail_addr = rte_pktmbuf_append(mbuf, pkt_len);
                if (unlikely(tail_addr == NULL)) {
                    p->nb_nombufs++;
                    break;
                }
                rte_memcpy(tail_addr, pkt_addr, pkt_len);
            }

            pkts[pkts_sent] = mbuf;
            pkts_sent++;
        }
    }

    vq->vdv_last_used_idx += pkts_sent;
    rte_wmb();
    vq->vdv_used->idx += pkts_sent;
    /* call guest if required (fixes iperf issue) */
    if (unlikely(!(vq->vdv_avail->flags & VRING_AVAIL_F_NO_INTERRUPT))) {
        p->nb_syscalls++;
        eventfd_write(vq->vdv_callfd, 1);
    }

    DPDK_UDEBUG(VROUTER, &vq->vdv_hash, "%s: queue %p pkts_sent %u\n",
            __func__, vq, pkts_sent);

    DPDK_VIRTIO_READER_STATS_PKTS_IN_ADD(p, pkts_sent);
    return pkts_sent;
}

#if DPDK_VIRTIO_WRITER_STATS_COLLECT == 1

#define DPDK_VIRTIO_WRITER_STATS_PKTS_IN_ADD(port, val) \
        port->stats.n_pkts_in += val
#define DPDK_VIRTIO_WRITER_STATS_PKTS_DROP_ADD(port, val) \
        port->stats.n_pkts_drop += val

#else

#define DPDK_VIRTIO_WRITER_STATS_PKTS_IN_ADD(port, val)
#define DPDK_VIRTIO_WRITER_STATS_PKTS_DROP_ADD(port, val)

#endif

/**
 * This function adds buffers to the virtio devices RX virtqueue. Buffers can
 * be received from the physical port or from another virtio device. A packet
 * count is returned to indicate the number of packets that are succesfully
 * added to the RX queue. This function works when mergeable is disabled.
 *
 * This is an adaptation of DPDK virtio_dev_rx() function.
 * Copyright(c) 2010-2014 Intel Corporation. All rights reserved.
 * BSD LICENSE
 */
static inline uint32_t __attribute__((always_inline))
dpdk_virtio_dev_to_vm_tx_burst(struct dpdk_virtio_writer *p,
        vr_dpdk_virtioq_t *vq, struct rte_mbuf **pkts, uint32_t count)
{
    struct vring_desc *desc;
    struct rte_mbuf *buff;
    /* The virtio_hdr is initialised to 0. */
    struct virtio_net_hdr_mrg_rxbuf virtio_hdr = {{0, 0, 0, 0, 0, 0}, 0};
    uint64_t buff_addr = 0;
    uint64_t buff_hdr_addr = 0;
    uint32_t head[VR_DPDK_VIRTIO_TX_BURST_SZ];
    uint32_t head_idx, packet_success = 0;
    uint16_t avail_idx, res_cur_idx;
    uint16_t res_base_idx, res_end_idx;
    uint16_t free_entries;
    uint8_t success = 0;
    vr_uvh_client_t *vru_cl;

    if (unlikely(vq->vdv_ready_state == VQ_NOT_READY))
        return 0;

    vru_cl = vr_dpdk_virtio_get_vif_client(vq->vdv_vif_idx);
    if (unlikely(vru_cl == NULL))
        return 0;

    /*
     * As many data cores may want access to available buffers,
     * they need to be reserved.
     */
    do {
        res_base_idx = vq->vdv_last_used_idx_res;
        avail_idx = *((volatile uint16_t *)&vq->vdv_avail->idx);

        free_entries = (avail_idx - res_base_idx);
        /*check that we have enough buffers*/
        if (unlikely(count > free_entries))
            count = free_entries;

        if (unlikely(count == 0))
            return 0;

        res_end_idx = res_base_idx + count;
        /* vq->vdv_last_used_idx_res is atomically updated. */
        /* TODO: Allow to disable cmpset if no concurrency in application. */
        success = rte_atomic16_cmpset(&vq->vdv_last_used_idx_res,
                res_base_idx, res_end_idx);
    } while (unlikely(success == 0));
    res_cur_idx = res_base_idx;
    RTE_LOG(DEBUG, VROUTER, "%s: Current Index %d| End Index %d\n",
            __func__, res_cur_idx, res_end_idx);

    /* Prefetch available ring to retrieve indexes. */
    rte_prefetch0(&vq->vdv_avail->ring[res_cur_idx & (vq->vdv_size - 1)]);

    /* Retrieve all of the head indexes first to avoid caching issues. */
    for (head_idx = 0; head_idx < count; head_idx++)
        head[head_idx] = vq->vdv_avail->ring[(res_cur_idx + head_idx) &
                    (vq->vdv_size - 1)];

    /* Prefetch descriptor index. */
    rte_prefetch0(&vq->vdv_desc[head[packet_success]]);

    while (res_cur_idx != res_end_idx) {
        uint32_t offset = 0, vb_offset = 0;
        uint32_t pkt_len, len_to_cpy, data_len, total_copied = 0;
        uint8_t hdr = 0, uncompleted_pkt = 0;

        /* Get descriptor from available ring */
        desc = &vq->vdv_desc[head[packet_success]];

        buff = pkts[packet_success];

        /* Convert from gpa to vva (guest physical addr -> vhost virtual addr) */
        buff_addr = (uintptr_t)vr_dpdk_guest_phys_to_host_virt(vru_cl, desc->addr);
        /* Prefetch buffer address. */
        rte_prefetch0((void *)(uintptr_t)buff_addr);

        /* Copy virtio_hdr to packet and increment buffer address */
        buff_hdr_addr = buff_addr;

        /*
         * If the descriptors are chained the header and data are
         * placed in separate buffers.
         */
        if (likely(desc->flags & VRING_DESC_F_NEXT)
            && (desc->len == sizeof(struct virtio_net_hdr))) {
            /*
             * TODO: verify that desc->next is sane below.
             */
            desc = &vq->vdv_desc[desc->next];
            /* Buffer address translation. */
            buff_addr = (uintptr_t)vr_dpdk_guest_phys_to_host_virt(vru_cl, desc->addr);
        } else {
            vb_offset += sizeof(struct virtio_net_hdr);
            hdr = 1;
        }

        pkt_len = rte_pktmbuf_pkt_len(buff);
        data_len = rte_pktmbuf_data_len(buff);
        len_to_cpy = RTE_MIN(data_len,
            hdr ? desc->len - sizeof(struct virtio_net_hdr) : desc->len);
        while (total_copied < pkt_len) {
            /* Copy mbuf data to buffer */
            rte_memcpy((void *)(uintptr_t)(buff_addr + vb_offset),
                rte_pktmbuf_mtod(buff, const void *) + offset,
                len_to_cpy);

            offset += len_to_cpy;
            vb_offset += len_to_cpy;
            total_copied += len_to_cpy;

            /* The whole packet completes */
            if (likely(total_copied == pkt_len))
                break;

            /* The current segment completes */
            if (offset == data_len) {
                buff = buff->next;
                offset = 0;
                data_len = rte_pktmbuf_data_len(buff);
            }

            /* The current vring descriptor done */
            if (vb_offset == desc->len) {
                if (desc->flags & VRING_DESC_F_NEXT) {
                    desc = &vq->vdv_desc[desc->next];
                    buff_addr = (uintptr_t)vr_dpdk_guest_phys_to_host_virt(vru_cl, desc->addr);
                    vb_offset = 0;
                } else {
                    /* Room in vring buffer is not enough */
                    uncompleted_pkt = 1;
                    break;
                }
            }
            len_to_cpy = RTE_MIN(data_len - offset, desc->len - vb_offset);
        };

        /* Update used ring with desc information */
        vq->vdv_used->ring[res_cur_idx & (vq->vdv_size - 1)].id =
                            head[packet_success];

        /* Drop the packet if it is uncompleted */
        if (unlikely(uncompleted_pkt == 1))
            vq->vdv_used->ring[res_cur_idx & (vq->vdv_size - 1)].len =
                            sizeof(struct virtio_net_hdr);
        else
            vq->vdv_used->ring[res_cur_idx & (vq->vdv_size - 1)].len =
                            pkt_len + sizeof(struct virtio_net_hdr);

        res_cur_idx++;
        packet_success++;

        if (unlikely(uncompleted_pkt == 1))
            continue;

        rte_memcpy((void *)(uintptr_t)buff_hdr_addr,
            (const void *)&virtio_hdr, sizeof(struct virtio_net_hdr));

        if (likely(res_cur_idx < res_end_idx)) {
            /* Prefetch descriptor index. */
            rte_prefetch0(&vq->vdv_desc[head[packet_success]]);
        }
    }

    rte_compiler_barrier();

    /* Wait until it's our turn to add our buffer to the used ring. */
    while (unlikely(vq->vdv_last_used_idx != res_base_idx))
        rte_pause();

    *(volatile uint16_t *)&vq->vdv_used->idx += count;
    vq->vdv_last_used_idx = res_end_idx;

    /* flush used->idx update before we read avail->flags. */
    rte_mb();

    /* Kick the guest if necessary. */
    if (unlikely(!(vq->vdv_avail->flags & VRING_AVAIL_F_NO_INTERRUPT))) {
        p->nb_syscalls++;
        eventfd_write(vq->vdv_callfd, 1);
    }
    return count;
}

static inline void
dpdk_virtio_send_burst(struct dpdk_virtio_writer *p)
{
    uint32_t nb_tx;

    nb_tx = dpdk_virtio_dev_to_vm_tx_burst(p, p->tx_virtioq,
                    p->tx_buf, p->tx_buf_count);

    DPDK_VIRTIO_WRITER_STATS_PKTS_DROP_ADD(p, p->tx_buf_count - nb_tx);
    /* dpdk_virtio_dev_to_vm_tx_burst() does not free any mbufs */
    while (likely(p->tx_buf_count)) {
        p->tx_buf_count--;
        rte_pktmbuf_free(p->tx_buf[p->tx_buf_count]);
    }
}

/*
 * dpdk_virtio_to_vm_tx - sends a packet from vrouter to a virtio client. The
 * virtio client is usually a VM.
 *
 * Returns nothing.
 */
static int
dpdk_virtio_to_vm_tx(void *port, struct rte_mbuf *pkt)
{
    struct dpdk_virtio_writer *p = (struct dpdk_virtio_writer *)port;

    p->tx_buf[p->tx_buf_count++] = pkt;
    DPDK_VIRTIO_WRITER_STATS_PKTS_IN_ADD(p, 1);

    if (unlikely(p->tx_buf_count >= VR_DPDK_VIRTIO_TX_BURST_SZ))
        dpdk_virtio_send_burst(p);

    return 0;
}

/*
 * dpdk_virtio_to_vm_flush - flushes packets from vrouter to a virtio client.
 * The virtio client is usually a VM.
 *
 * Returns nothing.
 */
static int
dpdk_virtio_to_vm_flush(void *port)
{
    struct dpdk_virtio_writer *p = (struct dpdk_virtio_writer *)port;

    if (p->tx_buf_count > 0)
        dpdk_virtio_send_burst(p);

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

    if ((vif_idx >= VR_MAX_INTERFACES)
        || (vring_idx >= (2 * VR_DPDK_VIRTIO_MAX_QUEUES))) {
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

    vq->vdv_last_used_idx = vring_base;
    vq->vdv_last_used_idx_res = vring_base;
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

    if ((vif_idx >= VR_MAX_INTERFACES)
        || (vring_idx >= (2 * VR_DPDK_VIRTIO_MAX_QUEUES))) {
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

    *vring_basep = vq->vdv_last_used_idx;

    /*
     * This is usually called when qemu shuts down a virtio queue. Set the
     * state to indicate that this queue should not be used any more.
     */
    vq->vdv_ready_state = VQ_NOT_READY;
    rte_wmb();
    synchronize_rcu();

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

    if ((vif_idx >= VR_MAX_INTERFACES)
        || (vring_idx >= (2 * VR_DPDK_VIRTIO_MAX_QUEUES))) {
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

    if ((vif_idx >= VR_MAX_INTERFACES) || (vring_idx > 2 * VR_DPDK_VIRTIO_MAX_QUEUES)) {
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

    if ((vif_idx >= VR_MAX_INTERFACES)
        || (vring_idx >= (2 * VR_DPDK_VIRTIO_MAX_QUEUES))) {
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

    if ((vif_idx >= VR_MAX_INTERFACES)
        || (vring_idx >= (2 * VR_DPDK_VIRTIO_MAX_QUEUES))) {
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

static int
dpdk_virtio_reader_stats_read(void *port,
    struct rte_port_in_stats *stats, int clear)
{
    struct dpdk_virtio_reader *p = (struct dpdk_virtio_reader *)port;

    if (stats != NULL)
        memcpy(stats, &p->stats, sizeof(p->stats));

    if (clear)
        memset(&p->stats, 0, sizeof(p->stats));

    return 0;
}

static int
dpdk_virtio_writer_stats_read(void *port,
    struct rte_port_out_stats *stats, int clear)
{
    struct dpdk_virtio_reader *p = (struct dpdk_virtio_reader *)port;

    if (stats != NULL)
        memcpy(stats, &p->stats, sizeof(p->stats));

    if (clear)
        memset(&p->stats, 0, sizeof(p->stats));

    return 0;
}

/* Update extra statistics for virtio queue */
void
vr_dpdk_virtio_xstats_update(struct vr_interface_stats *stats,
    struct vr_dpdk_queue *queue)
{
    struct dpdk_virtio_reader *reader;
    struct dpdk_virtio_writer *writer;

    if (queue->rxq_ops.f_rx == vr_dpdk_virtio_reader_ops.f_rx) {
        reader = (struct dpdk_virtio_reader *)queue->q_queue_h;
        stats->vis_port_isyscalls = reader->nb_syscalls;
        stats->vis_port_inombufs = reader->nb_nombufs;
    } else if (queue->txq_ops.f_tx == vr_dpdk_virtio_writer_ops.f_tx) {
        writer = (struct dpdk_virtio_writer *)queue->q_queue_h;
        stats->vis_port_osyscalls = writer->nb_syscalls;
    }
}
