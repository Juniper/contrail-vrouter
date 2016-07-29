/*
 * Copyright (C) 2016 Semihalf.
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
 * vr_dpdk_tapdev.c -- DPDK tap device
 *
 */

#include "vr_dpdk.h"
// #include "vr_packet.h"

#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_port_ring.h>
#include <rte_malloc.h>

#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>

/*
 * Multi-writer ring port implementation from the latest DPDK.
 * BSD LICENSE
 *
 * Copyright(c) 2010-2014 Intel Corporation. All rights reserved.
 *
 * TODO: remove after upgrade
 */
/** ring_multi_writer port parameters */
#define rte_port_ring_multi_writer_params rte_port_ring_writer_params

/** ring_multi_writer port operations */
struct rte_port_out_ops rte_port_ring_multi_writer_ops;

/*
 * Port RING Writer
 */
#ifdef RTE_PORT_STATS_COLLECT

#define RTE_PORT_RING_WRITER_STATS_PKTS_IN_ADD(port, val) \
    port->stats.n_pkts_in += val
#define RTE_PORT_RING_WRITER_STATS_PKTS_DROP_ADD(port, val) \
    port->stats.n_pkts_drop += val

#else

#define RTE_PORT_RING_WRITER_STATS_PKTS_IN_ADD(port, val)
#define RTE_PORT_RING_WRITER_STATS_PKTS_DROP_ADD(port, val)

#endif

struct rte_port_ring_writer {
    struct rte_port_out_stats stats;

    struct rte_mbuf *tx_buf[2 * RTE_PORT_IN_BURST_SIZE_MAX];
    struct rte_ring *ring;
    uint32_t tx_burst_sz;
    uint32_t tx_buf_count;
    uint64_t bsz_mask;
    uint32_t is_multi;
};

static int
rte_port_ring_writer_stats_read(void *port,
        struct rte_port_out_stats *stats, int clear)
{
    struct rte_port_ring_writer *p =
        (struct rte_port_ring_writer *) port;

    if (stats != NULL)
        memcpy(stats, &p->stats, sizeof(p->stats));

    if (clear)
        memset(&p->stats, 0, sizeof(p->stats));

    return 0;
}

static void *
rte_port_ring_writer_create_internal(void *params, int socket_id,
    uint32_t is_multi)
{
    struct rte_port_ring_writer_params *conf =
            (struct rte_port_ring_writer_params *) params;
    struct rte_port_ring_writer *port;

    /* Check input parameters */
    if ((conf == NULL) ||
        (conf->ring == NULL) ||
        (conf->ring->prod.sp_enqueue && is_multi) ||
        (!(conf ->ring->prod.sp_enqueue) && !is_multi) ||
        (conf->tx_burst_sz > RTE_PORT_IN_BURST_SIZE_MAX)) {
        RTE_LOG(ERR, PORT, "%s: Invalid Parameters\n", __func__);
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
    port->ring = conf->ring;
    port->tx_burst_sz = conf->tx_burst_sz;
    port->tx_buf_count = 0;
    port->bsz_mask = 1LLU << (conf->tx_burst_sz - 1);
    port->is_multi = is_multi;

    return port;
}

static void *
rte_port_ring_multi_writer_create(void *params, int socket_id)
{
    return rte_port_ring_writer_create_internal(params, socket_id, 1);
}

static inline void
send_burst_mp(struct rte_port_ring_writer *p)
{
    uint32_t nb_tx;

    nb_tx = rte_ring_mp_enqueue_burst(p->ring, (void **)p->tx_buf,
            p->tx_buf_count);

    RTE_PORT_RING_WRITER_STATS_PKTS_DROP_ADD(p, p->tx_buf_count - nb_tx);
    for ( ; nb_tx < p->tx_buf_count; nb_tx++)
        rte_pktmbuf_free(p->tx_buf[nb_tx]);

    p->tx_buf_count = 0;
}

static int
rte_port_ring_multi_writer_tx(void *port, struct rte_mbuf *pkt)
{
    struct rte_port_ring_writer *p = (struct rte_port_ring_writer *) port;

    p->tx_buf[p->tx_buf_count++] = pkt;
    RTE_PORT_RING_WRITER_STATS_PKTS_IN_ADD(p, 1);
    if (p->tx_buf_count >= p->tx_burst_sz)
        send_burst_mp(p);

    return 0;
}

static inline int __attribute__((always_inline))
rte_port_ring_writer_tx_bulk_internal(void *port,
        struct rte_mbuf **pkts,
        uint64_t pkts_mask,
        uint32_t is_multi)
{
    struct rte_port_ring_writer *p =
        (struct rte_port_ring_writer *) port;

    uint64_t bsz_mask = p->bsz_mask;
    uint32_t tx_buf_count = p->tx_buf_count;
    uint64_t expr = (pkts_mask & (pkts_mask + 1)) |
            ((pkts_mask & bsz_mask) ^ bsz_mask);

    if (expr == 0) {
        uint64_t n_pkts = __builtin_popcountll(pkts_mask);
        uint32_t n_pkts_ok;

        if (tx_buf_count) {
            send_burst_mp(p);
        }

        RTE_PORT_RING_WRITER_STATS_PKTS_IN_ADD(p, n_pkts);
        if (is_multi)
            n_pkts_ok = rte_ring_mp_enqueue_burst(p->ring, (void **)pkts,
                n_pkts);
        else
            n_pkts_ok = rte_ring_sp_enqueue_burst(p->ring, (void **)pkts,
                n_pkts);

        RTE_PORT_RING_WRITER_STATS_PKTS_DROP_ADD(p, n_pkts - n_pkts_ok);
        for ( ; n_pkts_ok < n_pkts; n_pkts_ok++) {
            struct rte_mbuf *pkt = pkts[n_pkts_ok];

            rte_pktmbuf_free(pkt);
        }
    } else {
        for ( ; pkts_mask; ) {
            uint32_t pkt_index = __builtin_ctzll(pkts_mask);
            uint64_t pkt_mask = 1LLU << pkt_index;
            struct rte_mbuf *pkt = pkts[pkt_index];

            p->tx_buf[tx_buf_count++] = pkt;
            RTE_PORT_RING_WRITER_STATS_PKTS_IN_ADD(p, 1);
            pkts_mask &= ~pkt_mask;
        }

        p->tx_buf_count = tx_buf_count;
        if (tx_buf_count >= p->tx_burst_sz) {
            send_burst_mp(p);
        }
    }

    return 0;
}

static int
rte_port_ring_multi_writer_tx_bulk(void *port,
        struct rte_mbuf **pkts,
        uint64_t pkts_mask)
{
    return rte_port_ring_writer_tx_bulk_internal(port, pkts, pkts_mask, 1);
}

static int
rte_port_ring_multi_writer_flush(void *port)
{
    struct rte_port_ring_writer *p = (struct rte_port_ring_writer *) port;

    if (p->tx_buf_count > 0)
        send_burst_mp(p);

    return 0;
}

static int
rte_port_ring_writer_free(void *port)
{
    if (port == NULL) {
        RTE_LOG(ERR, PORT, "%s: Port is NULL\n", __func__);
        return -EINVAL;
    }

    rte_port_ring_multi_writer_flush(port);

    rte_free(port);

    return 0;
}

struct rte_port_out_ops rte_port_ring_multi_writer_ops = {
    .f_create = rte_port_ring_multi_writer_create,
    .f_free = rte_port_ring_writer_free,
    .f_tx = rte_port_ring_multi_writer_tx,
    .f_tx_bulk = rte_port_ring_multi_writer_tx_bulk,
    .f_flush = rte_port_ring_multi_writer_flush,
    .f_stats = rte_port_ring_writer_stats_read,
};

/*
 * vr_dpdk_tapdev_init - initializes TAP device using specified Ethernet port.
 *
 * Returns 0 on success, < 0 otherwise.
 */
int
vr_dpdk_tapdev_init(struct vr_interface *vif)
{
    int i, fd;
    struct vr_dpdk_tapdev *tapdev = NULL;
    struct ifreq ifr;

    RTE_LOG(INFO, VROUTER, "    creating TAP device %s\n", vif->vif_name);

    /* Find an empty TAP slot. */
    for (i = 0; i < VR_DPDK_MAX_TAP_INTERFACES; i++) {
        if (vr_dpdk.tapdevs[i].tapdev_fd <= 0) {
            tapdev = &vr_dpdk.tapdevs[i];
            break;
        }
    }
    if (tapdev == NULL) {
        RTE_LOG(ERR, VROUTER, "    error allocating TAP device %s\n",
            vif->vif_name);
        return -ENOMEM;
    }

    /* Open TUN device. */
    fd = open("/dev/net/tun", O_RDWR | O_NONBLOCK);
    if (fd == -1) {
        RTE_LOG(ERR, VROUTER, "    error opening TAP device %s: %s (%d)\n",
            vif->vif_name, rte_strerror(errno), errno);
        goto error;
    }

    /* Create TAP interface. */
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, (char *)vif->vif_name, sizeof(ifr.ifr_name) - 1);
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        RTE_LOG(ERR, VROUTER, "    error creating TAP interface %s: %s (%d)\n",
            vif->vif_name, rte_strerror(errno), errno);
        goto error;
    }

    /* Enable TAP device. */
    vif->vif_os = tapdev;
    tapdev->tapdev_vif = vif;
    synchronize_rcu();
    tapdev->tapdev_fd = fd;
    // RTE_LOG(INFO, VROUTER, "XXX: TAPDEV FD %d\n", fd);

    return 0;

error:
    if (tapdev->tapdev_fd > 0) {
        close(tapdev->tapdev_fd);
        tapdev->tapdev_fd = -1;
    }

    return -EINVAL;
}

/*
 * vr_dpdk_tapdev_release - release TAP device.
 *
 * Returns 0 on success, < 0 otherwise.
 */
int
vr_dpdk_tapdev_release(struct vr_interface *vif)
{
    struct rte_mbuf *mbuf;
    struct vr_dpdk_tapdev *tapdev = vif->vif_os;

    RTE_LOG(INFO, VROUTER, "    releasing vif %u TAP device %s\n",
            vif->vif_idx, vif->vif_name);

    if (tapdev->tapdev_fd > 0) {
        close(tapdev->tapdev_fd);
        tapdev->tapdev_fd = -1;
        synchronize_rcu();
    }

    vif->vif_os = NULL;
    tapdev->tapdev_vif = NULL;

    /* Drop RX and TX mbufs. */
    if (tapdev->tapdev_rx_ring) {
        while (rte_ring_sc_dequeue(tapdev->tapdev_rx_ring,
                    (void **)&mbuf) == 0) {
            rte_pktmbuf_free(mbuf);
        }
    }
    if (tapdev->tapdev_tx_ring) {
        while (rte_ring_sc_dequeue(tapdev->tapdev_tx_ring,
                    (void **)&mbuf) == 0) {
            rte_pktmbuf_free(mbuf);
        }
    }

    return 0;
}

/*
 * dpdk_tapdev_rx_queue_release - release TAP RX queue.
 */
static void
dpdk_tapdev_rx_queue_release(unsigned lcore_id, struct vr_interface *vif)
{
    struct vr_dpdk_lcore *lcore = vr_dpdk.lcores[lcore_id];
    struct vr_dpdk_queue *rx_queue = &lcore->lcore_rx_queues[vif->vif_idx];
    struct vr_dpdk_queue_params *rx_queue_params
                        = &lcore->lcore_rx_queue_params[vif->vif_idx];

    /* Free the queue. */
    if (rx_queue->rxq_ops.f_free(rx_queue->q_queue_h)) {
        RTE_LOG(ERR, VROUTER, "    error freeing lcore %u TAP device RX queue\n",
                    lcore_id);
    }

    /* Reset the queue. */
    vrouter_put_interface(rx_queue->q_vif);
    memset(rx_queue, 0, sizeof(*rx_queue));
    memset(rx_queue_params, 0, sizeof(*rx_queue_params));
}


/*
 * vr_dpdk_tapdev_rx_queue_init - init TAP RX queue.
 *
 * Returns queue pointer on success, NULL otherwise.
 */
struct vr_dpdk_queue *
vr_dpdk_tapdev_rx_queue_init(unsigned lcore_id, struct vr_interface *vif,
    unsigned queue_id)
{
    struct vr_dpdk_lcore *lcore = vr_dpdk.lcores[lcore_id];
    const unsigned socket_id = rte_lcore_to_socket_id(lcore_id);
    unsigned vif_idx = vif->vif_idx;
    struct vr_dpdk_tapdev *tapdev = vif->vif_os;
    struct vr_dpdk_queue *rx_queue = &lcore->lcore_rx_queues[vif_idx];
    struct vr_dpdk_queue_params *rx_queue_params
                    = &lcore->lcore_rx_queue_params[vif_idx];

    /* Init queue. */
    rx_queue->rxq_ops = rte_port_ring_reader_ops;
    rx_queue->q_queue_h = NULL;
    rx_queue->q_vif = vrouter_get_interface(vif->vif_rid, vif_idx);

    /* Allocate RX ring if needed. */
    if (tapdev->tapdev_rx_ring == NULL) {
        tapdev->tapdev_rx_ring = vr_dpdk_ring_allocate(lcore_id,
            "tapdev_rx_ring", VR_DPDK_RX_RING_SZ,
            RING_F_SP_ENQ | RING_F_SC_DEQ);
        if (tapdev->tapdev_rx_ring == NULL)
            goto error;
    }

    /* Create the queue. */
    struct rte_port_ring_reader_params reader_params = {
        .ring = tapdev->tapdev_rx_ring,
    };
    rx_queue->q_queue_h = rx_queue->rxq_ops.f_create(&reader_params,
                                                        socket_id);
    if (rx_queue->q_queue_h == NULL)
        goto error;

    /* Store queue params. */
    rx_queue_params->qp_release_op = &dpdk_tapdev_rx_queue_release;
    rx_queue_params->qp_ring.ring_p = tapdev->tapdev_rx_ring;

    return rx_queue;

error:
    RTE_LOG(ERR, VROUTER,
        "    error initializing tapdev %s RX queue\n", vif->vif_name);
    return NULL;
}

/*
 * dpdk_tapdev_tx_queue_release - release TAP TX queue.
 */
static void
dpdk_tapdev_tx_queue_release(unsigned lcore_id, struct vr_interface *vif)
{
    struct vr_dpdk_lcore *lcore = vr_dpdk.lcores[lcore_id];
    struct vr_dpdk_queue *tx_queue = &lcore->lcore_tx_queues[vif->vif_idx];
    struct vr_dpdk_queue_params *tx_queue_params
                        = &lcore->lcore_tx_queue_params[vif->vif_idx];

    tx_queue->txq_ops.f_tx = NULL;
    rte_wmb();

    /* Flush and free the queue. */
    if (tx_queue->txq_ops.f_free(tx_queue->q_queue_h)) {
        RTE_LOG(ERR, VROUTER, "    error freeing lcore %u TAP device TX queue\n",
                    lcore_id);
    }

    /* Reset the queue. */
    vrouter_put_interface(tx_queue->q_vif);
    memset(tx_queue, 0, sizeof(*tx_queue));
    memset(tx_queue_params, 0, sizeof(*tx_queue_params));
}

/*
 * vr_dpdk_tapdev_tx_queue_init - init TAP TX queue.
 *
 * Returns queue pointer on success, NULL otherwise.
 */
struct vr_dpdk_queue *
vr_dpdk_tapdev_tx_queue_init(unsigned lcore_id, struct vr_interface *vif,
    unsigned queue_id)
{
    struct vr_dpdk_lcore *lcore = vr_dpdk.lcores[lcore_id];
    const unsigned socket_id = rte_lcore_to_socket_id(lcore_id);
    unsigned vif_idx = vif->vif_idx;
    struct vr_dpdk_tapdev *tapdev = vif->vif_os;
    struct vr_dpdk_queue *tx_queue = &lcore->lcore_tx_queues[vif_idx];
    struct vr_dpdk_queue_params *tx_queue_params
                    = &lcore->lcore_tx_queue_params[vif_idx];

    /* Init queue. */
    tx_queue->txq_ops = rte_port_ring_multi_writer_ops;
    tx_queue->q_queue_h = NULL;
    tx_queue->q_vif = vrouter_get_interface(vif->vif_rid, vif_idx);

    /* Allocate TX ring if needed. */
    if (tapdev->tapdev_tx_ring == NULL) {
        tapdev->tapdev_tx_ring = vr_dpdk_ring_allocate(lcore_id,
            "tapdev_tx_ring", VR_DPDK_TX_RING_SZ,
            RING_F_SC_DEQ);
        if (tapdev->tapdev_tx_ring == NULL)
            goto error;
    }

    /* Create the queue. */
    struct rte_port_ring_multi_writer_params writer_params = {
        .ring = tapdev->tapdev_tx_ring,
        .tx_burst_sz = VR_DPDK_TX_BURST_SZ,
    };
    tx_queue->q_queue_h = tx_queue->txq_ops.f_create(&writer_params,
                                                        socket_id);
    if (tx_queue->q_queue_h == NULL)
        goto error;

    /* Store queue params. */
    tx_queue_params->qp_release_op = &dpdk_tapdev_tx_queue_release;
    tx_queue_params->qp_ring.ring_p = tapdev->tapdev_tx_ring;

    return tx_queue;

error:
    RTE_LOG(ERR, VROUTER,
        "    error initializing tapdev %s TX queue\n", vif->vif_name);
    return NULL;
}

/*
 * vr_dpdk_tapdev_rx_burst - RX a burst of packets from the TAP device.
 *
 * Returns number of actual packets received, or 0 otherwise.
 */
unsigned
vr_dpdk_tapdev_rx_burst(struct vr_dpdk_tapdev *tapdev, struct rte_mbuf **mbufs,
    unsigned num)
{
    int i, fd;
    unsigned ret = 0;
    struct rte_mbuf *mbuf;
    struct vr_interface *vif;
    struct vr_interface_stats *stats;
    unsigned lcore_id = rte_lcore_id();
    ssize_t len;

    fd = tapdev->tapdev_fd;
    if (unlikely(fd <= 0))
        return 0;

    for (i = 0; i < num; i++) {
        vif = tapdev->tapdev_vif;
        stats = vif_get_stats(vif, lcore_id);

        mbuf = rte_pktmbuf_alloc(vr_dpdk.rss_mempool);
        if (unlikely(mbuf == NULL)) {
            stats->vis_dev_inombufs++;
            break;
        }

        len = read(fd, rte_pktmbuf_mtod(mbuf, void *),
                (mbuf->buf_len - rte_pktmbuf_headroom(mbuf)));
        if (unlikely(len <= 0)) {
            /* No packets to receive. */
            rte_pktmbuf_free(mbuf);
            break;
        } else {
            ret++;

            mbuf->pkt_len = mbuf->data_len = len;
            stats->vis_dev_ibytes += len;
            stats->vis_dev_ipackets++;
            mbufs[i] = mbuf;
       }
   }
   return ret;
}

/*
 * vr_dpdk_tapdev_tx_burst - TX a burst of packets to the TAP device.
 *
 * Returns number of actual packets sent, or 0 otherwise.
 */
unsigned
vr_dpdk_tapdev_tx_burst(struct vr_dpdk_tapdev *tapdev, struct rte_mbuf **mbufs,
        unsigned num)
{
    int i, fd;
    unsigned ret = 0;
    struct rte_mbuf *mbuf;
    struct vr_interface *vif;
    struct vr_interface_stats *stats;
    unsigned lcore_id = rte_lcore_id();
    ssize_t len;

    fd = tapdev->tapdev_fd;
    if (unlikely(fd <= 0))
        return 0;

    for (i = 0; i < num; i++) {
        vif = tapdev->tapdev_vif;
        stats = vif_get_stats(vif, lcore_id);
        mbuf = mbufs[i];

        len = write(fd, rte_pktmbuf_mtod(mbufs[i], void *),
            rte_pktmbuf_data_len(mbuf));
        if (unlikely(len != (ssize_t)rte_pktmbuf_data_len(mbufs[i]))) {
            /* Error sending packet. */
            stats->vis_dev_oerrors++;
            break;
        } else {
            stats->vis_dev_obytes += len;
            stats->vis_dev_opackets++;
            ret++;
        }
        rte_pktmbuf_free(mbuf);
    }

   return ret;
}

/*
 * vr_dpdk_tapdev_rxtx -- RX/TX to/from all the TAP devices.
 *
 * Returns total number of packets processed.
 */
uint64_t
vr_dpdk_tapdev_rxtx(void)
{
    int i, fd;
    struct vr_dpdk_tapdev *tapdev;
    struct rte_mbuf *mbuf;
    struct vr_interface *vif;
    struct vr_interface_stats *stats;
    unsigned lcore_id = rte_lcore_id();
    uint64_t total_pkts = 0;
    unsigned nb_pkts;

    for (i = 0; i < VR_DPDK_MAX_TAP_INTERFACES; i++) {
        tapdev = &vr_dpdk.tapdevs[i];

        fd = tapdev->tapdev_fd;
        if (fd > 0) {
            vif = tapdev->tapdev_vif;
            stats = vif_get_stats(vif, lcore_id);

            /* Try to RX from the TAP. */
            if (likely(tapdev->tapdev_rx_ring != NULL)) {
                nb_pkts = vr_dpdk_tapdev_rx_burst(tapdev, &mbuf, 1);

                if (likely(nb_pkts > 0)) {
                    total_pkts++;
                    if (unlikely(rte_ring_sp_enqueue(tapdev->tapdev_rx_ring,
                        mbuf) != 0)) {
                        rte_pktmbuf_free(mbuf);
                        stats->vis_dev_ierrors++;
                    }
                }
            }

            /* Now try to TX to the TAP. */
            if (likely(tapdev->tapdev_tx_ring != NULL)) {
                if (likely(rte_ring_sc_dequeue(tapdev->tapdev_tx_ring,
                    (void **)&mbuf) == 0))
                {
                    total_pkts++;
                    nb_pkts = vr_dpdk_tapdev_tx_burst(tapdev, &mbuf, 1);

                    if (likely(nb_pkts > 0)) {
                        total_pkts++;
                    } else {
                        rte_pktmbuf_free(mbuf);
                    }
                }
            } /* if TAP TX ring. */
        } /* if TAP FD. */
    } /* for all TAP devices. */

    return total_pkts;
}