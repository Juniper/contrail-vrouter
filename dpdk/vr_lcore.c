/*
 * Copyright (C) 2014 Semihalf.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation version 2.
 *
 * This program is distributed "as is" WITHOUT ANY WARRANTY of any
 * kind, whether express or implied; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * vr_lcore.c -- lcore support functions
 *
 */

#include <sched.h>
#include <rte_malloc.h>

#include "vr_dpdk.h"

/* Returns the least used lcore or RTE_MAX_LCORE */
static unsigned
dpdk_lcore_least_used_get(void)
{
    /* loop iterator */
    unsigned lcore_id;
    /* loop pointer to lcore context */
    struct vr_dpdk_lcore *lcore;
    /* least used lcore */
    unsigned least_used_id = RTE_MAX_LCORE;
    /* number of RX queues for least used lcore */
    uint16_t least_used_nb_queues = VR_MAX_INTERFACES;

    RTE_LCORE_FOREACH(lcore_id) {
        lcore = vr_dpdk.lcores[lcore_id];
        if (lcore->lcore_nb_rx_queues < least_used_nb_queues) {
            least_used_nb_queues = lcore->lcore_nb_rx_queues;
            least_used_id = lcore_id;
        }
    }

    return least_used_id;
}

/* Add a RX queue to a lcore */
void
dpdk_lcore_rx_queue_add(unsigned lcore_id, struct vr_dpdk_rx_queue *rx_queue)
{
    /* current lcore context */
    struct vr_dpdk_lcore *lcore = vr_dpdk.lcores[lcore_id];
    /* interface id */
    unsigned vif_idx = rx_queue->rxq_vif->vif_idx;
    /* prev RX queue */
    struct vr_dpdk_rx_queue *prev_rx_queue;
    /* loop RX queue */
    struct vr_dpdk_rx_queue *cur_rx_queue;

    /* write barrier */
    rte_wmb();

    /* add queue to the list */
    if (SLIST_EMPTY(&lcore->lcore_rx_head)) {
        /* insert first queue */
        SLIST_INSERT_HEAD(&lcore->lcore_rx_head, rx_queue, rxq_next);
    } else {
        /* sort RX queues by vif_idx to optimize CPU cache usage */
        prev_rx_queue = NULL;
        SLIST_FOREACH(cur_rx_queue, &lcore->lcore_rx_head, rxq_next) {
            if (cur_rx_queue->rxq_vif->vif_idx < vif_idx)
                prev_rx_queue = cur_rx_queue;
            else
                break;
        }
        /* insert new queue */
        if (prev_rx_queue == NULL)
            SLIST_INSERT_HEAD(&lcore->lcore_rx_head, rx_queue, rxq_next);
        else
            SLIST_INSERT_AFTER(prev_rx_queue, rx_queue, rxq_next);
    }

    /* increase the number of RX queues */
    lcore->lcore_nb_rx_queues++;
}

/* Add a TX queue to a lcore */
void
dpdk_lcore_tx_queue_add(unsigned lcore_id, struct vr_dpdk_tx_queue *tx_queue)
{
    /* current lcore context */
    struct vr_dpdk_lcore *lcore = vr_dpdk.lcores[lcore_id];
    /* interface id */
    unsigned vif_idx = tx_queue->txq_vif->vif_idx;
    /* prev TX queue */
    struct vr_dpdk_tx_queue *prev_tx_queue;
    /* loop TX queue */
    struct vr_dpdk_tx_queue *cur_tx_queue;

    /* write barrier */
    rte_wmb();

    /* add queue to the list */
    if (SLIST_EMPTY(&lcore->lcore_tx_head)) {
        /* insert first queue */
        SLIST_INSERT_HEAD(&lcore->lcore_tx_head, tx_queue, txq_next);
    } else {
        /* sort TX queues by vif_idx to optimize CPU cache usage */
        prev_tx_queue = NULL;
        SLIST_FOREACH(cur_tx_queue, &lcore->lcore_tx_head, txq_next) {
            if (cur_tx_queue->txq_vif->vif_idx < vif_idx)
                prev_tx_queue = cur_tx_queue;
            else
                break;
        }
        /* insert new queue */
        if (prev_tx_queue == NULL)
            SLIST_INSERT_HEAD(&lcore->lcore_tx_head, tx_queue, txq_next);
        else
            SLIST_INSERT_AFTER(prev_tx_queue, tx_queue, txq_next);
    }
}

/* Schedule an interface */
int
vr_dpdk_lcore_if_schedule(struct vr_interface *vif,
    uint16_t nb_rx_queues, vr_dpdk_rx_queue_init_op rx_queue_init_op,
    uint16_t nb_tx_queues, vr_dpdk_tx_queue_init_op tx_queue_init_op)
{
    /* loop iterator */
    unsigned lcore_id;
    /* least used lcore id */
    unsigned least_used_id = dpdk_lcore_least_used_get();
    /* loop queue index */
    uint16_t queue_id;
    /* loop RX queue */
    struct vr_dpdk_rx_queue *rx_queue;
    /* loop TX queue */
    struct vr_dpdk_tx_queue *tx_queue;

    RTE_LOG(DEBUG, VROUTER, "%s: nb_rx_queues=%u  nb_tx_queues=%u least_used_id=%u\n",
        __func__, (unsigned)nb_rx_queues, (unsigned)nb_tx_queues, (unsigned)least_used_id);
    if (least_used_id == RTE_MAX_LCORE) {
        RTE_LOG(ERR, VROUTER, "\terror getting the least used lcore ID\n");
        return -EFAULT;
    }

    /* init TX queues starting with the least used lcore */
    lcore_id = least_used_id;
    queue_id = 0;
    /* for all lcores */
    do {
        /* init hardware or ring queue */
        if (queue_id < nb_tx_queues) {
            /* there is a hardware queue available */
            RTE_LOG(INFO, VROUTER, "\tlcore %u - HW TX queue %" PRIu16 "\n",
                lcore_id, queue_id);
            tx_queue = (*tx_queue_init_op)(lcore_id, vif, queue_id);
            if (tx_queue == NULL)
                return -EFAULT;
        } else {
            /* no more hardware queues left, so we use rings instead */
            RTE_LOG(INFO, VROUTER, "\tlcore %u - SW TX ring\n", lcore_id);
            tx_queue = vr_dpdk_ring_tx_queue_init(lcore_id, vif, least_used_id);
            if (tx_queue == NULL)
                return -EFAULT;
        }

        /* add the queue to the lcore */
        dpdk_lcore_tx_queue_add(lcore_id, tx_queue);

        /* next queue */
        queue_id++;

        /* do not skip master lcore but wrap */
        lcore_id = rte_get_next_lcore(lcore_id, 0, 1);
    } while (lcore_id != least_used_id);

    /* init RX queues starting with the least used lcore */
    lcore_id = least_used_id;
    queue_id = 0;
    /* for all lcores */
    do {
        /* init hardware or ring queue */
        if (queue_id < nb_rx_queues) {
            /* there is a hardware queue available */
            RTE_LOG(INFO, VROUTER, "\tlcore %u - HW RX queue %" PRIu16 "\n",
                lcore_id, queue_id);
            rx_queue = (*rx_queue_init_op)(lcore_id, vif, queue_id);
            if (rx_queue == NULL)
                return -EFAULT;
        } else {
            /* break if no more hardware queues left */
            break;
        }
        /* add the queue to the lcore */
        dpdk_lcore_rx_queue_add(lcore_id, rx_queue);

        /* next queue */
        queue_id++;

        /* do not skip master lcore but wrap */
        lcore_id = rte_get_next_lcore(lcore_id, 0, 1);
    } while (lcore_id != least_used_id);

    return 0;
}

/* Flush TX queues */
static inline void
dpdk_lcore_flush(struct vr_dpdk_lcore *lcore)
{
    /* loop pointer to TX queue */
    struct vr_dpdk_tx_queue *tx_queue;

    SLIST_FOREACH(tx_queue, &lcore->lcore_tx_head, txq_next) {
        tx_queue->txq_ops.f_flush(tx_queue->txq_queue_h);
    }
}

/* Send a burst of packets to vRouter */
static inline void
dpdk_vroute(struct vr_interface *vif, struct rte_mbuf *pkts[VR_DPDK_MAX_BURST_SZ],
    uint32_t nb_pkts)
{
    /* packet iterator */
    unsigned i;
    /* loop mbuf pointer */
    struct rte_mbuf *mbuf;
    /* loop packet pointer */
    struct vr_packet *pkt;

    RTE_LOG(DEBUG, VROUTER, "%s: RX %" PRIu32 " packet(s) from interface %s\n",
         __func__, nb_pkts, vif->vif_name);
    for (i = 0; i < nb_pkts; i++) {
        mbuf = pkts[i];
#ifdef VR_DPDK_RX_PKT_DUMP
        rte_pktmbuf_dump(mbuf, 0x60);
#endif
        rte_prefetch0(vr_dpdk_mbuf_to_pkt(mbuf));
        rte_prefetch0(rte_pktmbuf_mtod(mbuf, void *));

        /* convert mbuf to vr_packet */
        pkt = vr_dpdk_packet_get(mbuf, vif);
        /* send the packet to vRouter */
        vif->vif_rx(vif, pkt, VLAN_ID_INVALID);
    }
}

/* Forwarding lcore run */
static inline void
dpdk_lcore_run(struct vr_dpdk_lcore *lcore)
{
    /* loop pointer to RX queue */
    struct vr_dpdk_rx_queue *rx_queue;
    /* number of packets read */
    uint32_t nb_pkts;
    /* total packets counter */
    uint64_t total_pkts = 0;
    /* list of packets read */
    struct rte_mbuf *pkts[VR_DPDK_MAX_BURST_SZ];
    /* loop iterator */
    int i;
    /* loop ring to push pointer */
    struct vr_dpdk_ring_to_push *rtp;

    /* for all RX queues */
    SLIST_FOREACH(rx_queue, &lcore->lcore_rx_head, rxq_next) {
        /* burst RX */
        nb_pkts = rx_queue->rxq_ops.f_rx(rx_queue->rxq_queue_h, pkts,
            rx_queue->rxq_burst_size);
        if (unlikely(nb_pkts == 0))
            continue;

        total_pkts += nb_pkts;
        /* transmit packets to vrouter */
        dpdk_vroute(rx_queue->rxq_vif, pkts, nb_pkts);
    }

    /* for all TX rings to push */
    rtp = &lcore->lcore_rings_to_push[0];
    while (unlikely(rtp->rtp_tx_queue != NULL)) {
        nb_pkts = rte_ring_sc_dequeue_burst(rtp->rtp_tx_ring, (void **)pkts,
            VR_DPDK_MAX_BURST_SZ-1);
        if (likely(nb_pkts != 0)) {
            total_pkts += nb_pkts;

            /* push packets to the TX queue */
            for (i = 0; i < nb_pkts; i++) {
                rtp->rtp_tx_queue->txq_ops.f_tx(rtp->rtp_tx_queue->txq_queue_h, pkts[i]);
            }
        }
        rtp++;
    }

#if VR_DPDK_SLEEP_NO_PACKETS_US > 0
    /* sleep if no single packet received */
    if (unlikely(total_pkts == 0)) {
        usleep(VR_DPDK_SLEEP_NO_PACKETS_US);
    }
#endif
#if VR_DPDK_YIELD_NO_PACKETS > 0
    /* yield if no single packet received */
    if (unlikely(total_pkts == 0)) {
        sched_yield();
    }
#endif
}

/* Init forwarding lcore */
static int
dpdk_lcore_init(void)
{
    /* current lcore id */
    const unsigned lcore_id = rte_lcore_id();
    /* current lcore context */
    struct vr_dpdk_lcore *lcore;

    /* allocate lcore context */
    lcore = rte_zmalloc_socket("vr_dpdk_lcore", sizeof(struct vr_dpdk_lcore),
        CACHE_LINE_SIZE, rte_socket_id());
    if (lcore == NULL) {
        RTE_LOG(CRIT, VROUTER, "Error allocating lcore %u context\n", lcore_id);
        return -ENOMEM;
    }

    /* init lcore lists */
    SLIST_INIT(&lcore->lcore_rx_head);
    SLIST_INIT(&lcore->lcore_tx_head);

    vr_dpdk.lcores[lcore_id] = lcore;

    return 0;
}

/* Exit forwarding lcore */
static void
dpdk_lcore_exit()
{
    /* current lcore id */
    const unsigned lcore_id = rte_lcore_id();
    /* current lcore context */
    struct vr_dpdk_lcore *lcore = vr_dpdk.lcores[lcore_id];

    /* free lcore context */
    vr_dpdk.lcores[lcore_id] = NULL;
    rte_free(lcore);
}

/* Forwarding lcore main loop */
int
vr_dpdk_lcore_loop(__attribute__((unused)) void *dummy)
{
    /* current lcore id */
    const unsigned lcore_id = rte_lcore_id();
    /* current lcore context */
    struct vr_dpdk_lcore *lcore;

    /* cycles counters */
    uint64_t cur_cycles = 0;
    uint64_t diff_cycles;
    uint64_t last_tx_cycles = 0;
#if VR_DPDK_USE_TIMER == true
    /* calculate timeouts in CPU cycles */
    const uint64_t tx_flush_cycles = (rte_get_timer_hz() + US_PER_S - 1)
        * VR_DPDK_TX_FLUSH_US / US_PER_S;
#else
    const uint64_t tx_flush_cycles = VR_DPDK_TX_FLUSH_LOOPS;
#endif

    RTE_LOG(DEBUG, VROUTER, "Hello from forwarding lcore %u\n", lcore_id);

    /* init forwarding lcore */
    if (dpdk_lcore_init() != 0)
        return -ENOMEM;

    /* set current lcore context */
    lcore = vr_dpdk.lcores[lcore_id];

    while (likely(1)) {
        rte_prefetch0(lcore);

        /* update cycles counter */
#if VR_DPDK_USE_TIMER == true
        cur_cycles = rte_get_timer_cycles();
#else
        cur_cycles++;
#endif

        /* run lcore loop */
        dpdk_lcore_run(lcore);

        /* check if we need to flush TX queues */
        diff_cycles = cur_cycles - last_tx_cycles;
        if (unlikely(tx_flush_cycles < diff_cycles)) {
            /* update TX flush cycles */
            last_tx_cycles = cur_cycles;

            /* flush all TX queues */
            dpdk_lcore_flush(lcore);

            /* check if any port attached */
            if (unlikely(lcore->lcore_nb_rx_queues == 0)) {
                /* no RX queues -> just sleep */
                usleep(VR_DPDK_SLEEP_NO_QUEUES_US);
            }

            /* check for the stop flag */
            if (unlikely(rte_atomic16_read(&lcore->lcore_stop_flag) != 0))
                break;
        } /* flush TX queues */
    } /* lcore loop */

    RTE_LOG(DEBUG, VROUTER, "Bye-bye from forwarding lcore %u\n", lcore_id);

    /* exit forwarding lcore */
    dpdk_lcore_exit();

    return 0;
}
