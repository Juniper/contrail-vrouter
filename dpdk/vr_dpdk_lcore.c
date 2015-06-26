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
 * vr_dpdk_lcore.c -- lcore support functions
 *
 */

#include "vr_dpdk.h"
#include "vr_dpdk_netlink.h"
#include "vr_dpdk_usocket.h"
#include "vr_dpdk_virtio.h"
#include "vr_uvhost.h"

#include <urcu-qsbr.h>

#include <rte_cycles.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>
#include <rte_port_ethdev.h>
#include <rte_timer.h>

extern struct vr_interface_stats *vif_get_stats(struct vr_interface *,
        unsigned short);

/* Returns the least used lcore or VR_MAX_CPUS */
unsigned
vr_dpdk_lcore_least_used_get(void)
{
    unsigned lcore_id;
    struct vr_dpdk_lcore *lcore;
    unsigned least_used_id = VR_MAX_CPUS;
    uint16_t least_used_nb_queues = 2 * VR_MAX_INTERFACES;
    unsigned int num_queues;

    /* never use master (NetLink) lcore */
    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
        if (lcore_id < VR_DPDK_FWD_LCORE_ID)
            continue;
        lcore = vr_dpdk.lcores[lcore_id];

        num_queues = lcore->lcore_nb_rx_queues +
                      lcore->lcore_nb_rings_to_push;
        if (num_queues < least_used_nb_queues) {
            least_used_nb_queues = num_queues;
            least_used_id = lcore_id;
        }
    }

    return least_used_id;
}

/* Add a queue to a lcore
 * The moment the function is called from the NetLink lcore ATM.
 */
void
dpdk_lcore_queue_add(unsigned lcore_id, struct vr_dpdk_q_slist *q_head,
                        struct vr_dpdk_queue *queue)
{
    unsigned vif_idx = queue->q_vif->vif_idx;
    struct vr_dpdk_queue *prev_queue;
    struct vr_dpdk_queue *cur_queue;
    struct vr_dpdk_lcore *lcore = vr_dpdk.lcores[lcore_id];

    /* write barrier */
    rte_wmb();

    /* add queue to the list */
    if (SLIST_EMPTY(q_head)) {
        /* insert first queue */
        SLIST_INSERT_HEAD(q_head, queue, q_next);
    } else {
        /* sort TX queues by vif_idx to optimize CPU cache usage */
        prev_queue = NULL;
        SLIST_FOREACH(cur_queue, q_head, q_next) {
            if (cur_queue->q_vif->vif_idx < vif_idx)
                prev_queue = cur_queue;
            else
                break;
        }
        /* insert new queue */
        if (prev_queue == NULL)
            SLIST_INSERT_HEAD(q_head, queue, q_next);
        else
            SLIST_INSERT_AFTER(prev_queue, queue, q_next);
    }

    /* increase the number of RX queues */
    if (q_head == &lcore->lcore_rx_head)
        lcore->lcore_nb_rx_queues++;
}

/* Flush and remove TX queue from a lcore
 * The function is called by each forwaring lcore
 */
static void
dpdk_lcore_tx_queue_remove(struct vr_dpdk_lcore *lcore,
                            struct vr_dpdk_queue *tx_queue)
{
    tx_queue->txq_ops.f_tx = NULL;
    SLIST_REMOVE(&lcore->lcore_tx_head, tx_queue, vr_dpdk_queue,
        q_next);
    tx_queue->txq_ops.f_flush(tx_queue->q_queue_h);
}

/* Remove RX queue from a lcore
 * The function is called by each forwaring lcore
 */
static void
dpdk_lcore_rx_queue_remove(struct vr_dpdk_lcore *lcore,
                            struct vr_dpdk_queue *rx_queue)
{
    rx_queue->rxq_ops.f_rx = NULL;
    SLIST_REMOVE(&lcore->lcore_rx_head, rx_queue, vr_dpdk_queue,
        q_next);

    /* decrease the number of RX queues */
    lcore->lcore_nb_rx_queues--;
    RTE_VERIFY(lcore->lcore_nb_rx_queues <= VR_MAX_INTERFACES);
}

/* Schedule an MPLS label queue */
int
vr_dpdk_lcore_mpls_schedule(struct vr_interface *vif, unsigned dst_ip,
    unsigned mpls_label)
{
    int ret;
    uint16_t queue_id;
    struct vr_dpdk_queue *rx_queue;
    unsigned least_used_id = vr_dpdk_lcore_least_used_get();

    if (least_used_id == VR_MAX_CPUS) {
        RTE_LOG(ERR, VROUTER, "    error getting the least used lcore ID\n");
        return -EFAULT;
    }

    queue_id = vr_dpdk_ethdev_ready_queue_id_get(vif);
    if (queue_id == VR_DPDK_INVALID_QUEUE_ID)
        return -ENOMEM;

    /* add hardware filter */
    ret = vr_dpdk_ethdev_filter_add(vif, queue_id, dst_ip, mpls_label);
    if (ret < 0)
        return ret;

    /* init RX queue */
    RTE_LOG(INFO, VROUTER, "    lcore %u RX from filtering queue %" PRIu16
        " MPLS %u\n", least_used_id, queue_id, mpls_label);
    rx_queue = vr_dpdk_ethdev_rx_queue_init(least_used_id, vif, queue_id);
    if (rx_queue == NULL)
        return -EFAULT;

    /* add the queue to the lcore */
    dpdk_lcore_queue_add(least_used_id, &vr_dpdk.lcores[least_used_id]->lcore_rx_head,
                        rx_queue);

    return 0;
}

/* Schedule an interface */
int
vr_dpdk_lcore_if_schedule(struct vr_interface *vif, unsigned least_used_id,
    uint16_t nb_rx_queues, vr_dpdk_queue_init_op rx_queue_init_op,
    uint16_t nb_tx_queues, vr_dpdk_queue_init_op tx_queue_init_op)
{
    unsigned lcore_id;
    uint16_t queue_id;
    struct vr_dpdk_queue *rx_queue;
    struct vr_dpdk_queue *tx_queue;
    struct vr_dpdk_lcore *lcore;

    if (least_used_id == VR_MAX_CPUS) {
        RTE_LOG(ERR, VROUTER, "    error getting the least used lcore ID\n");
        return -EFAULT;
    }

    /* init TX queues starting with the least used lcore */
    lcore_id = least_used_id;
    queue_id = 0;
    /* for all lcores */
    do {
        /* TX queues are just for packet lcore and forwarding lcores */
        if (lcore_id >= VR_DPDK_PACKET_LCORE_ID) {
            /*
             * Do not schedule hardware TX queue on packet lcore if there
             * are no enough lcores for all the forwarding lcores.
             */
            if (((lcore_id != VR_DPDK_PACKET_LCORE_ID) ||
                    (nb_tx_queues > vr_dpdk.nb_fwd_lcores)) &&
                (queue_id < nb_tx_queues)) {
                /* there is a hardware queue available */
                RTE_LOG(INFO, VROUTER, "    lcore %u TX to HW queue %" PRIu16 "\n",
                    lcore_id, queue_id);
                tx_queue = (*tx_queue_init_op)(lcore_id, vif, queue_id);
                if (tx_queue == NULL)
                    return -EFAULT;
                /* next queue */
                queue_id++;
            } else {
                /* no more hardware queues left, so we use rings instead */
                RTE_LOG(INFO, VROUTER, "    lcore %u TX to SW ring\n", lcore_id);
                tx_queue = vr_dpdk_ring_tx_queue_init(lcore_id, vif, least_used_id);
                if (tx_queue == NULL)
                    return -EFAULT;
            }

            /* add the queue to the lcore */
            lcore = vr_dpdk.lcores[lcore_id];
            dpdk_lcore_queue_add(lcore_id, &lcore->lcore_tx_head, tx_queue);
        }

        /* skip master (NetLink) lcore and wrap */
        lcore_id = rte_get_next_lcore(lcore_id, 1, 1);
    } while (lcore_id != least_used_id);

    /* init RX queues starting with the least used lcore */
    lcore_id = least_used_id;
    queue_id = 0;
    /* for all lcores */
    do {
        /* RX queues are just for forwarding lcores */
        if (lcore_id >= VR_DPDK_FWD_LCORE_ID) {
            /* init hardware queue */
            if (queue_id < nb_rx_queues) {
                /* there is a hardware queue available */
                RTE_LOG(INFO, VROUTER, "    lcore %u RX from HW queue %" PRIu16
                        "\n", lcore_id, queue_id);
                rx_queue = (*rx_queue_init_op)(lcore_id, vif, queue_id);
                if (rx_queue == NULL)
                    return -EFAULT;

                /* add the queue to the lcore */
                lcore = vr_dpdk.lcores[lcore_id];
                dpdk_lcore_queue_add(lcore_id, &lcore->lcore_rx_head, rx_queue);

                /* next queue */
                queue_id++;
            } else {
                /* break if no more hardware queues left */
                break;
            }
        }

        /* skip master (NetLink) lcore and wrap */
        lcore_id = rte_get_next_lcore(lcore_id, 1, 1);
    } while (lcore_id != least_used_id);

    return 0;
}

/* Wait for a command to complete */
static void
dpdk_lcore_cmd_wait_all(void)
{
    unsigned lcore_id;
    struct vr_dpdk_lcore *lcore;

    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
        /* only packet and forwarding lcores handle commands */
        if (lcore_id < VR_DPDK_PACKET_LCORE_ID)
            continue;

        lcore = vr_dpdk.lcores[lcore_id];

        while (rte_atomic16_read(&lcore->lcore_cmd)
                            != VR_DPDK_LCORE_NO_CMD);
    }
}

/* Post an lcore command */
void
vr_dpdk_lcore_cmd_post_all(uint16_t cmd, uint32_t cmd_param)
{
    unsigned lcore_id;
    struct vr_dpdk_lcore *lcore;

    /* wait for previous command to complete */
    /* TODO: rte_atomic16_cmpset() to make it thread safe */
    dpdk_lcore_cmd_wait_all();

    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
        /* only packet and forwarding lcores handle commands */
        if (lcore_id < VR_DPDK_PACKET_LCORE_ID)
            continue;

        lcore = vr_dpdk.lcores[lcore_id];

        rte_atomic32_set(&lcore->lcore_cmd_param, cmd_param);
        rte_atomic16_set(&lcore->lcore_cmd, cmd);
    }
    /* we need to wake up the pkt0 thread so it could handle the command */
    vr_dpdk_packet_wakeup();
}

/* Release all RX and TX queues for a given vif
 * The function is called by the NetLink lcore only.
 */
void
dpdk_lcore_rxtx_release_all(struct vr_interface *vif)
{
    unsigned lcore_id;
    struct vr_dpdk_lcore *lcore;
    struct vr_dpdk_queue_params *rx_queue_params;
    struct vr_dpdk_queue_params *tx_queue_params;

    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
        /* only packet and forwarding lcores handle RX/TX queues */
        if (lcore_id < VR_DPDK_PACKET_LCORE_ID)
            continue;

        lcore = vr_dpdk.lcores[lcore_id];
        rx_queue_params = &lcore->lcore_rx_queue_params[vif->vif_idx];
        if (rx_queue_params->qp_release_op) {
            RTE_LOG(INFO, VROUTER, "    releasing lcore %u RX queue\n", lcore_id);
            rx_queue_params->qp_release_op(lcore_id, vif);
        }

        tx_queue_params = &lcore->lcore_tx_queue_params[vif->vif_idx];
        if (tx_queue_params->qp_release_op) {
            RTE_LOG(INFO, VROUTER, "    releasing lcore %u TX queue\n", lcore_id);
            tx_queue_params->qp_release_op(lcore_id, vif);
        }
    }
}

/* Unschedule an interface
 * The function is called by the NetLink lcore only.
 */
void
vr_dpdk_lcore_if_unschedule(struct vr_interface *vif)
{
    /* Remove RX queues first */
    vr_dpdk_lcore_cmd_post_all(VR_DPDK_LCORE_RX_RM_CMD,
                        (uint32_t)vif->vif_idx);
    /* Flush and remove TX queues */
    vr_dpdk_lcore_cmd_post_all(VR_DPDK_LCORE_TX_RM_CMD,
                        (uint32_t)vif->vif_idx);
    dpdk_lcore_cmd_wait_all();

    /* release RX and TX queues */
    dpdk_lcore_rxtx_release_all(vif);
}

/* Hash and distribute mbufs */
void
vr_dpdk_lcore_distribute(struct vr_interface *vif, struct rte_mbuf *pkts[VR_DPDK_RX_BURST_SZ],
    uint32_t nb_pkts)
{
    struct rte_mbuf *mbuf;
    int i, j, ret;
    unsigned dst_lcore_id;
    uint32_t lcore_nb_pkts, chunk_nb_pkts;
    const unsigned nb_fwd_lcores = vr_dpdk.nb_fwd_lcores;
    const unsigned this_lcore_id = rte_lcore_id() - VR_DPDK_FWD_LCORE_ID;
    /* Per lcore bursts (+1 for the header) */
    /* Header bits:
     *   63    - always set to 1
     *   48-32 - vif_idx
     *   31-0  - nb_pkts + 1 (the header)
     */
    /* +chunk size for the round up */
    struct rte_mbuf *lcore_pkts[nb_fwd_lcores][nb_pkts + VR_DPDK_RX_RING_CHUNK_SZ];

    RTE_LOG(DEBUG, VROUTER, "%s: distributing %" PRIu32 " packet(s) from interface %s\n",
         __func__, nb_pkts, vif->vif_name);

    /* init the headers */
    for (i = 0; i < nb_fwd_lcores; i++) {
        lcore_pkts[i][0] = (struct rte_mbuf *)(((uintptr_t)1 << 63)
                | ((uintptr_t)vif->vif_idx << 32) | 1);
        rte_prefetch0(vr_dpdk.lcores[i + VR_DPDK_FWD_LCORE_ID]->lcore_rx_ring);
    }

    /* distribute the burst among the forwarding lcores */
    for (i = 0; i < nb_pkts; i++) {
        mbuf = pkts[i];
        rte_prefetch0(rte_pktmbuf_mtod(mbuf, char *));

//        dst_lcore_id = mbuf->hash.rss % nb_fwd_lcores;
        /* TODO: emulate IO core TX, i.e. pass all the mbufs to other lcores */
        dst_lcore_id = mbuf->hash.rss % (nb_fwd_lcores - 1);
        if (dst_lcore_id >= this_lcore_id) {
            dst_lcore_id++;
        }

        /* put the mbuf to the burst */
        lcore_nb_pkts = (uintptr_t)lcore_pkts[dst_lcore_id][0] & 0xFFFFFFFFU;

        RTE_LOG(DEBUG, VROUTER, "%s: RSS hash 0x%x packet %u dst lcore %u\n",
             __func__, mbuf->hash.rss, lcore_nb_pkts, dst_lcore_id + VR_DPDK_FWD_LCORE_ID);

        lcore_pkts[dst_lcore_id][lcore_nb_pkts] = mbuf;
        /* increase number of packets in the burst */
        lcore_pkts[dst_lcore_id][0] = (struct rte_mbuf *)(
                            (uintptr_t)lcore_pkts[dst_lcore_id][0] + 1);
    }

    /* pass distributed bursts to other forwarding lcores */
    for (i = 0; i < nb_fwd_lcores; i++) {
        lcore_nb_pkts = (uintptr_t)lcore_pkts[i][0] & 0xFFFFFFFFU;
        /* we route this lcore packets later */
        if (likely(lcore_nb_pkts > 1 && i != this_lcore_id)) {
            RTE_LOG(DEBUG, VROUTER, "%s: enqueueing %u packet to lcore %u\n",
                 __func__, lcore_nb_pkts, dst_lcore_id + VR_DPDK_FWD_LCORE_ID);

            /* round up the number of packets to the chunk size */
            chunk_nb_pkts = (lcore_nb_pkts + VR_DPDK_RX_RING_CHUNK_SZ - 1)
                    /VR_DPDK_RX_RING_CHUNK_SZ*VR_DPDK_RX_RING_CHUNK_SZ;
            ret = rte_ring_mp_enqueue_bulk(
                    vr_dpdk.lcores[i + VR_DPDK_FWD_LCORE_ID]->lcore_rx_ring,
                    (void **)&lcore_pkts[i][0],
                    chunk_nb_pkts);
            if (unlikely(ret == -ENOBUFS)) {
                /* never happens, because the size of the ring is greater than mempool */
                RTE_LOG(INFO, VROUTER, "%s: lcore %u ring is full, dropping %u packets: %d/%d\n",
                     __func__, i + VR_DPDK_FWD_LCORE_ID, lcore_nb_pkts,
                     rte_ring_count(vr_dpdk.lcores[i + VR_DPDK_FWD_LCORE_ID]->lcore_rx_ring),
                     rte_ring_free_count(vr_dpdk.lcores[i + VR_DPDK_FWD_LCORE_ID]->lcore_rx_ring));
                /* ring is full, drop the packets */
                /* TODO: increment per-ring counters */
                for (j = 1; j < lcore_nb_pkts; j++) {
                    vr_dpdk_pfree(lcore_pkts[i][j], VP_DROP_INTERFACE_DROP);
                }
            }
        }
    }

    /* route the mbufs destined for this lcore */
    lcore_nb_pkts = (uintptr_t)lcore_pkts[this_lcore_id][0] & 0xFFFFFFFFU;
    if (unlikely(lcore_nb_pkts > 1)) {
        RTE_LOG(DEBUG, VROUTER, "%s: lcore %u number of packets left: %u\n",
                 __func__, this_lcore_id, lcore_nb_pkts);
        vr_dpdk_lcore_vroute(vif, &lcore_pkts[this_lcore_id][1], lcore_nb_pkts - 1);
    }
}

/* Send a burst of mbufs to vRouter */
void
vr_dpdk_lcore_vroute(struct vr_interface *vif, struct rte_mbuf *pkts[VR_DPDK_RX_BURST_SZ],
    uint32_t nb_pkts)
{
    unsigned i;
    struct rte_mbuf *mbuf;
    struct vr_packet *pkt;
    unsigned lcore_id;
    struct vr_dpdk_lcore * lcore;
    struct vr_dpdk_queue *monitoring_tx_queue;
    struct vr_packet *p_clone;

    RTE_LOG(DEBUG, VROUTER, "%s: RX %" PRIu32 " packet(s) from interface %s\n",
         __func__, nb_pkts, vif->vif_name);

    if (unlikely(vif->vif_flags & VIF_FLAG_MONITORED)) {
        lcore_id = rte_lcore_id();
        lcore = vr_dpdk.lcores[lcore_id];
        monitoring_tx_queue = &lcore->lcore_tx_queues[vr_dpdk.monitorings[vif->vif_idx]];
        if (likely(monitoring_tx_queue && monitoring_tx_queue->txq_ops.f_tx)) {
            for (i = 0; i < nb_pkts; i++) {
                mbuf = pkts[i];
                /* convert mbuf to vr_packet */
                pkt = vr_dpdk_packet_get(mbuf, vif);
                p_clone = vr_pclone(pkt);
                if (likely(p_clone != NULL))
                    monitoring_tx_queue->txq_ops.f_tx(monitoring_tx_queue->q_queue_h,
                        vr_dpdk_pkt_to_mbuf(p_clone));
            }
        }
    }

    for (i = 0; i < nb_pkts; i++) {
        mbuf = pkts[i];
        rte_prefetch0(rte_pktmbuf_mtod(mbuf, char *));

        /*
         * If vRouter works in VLAN, we check if the packet received on physical
         * interface belongs to our VLAN. If it does, the tag should be stripped.
         * If not (untagged or another tag), it should be forwarded to the kernel.
         */
        if (unlikely(vr_dpdk.vlan_tag != VLAN_ID_INVALID && vif_is_fabric(vif)
            && mbuf->vlan_tci != vr_dpdk.vlan_tag)) {
                /* TODO: forward the packet to kernel */
                vr_dpdk_pfree(mbuf, VP_DROP_INVALID_PACKET);
                continue;
        }

#ifdef VR_DPDK_RX_PKT_DUMP
#ifdef VR_DPDK_PKT_DUMP_VIF_FILTER
        if (VR_DPDK_PKT_DUMP_VIF_FILTER(vif))
#endif
        rte_pktmbuf_dump(stdout, mbuf, 0x60);
#endif

        /* convert mbuf to vr_packet */
        pkt = vr_dpdk_packet_get(mbuf, vif);
        /* send the packet to vRouter */
        vif->vif_rx(vif, pkt, VLAN_ID_INVALID);
    }
}

/* Forwarding lcore RX */
static inline uint64_t
dpdk_lcore_rx(struct vr_dpdk_lcore *lcore)
{
    uint64_t total_pkts = 0;
    struct rte_mbuf *pkts[VR_DPDK_RX_BURST_SZ];
    struct vr_dpdk_queue *rx_queue;
    uint32_t nb_pkts;
    const unsigned lcore_id = rte_lcore_id();
    struct rte_port_in_stats port_stats;
    struct vr_interface_stats *vr_stats;

    /* for all hardware RX queues */
    SLIST_FOREACH(rx_queue, &lcore->lcore_rx_head, q_next) {
        /* burst RX */
        rte_prefetch0(rx_queue->q_queue_h);
        nb_pkts = rx_queue->rxq_ops.f_rx(rx_queue->q_queue_h, pkts,
                VR_DPDK_RX_BURST_SZ);
        if (likely(nb_pkts > 0)) {
            rte_prefetch0(rx_queue->q_vif);

            total_pkts += nb_pkts;
            /**
             * TODO: When we hash MPLSoGRE packets to different lcores, we will
             * need to increment vis_ifrxrngenqpkts for physical interface here.
             */
            if (likely(vr_dpdk_ethdev_rx_emulate(rx_queue->q_vif, pkts, nb_pkts) == 0)) {
                /* packets have been hashed by NIC, just route them */
                vr_dpdk_lcore_vroute(rx_queue->q_vif, pkts, nb_pkts);
            } else {
                /* distribute the packets among forwarding lcores */
                vr_dpdk_lcore_distribute(rx_queue->q_vif, pkts, nb_pkts);
            }

            vr_stats = vif_get_stats(rx_queue->q_vif, lcore_id);
            dpdk_port_in_stats_update(rx_queue, &port_stats, vr_stats);
        }
    }

    return total_pkts;
}

/* Forwarding lcore RX ring handling */
static inline uint64_t
dpdk_lcore_ring_rx(struct vr_dpdk_lcore *lcore)
{
    uint64_t total_pkts = 0;
    uintptr_t header;
    struct vr_interface *vif;
    struct vrouter *router = vrouter_get(0);
    int i, ret;
    uint32_t nb_pkts, chunk_nb_pkts;
    unsigned short vif_idx;
    struct rte_mbuf *pkts[VR_DPDK_RX_BURST_SZ + VR_DPDK_RX_RING_CHUNK_SZ];

    /* dequeue the first chunk */
    ret = rte_ring_sc_dequeue_bulk(lcore->lcore_rx_ring, (void **)pkts,
            VR_DPDK_RX_RING_CHUNK_SZ);
    if (likely(ret == 0)) {
        header = (uintptr_t)pkts[0];
        RTE_VERIFY((header & (1ULL << 63)) != 0);
        nb_pkts = header & 0xFFFFFFFFU;
        RTE_VERIFY(nb_pkts - 1 <= VR_DPDK_RX_BURST_SZ);
        total_pkts += nb_pkts - 1;
        vif_idx = header >> 32 & 0xFFFF;

        if (nb_pkts > VR_DPDK_RX_RING_CHUNK_SZ) {
            /* round up to the chunk size */
            chunk_nb_pkts = (nb_pkts + VR_DPDK_RX_RING_CHUNK_SZ - 1)
                    /VR_DPDK_RX_RING_CHUNK_SZ*VR_DPDK_RX_RING_CHUNK_SZ;
            ret = rte_ring_sc_dequeue_bulk(lcore->lcore_rx_ring,
                    (void **)(pkts + VR_DPDK_RX_RING_CHUNK_SZ),
                    chunk_nb_pkts - VR_DPDK_RX_RING_CHUNK_SZ);
            /* we always should be able to dequeue the mbufs */
            RTE_VERIFY(ret == 0);
        }
        vif = __vrouter_get_interface(router, vif_idx);
        if (likely(vif != NULL)) {
            /* skip the header */
            vr_dpdk_lcore_vroute(vif, &pkts[1], nb_pkts - 1);
        } else {
            /* the vif is no longer available, just drop the packets */
            for (i = 1; i < nb_pkts; i++)
                vr_dpdk_pfree(pkts[i], VP_DROP_INTERFACE_DROP);
        }
    }

    return total_pkts;
}

/* Forwarding lcore push TX rings */
static inline uint64_t
dpdk_lcore_rings_push(struct vr_dpdk_lcore *lcore)
{
    uint64_t total_pkts = 0;
    struct rte_ring *ring;
    struct vr_dpdk_ring_to_push *rtp;
    struct vr_interface_stats *vr_stats;
    int i;
    uint32_t nb_pkts;
    uint16_t nb_rtp;
    struct rte_mbuf *pkts[VR_DPDK_TX_BURST_SZ];
    struct rte_port_out_stats port_stats;
    const unsigned lcore_id = rte_lcore_id();

    /* for all TX rings to push */
    rtp = &lcore->lcore_rings_to_push[0];
    nb_rtp = lcore->lcore_nb_rings_to_push;
    while (nb_rtp > 0) {
        nb_rtp--;
        ring = rtp->rtp_tx_ring;
        if (unlikely(ring == NULL)) {
            rtp++;
            continue;
        }

        nb_pkts = rte_ring_sc_dequeue_burst(ring, (void **)pkts, VR_DPDK_TX_BURST_SZ);
        if (likely(nb_pkts != 0)) {
            total_pkts += nb_pkts;

            vr_stats = vif_get_stats(rtp->rtp_tx_queue->q_vif, lcore_id);
            /* check if TX queue is available */
            if (likely(rtp->rtp_tx_queue->txq_ops.f_tx != NULL)) {
                /* push packets to the TX queue */
                /* TODO: use f_tx_bulk instead */
                for (i = 0; i < nb_pkts; i++) {
                    rtp->rtp_tx_queue->txq_ops.f_tx(
                        rtp->rtp_tx_queue->q_queue_h, pkts[i]);
                }

                dpdk_port_out_stats_update(rtp->rtp_tx_queue, &port_stats,
                                            vr_stats);
            } else {
                /* TX queue has been deleted, so just drop the packets */
                vr_stats->vis_ifenqdrops += nb_pkts;
                for (i = 0; i < nb_pkts; i++)
                    /* TODO: a separate counter for this drop */
                    vr_dpdk_pfree(pkts[i], VP_DROP_INTERFACE_DROP);
            }
        }
        rtp++;
    }
    return total_pkts;
}

/* Forwarding lcore IO */
static inline void
dpdk_lcore_fwd_io(struct vr_dpdk_lcore *lcore)
{
    uint64_t total_pkts = 0;

    /* TODO: skip RX queues with no packets to read
     * RX operation for KNIs is quite expensive. We used rx_queue_mask to
     * mask out the ports with no packets to read (i.e. read them less
     * frequently). We need to implement the same functionality for the
     * list of RX queues now.
     */
    total_pkts += dpdk_lcore_rx(lcore);
    /* handle lcore RX ring */
    total_pkts += dpdk_lcore_ring_rx(lcore);
    /* push TX rings */
    total_pkts += dpdk_lcore_rings_push(lcore);

    rcu_quiescent_state();

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

/* Init lcore context */
static int
dpdk_lcore_init(unsigned lcore_id)
{
    struct vr_dpdk_lcore *lcore;

    /* allocate lcore context */
    lcore = rte_zmalloc_socket("vr_dpdk_lcore", sizeof(struct vr_dpdk_lcore),
        RTE_CACHE_LINE_SIZE,  rte_lcore_to_socket_id(lcore_id));
    if (lcore == NULL) {
        RTE_LOG(CRIT, VROUTER, "Error allocating lcore %u context\n", lcore_id);
        return -ENOMEM;
    }

    /* init lcore lists */
    SLIST_INIT(&lcore->lcore_tx_head);

    /* allocate RX ring (multi-producer single-consumer) */
    lcore->lcore_rx_ring = vr_dpdk_ring_allocate(lcore_id, "lcore RX ring",
            VR_DPDK_RX_RING_SZ, RING_F_SC_DEQ);
    if (lcore->lcore_rx_ring == NULL) {
        RTE_LOG(CRIT, VROUTER, "Error allocating lcore %u RX ring\n", lcore_id);
        return -ENOMEM;
    }

    vr_dpdk.lcores[lcore_id] = lcore;

    rcu_register_thread();
    rcu_thread_offline();

    return 0;
}

/* Exit forwarding lcore */
static void
dpdk_lcore_exit(unsigned lcore_id)
{
    struct vr_dpdk_lcore *lcore = vr_dpdk.lcores[lcore_id];
    rcu_unregister_thread();

    /* wait for interface operation to complete */
    vr_dpdk_if_lock();
    vr_dpdk_if_unlock();

    /* free lcore context */
    vr_dpdk.lcores[lcore_id] = NULL;
    rte_free(lcore->lcore_rx_ring);
    rte_free(lcore);
}

/* Handle an IPC command
 * Returns -1 if if there is a stop command
 */
int
vr_dpdk_lcore_cmd_handle(struct vr_dpdk_lcore *lcore)
{
    uint16_t cmd = (uint16_t)rte_atomic16_read(&lcore->lcore_cmd);
    uint32_t cmd_param = (uint32_t)rte_atomic32_read(&lcore->lcore_cmd_param);
    int ret = 0;
    unsigned vif_idx;
    struct vr_dpdk_queue *rx_queue;
    struct vr_dpdk_queue *tx_queue;

    if (likely(cmd == VR_DPDK_LCORE_NO_CMD))
        return 0;

    switch (cmd) {
    case VR_DPDK_LCORE_RX_RM_CMD:
        vif_idx = cmd_param;
        rx_queue = &lcore->lcore_rx_queues[vif_idx];
        if (rx_queue->q_queue_h) {
            /* remove the queue from the lcore */
            dpdk_lcore_rx_queue_remove(lcore, rx_queue);
        }
        rte_atomic16_set(&lcore->lcore_cmd, VR_DPDK_LCORE_NO_CMD);
        break;
    case VR_DPDK_LCORE_TX_RM_CMD:
        vif_idx = cmd_param;
        tx_queue = &lcore->lcore_tx_queues[vif_idx];
        if (tx_queue->q_queue_h) {
            /* remove the queue from the lcore */
            dpdk_lcore_tx_queue_remove(lcore, tx_queue);
        }
        rte_atomic16_set(&lcore->lcore_cmd, VR_DPDK_LCORE_NO_CMD);
        break;
    case VR_DPDK_LCORE_STOP_CMD:
        ret = -1;
        /* do not reset stop command, so we can break nested loops */
        break;
    }

    return ret;
}

/* TX bond queues */
static void
dpdk_lcore_bond_tx(struct vr_dpdk_lcore *lcore)
{
    int i;
    struct vr_dpdk_queue_params *tx_queue_params;

    for (i = 0; i < lcore->lcore_nb_bonds_to_tx; i++) {
        tx_queue_params = lcore->lcore_bonds_to_tx[i];
        /* TX any pending LACP packets */
        rte_eth_tx_burst(tx_queue_params->qp_ethdev.port_id,
            tx_queue_params->qp_ethdev.queue_id, NULL, 0);
    }
}

/* Forwarding lcore main loop */
int
dpdk_lcore_fwd_loop(void)
{
    unsigned lcore_id = rte_lcore_id();
    struct vr_dpdk_lcore *lcore = vr_dpdk.lcores[lcore_id];
    /* cycles counters */
    uint64_t cur_cycles = 0;
    uint64_t cur_bond_cycles = 0;
    uint64_t diff_cycles;
    uint64_t last_tx_cycles = 0;
    uint64_t last_bond_tx_cycles = 0;
    /* always calculate bond TX timeout in CPU cycles */
    const uint64_t bond_tx_cycles = (rte_get_timer_hz() + MS_PER_S - 1)
        * VR_DPDK_BOND_TX_MS / MS_PER_S;
#if VR_DPDK_USE_TIMER
    /* calculate timeouts in CPU cycles */
    const uint64_t tx_flush_cycles = (rte_get_timer_hz() + US_PER_S - 1)
        * VR_DPDK_TX_FLUSH_US / US_PER_S;
#else
    const uint64_t tx_flush_cycles = VR_DPDK_TX_FLUSH_LOOPS;
#endif

    RTE_LOG(DEBUG, VROUTER, "Hello from forwarding lcore %u\n", lcore_id);

    while (1) {
        rte_prefetch0(lcore);

        /* update cycles counter */
#if VR_DPDK_USE_TIMER
        cur_cycles = rte_get_timer_cycles();
#else
        cur_cycles++;
#endif

        /* run forwarding lcore IO */
        dpdk_lcore_fwd_io(lcore);

        /* check if we need to flush TX queues */
        diff_cycles = cur_cycles - last_tx_cycles;
        if (unlikely(tx_flush_cycles < diff_cycles)) {
            /* update TX flush cycles */
            last_tx_cycles = cur_cycles;

            /* flush all TX queues */
            vr_dpdk_lcore_flush(lcore);

            /* check if we need to TX bond queues */
            if (unlikely(lcore->lcore_nb_bonds_to_tx > 0)) {
#if VR_DPDK_USE_TIMER
                /* we already got the CPU cycles */
                cur_bond_cycles = cur_cycles;
#else
                cur_bond_cycles = rte_get_timer_cycles();
#endif
                diff_cycles = cur_bond_cycles - last_bond_tx_cycles;
                if (unlikely(bond_tx_cycles < diff_cycles)) {
                    last_bond_tx_cycles = cur_bond_cycles;

                    dpdk_lcore_bond_tx(lcore);
                }
            }

            if (unlikely(lcore->lcore_nb_rx_queues == 0)) {
                /* no queues to poll -> sleep a bit */
                usleep(VR_DPDK_SLEEP_NO_QUEUES_US);
            }

            /* handle an IPC command */
            if (unlikely(vr_dpdk_lcore_cmd_handle(lcore)))
                break;
        } /* flush TX queues */
    } /* lcore loop */

    RTE_LOG(DEBUG, VROUTER, "Bye-bye from forwarding lcore %u\n", lcore_id);
    return 0;
}

/* NetLink lcore main loop */
static int
dpdk_lcore_netlink_loop(void)
{
    unsigned lcore_id = rte_lcore_id();
    RTE_LOG(DEBUG, VROUTER, "Hello from NetLink lcore %u\n", lcore_id);

    while (1) {
        RTE_LOG(DEBUG, VROUTER, "%s: NetLink IO on lcore %u\n",
            __func__, lcore_id);

        /* init the communication socket with Agent */
        if (vr_dpdk_netlink_init() == 0)
            vr_usocket_io(vr_dpdk.netlink_sock);

        if (unlikely(vr_dpdk_is_stop_flag_set()))
            break;
    } /* lcore loop */

    RTE_LOG(DEBUG, VROUTER, "Bye-bye from NetLink lcore %u\n", lcore_id);
    return 0;
}

/* Packet (pkt0) lcore main loop */
static int
dpdk_lcore_packet_loop(void)
{
    unsigned lcore_id = rte_lcore_id();
    RTE_LOG(DEBUG, VROUTER, "Hello from packet lcore %u\n", lcore_id);

    while (1) {
        RTE_LOG(DEBUG, VROUTER, "%s: packet IO on lcore %u\n",
            __func__, lcore_id);

        dpdk_packet_io();

        if (unlikely(vr_dpdk_is_stop_flag_set()))
            break;
    } /* lcore loop */

    RTE_LOG(DEBUG, VROUTER, "Bye-bye from packet lcore %u\n", lcore_id);
    return 0;
}

/* KNI handling loop */
static int
dpdk_lcore_kni_loop(void)
{
    unsigned lcore_id = rte_lcore_id();
    RTE_LOG(DEBUG, VROUTER, "Hello from KNI lcore %u\n", lcore_id);

    while (1) {
        vr_dpdk_knidev_all_handle();

        /* check for the global stop flag */
        if (unlikely(vr_dpdk_is_stop_flag_set()))
            break;

        usleep(VR_DPDK_SLEEP_KNI_US);
    };

    RTE_LOG(DEBUG, VROUTER, "Bye-bye from KNI lcore %u\n", lcore_id);
    return 0;
}

/* Timer lcore main loop */
static int
dpdk_lcore_timer_loop(void)
{
    unsigned lcore_id = rte_lcore_id();
    RTE_LOG(DEBUG, VROUTER, "Hello from timer lcore %u\n", lcore_id);

    while (1) {
        rte_timer_manage();

        /* check for the global stop flag */
        if (unlikely(vr_dpdk_is_stop_flag_set()))
            break;

        usleep(VR_DPDK_SLEEP_TIMER_US);
    };

    RTE_LOG(DEBUG, VROUTER, "Bye-bye from timer lcore %u\n", lcore_id);
    return 0;
}

/*
 * UVHost handling loop
 * Now we use this function instead of vr_uvhost_init().
 */
static int
dpdk_lcore_uvhost_loop(void)
{
    unsigned lcore_id = rte_lcore_id();
    RTE_LOG(DEBUG, VROUTER, "Hello from UVHost lcore %u\n", lcore_id);

    vr_uvhost_exit_fn = vr_dpdk_exit_trigger;

    while (1) {
        vr_uvhost_start(NULL);

        /* check for the global stop flag */
        if (unlikely(vr_dpdk_is_stop_flag_set()))
            break;
    };

    RTE_LOG(DEBUG, VROUTER, "Bye-bye from UVHost lcore %u\n", lcore_id);
    return 0;
}

/* Launch lcore main loop */
int
vr_dpdk_lcore_launch(__attribute__((unused)) void *dummy)
{
    const unsigned lcore_id = rte_lcore_id();

    /* init lcore context */
    if (dpdk_lcore_init(lcore_id) != 0)
        return -ENOMEM;

    switch (lcore_id) {
    case VR_DPDK_NETLINK_LCORE_ID:
        dpdk_lcore_netlink_loop();
        break;
    case VR_DPDK_KNI_LCORE_ID:
        dpdk_lcore_kni_loop();
        break;
    case VR_DPDK_TIMER_LCORE_ID:
        dpdk_lcore_timer_loop();
        break;
    case VR_DPDK_UVHOST_LCORE_ID:
        dpdk_lcore_uvhost_loop();
        break;
    case VR_DPDK_PACKET_LCORE_ID:
        dpdk_lcore_packet_loop();
        break;
    default:
        dpdk_lcore_fwd_loop();
        break;
    }

    dpdk_lcore_exit(lcore_id);

    return 0;
}
