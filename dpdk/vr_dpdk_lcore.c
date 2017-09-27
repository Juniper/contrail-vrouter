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
#include "vr_dpdk_lcore.h"
#include "vr_dpdk_netlink.h"
#include "vr_dpdk_usocket.h"
#include "vr_dpdk_virtio.h"
#include "vr_uvhost.h"
#include "vr_dpdk_gro.h"

#include <signal.h>

#include <rte_cycles.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>
#include <rte_port_ethdev.h>
#include <rte_timer.h>
#include <rte_kni.h>

/* Returns the least used lcore or VR_MAX_CPUS */
unsigned
vr_dpdk_lcore_least_used_get(void)
{
    unsigned lcore_id;
    struct vr_dpdk_lcore *lcore;
    unsigned least_used_id = VR_MAX_CPUS;
    uint16_t least_used_nb_queues = 2 * VR_MAX_INTERFACES;
    unsigned int num_queues;

    /* never use master lcore */
    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
        if (lcore_id < VR_DPDK_FWD_LCORE_ID ||
                lcore_id == vr_dpdk.vf_lcore_id)
            continue;
        lcore = vr_dpdk.lcores[lcore_id];

        num_queues = lcore->lcore_nb_rx_queues;
        if (num_queues < least_used_nb_queues) {
            least_used_nb_queues = num_queues;
            least_used_id = lcore_id;
        }
    }

    return least_used_id;
}

/* Returns the least used IO lcore or VR_MAX_CPUS */
unsigned
dpdk_lcore_least_used_io_get(void)
{
    unsigned lcore_id;
    struct vr_dpdk_lcore *lcore;
    unsigned least_used_id = VR_MAX_CPUS;
    uint16_t least_used_nb_queues = 2 * VR_MAX_INTERFACES;
    unsigned int num_queues;

    for (lcore_id = VR_DPDK_IO_LCORE_ID;
            lcore_id <= VR_DPDK_LAST_IO_LCORE_ID; lcore_id++) {

        lcore = vr_dpdk.lcores[lcore_id];
        /* IO lcores are optional */
        if (lcore == NULL)
            continue;

        num_queues = lcore->lcore_nb_rx_queues;
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

    /* do not add queue twice */
    if (queue->enabled)
        return;

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

    queue->enabled = true;
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
void
dpdk_lcore_rx_queue_remove(struct vr_dpdk_lcore *lcore,
                           struct vr_dpdk_queue *rx_queue,
                           bool clear_f_rx)
{
    if (clear_f_rx)
        rx_queue->rxq_ops.f_rx = NULL;

    /* do not delete queue twice */
    if (rx_queue->enabled) {
        SLIST_REMOVE(&lcore->lcore_rx_head, rx_queue, vr_dpdk_queue,
            q_next);
        rx_queue->enabled = false;

        /* decrease the number of RX queues */
        lcore->lcore_nb_rx_queues--;
        RTE_VERIFY(lcore->lcore_nb_rx_queues <= VR_MAX_INTERFACES);
    }
}

/* Schedule an MPLS label queue */
int
vr_dpdk_lcore_mpls_schedule(struct vr_interface *vif, unsigned dst_ip,
    unsigned mpls_label)
{
#if VR_DPDK_USE_HW_FILTERING
    int ret;
#endif
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

#if VR_DPDK_USE_HW_FILTERING
    /* add hardware filter */
    ret = vr_dpdk_ethdev_filter_add(vif, queue_id, dst_ip, mpls_label);
    if (ret < 0)
        return ret;
#endif

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

static int
vr_dpdk_init_hw_tx_queues(struct vr_interface *vif, unsigned int least_used_id,
        uint16_t nb_tx_queues, vr_dpdk_queue_init_op tx_queue_init_op)
{

    bool use_packet_lcore = false;
    unsigned int lcore_id, queue, queue_index, num_fwd_cores;

    struct vr_dpdk_queue *tx_queue;
    struct vr_dpdk_lcore *lcore;
    struct vif_queue_dpdk_data *q_data = NULL;

    num_fwd_cores = vr_dpdk.nb_fwd_lcores + VR_DPDK_FWD_LCORE_ID -
        VR_DPDK_PACKET_LCORE_ID;

    if (vif->vif_num_hw_queues) {
        if (vif->vif_num_hw_queues > VR_DPDK_MAX_NB_TX_QUEUES) {
            return -EINVAL;
        }

        nb_tx_queues = vif->vif_num_hw_queues;
        q_data = (struct vif_queue_dpdk_data *)vif->vif_queue_host_data;
    } else {
        if (nb_tx_queues > num_fwd_cores) {
            nb_tx_queues = num_fwd_cores;
        }
    }

    if (nb_tx_queues >= num_fwd_cores) {
        use_packet_lcore = true;
    }

    lcore_id = least_used_id;
    for (queue_index = 0; queue_index < nb_tx_queues; queue_index++) {
        if (lcore_id >= VR_DPDK_PACKET_LCORE_ID) {
            if (!use_packet_lcore) {
                while (lcore_id < VR_DPDK_FWD_LCORE_ID) {
                    lcore_id = rte_get_next_lcore(lcore_id, 1, 1);
                }
            }

            if (vif->vif_num_hw_queues) {
                queue = vif->vif_hw_queues[queue_index];
            } else {
                queue = queue_index;
            }

            RTE_LOG(INFO, VROUTER, "    lcore %2u TX to HW queue %" PRIu16 "\n",
                    lcore_id, queue);

            lcore = vr_dpdk.lcores[lcore_id];
            if (lcore->lcore_hw_queue_to_dpdk_index[vif->vif_idx]) {
                lcore->lcore_hw_queue_to_dpdk_index[vif->vif_idx][queue] =
                    queue_index;
            }

            tx_queue = (*tx_queue_init_op)(lcore_id, vif, queue);
            if (tx_queue == NULL)
                return -EFAULT;

            if (q_data) {
                q_data->vqdd_queue_to_lcore[queue] = lcore_id;
            }

            dpdk_lcore_queue_add(lcore_id, &lcore->lcore_tx_head, tx_queue);

            if (lcore->lcore_hw_queue[vif->vif_idx] < 0) {
                lcore->lcore_hw_queue[vif->vif_idx] = queue;
            }
        }

        lcore_id = rte_get_next_lcore(lcore_id, 1, 1);
        while (lcore_id < VR_DPDK_PACKET_LCORE_ID) {
            lcore_id = rte_get_next_lcore(lcore_id, 1, 1);
        }

        if ((lcore_id == least_used_id) &&
                (nb_tx_queues == VR_DPDK_ONE_QUEUE_PER_CORE)) {
            break;
        }
    }


    return queue_index;
}

static int
vr_dpdk_init_sw_tx_rings(struct vr_interface *vif, unsigned int least_used_id)
{
    unsigned int queue, queue_index, num_queues_per_lcore = 1;
    unsigned int lcore_id, host_lcore_id;

    struct vr_dpdk_queue *tx_queue;
    struct vif_queue_dpdk_data *q_data = NULL;
    struct vr_dpdk_lcore *lcore;

    if (vif->vif_num_hw_queues) {
        num_queues_per_lcore = vif->vif_num_hw_queues;
        q_data = (struct vif_queue_dpdk_data *)vif->vif_queue_host_data;
    }

    /* init TX queues starting with the least used lcore */
    lcore_id = least_used_id;
    /* for all lcores */
    do {
        if (lcore_id >= VR_DPDK_PACKET_LCORE_ID) {
            lcore = vr_dpdk.lcores[lcore_id];

            if ((num_queues_per_lcore == 1) &&
                    (lcore->lcore_hw_queue[vif->vif_idx] >= 0)) {
                goto get_next_lcore;
            }

            for (queue_index = 0; queue_index < num_queues_per_lcore;
                    queue_index++) {
                if (vif->vif_hw_queues) {
                    queue = vif->vif_hw_queues[queue_index];
                    host_lcore_id = q_data->vqdd_queue_to_lcore[queue];
                } else {
                    queue = queue_index;
                    host_lcore_id = least_used_id;
                }

                if (host_lcore_id == lcore_id) {
                    continue;
                }

                RTE_LOG(INFO, VROUTER,
                        "    lcore %2u TX queue %u to SW ring in lcore %u\n",
                        lcore_id, queue, host_lcore_id);
                if (lcore->lcore_hw_queue_to_dpdk_index[vif->vif_idx]) {
                    lcore->lcore_hw_queue_to_dpdk_index[vif->vif_idx][queue] =
                        queue_index;
                }
                tx_queue = vr_dpdk_ring_tx_queue_init(lcore_id, vif,
                        queue, host_lcore_id);
                if (tx_queue == NULL) {
                    lcore->lcore_hw_queue_to_dpdk_index[vif->vif_idx][queue] = -1;
                    return -EFAULT;
                }

                /* add the queue to the lcore */
                dpdk_lcore_queue_add(lcore_id, &lcore->lcore_tx_head,
                        tx_queue);
            }
        }

get_next_lcore:
        /* skip master lcore and wrap */
        lcore_id = rte_get_next_lcore(lcore_id, 1, 1);
    } while (lcore_id != least_used_id);

    return 0;
}

/* Schedule an interface */
int
vr_dpdk_lcore_if_schedule(struct vr_interface *vif, unsigned least_used_id,
    uint16_t nb_rx_queues, vr_dpdk_queue_init_op rx_queue_init_op,
    uint16_t nb_tx_queues, vr_dpdk_queue_init_op tx_queue_init_op)
{
    int16_t queue_id;
    unsigned int lcore_id, usable_queues;

    struct vr_dpdk_queue *rx_queue;
    struct vr_dpdk_lcore *lcore;

    if (least_used_id == VR_MAX_CPUS) {
        RTE_LOG(ERR, VROUTER, "    error getting the least used lcore ID\n");
        return -EFAULT;
    }

    /* Check if we have dedicated an lcore for SR-IOV VF IO. */
    if (vif_is_fabric(vif) && vr_dpdk.vf_lcore_id)
        least_used_id = vr_dpdk.vf_lcore_id;

    usable_queues = vr_dpdk_init_hw_tx_queues(vif, least_used_id,
            nb_tx_queues, tx_queue_init_op);
    if (usable_queues < 0)
        return usable_queues;

    usable_queues = vr_dpdk_init_sw_tx_rings(vif, least_used_id);
    if (usable_queues < 0)
        return usable_queues;

    if (VR_DPDK_USE_IO_LCORES && nb_rx_queues == 1
        && vif_is_virtual(vif)) {
        /* assign RX queue to an IO lcore */
        lcore_id = dpdk_lcore_least_used_io_get();
        if (lcore_id == VR_MAX_CPUS) {
            RTE_LOG(ERR, VROUTER, "    error getting the least used IO lcore ID\n");
            return -EFAULT;
        }
        queue_id = 0;

        RTE_LOG(INFO, VROUTER, "    IO lcore %2u RX from HW queue %" PRIu16
                "\n", lcore_id, queue_id);
        rx_queue = (*rx_queue_init_op)(lcore_id, vif, queue_id);
        if (rx_queue == NULL)
            return -EFAULT;

        /* add the queue to the IO lcore */
        lcore = vr_dpdk.lcores[lcore_id];
        dpdk_lcore_queue_add(lcore_id, &lcore->lcore_rx_head, rx_queue);
    } else {
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
                    RTE_LOG(INFO, VROUTER, "    lcore %2u RX from HW queue %" PRIu16
                            "\n", lcore_id, queue_id);
                    rx_queue = (*rx_queue_init_op)(lcore_id, vif, queue_id);
                    if (rx_queue == NULL)
                        return -EFAULT;

                    lcore = vr_dpdk.lcores[lcore_id];

                    /*
                     * For virtio interfaces, add the queue to the lcore only
                     * for queue 0. The rest will be added by QEMU with
                     * VHOST_USER_SET_VRING_ENABLE message.
                     */
                    if (!vif_is_virtual(vif) || queue_id == 0)
                        dpdk_lcore_queue_add(lcore_id, &lcore->lcore_rx_head,
                                             rx_queue);

                    /* next queue */
                    queue_id++;
                } else {
                    /* break if no more hardware queues left */
                    break;
                }
            }

            /* skip master lcore and wrap */
            lcore_id = rte_get_next_lcore(lcore_id, 1, 1);
        } while (lcore_id != least_used_id);
    }

    return 0;
}

/* Busy wait for a command to complete on a specific lcore */
void
vr_dpdk_lcore_cmd_wait(unsigned lcore_id)
{
    struct vr_dpdk_lcore *lcore;

    /* only IO_LCORE_ID and up handle commands */
    if (lcore_id < VR_DPDK_IO_LCORE_ID)
        return;

    lcore = vr_dpdk.lcores[lcore_id];
    /* IO lcores are optional */
    if (lcore == NULL)
        return;

    while (lcore->lcore_cmd != VR_DPDK_LCORE_NO_CMD)
        rte_pause();
}

/* Wait for a command to complete */
static void
dpdk_lcore_cmd_wait_all(void)
{
    unsigned lcore_id;

    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
        vr_dpdk_lcore_cmd_wait(lcore_id);
    }
}

/* Post an lcore command to a specific lcore */
void
vr_dpdk_lcore_cmd_post(unsigned lcore_id, uint16_t cmd, uint64_t cmd_arg)
{
    struct vr_dpdk_lcore *lcore;

    /* only IO_LCORE_ID and up handle commands */
    if (lcore_id < VR_DPDK_IO_LCORE_ID)
        return;

    lcore = vr_dpdk.lcores[lcore_id];
    /* IO lcores are optional */
    if (lcore == NULL)
        return;

    /* set the command is being published */
    while (rte_atomic16_cmpset(&lcore->lcore_cmd,
                VR_DPDK_LCORE_NO_CMD, VR_DPDK_LCORE_IN_PROGRESS_CMD) == 0);
    lcore->lcore_cmd_arg = cmd_arg;
    /* publish the command */
    while (rte_atomic16_cmpset(&lcore->lcore_cmd,
                VR_DPDK_LCORE_IN_PROGRESS_CMD, cmd) == 0);

    /* handle the command if it was posted to this lcore */
    if (lcore_id == rte_lcore_id())
        vr_dpdk_lcore_cmd_handle(lcore);
    /* we need to wake up service lcores so they could handle the command */
    else if (lcore_id == VR_DPDK_PACKET_LCORE_ID)
        vr_dpdk_packet_wakeup(NULL);
    else if (lcore_id == VR_DPDK_NETLINK_LCORE_ID)
        vr_dpdk_netlink_wakeup();
}

/* Post an lcore command to all the lcores */
void
vr_dpdk_lcore_cmd_post_all(uint16_t cmd, uint64_t cmd_arg)
{
    unsigned lcore_id;

    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
        vr_dpdk_lcore_cmd_post(lcore_id, cmd, cmd_arg);
    }
}

/* Release all RX and TX queues for a given vif
 * The function is called by the NetLink lcore only.
 */
void
dpdk_lcore_rxtx_release_all(struct vr_interface *vif)
{
    unsigned lcore_id, i;
    struct vr_dpdk_lcore *lcore;
    struct vr_dpdk_queue_params *rx_queue_params;
    struct vr_dpdk_queue_params *tx_queue_params;

    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
        /* only IO_LCORE_ID and up handle RX/TX queues */
        if (lcore_id < VR_DPDK_IO_LCORE_ID)
            continue;

        lcore = vr_dpdk.lcores[lcore_id];
        rx_queue_params = &lcore->lcore_rx_queue_params[vif->vif_idx];
        if (rx_queue_params->qp_release_op) {
            RTE_LOG(INFO, VROUTER, "    releasing lcore %u RX queue\n", lcore_id);
            rx_queue_params->qp_release_op(lcore_id, 0, vif);
        }

        for (i = 0; i < lcore->num_tx_queues_per_lcore[vif->vif_idx]; i++) {
            tx_queue_params = &lcore->lcore_tx_queue_params[vif->vif_idx][i];
            if (tx_queue_params->qp_release_op) {
                RTE_LOG(INFO, VROUTER, "    releasing lcore %u TX queue %u\n",
                        lcore_id, i);
                tx_queue_params->qp_release_op(lcore_id, i, vif);
            }
        }
    }
}

/* Unschedule an interface
 * The function is called by the NetLink lcore only.
 */
void
vr_dpdk_lcore_if_unschedule(struct vr_interface *vif)
{
    struct vr_dpdk_lcore_rx_queue_remove_arg *arg;

    /* Remove RX queues first */
    arg = rte_malloc("lcore_rx_queue_rm_cmd", sizeof(*arg), 0);
    arg->vif_id = vif->vif_idx;
    arg->clear_f_rx = true;
    arg->free_arg = false; /* can not free an all fwd lcores the same arg */
    vr_dpdk_lcore_cmd_post_all(VR_DPDK_LCORE_RX_RM_CMD, (uint64_t)arg);

    /* Flush and remove TX queues */
    vr_dpdk_lcore_cmd_post_all(VR_DPDK_LCORE_TX_RM_CMD,
                        (uint32_t)vif->vif_idx);
    dpdk_lcore_cmd_wait_all();
    /* now arg can be freed */
    rte_free(arg);

    /* release RX and TX queues */
    dpdk_lcore_rxtx_release_all(vif);
}

inline static void
dpdk_lcore_delay_us(unsigned us)
{
    rcu_thread_offline();
#if VR_DPDK_SLEEP_NO_PACKETS_US > 0
    usleep(us);
#endif
#if VR_DPDK_YIELD_NO_PACKETS > 0
    /*
     * Yielding specified time reduces TX side enqueue drops,
     * but also reduces PPS on RX side.
     */
//    const uint64_t start = rte_get_timer_cycles();
//    const uint64_t ticks = (uint64_t)us * rte_get_timer_hz() / 1E6;
//    while ((rte_get_timer_cycles() - start) < ticks)
        sched_yield();

#endif
    rcu_thread_online();
}

/*
 * Distribute mbufs among forwarding lcores using hash.rss.
 * The destination lcores are listed in lcore->lcore_dst_lcore_idxs.
 */
void
vr_dpdk_lcore_distribute(struct vr_dpdk_lcore *lcore, const bool io_lcore,
    struct vr_interface *vif, struct rte_mbuf *pkts[VR_DPDK_RX_BURST_SZ],
    uint32_t nb_pkts)
{
    const unsigned lcore_id = rte_lcore_id();
    uint16_t nb_dst_lcores = lcore->lcore_nb_dst_lcores;
    uint16_t *dst_lcore_idxs = lcore->lcore_dst_lcore_idxs;
    struct rte_mbuf *mbuf;
    int i, j, ret, retry;
    int nb_retry_lcores;
    uint16_t dst_lcore_idx, dst_fwd_lcore_idx;
    uint32_t lcore_nb_pkts, chunk_nb_pkts, hashval;
    struct rte_mbuf *lcore_pkts[nb_dst_lcores][nb_pkts + VR_DPDK_RX_RING_CHUNK_SZ];
    struct vr_interface_stats *stats;
    unsigned retry_lcores[nb_dst_lcores];

    RTE_LOG_DP(DEBUG, VROUTER, "%s: distributing %" PRIu32 " packet(s) from interface %s\n",
         __func__, nb_pkts, vif->vif_name);

    /* init the headers */
    for (i = 0; i < nb_dst_lcores; i++) {
        lcore_pkts[i][0] = (struct rte_mbuf *)(((uintptr_t)1
                                            << LCORE_RX_RING_HEADER_OFF)
                | ((uintptr_t)vif->vif_idx << LCORE_RX_RING_VIF_IDX_OFF)
                | ((uintptr_t)vif->vif_gen << LCORE_RX_RING_VIF_GEN_OFF)
                | 1 /* the header */);
        retry_lcores[i] = i;
        if (io_lcore) {
            rte_prefetch0(vr_dpdk.lcores[dst_lcore_idxs[i]
                          + VR_DPDK_FWD_LCORE_ID]->lcore_io_rx_ring);
        } else {
            rte_prefetch0(vr_dpdk.lcores[dst_lcore_idxs[i]
                          + VR_DPDK_FWD_LCORE_ID]->lcore_rx_ring);
        }
    }

    /* distribute the burst among the forwarding lcores */
    for (i = 0; i < nb_pkts; i++) {
        mbuf = pkts[i];
        rte_prefetch0(rte_pktmbuf_mtod(mbuf, char *));
        if (likely(mbuf->ol_flags & PKT_RX_RSS_HASH))
            hashval = mbuf->hash.rss;
        else
            hashval = 0;

        dst_lcore_idx = hashval % nb_dst_lcores;
        dst_fwd_lcore_idx = dst_lcore_idxs[dst_lcore_idx] + VR_DPDK_FWD_LCORE_ID;

        /* put the mbuf to the burst */
        lcore_nb_pkts = (uintptr_t)lcore_pkts[dst_lcore_idx][0]
                                                 & LCORE_RX_RING_NB_PKTS_MASK;
        RTE_LOG_DP(DEBUG, VROUTER, "%s: lcore %u RSS hash 0x%x packet %u dst lcore %u\n",
             __func__, lcore_id, hashval, lcore_nb_pkts, dst_fwd_lcore_idx);
        lcore_pkts[dst_lcore_idx][lcore_nb_pkts] = mbuf;

        /* increase number of packets in the burst */
        lcore_pkts[dst_lcore_idx][0] = (struct rte_mbuf *)(
                            (uintptr_t)lcore_pkts[dst_lcore_idx][0] + 1);
    }

    stats = vif_get_stats(vif, lcore_id);

    /*
     * Pass distributed bursts to other forwarding lcores.
     * Retry on full RX rings.
     */
    for (retry = 0; retry < VR_DPDK_RETRY_NUM; retry++) {
        nb_retry_lcores = 0;
        for (i = 0; i < nb_dst_lcores; i++) {
            dst_lcore_idx = retry_lcores[i];
            dst_fwd_lcore_idx = dst_lcore_idxs[dst_lcore_idx] + VR_DPDK_FWD_LCORE_ID;

            lcore_nb_pkts = (uintptr_t)lcore_pkts[dst_lcore_idx][0]
                                                  & LCORE_RX_RING_NB_PKTS_MASK;
            if (likely(lcore_nb_pkts > 1)) {
                RTE_LOG_DP(DEBUG, VROUTER, "%s: enqueueing %u packet(s) to lcore %u\n",
                     __func__, lcore_nb_pkts - 1, dst_fwd_lcore_idx);

                /* round up the number of packets to the chunk size */
                chunk_nb_pkts = (lcore_nb_pkts + VR_DPDK_RX_RING_CHUNK_SZ - 1)
                        /VR_DPDK_RX_RING_CHUNK_SZ*VR_DPDK_RX_RING_CHUNK_SZ;
                if (io_lcore) {
                    /* IO lcore enqueue packets. */
                    ret = rte_ring_sp_enqueue_bulk(
                            vr_dpdk.lcores[dst_fwd_lcore_idx]->lcore_io_rx_ring,
                            (void **)&lcore_pkts[dst_lcore_idx][0],
                            chunk_nb_pkts);
                } else {
                    /* Other forwarding lcores enqueue packets. */
                    ret = rte_ring_mp_enqueue_bulk(
                            vr_dpdk.lcores[dst_fwd_lcore_idx]->lcore_rx_ring,
                            (void **)&lcore_pkts[dst_lcore_idx][0],
                            chunk_nb_pkts);
                }
                if (unlikely(ret == -ENOBUFS)) {
                    /* drop packets if it's the last retry */
                    if (unlikely(retry == VR_DPDK_RETRY_NUM - 1)) {
                        /* count out the header */
                        stats->vis_queue_ierrors += lcore_nb_pkts - 1;
                        stats->vis_queue_ierrors_to_lcore[dst_fwd_lcore_idx]
                                                          += lcore_nb_pkts - 1;

                        if (io_lcore) {
                            RTE_LOG_DP(DEBUG, VROUTER, "%s: lcore %u IO ring is full, dropping %u packets: %d/%d\n",
                                    __func__, dst_fwd_lcore_idx,
                                    lcore_nb_pkts,
                                    rte_ring_count(vr_dpdk.lcores[dst_fwd_lcore_idx]->lcore_io_rx_ring),
                                    rte_ring_free_count(vr_dpdk.lcores[dst_fwd_lcore_idx]->lcore_io_rx_ring));
                        } else {
                            RTE_LOG_DP(DEBUG, VROUTER, "%s: lcore %u ring is full, dropping %u packets: %d/%d\n",
                                    __func__, dst_fwd_lcore_idx,
                                    lcore_nb_pkts,
                                    rte_ring_count(vr_dpdk.lcores[dst_fwd_lcore_idx]->lcore_rx_ring),
                                    rte_ring_free_count(vr_dpdk.lcores[dst_fwd_lcore_idx]->lcore_rx_ring));
                        }

                        /* ring is full, drop the packets */
                        for (j = 1; j < lcore_nb_pkts; j++) {
                            vr_dpdk_pfree(lcore_pkts[dst_lcore_idx][j], vif, VP_DROP_INTERFACE_DROP);
                        }
                    } else {
                        /* mark the lcore to retry */
                        retry_lcores[nb_retry_lcores++] = dst_lcore_idx;
                        RTE_LOG_DP(DEBUG, VROUTER, "%s: retrying %d lcore %u...\n",
                            __func__, retry, dst_fwd_lcore_idx);

                    }
                } else {
                    /* count out the header */
                    stats->vis_queue_ipackets += lcore_nb_pkts - 1;
                }
            } /* if there are packets to pass */
        } /* for all lcores */

        if (likely(nb_retry_lcores == 0))
            break;
        /* pause a bit */
        dpdk_lcore_delay_us(VR_DPDK_RETRY_US);

        nb_dst_lcores = nb_retry_lcores;
    } /* for all tries */
}

/*
 * vr_dpdk_lcore_vroute - pass mbufs to dp-core.
 */
void
vr_dpdk_lcore_vroute(struct vr_dpdk_lcore *lcore, struct vr_interface *vif,
    struct rte_mbuf *pkts[VR_DPDK_RX_BURST_SZ], uint32_t nb_pkts)
{
    int i;
    struct rte_mbuf *mbuf;
    struct vr_packet *pkt;
    struct vr_dpdk_queue *monitoring_tx_queue;
    struct rte_mbuf *p_copy;
    unsigned short vlan_id = VLAN_ID_INVALID;

    RTE_LOG_DP(DEBUG, VROUTER, "%s: RX %" PRIu32 " packet(s) from interface %s\n",
         __func__, nb_pkts, vif->vif_name);

    if (unlikely(vif->vif_flags & VIF_FLAG_MONITORED)) {
        monitoring_tx_queue =
            &lcore->lcore_tx_queues[vr_dpdk.monitorings[vif->vif_idx]][0];
        if (likely(monitoring_tx_queue && monitoring_tx_queue->txq_ops.f_tx)) {
            for (i = 0; i < nb_pkts; i++) {
                mbuf = pkts[i];
                /* convert mbuf to vr_packet */
                pkt = vr_dpdk_packet_get(mbuf, vif);
                /*
                 * dp-core changes the original packet, so clone does not work
                 * as expected here.
                 */
                p_copy = vr_dpdk_pktmbuf_copy_mon(mbuf, vr_dpdk.rss_mempool);
                if (likely(p_copy != NULL)) {
                    monitoring_tx_queue->txq_ops.f_tx(monitoring_tx_queue->q_queue_h,
                                                        p_copy);
                }
            }
        }
    }

    for (i = 0; i < nb_pkts; i++) {
        mbuf = pkts[i];
        rte_prefetch0(rte_pktmbuf_mtod(mbuf, char *));

        /*
         * If vRouter works in VLAN, we check if the packet received on the
         * physical interface belongs to our VLAN. If it does, the tag should
         * be stripped. If not (untagged or another tag), it should be
         * forwarded to the kernel.
         */
        if (unlikely(vr_dpdk.vlan_tag != VLAN_ID_INVALID &&
                vif_is_fabric(vif))) {
            if ((mbuf->vlan_tci & 0xFFF) != vr_dpdk.vlan_tag) {
                if (vr_dpdk.vlan_ring == NULL || rte_vlan_insert(&mbuf)) {
                    vr_dpdk_pfree(mbuf, vif, VP_DROP_VLAN_FWD_ENQ);
                    continue;
                }
                /* Packets will be dequeued in dpdk_lcore_fwd_io() */
                if (rte_ring_mp_enqueue(vr_dpdk.vlan_ring, mbuf) != 0)
                    vr_dpdk_pfree(mbuf, vif, VP_DROP_VLAN_FWD_ENQ);
                /* Nothing to route, take the next packet. */
                continue;
            } else {
                /* Clear the VLAN flag for the case when the received packet
                 * belongs to vRouter's VLAN. This resembles the kernel vRouter
                 * behaviour, in which case a separate vlanX interface (that
                 * the vRouter is binded to) strips the tag and vRouter gets
                 * clean ethernet frames from fabric interface. If we did not
                 * do this, the VLAN tag would be passed to dp-core processing
                 * and vhost connectivity would be corrupted. */
                mbuf->ol_flags &= ~PKT_RX_VLAN_PKT;
            }
        }

#ifdef VR_DPDK_RX_PKT_DUMP
#ifdef VR_DPDK_PKT_DUMP_VIF_FILTER
        if (VR_DPDK_PKT_DUMP_VIF_FILTER(vif))
#endif
        rte_pktmbuf_dump(stdout, mbuf, 0x60);
#endif

        if ((mbuf->ol_flags & PKT_RX_VLAN_PKT) != 0) {
            vlan_id = mbuf->vlan_tci & 0xFFF;
        }

        /* convert mbuf to vr_packet */
        pkt = vr_dpdk_packet_get(mbuf, vif);
        /* send the packet to vRouter */
        vif->vif_rx(vif, pkt, vlan_id);
    }
}

/*
 * dpdk_lcore_rxqs_vroute - receive packets from RX queues and pass them
 * to dp-core.
 *
 * The function is used by forwarding lcores.
 *
 * For MPLSoGRE traffic the packets will be distributed among other
 * forwarding lcores.
 *
 * Returns total number of received packets.
 */
static uint64_t
dpdk_lcore_rxqs_vroute(struct vr_dpdk_lcore *lcore)
{
    uint64_t total_pkts = 0;
    struct rte_mbuf *pkts[VR_DPDK_RX_BURST_SZ];
    struct rte_mbuf *pkts_to_distribute[VR_DPDK_RX_BURST_SZ];
    struct vr_dpdk_queue *rx_queue;
    uint32_t nb_pkts;
    uint32_t nb_pkts_to_route;
    uint32_t nb_pkts_to_distribute;
    uint64_t mask_to_distribute;
    int i;

    /* for all hardware RX queues */
    SLIST_FOREACH(rx_queue, &lcore->lcore_rx_head, q_next) {
        /* burst RX */
        rte_prefetch0(rx_queue->q_queue_h);
        nb_pkts = rx_queue->rxq_ops.f_rx(rx_queue->q_queue_h, pkts,
                VR_DPDK_RX_BURST_SZ);
        if (likely(nb_pkts > 0)) {
            rte_prefetch0(rx_queue->q_vif);

            total_pkts += nb_pkts;

            /*
             * Thanks to NIC RSS packets received from the fabric should
             * be just routed.
             *
             * Yet for MPLSoGRE packets we recalculate the hashes and
             * redistribute only those altered packets to other lcores.
             */
            if (vif_is_fabric(rx_queue->q_vif)) {
                /* (Re)calculate hashes and strip VLAN tags. */
                mask_to_distribute = vr_dpdk_ethdev_rx_emulate(rx_queue->q_vif,
                                                    pkts, &nb_pkts);
                if (likely(mask_to_distribute == 0)) {
                    /* Packets have been hashed by NIC, just route them. */
                    vr_dpdk_lcore_vroute(lcore, rx_queue->q_vif, pkts, nb_pkts);
                } else {
                    /* Split packets to route and to distribute. */

                    nb_pkts_to_route = 0;
                    nb_pkts_to_distribute = 0;
                    for (i = 0; i < nb_pkts; i++) {
                        if (mask_to_distribute & (1ULL << i)) {
                            pkts_to_distribute[nb_pkts_to_distribute++] = pkts[i];
                        } else {
                            pkts[nb_pkts_to_route++] = pkts[i];
                        }
                    }

                    /* Some of the packets got new hash, distribute them. */
                    vr_dpdk_lcore_distribute(lcore, false, rx_queue->q_vif,
                            pkts_to_distribute, nb_pkts_to_distribute);
                    /* Route the rest of the packets. */
                    vr_dpdk_lcore_vroute(lcore, rx_queue->q_vif, pkts,
                            nb_pkts_to_route);
                }
            } else {
                /* For non-fabric interfaces we always distribute the packets. */
                mask_to_distribute = vr_dpdk_ethdev_rx_emulate(rx_queue->q_vif,
                        pkts, &nb_pkts);
                if (likely(mask_to_distribute != 0)) {
                    /* Distribute all the packets. */
                    vr_dpdk_lcore_distribute(lcore, false, rx_queue->q_vif,
                            pkts, nb_pkts);
                } else {
                    /* No other lcores to distribute, so just route the packets. */
                    vr_dpdk_lcore_vroute(lcore, rx_queue->q_vif, pkts, nb_pkts);
                }
            }
        }
    }

    return total_pkts;
}

/*
 * dpdk_lcore_rxqs_distribute - receive packets from RX queues and
 * distribute them among forwarding lcores.
 *
 * The function is used by IO and SR-IOV virtual function dedicated lcores.
 *
 * Returns total number of received packets.
 */
static uint64_t
dpdk_lcore_rxqs_distribute(struct vr_dpdk_lcore *lcore, const bool io_core)
{
    uint64_t total_pkts = 0;
    struct rte_mbuf *pkts[VR_DPDK_RX_BURST_SZ];
    struct vr_dpdk_queue *rx_queue;
    uint32_t nb_pkts, i;

    /* for all hardware RX queues */
    SLIST_FOREACH(rx_queue, &lcore->lcore_rx_head, q_next) {
        /* burst RX */
        rte_prefetch0(rx_queue->q_queue_h);
        nb_pkts = rx_queue->rxq_ops.f_rx(rx_queue->q_queue_h, pkts,
                VR_DPDK_RX_BURST_SZ);
        if (likely(nb_pkts > 0)) {
            rte_prefetch0(rx_queue->q_vif);

            total_pkts += nb_pkts;

            /*
             * Force hash recalculation in software.
             * On my setup Intel 82599 NIC hash just src/dst IPs for
             * UDP traffic, not the src/dst ports. So MPLSoUDP packets
             * always have the same RSS hash, hence the SR-IOV IO lcore
             * distribute all the MPLSoUDP packets to just one
             * forwarding lcore.
             *
             * The issue could be fixed by enabling UDP port hashing on host:
             *     ethtool -U <physical function> rx-flow-hash udp4 sdfn
             *
             * Alternatively we can force vRouter to recalculate the hashes.
             */
            for (i = 0; i < nb_pkts; i++) {
                pkts[i]->ol_flags &= ~PKT_RX_RSS_HASH;
            }

            /* (Re)calculate hashes and strip VLAN tags. */
            vr_dpdk_ethdev_rx_emulate(rx_queue->q_vif, pkts, &nb_pkts);
            /* Distribute all the packets. */
            vr_dpdk_lcore_distribute(lcore, io_core, rx_queue->q_vif, pkts, nb_pkts);
        }
    }

    return total_pkts;
}


/* Forwarding lcore RX ring handling */
static inline uint64_t
dpdk_lcore_rx_ring_vroute(struct vr_dpdk_lcore *lcore, struct rte_ring *ring)
{
    uint64_t total_pkts = 0;
    uintptr_t header;
    struct vr_interface *vif;
    struct vrouter *router = vrouter_get(0);
    int i, ret;
    uint32_t nb_pkts, chunk_nb_pkts;
    unsigned short vif_idx;
    unsigned int vif_gen;
    struct rte_mbuf *pkts[VR_DPDK_RX_BURST_SZ + VR_DPDK_RX_RING_CHUNK_SZ];

    /* dequeue the first chunk */
    ret = rte_ring_sc_dequeue_bulk(ring, (void **)pkts,
            VR_DPDK_RX_RING_CHUNK_SZ);
    if (likely(ret == 0)) {
        header = (uintptr_t)pkts[0];
        RTE_VERIFY((header & (1ULL << LCORE_RX_RING_HEADER_OFF)) != 0);
        nb_pkts = header & LCORE_RX_RING_NB_PKTS_MASK;
        RTE_VERIFY(nb_pkts - 1 <= VR_DPDK_RX_BURST_SZ);
        total_pkts += nb_pkts - 1;
        vif_idx = header >> LCORE_RX_RING_VIF_IDX_OFF
                & LCORE_RX_RING_VIF_IDX_MASK;
        vif_gen = header >> LCORE_RX_RING_VIF_GEN_OFF
                & LCORE_RX_RING_VIF_GEN_MASK;

        if (nb_pkts > VR_DPDK_RX_RING_CHUNK_SZ) {
            /* round up to the chunk size */
            chunk_nb_pkts = (nb_pkts + VR_DPDK_RX_RING_CHUNK_SZ - 1)
                    /VR_DPDK_RX_RING_CHUNK_SZ*VR_DPDK_RX_RING_CHUNK_SZ;
            ret = rte_ring_sc_dequeue_bulk(ring,
                    (void **)(pkts + VR_DPDK_RX_RING_CHUNK_SZ),
                    chunk_nb_pkts - VR_DPDK_RX_RING_CHUNK_SZ);
            /* we always should be able to dequeue the mbufs */
            RTE_VERIFY(ret == 0);
        }
        vif = __vrouter_get_interface(router, vif_idx);
        if (likely(vif != NULL) && vif->vif_gen == vif_gen) {
            /* skip the header */
            vr_dpdk_lcore_vroute(lcore, vif, &pkts[1], nb_pkts - 1);
        } else {
            /* the vif is no longer available, just drop the packets */
            for (i = 1; i < nb_pkts; i++)
                vr_dpdk_pfree(pkts[i], NULL, VP_DROP_INTERFACE_DROP);
        }
    }

    return total_pkts;
}

/* Forwarding lcore push TX rings */
static inline uint64_t
dpdk_lcore_tx_rings_push(struct vr_dpdk_lcore *lcore)
{
    uint64_t total_pkts = 0;
    struct rte_ring *ring;
    struct vr_dpdk_ring_to_push *rtp;
    struct vr_interface_stats *stats;
    int i;
    uint32_t nb_pkts;
    uint16_t nb_rtp;
    struct rte_mbuf *pkts[VR_DPDK_TX_BURST_SZ];
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

            /* check if TX queue is available */
            if (likely(rtp->rtp_tx_queue->txq_ops.f_tx != NULL)) {
                /* push packets to the TX queue */
                /* TODO: use f_tx_bulk instead */
                for (i = 0; i < nb_pkts; i++) {
                    rtp->rtp_tx_queue->txq_ops.f_tx(
                        rtp->rtp_tx_queue->q_queue_h, pkts[i]);
                }
            } else {
                /* TX queue has been deleted, so just drop the packets */
                stats = vif_get_stats(rtp->rtp_tx_queue->q_vif, lcore_id);
                stats->vis_port_oerrors += nb_pkts;
                for (i = 0; i < nb_pkts; i++)
                    /* TODO: a separate counter for this drop */
                    vr_dpdk_pfree(pkts[i], NULL, VP_DROP_INTERFACE_DROP);
            }
        }
        rtp++;
    }
    return total_pkts;
}

/* IO lcore RX/TX */
static inline void
dpdk_lcore_io_rxtx(struct vr_dpdk_lcore *lcore)
{
    uint64_t total_pkts;

    total_pkts = dpdk_lcore_rxqs_distribute(lcore, true);

    /* make a short pause if no single packet received */
    if (unlikely(total_pkts == 0)) {
        rcu_thread_offline();
#if VR_DPDK_SLEEP_NO_PACKETS_US > 0
        usleep(VR_DPDK_SLEEP_NO_PACKETS_US);
#endif
#if VR_DPDK_YIELD_NO_PACKETS > 0
        sched_yield();
#endif
        rcu_thread_online();
    }
}

/*
 * dpdk_lcore_vlan_fwd - forward VLAN packets with unmatching tag.
 */
static void
dpdk_lcore_vlan_fwd(struct vr_dpdk_lcore* lcore)
{
    struct vr_dpdk_queue* tx_queue;
    struct vrouter* router = vrouter_get(0);
    struct rte_mbuf* pkts[VR_DPDK_RX_BURST_SZ];
    struct vr_interface *eth_vif;
    uint16_t hw_queue;
    unsigned nb_pkts, i;

    /*
     * Receive packets from VLAN interface and send them to the wire.
     * Those packets will not be seen in vifdump on the physical vif.
     */
    eth_vif = router->vr_eth_if;
    if (eth_vif) {
        hw_queue = lcore->lcore_hw_queue[eth_vif->vif_idx];
        if (hw_queue < 0)
            hw_queue = 0;

        tx_queue = &lcore->lcore_tx_queues[eth_vif->vif_idx][hw_queue];
        if (tx_queue && tx_queue->txq_ops.f_tx) {
            if (vr_dpdk.kni_state > 0)
                nb_pkts = rte_kni_rx_burst(vr_dpdk.vlan_dev, pkts,
                        VR_DPDK_RX_BURST_SZ);
            else
                nb_pkts = vr_dpdk_tapdev_rx_burst(vr_dpdk.vlan_dev, pkts,
                        VR_DPDK_RX_BURST_SZ);
            for (i = 0; i < nb_pkts; i++)
                tx_queue->txq_ops.f_tx(tx_queue->q_queue_h, pkts[i]);
        }
    }
    /* Get packets from VLAN ring and forward them to kernel. */
    nb_pkts = rte_ring_sc_dequeue_burst(vr_dpdk.vlan_ring, (void**) &pkts,
            VR_DPDK_RX_BURST_SZ);
    if (vr_dpdk.kni_state > 0)
        i = rte_kni_tx_burst(vr_dpdk.vlan_dev, pkts, nb_pkts);
    else
        i = vr_dpdk_tapdev_tx_burst(vr_dpdk.vlan_dev, pkts, nb_pkts);
    for (; i < nb_pkts; i++)
        vr_dpdk_pfree(pkts[i], NULL, VP_DROP_VLAN_FWD_TX);
}

/*
 * dpdk_lcore_io_rxtx - SR-IOV VF IO lcore RX/TX
 */
static inline void
dpdk_lcore_sriov_rxtx(struct vr_dpdk_lcore *lcore)
{
    uint64_t total_pkts = 0;

    /* Distribute all packets to other lcores. */
    total_pkts += dpdk_lcore_rxqs_distribute(lcore, false);
    /* Push TX rings. */
    total_pkts += dpdk_lcore_tx_rings_push(lcore);

    /* Make a short pause if no single packet received. */
    if (unlikely(total_pkts == 0)) {
        rcu_thread_offline();
#if VR_DPDK_SLEEP_NO_PACKETS_US > 0
        usleep(VR_DPDK_SLEEP_NO_PACKETS_US);
#endif
#if VR_DPDK_YIELD_NO_PACKETS > 0
        sched_yield();
#endif
        rcu_thread_online();
    }

    /*
     * Forward VLAN packets with unmatching tag.
     * This is done only by the first forwarding lcore.
     */
    if (vr_dpdk.vlan_tag != VLAN_ID_INVALID
            && vr_dpdk.vlan_ring) {
        dpdk_lcore_vlan_fwd(lcore);
    }
}

/* Forwarding lcore RX/TX */
static inline void
dpdk_lcore_fwd_rxtx(struct vr_dpdk_lcore *lcore)
{
    uint64_t total_pkts = 0;

    /*
     * TODO: skip RX queues with no packets to read
     * RX operation for KNIs is quite expensive. We used rx_queue_mask to
     * mask out the ports with no packets to read (i.e. read them less
     * frequently). We need to implement the same functionality for the
     * list of RX queues now.
     */
    total_pkts += dpdk_lcore_rxqs_vroute(lcore);
    /* Route packets from other forwarding lcores. */
    total_pkts += dpdk_lcore_rx_ring_vroute(lcore, lcore->lcore_rx_ring);
    if (VR_DPDK_USE_IO_LCORES) {
        /* Route packets from IO lcore. */
        total_pkts += dpdk_lcore_rx_ring_vroute(lcore, lcore->lcore_io_rx_ring);
    }
    /* push TX rings */
    total_pkts += dpdk_lcore_tx_rings_push(lcore);

    /* make a short pause if no single packet received */
    if (unlikely(total_pkts == 0)) {
        rcu_thread_offline();
#if VR_DPDK_SLEEP_NO_PACKETS_US > 0
        usleep(VR_DPDK_SLEEP_NO_PACKETS_US);
#endif
#if VR_DPDK_YIELD_NO_PACKETS > 0
        sched_yield();
#endif
        rcu_thread_online();
    }

    /*
     * Forward VLAN packets with unmatching tag.
     * This is done only by the first forwarding lcore.
     */
    if (vr_dpdk.vlan_tag != VLAN_ID_INVALID
            && lcore == vr_dpdk.lcores[VR_DPDK_FWD_LCORE_ID]
            && vr_dpdk.vlan_ring) {
        dpdk_lcore_vlan_fwd(lcore);
    }
}

/* Setup signal handlers */
static void
dpdk_lcore_signals_init(unsigned lcore_id)
{
    sigset_t set;

    /* Due to the extra threads we cant block signals on, our only
     * option is to handle the signals on master (KNI) lcore */
    if (lcore_id == rte_get_master_lcore()) {
        RTE_LOG_DP(DEBUG, VROUTER, "Unblocking signals for lcore %u\n",
                    lcore_id);
        sigfillset(&set);
        if (pthread_sigmask(SIG_UNBLOCK, &set, NULL) != 0) {
            RTE_LOG(CRIT, VROUTER, "Error setting signal mask for lcore %u\n",
                        lcore_id);
        }
    }
}

/*
 * dpdk_lcore_dst_lcores_stringify - stringify lcores to distribute packets.
 */
static char *
dpdk_lcore_dst_lcores_stringify(struct vr_dpdk_lcore *lcore)
{
    int i;
    static char lcores_str[VR_DPDK_STR_BUF_SZ];
    char *p = lcores_str;

    for (i = 0; i < lcore->lcore_nb_dst_lcores; i++) {
        if (p != lcores_str)
            *p++ = ',';

        p += snprintf(p,
                sizeof(lcores_str) - (p - lcores_str),
                "%d", lcore->lcore_dst_lcore_idxs[i] + VR_DPDK_FWD_LCORE_ID);
        if (p - lcores_str >= sizeof(lcores_str)) {
            RTE_LOG(ERR, VROUTER,
                "Error stringifying lcores to distribute: buffer overflow\n");
            return "(incomplete)";
        }
    }
    *p = '\0';
    return lcores_str;
}

/*
 * dpdk_lcore_fwd_dsts_init - init forwarding lcore destinations for MPLSoGRE.
 */
static void
dpdk_lcore_fwd_dsts_init(unsigned lcore_id, struct vr_dpdk_lcore *lcore)
{
    int i;

    /* Init table of lcores to distribute packets to. */
    if (vr_dpdk.vf_lcore_id) {
        /* We have an lcore dedicated to SR-IOV virtual function IO. */
        if (lcore_id == vr_dpdk.vf_lcore_id) {
            lcore->lcore_nb_dst_lcores = vr_dpdk.nb_fwd_lcores - 1;
            for (i = 0; i < lcore->lcore_nb_dst_lcores; i++) {
                lcore->lcore_dst_lcore_idxs[i] = i + 1;
            }
        } else {
            /* Do not distribute and to itself and to the SR-IOV VF IO. */
            lcore->lcore_nb_dst_lcores = vr_dpdk.nb_fwd_lcores - 2;
            for (i = 0; i < lcore->lcore_nb_dst_lcores; i++) {
                lcore->lcore_dst_lcore_idxs[i] = i + 1;
                if (lcore->lcore_dst_lcore_idxs[i] >=
                        lcore_id - VR_DPDK_FWD_LCORE_ID)
                    lcore->lcore_dst_lcore_idxs[i]++;
            }
        }
    } else {
        /* No dedicated lcore, so do a normal distribution. */
        lcore->lcore_nb_dst_lcores = vr_dpdk.nb_fwd_lcores - 1;
        for (i = 0; i < lcore->lcore_nb_dst_lcores; i++) {
            lcore->lcore_dst_lcore_idxs[i] = i;
            if (lcore->lcore_dst_lcore_idxs[i] >=
                    lcore_id - VR_DPDK_FWD_LCORE_ID)
                lcore->lcore_dst_lcore_idxs[i]++;
        }
    }

    if (lcore_id == vr_dpdk.vf_lcore_id) {
        RTE_LOG(INFO, VROUTER, "Lcore %u: distributing all packets to [%s]\n",
                lcore_id, dpdk_lcore_dst_lcores_stringify(lcore));
    } else {
        RTE_LOG(INFO, VROUTER,
                "Lcore %u: distributing MPLSoGRE packets to [%s]\n", lcore_id,
                dpdk_lcore_dst_lcores_stringify(lcore));
    }
}

/*
 * dpdk_lcore_fwd_init - init forwarding lcore context.
 * Returns 0 on success, -errno otherwise.
 */
static int
dpdk_lcore_fwd_init(unsigned lcore_id, struct vr_dpdk_lcore *lcore)
{
    /* Init destinations for hashed packets (i.e. MPLSoGRE). */
    dpdk_lcore_fwd_dsts_init(lcore_id, lcore);

    /*
     * Allocate multi-producer single-consumer RX ring.
     * Other forwarding lcores will enqueue MPLSoGRE packets here.
     */
    lcore->lcore_rx_ring = vr_dpdk_ring_allocate(lcore_id, "lcore RX ring",
            VR_DPDK_RX_RING_SZ, RING_F_SC_DEQ);
    if (lcore->lcore_rx_ring == NULL) {
        RTE_LOG(CRIT, VROUTER, "Error allocating lcore %u RX ring\n", lcore_id);
        rte_free(lcore);
        return -ENOMEM;
    }

    /*
     * Allocate single-producer single-consumer RX ring.
     * IO lcores will enqueue packets here.
     */
    if (VR_DPDK_USE_IO_LCORES) {
        lcore->lcore_io_rx_ring = vr_dpdk_ring_allocate(lcore_id, "lcore IO RX ring",
                VR_DPDK_RX_RING_SZ, RING_F_SC_DEQ | RING_F_SP_ENQ);
        if (lcore->lcore_io_rx_ring == NULL) {
            RTE_LOG(CRIT, VROUTER, "Error allocating lcore %u IO RX ring\n", lcore_id);
            rte_free(lcore);
            return -ENOMEM;
        }
    }

    if (vr_dpdk_gro_init(lcore_id, lcore) < 0) {
        RTE_LOG(CRIT, VROUTER, "Error initializing GRO tables on lcore %u\n", lcore_id);
    }

    return 0;
}

/*
 * dpdk_lcore_io_init - init IO lcore context.
 * Returns 0 on success, -errno otherwise.
 */
static int
dpdk_lcore_io_init(unsigned lcore_id, struct vr_dpdk_lcore *lcore)
{
    int i;
    unsigned first_fwd_lcore_idx = VR_DPDK_FWD_LCORES_PER_IO
            * (lcore_id - VR_DPDK_IO_LCORE_ID);

    /* Init table of lcores to distribute packets to. */
    lcore->lcore_nb_dst_lcores = vr_dpdk.nb_fwd_lcores
            - first_fwd_lcore_idx;
    if (lcore->lcore_nb_dst_lcores > VR_DPDK_FWD_LCORES_PER_IO)
        lcore->lcore_nb_dst_lcores = VR_DPDK_FWD_LCORES_PER_IO;

    for (i = 0; i < lcore->lcore_nb_dst_lcores; i++) {
        lcore->lcore_dst_lcore_idxs[i] = first_fwd_lcore_idx + i;
    }
    RTE_LOG(INFO, VROUTER, "IO lcore %u: distributing all packets to [%s]\n",
        lcore_id, dpdk_lcore_dst_lcores_stringify(lcore));

    return 0;
}

/* Init lcore context */
static int
dpdk_lcore_init(unsigned lcore_id)
{
    struct vr_dpdk_lcore *lcore;
    int ret;

    /* allocate lcore context */
    lcore = rte_zmalloc_socket("vr_dpdk_lcore", sizeof(struct vr_dpdk_lcore),
        RTE_CACHE_LINE_SIZE,  rte_lcore_to_socket_id(lcore_id));
    if (lcore == NULL) {
        RTE_LOG(CRIT, VROUTER, "Error allocating lcore %u context\n", lcore_id);
        return -ENOMEM;
    }

    /* init lcore lists */
    SLIST_INIT(&lcore->lcore_tx_head);

    /* lcore-specific initializations */
    if (lcore_id >= VR_DPDK_IO_LCORE_ID
        && lcore_id <= VR_DPDK_LAST_IO_LCORE_ID) {
        ret = dpdk_lcore_io_init(lcore_id, lcore);
        if (ret != 0)
            return ret;
    } else if (lcore_id >= VR_DPDK_FWD_LCORE_ID) {
        ret = dpdk_lcore_fwd_init(lcore_id, lcore);
        if (ret != 0)
            return ret;
    }

    vr_dpdk.lcores[lcore_id] = lcore;

    rcu_register_thread();
    dpdk_lcore_signals_init(lcore_id);

    return 0;
}

/* Exit forwarding lcore */
void
dpdk_lcore_exit(unsigned lcore_id)
{
    struct vr_dpdk_lcore *lcore = vr_dpdk.lcores[lcore_id];

    /* wait for interface operation to complete */
    vr_dpdk_if_lock();
    vr_dpdk_if_unlock();

    /* lcore-specific initializations */
    if (lcore_id >= VR_DPDK_FWD_LCORE_ID) {
        /* Free forwarding lcore RX rings. */
        rte_free(lcore->lcore_rx_ring);
        if (VR_DPDK_USE_IO_LCORES) {
            rte_free(lcore->lcore_io_rx_ring);
        }
    }

    /* free lcore context */
    vr_dpdk.lcores[lcore_id] = NULL;
    rte_free(lcore);
}

/* Handle an IPC command
 * Returns -1 if if there is a stop command
 */
int
vr_dpdk_lcore_cmd_handle(struct vr_dpdk_lcore *lcore)
{
    uint16_t cmd = lcore->lcore_cmd;
    uint64_t cmd_arg = lcore->lcore_cmd_arg;
    int ret = 0;
    unsigned vif_idx, i;
    struct vr_dpdk_queue *rx_queue;
    struct vr_dpdk_queue *tx_queue;
    struct vr_dpdk_lcore_rx_queue_remove_arg *rxq_rm_arg;

    if (likely(cmd == VR_DPDK_LCORE_NO_CMD
        || cmd == VR_DPDK_LCORE_IN_PROGRESS_CMD))
        return 0;

    switch (cmd) {
    case VR_DPDK_LCORE_RX_RM_CMD:
        rxq_rm_arg = (struct vr_dpdk_lcore_rx_queue_remove_arg *)cmd_arg;
        vif_idx = rxq_rm_arg->vif_id;
        rx_queue = &lcore->lcore_rx_queues[vif_idx];
        if (rx_queue->q_queue_h) {
            /* remove the queue from the lcore */
            dpdk_lcore_rx_queue_remove(lcore, rx_queue, rxq_rm_arg->clear_f_rx);
        }
        if (rxq_rm_arg->free_arg)
            rte_free(rxq_rm_arg);
        lcore->lcore_cmd = VR_DPDK_LCORE_NO_CMD;
        break;
    case VR_DPDK_LCORE_TX_RM_CMD:
        vif_idx = (unsigned)cmd_arg;
        for (i = 0; i < lcore->num_tx_queues_per_lcore[vif_idx]; i++) {
            tx_queue = &lcore->lcore_tx_queues[vif_idx][i];
            if (tx_queue->q_queue_h) {
                /* remove the queue from the lcore */
                dpdk_lcore_tx_queue_remove(lcore, tx_queue);
            }
        }
        lcore->lcore_cmd = VR_DPDK_LCORE_NO_CMD;
        break;
    case VR_DPDK_LCORE_RCU_CMD:
        vr_dpdk_packet_rcu_cb((struct rcu_head *)cmd_arg);
        lcore->lcore_cmd = VR_DPDK_LCORE_NO_CMD;
        break;
    case VR_DPDK_LCORE_STOP_CMD:
        ret = -1;
        /* do not reset stop command, so we can break nested loops */
        break;
    case VR_DPDK_LCORE_TX_QUEUE_SET_CMD:
        vr_dpdk_virtio_tx_queue_set((void *)cmd_arg);
        lcore->lcore_cmd = VR_DPDK_LCORE_NO_CMD;
        break;
    case VR_DPDK_LCORE_RX_QUEUE_SET_CMD:
        vr_dpdk_virtio_rx_queue_set((void *)cmd_arg);
        lcore->lcore_cmd = VR_DPDK_LCORE_NO_CMD;
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

/* IO lcore main loop */
int
dpdk_lcore_io_loop(void)
{
    unsigned lcore_id = rte_lcore_id();
    struct vr_dpdk_lcore *lcore = vr_dpdk.lcores[lcore_id];
    /* cycles counters */
    uint64_t cur_cycles = 0;
    uint64_t diff_cycles;
    uint64_t last_tx_cycles = 0;
#if VR_DPDK_USE_TIMER
    /* calculate timeouts in CPU cycles */
    const uint64_t tx_flush_cycles = (rte_get_timer_hz() + US_PER_S - 1)
        * VR_DPDK_TX_FLUSH_US / US_PER_S;
#else
    const uint64_t tx_flush_cycles = VR_DPDK_TX_FLUSH_LOOPS;
#endif

    RTE_LOG_DP(DEBUG, VROUTER, "Hello from IO lcore %u\n", lcore_id);

    while (1) {
        rte_prefetch0(lcore);

        /* update cycles counter */
#if VR_DPDK_USE_TIMER
        cur_cycles = rte_get_timer_cycles();
#else
        cur_cycles++;
#endif

        /* run IO lcore RX/TX cycle */
        dpdk_lcore_io_rxtx(lcore);

        diff_cycles = cur_cycles - last_tx_cycles;
        if (unlikely(tx_flush_cycles < diff_cycles)) {
            /* update TX flush cycles */
            last_tx_cycles = cur_cycles;

            rcu_quiescent_state();
            if (unlikely(lcore->lcore_nb_rx_queues == 0)) {
                /* no queues to poll -> sleep a bit */
                rcu_thread_offline();
                usleep(VR_DPDK_SLEEP_NO_QUEUES_US);
                rcu_thread_online();
            }

            /* handle an IPC command */
            if (unlikely(vr_dpdk_lcore_cmd_handle(lcore)))
                break;
        } /* flush TX queues */
    } /* lcore loop */

    RTE_LOG_DP(DEBUG, VROUTER, "Bye-bye from IO lcore %u\n", lcore_id);
    return 0;
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
    uint64_t cur_assembler_cycles = 0;
    uint64_t diff_cycles;
    uint64_t last_tx_cycles = 0, last_gro_flush_cycles = 0;
    uint64_t last_bond_tx_cycles = 0;
    uint64_t last_assembler_cycles = 0;
    /* always calculate bond TX timeout in CPU cycles */
    const uint64_t bond_tx_cycles = (rte_get_timer_hz() + MS_PER_S - 1)
        * VR_DPDK_BOND_TX_MS / MS_PER_S;
    /* timeout for IP fragment assembler */
    const uint64_t assembler_cycles = (rte_get_timer_hz() + MS_PER_S - 1)
        * (VR_ASSEMBLER_TIMEOUT_TIME * 1000) / VR_LINUX_ASSEMBLER_BUCKETS
        / MS_PER_S;
#if VR_DPDK_USE_TIMER
    /* calculate timeouts in CPU cycles */
    const uint64_t tx_flush_cycles = (rte_get_timer_hz() + US_PER_S - 1)
        * VR_DPDK_TX_FLUSH_US / US_PER_S;
    const uint64_t gro_flush_cycles = 100 * tx_flush_cycles;
#else
    const uint64_t tx_flush_cycles = VR_DPDK_TX_FLUSH_LOOPS;
    const uint64_t gro_flush_cycles = 100 * tx_flush_cycles;
#endif

    RTE_LOG_DP(DEBUG, VROUTER, "Hello from forwarding lcore %u\n", lcore_id);

    while (1) {
        rte_prefetch0(lcore);

        /* update cycles counter */
#if VR_DPDK_USE_TIMER
        cur_cycles = rte_get_timer_cycles();
#else
        cur_cycles++;
        lcore->lcore_fwd_loops = cur_cycles;
#endif

        /* Run forwarding lcore or SR-IOV VF RX/TX cycle. */
        if (lcore_id == vr_dpdk.vf_lcore_id)
            dpdk_lcore_sriov_rxtx(lcore);
        else
            dpdk_lcore_fwd_rxtx(lcore);

        /* IP fragment assembler timers */
#if VR_DPDK_USE_TIMER
        /* we already got the CPU cycles */
        cur_assembler_cycles = cur_cycles;
#else
        cur_assembler_cycles = rte_get_timer_cycles();
#endif
        diff_cycles = cur_assembler_cycles - last_assembler_cycles;
        if (unlikely(assembler_cycles < diff_cycles)) {
            last_assembler_cycles = cur_assembler_cycles;
            dpdk_fragment_assembler_table_scan(NULL);
        }

        /* check if we need to flush TX queues and timeout GRO flows */
        diff_cycles = cur_cycles - last_gro_flush_cycles;
        if (unlikely(gro_flush_cycles < diff_cycles)) {
            last_gro_flush_cycles = cur_cycles;
            dpdk_gro_flush_all_inactive(lcore);
        }
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

            if (unlikely(lcore->do_fragment_assembly)) {
                lcore->do_fragment_assembly = false;
                lcore->fragment_assembly_func(lcore->fragment_assembly_arg);
            }

            rcu_quiescent_state();

            /*
             * Forwarding lcore might get packets from another lcore,
             * so it never sleeps.
             */

            /* handle an IPC command */
            if (unlikely(vr_dpdk_lcore_cmd_handle(lcore)))
                break;
        } /* flush TX queues */
    } /* lcore loop */

    RTE_LOG_DP(DEBUG, VROUTER, "Bye-bye from forwarding lcore %u\n", lcore_id);
    return 0;
}

/* NetLink lcore main loop */
static int
dpdk_lcore_netlink_loop(void)
{
    unsigned lcore_id = rte_lcore_id();
    RTE_LOG_DP(DEBUG, VROUTER, "Hello from NetLink lcore %u\n", lcore_id);

    while (1) {
        RTE_LOG_DP(DEBUG, VROUTER, "%s: NetLink IO on lcore %u\n",
            __func__, lcore_id);

        /* init the communication socket with Agent */
        if (vr_dpdk_netlink_init() == 0)
            vr_usocket_io(vr_dpdk.netlink_sock);

        if (unlikely(vr_dpdk_is_stop_flag_set()))
            break;
        usleep(VR_DPDK_SLEEP_SERVICE_US);
    } /* lcore loop */

    RTE_LOG_DP(DEBUG, VROUTER, "Bye-bye from NetLink lcore %u\n", lcore_id);
    return 0;
}

/* Packet (pkt0) lcore main loop */
static int
dpdk_lcore_packet_loop(void)
{
    unsigned lcore_id = rte_lcore_id();
    RTE_LOG_DP(DEBUG, VROUTER, "Hello from packet lcore %u\n", lcore_id);

    while (1) {
        RTE_LOG_DP(DEBUG, VROUTER, "%s: packet IO on lcore %u\n",
            __func__, lcore_id);

        dpdk_packet_io();

        if (unlikely(vr_dpdk_is_stop_flag_set()))
            break;
        usleep(VR_DPDK_SLEEP_SERVICE_US);
    } /* lcore loop */

    RTE_LOG_DP(DEBUG, VROUTER, "Bye-bye from packet lcore %u\n", lcore_id);
    return 0;
}

/*
 * dpdk_lcore_knidev_loop - KNI handling loop.
 */
static int
dpdk_lcore_knidev_loop(void)
{
    unsigned lcore_id = rte_lcore_id();
    RTE_LOG_DP(DEBUG, VROUTER, "Hello from KNI lcore %u\n", lcore_id);

    rcu_thread_offline();

    while (1) {
        vr_dpdk_knidev_all_handle();

        /* Check for the global stop flag. */
        if (unlikely(vr_dpdk_is_stop_flag_set()))
            break;

        usleep(VR_DPDK_SLEEP_KNI_US);
    };

    RTE_LOG_DP(DEBUG, VROUTER, "Bye-bye from KNI lcore %u\n", lcore_id);
    return 0;
}

/*
 * dpdk_lcore_tapdev_loop - TAP device handling loop.
 */
static int
dpdk_lcore_tapdev_loop(void)
{
    uint64_t total_pkts;
    unsigned lcore_id = rte_lcore_id();
    RTE_LOG_DP(DEBUG, VROUTER, "Hello from TAP lcore %u\n", lcore_id);

    while (1) {
        /* Handle link up/down/mtu change */
        vr_dpdk_tapdev_handle_notifications();

        total_pkts = vr_dpdk_tapdev_rxtx();

        /* make a short pause if no single packet received */
        if (unlikely(total_pkts == 0)) {
            rcu_thread_offline();
#if VR_DPDK_TAPDEV_SLEEP_NO_PACKETS_US > 0
            usleep(VR_DPDK_TAPDEV_SLEEP_NO_PACKETS_US);
#endif
            rcu_thread_online();
        } else {
            rcu_quiescent_state();
        }

        /* Check for the global stop flag. */
        if (unlikely(vr_dpdk_is_stop_flag_set()))
            break;
    };

    RTE_LOG_DP(DEBUG, VROUTER, "Bye-bye from TAP lcore %u\n", lcore_id);
    return 0;
}

/*
 * dpdk_lcore_knitap_loop - KNI or TAP handling loop.
 *
 * Once KNI is enabled, run KNI handling loop. In case KNI is not
 * available on the host, run TAP handling loop.
 */
static int
dpdk_lcore_knitap_loop(void)
{
    unsigned lcore_id = rte_lcore_id();
    RTE_LOG_DP(DEBUG, VROUTER, "Hello from KNI and TAP lcore %u\n", lcore_id);

    rcu_thread_offline();
    while (vr_dpdk.kni_state == 0) {
        /* Check for the global stop flag. */
        if (unlikely(vr_dpdk_is_stop_flag_set()))
            break;

        usleep(VR_DPDK_SLEEP_KNI_US);
    };
    rcu_thread_online();

    if (vr_dpdk.kni_state > 0) {
        dpdk_lcore_knidev_loop();
    } else {
        dpdk_lcore_tapdev_loop();
    }

    RTE_LOG_DP(DEBUG, VROUTER, "Bye-bye from KNI and TAP lcore %u\n", lcore_id);
    return 0;
}

/* Timer lcore main loop */
static int
dpdk_lcore_timer_loop(void)
{
    unsigned lcore_id = rte_lcore_id();
    RTE_LOG_DP(DEBUG, VROUTER, "Hello from timer lcore %u\n", lcore_id);

    rcu_thread_offline();

    while (1) {
        rte_timer_manage();

        /* check for the global stop flag */
        if (unlikely(vr_dpdk_is_stop_flag_set()))
            break;

        usleep(VR_DPDK_SLEEP_TIMER_US);
    };

    RTE_LOG_DP(DEBUG, VROUTER, "Bye-bye from timer lcore %u\n", lcore_id);
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
    RTE_LOG_DP(DEBUG, VROUTER, "Hello from UVHost lcore %u\n", lcore_id);

    vr_uvhost_exit_fn = vr_dpdk_exit_trigger;

    while (1) {
        vr_uvhost_start(NULL);

        /* check for the global stop flag */
        if (unlikely(vr_dpdk_is_stop_flag_set()))
            break;
    };

    RTE_LOG_DP(DEBUG, VROUTER, "Bye-bye from UVHost lcore %u\n", lcore_id);
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
    case VR_DPDK_KNITAP_LCORE_ID:
        dpdk_lcore_knitap_loop();
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
    case VR_DPDK_NETLINK_LCORE_ID:
        dpdk_lcore_netlink_loop();
        break;
    default:
        if (lcore_id >= VR_DPDK_IO_LCORE_ID
            && lcore_id <= VR_DPDK_LAST_IO_LCORE_ID) {
            dpdk_lcore_io_loop();
        } else if (lcore_id >= VR_DPDK_FWD_LCORE_ID) {
            dpdk_lcore_fwd_loop();
        }
        break;
    }

    rcu_unregister_thread();

    return 0;
}

/**
 * Schedule an assembler work on given lcore.
 *
 * This is always called from the same lcore the work is to be scheduled.
 */
void
vr_dpdk_lcore_schedule_assembler_work(struct vr_dpdk_lcore *lcore,
                                      void (*fun)(void *arg), void *arg)
{
    lcore->do_fragment_assembly = true;
    lcore->fragment_assembly_func = fun;
    lcore->fragment_assembly_arg = arg;
}

