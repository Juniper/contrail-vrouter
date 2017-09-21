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

#define VIRTIO_HDR_MRG_RXBUF 1

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
    /* last packet TX */
    uint64_t last_pkt_tx;
    /* last TX flush */
    uint64_t last_pkt_tx_flush;

    vr_dpdk_virtioq_t *tx_virtioq;
    struct rte_mbuf *tx_buf[VR_DPDK_VIRTIO_TX_BURST_SZ];
    /* Total number of mbuf chains
     * Say if a mbuf chain contains 10 segments, it is counted as 1
     */
    uint32_t tx_buf_count;
    /* Total number of mbufs in all the chains */
    uint32_t tx_mbufs;
};

struct dpdk_virtio_writer_params {
    /* virtio TX queue pointer */
    vr_dpdk_virtioq_t *tx_virtioq;
};

/*
 * vr_dpdk_virtio_stop - stop the virtio interface.
 *
 * Returns 0 on success, -1 otherwise.
 */
int
vr_dpdk_virtio_stop(unsigned int vif_idx)
{
    int i;
    vr_dpdk_virtioq_t *vq;

    if (vif_idx >= VR_MAX_INTERFACES) {
        return -1;
    }

    /* Disable and reset all the virtio queues. */
    for (i = 0; i < VR_DPDK_VIRTIO_MAX_QUEUES*2; i++) {
        if (i & 1) {
            vq = &vr_dpdk_virtio_rxqs[vif_idx][i/2];
        } else {
            vq = &vr_dpdk_virtio_txqs[vif_idx][i/2];
        }

        if (vq->vdv_ready_state != VQ_NOT_READY) {
            vr_dpdk_set_virtq_ready(vif_idx, i, VQ_NOT_READY);
            rte_wmb();
            synchronize_rcu();
            /*
             * TODO: code duplication to minimize the changes.
             * See vr_dpdk_virtio_get_vring_base().
             */
            vq->vdv_desc = NULL;
            if (vq->vdv_callfd) {
                close(vq->vdv_callfd);
                vq->vdv_callfd = 0;
            }
        }
    }

    return 0;
}

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
        RTE_LOG_DP(DEBUG, UVHOST, "Error getting file status for FD %d: %s (%d)\n",
                fd, strerror(errno), errno);
    }

    return ret;
}

/*
 * vr_dpdk_virtio_nrxqs - returns the number of receives queues for a virtio
 * interface.
 */
uint16_t
vr_dpdk_virtio_nrxqs(struct vr_interface *vif)
{
    return vr_dpdk.nb_fwd_lcores;
}

/*
 * vr_dpdk_virtio_ntxqs - returns the number of transmit queues for a virtio
 * interface.
 */
uint16_t
vr_dpdk_virtio_ntxqs(struct vr_interface *vif)
{
    return vr_dpdk.nb_fwd_lcores;
}

static unsigned int vif_rx_queue_lcore[VR_MAX_INTERFACES][VR_MAX_INTERFACES];

/*
 * dpdk_virtio_rx_queue_release - releases a virtio RX queue.
 *
 * Returns nothing.
 */
static void
dpdk_virtio_rx_queue_release(unsigned lcore_id,
        unsigned queue_index __attribute__((unused)),
        struct vr_interface *vif)
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

    /* save the lcore serving the queue for later enabling/disabling */
    vif_rx_queue_lcore[vif_idx][queue_id] = lcore_id;

    return rx_queue;
}

/*
 * dpdk_virtio_tx_queue_release - releases a virtio TX queue.
 *
 * Returns nothing.
 */
static void
dpdk_virtio_tx_queue_release(unsigned lcore_id, unsigned queue_index,
        struct vr_interface *vif)
{
    struct vr_dpdk_lcore *lcore = vr_dpdk.lcores[lcore_id];
    struct vr_dpdk_queue *tx_queue =
        &lcore->lcore_tx_queues[vif->vif_idx][queue_index];
    struct vr_dpdk_queue_params *tx_queue_params
        = &lcore->lcore_tx_queue_params[vif->vif_idx][queue_index];

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
    struct vr_dpdk_queue *tx_queue = &lcore->lcore_tx_queues[vif_idx][0];
    struct vr_dpdk_queue_params *tx_queue_params
                = &lcore->lcore_tx_queue_params[vif_idx][0];

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
        /*
         * Always initialize each lcore's tx_queue with virtio queue number 0.
         * If there are more queues, they will be enabled later via
         * VHOST_USER_SET_VRING_ENABLE message.
         */
        .tx_virtioq = &vr_dpdk_virtio_txqs[vif_idx][0],
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

struct dpdk_virtio_tx_queue_set_params {
    unsigned int vif_id;
    unsigned int vif_gen;
    unsigned int queue_id;
};

static unsigned int vif_lcore_tx_queue[VR_MAX_INTERFACES][VR_MAX_CPUS];
static unsigned int vif_tx_queues_enabled[VR_MAX_INTERFACES];

/*
 * Enable or disable given queue for a vif.
 *
 * In current vRouter design, every lcore that can send packets has to have a
 * TX queue available for every existing vif. It is because we do not know
 * which lcore wil eventually send the packet, and thus each has to have a
 * queue to use.
 *
 * If VM requests more than one virtio queue, then we distribute them among the
 * forwarding lcores as evenly as possible.
 *
 * The entire process (this function, which sends commands to other lcores and
 * then vr_dpdk_virtio_tx_queue_set(), which is called from the destination
 * lcores' main loop) works fine as long as the QEMU enables/disables each
 * queues in ascending order. For example, if the maximal number of queues is
 * 4, and inside a VM ethtool -L eth0 combined 2 is issued, the QEMU will send
 * the following messages:
 * 1. Enable queue 0.
 * 2. Enable queue 1.
 * 3. Disable queue 2.
 * 4. Disable queue 3.
 *
 * TODO: Remove the above assumption as there is no guarantee that QEMU will
 * always work as described.
 */
void
vr_dpdk_virtio_tx_queue_enable_disable(unsigned int vif_id,
                                       unsigned int vif_gen,
                                       unsigned int queue_id,
                                       bool enable)
{
    unsigned int lcore_id;
    unsigned int starting_lcore;
    struct dpdk_virtio_tx_queue_set_params *arg;
    unsigned int qid;
    unsigned int queue_num;

    /* If command is 'disable', we enable all lower numbered queues */
    if (!enable)
        queue_num = queue_id - 1;
    else
        queue_num = queue_id;

    /*
     * Subsequent 'disable' commands are ignored. For example if we enabled
     * queues 0 and 1, then all higher queues (2, 3, ..) had already been
     * disabled. Thus we ignore the 'disable' request for them
     */
    if (!enable && queue_num > vif_tx_queues_enabled[vif_id])
        return;

    /*
     * Each lcore that does tx has to have a queue assigned for every
     * interface. We assign queue 0 for pkt and netlink lcores. All
     * other queues (including queue 0) are distributed among forwarding
     * lcores.
     */
    if (queue_id == 0)
        starting_lcore = VR_DPDK_PACKET_LCORE_ID;
    else
        starting_lcore = VR_DPDK_FWD_LCORE_ID;

    for (lcore_id = starting_lcore, qid = 0; lcore_id < vr_dpdk.nb_fwd_lcores +
            VR_DPDK_FWD_LCORE_ID; ++lcore_id) {

        /*
         * Send cmd to destination lcore only if it has different queue enabled
         * curently.
         */
        if (vif_lcore_tx_queue[vif_id][lcore_id - VR_DPDK_PACKET_LCORE_ID] !=
                qid) {
            vif_lcore_tx_queue[vif_id][lcore_id - VR_DPDK_PACKET_LCORE_ID] =
                    qid;

            arg = rte_malloc("virtio_tx_queue_set", sizeof(*arg), 0);

            arg->vif_id = vif_id;
            arg->queue_id = qid;
            arg->vif_gen = vif_gen;

            vr_dpdk_lcore_cmd_post(lcore_id, VR_DPDK_LCORE_TX_QUEUE_SET_CMD,
                                   (uint64_t)arg);
        }

        ++qid;
        qid %= queue_num + 1;
    }

    /* Save current number of TX queues enabled for vif */
    vif_tx_queues_enabled[vif_id] = queue_num;
}

/*
 * Assign given virtio queue to vRouter's dpdk (per lcore) tx queue.
 *
 * The assignment is done by setting correct virtio queue pointer in the
 * lcore's tx queue handler.
 *
 * This function is called only from the main loops of the lcores that have TX
 * queues (packet lcore, netlink lcore, forwarding lcores).
 */
void
vr_dpdk_virtio_tx_queue_set(void *arg)
{
    struct dpdk_virtio_tx_queue_set_params *p = arg;
    struct vr_dpdk_queue *tx_queue;
    struct dpdk_virtio_writer *port;
    struct vr_dpdk_lcore *lcore;
    struct vr_interface *vif;

    /* Check if vif is still valid */
    vif = __vrouter_get_interface(vrouter_get(0), p->vif_id);
    if (!vif || vif->vif_gen != p->vif_gen) {
        rte_free(arg);
        return;
    }

    lcore = vr_dpdk.lcores[rte_lcore_id()];
    tx_queue = &lcore->lcore_tx_queues[p->vif_id][0];
    port = (struct dpdk_virtio_writer *)tx_queue->q_queue_h;

    /* Assign new queue to the lcore's tx_queue handler */
    port->tx_virtioq = &vr_dpdk_virtio_txqs[p->vif_id][p->queue_id];

    /*
     * Each tx_queue has to have a f_flush method, but we do not need to crash
     * in other case.
     */
    if (tx_queue->txq_ops.f_flush)
        tx_queue->txq_ops.f_flush(tx_queue->q_queue_h);
    else
        RTE_LOG(ERR, VROUTER, "%s: Flush function for tx_queue(%p) unavailable\n",
                __func__, tx_queue);

    rte_free(arg);
}

struct dpdk_virtio_rx_queue_set_params {
    bool enable;
    unsigned int vif_id;
    unsigned int vif_gen;
    unsigned int queue_id;
};


void
dpdk_lcore_queue_add(unsigned lcore_id, struct vr_dpdk_q_slist *q_head,
                     struct vr_dpdk_queue *queue);
void
dpdk_lcore_rx_queue_remove(struct vr_dpdk_lcore *lcore,
                           struct vr_dpdk_queue *rx_queue,
                           bool clear_f_rx);

/*
 * Called on uvhost lcore only.
 */
void
vr_dpdk_virtio_rx_queue_enable_disable(unsigned int vif_id,
                                       unsigned int vif_gen,
                                       unsigned int queue_id,
                                       bool enable)
{
    struct dpdk_virtio_rx_queue_set_params *arg;

    /*
     * Ignore requests for queue number 0. It has already been added to lcore's
     * list of queues and can never be disabled (qemu never sends the 'disable'
     * command for queue 0). Doing otherwise would result in double adding the
     * virtio queue to lcore's list of rx queues.
     */
    if (queue_id == 0)
        return;

    arg = rte_malloc("virtio_rx_queue_set", sizeof(*arg), 0);

    arg->vif_id = vif_id;
    arg->vif_gen = vif_gen;
    arg->queue_id = queue_id;
    arg->enable = enable;

    vr_dpdk_lcore_cmd_post(VR_DPDK_NETLINK_LCORE_ID,
                           VR_DPDK_LCORE_RX_QUEUE_SET_CMD, (uint64_t)arg);
}

/*
 * Called only on netlink lcore.
 */
void
vr_dpdk_virtio_rx_queue_set(void *arg)
{
    struct dpdk_virtio_rx_queue_set_params *p = arg;
    struct vr_interface *vif;
    struct vr_dpdk_queue *rx_queue;
    struct vr_dpdk_lcore *lcore;
    unsigned int lcore_id;
    struct vr_dpdk_lcore_rx_queue_remove_arg *rx_rm_arg;

    /* Check if vif is still valid */
    vif = __vrouter_get_interface(vrouter_get(0), p->vif_id);
    if (!vif || vif->vif_gen != p->vif_gen) {
        rte_free(arg);
        return;
    }

    if (p->enable) {
        lcore_id = vif_rx_queue_lcore[p->vif_id][p->queue_id];
        lcore = vr_dpdk.lcores[lcore_id];
        rx_queue = &lcore->lcore_rx_queues[p->vif_id];
        dpdk_lcore_queue_add(lcore_id, &lcore->lcore_rx_head, rx_queue);

    } else {
        lcore_id = vif_rx_queue_lcore[p->vif_id][p->queue_id];
        lcore = vr_dpdk.lcores[lcore_id];
        rx_queue = &lcore->lcore_rx_queues[p->vif_id];
        if (rx_queue->enabled) {
            rx_rm_arg = rte_malloc("lcore_rx_queue_rm_cmd", sizeof(*rx_rm_arg),
                    0);
            rx_rm_arg->vif_id = vif->vif_idx;
            rx_rm_arg->clear_f_rx = false;
            rx_rm_arg->free_arg = true;
            vr_dpdk_lcore_cmd_post(lcore_id, VR_DPDK_LCORE_RX_RM_CMD,
                                   (uint64_t)rx_rm_arg);
        }
    }

    rte_free(arg);
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

#ifdef RTE_PORT_STATS_COLLECT

#define DPDK_VIRTIO_READER_STATS_PKTS_IN_ADD(port, val) \
        port->stats.n_pkts_in += val
#define DPDK_VIRTIO_READER_STATS_PKTS_DROP_ADD(port, val) \
        port->stats.n_pkts_drop += val

#else

#define DPDK_VIRTIO_READER_STATS_PKTS_IN_ADD(port, val)
#define DPDK_VIRTIO_READER_STATS_PKTS_DROP_ADD(port, val)

#endif

static inline uint32_t
dpdk_virtio_get_ip_tcp_hdr_len(char *pkt_addr, uint32_t pkt_len)
{
    struct vr_eth *eth_hdr = (struct vr_eth*)pkt_addr;
    struct vr_ip6 *ipv6_hdr = NULL;
    struct vr_tcp *tcp_hdr = NULL;
    unsigned int pull_len = VR_ETHER_HLEN;
    unsigned short eth_proto;

    if (unlikely(pkt_len < pull_len))
        return 0;

    eth_proto = eth_hdr->eth_proto;

    /* Skip VLAN tag which may be present if VM sends tagged pkts */
    while (eth_proto == rte_cpu_to_be_16(VR_ETH_PROTO_VLAN)) {
        if (unlikely(pkt_len < pull_len + VR_VLAN_HLEN))
            return 0;
        eth_proto = ((struct vr_vlan_hdr *)((uintptr_t)eth_hdr + pull_len))->vlan_proto;
        pull_len += VR_VLAN_HLEN;
    }

    if (likely(eth_proto == rte_cpu_to_be_16(VR_ETH_PROTO_IP))) {
        struct vr_ip *ipv4_hdr = NULL;
        uint32_t ipv4_hlen;
        ipv4_hdr = (struct vr_ip *)((uintptr_t)eth_hdr + pull_len);

        if (unlikely(pkt_len < pull_len + sizeof(struct vr_ip)))
            return 0;

        ipv4_hlen = ((ipv4_hdr->ip_hl) * IPV4_IHL_MULTIPLIER);
        pull_len += ipv4_hlen;
        tcp_hdr = (struct vr_tcp*)((uint8_t*)ipv4_hdr + ipv4_hlen);
    } else if (eth_proto == rte_cpu_to_be_16(VR_ETH_PROTO_IP6)) {
        ipv6_hdr = (struct vr_ip6 *)((uintptr_t)eth_hdr + pull_len);

        if (unlikely(pkt_len < pull_len + sizeof(struct vr_ip6)))
            return 0;

        pull_len += sizeof(*ipv6_hdr);
        tcp_hdr = (struct vr_tcp*)((uint8_t*)ipv6_hdr + sizeof(*ipv6_hdr));
    }
    if (likely(tcp_hdr != NULL)) {
        pull_len +=  (VR_TCP_OFFSET(tcp_hdr->tcp_offset_r_flags) << 2);
    }

    return pull_len;
}

static inline char *dpdk_pktmbuf_append(struct rte_mbuf *m, struct rte_mbuf *last, uint16_t len)
{
    void *tail;
    struct rte_mbuf *m_last;

    __rte_mbuf_sanity_check(m, 1);
    __rte_mbuf_sanity_check(last, 1);

    m_last = rte_pktmbuf_lastseg(last);
    if (unlikely(len > rte_pktmbuf_tailroom(m_last)))
        return NULL;

    tail = (char *)m_last->buf_addr + m_last->data_off + m_last->data_len;
    m_last->data_len = (uint16_t)(m_last->data_len + len);
    m->pkt_len  = (m->pkt_len + len);
    return (char*) tail;
}

/*
 * dpdk_virtio_create_mss_sized_mbuf_chain - Create a chained mbuf where each segment
 * in the chain is of length 'mss' and copy the data pointed to by pkt_addr
 * 
 * @input -
 *    mbuf:       pointer to the mbuf where the chain needs to be created
 *    mss:        lenght of each segment in the chain
 *    pkt_addr:   pointer to the data which has to be copied to mbuf
 *    pkt_len:    length of the data which has to be copied
 *    header_len: first segment of the chain will have a length of mss + this value
 *                to account for the headers
 *
 * @output -
 *    0: success
 *   -1: failure
 */
static int
dpdk_virtio_create_mss_sized_mbuf_chain(struct rte_mbuf *mbuf,
        uint32_t mss, char* pkt_addr, uint32_t pkt_len, uint32_t header_len)
{
    char *tail_addr, *append_addr = pkt_addr;
    uint32_t pktlen_to_copy = pkt_len, copy_len;
    struct rte_mbuf *new_mbuf, *last_mbuf = rte_pktmbuf_lastseg(mbuf);

    /* header is only applicable for first segment */
    if (mbuf->nb_segs > 1)
        header_len = 0;

    while (pktlen_to_copy > 0) {
        copy_len = mss + header_len - last_mbuf->data_len;
        header_len = 0;
        if (pktlen_to_copy > copy_len) {
            tail_addr = dpdk_pktmbuf_append(mbuf, last_mbuf, copy_len);
            if (unlikely(tail_addr == NULL))
                return -1;
            rte_memcpy(tail_addr, append_addr, copy_len);
            pktlen_to_copy -= copy_len;
            append_addr += copy_len;
            new_mbuf = rte_pktmbuf_alloc(vr_dpdk.rss_mempool);
            if (unlikely(new_mbuf == NULL)) {
                RTE_LOG_DP(DEBUG, VROUTER, "%s: mbuf alloc failed\n",__func__);
                return -1;
            }
            last_mbuf->next = new_mbuf;
            last_mbuf = new_mbuf;
            mbuf->nb_segs += 1;
        } else {
            /* for last segment */
            tail_addr = dpdk_pktmbuf_append(mbuf, last_mbuf, pktlen_to_copy);
            if (unlikely(tail_addr == NULL))
                return -1;
            rte_memcpy(tail_addr, append_addr, pktlen_to_copy);
            pktlen_to_copy = 0;
        }
    }
    return 0;
}

/*
 * dpdk_virtio_create_chained_mbuf - Create a chained mbuf and copy the data pointed
 * to by pkt_addr of len pkt_len
 */
static int
dpdk_virtio_create_chained_mbuf(struct rte_mbuf *mbuf, char* pkt_addr, uint32_t pkt_len)
{
    char *tail_addr, *append_addr = pkt_addr;
    uint32_t append_len = pkt_len;
    struct rte_mbuf *new_mbuf;

    while((tail_addr = rte_pktmbuf_append(mbuf, append_len)) == NULL) {
        uint32_t pkt_tailroom = rte_pktmbuf_tailroom(rte_pktmbuf_lastseg(mbuf));
        tail_addr = rte_pktmbuf_append(mbuf, pkt_tailroom);
        if (unlikely(tail_addr == NULL))
            return -1;
        rte_memcpy(tail_addr, append_addr, pkt_tailroom);
        append_len -= pkt_tailroom;
        append_addr += pkt_tailroom;
        new_mbuf = rte_pktmbuf_alloc(vr_dpdk.rss_mempool);
        if (unlikely(new_mbuf == NULL)) {
            RTE_LOG_DP(DEBUG, VROUTER, "%s: mbuf alloc failed\n",__func__);
            return -1;
        }
        rte_pktmbuf_lastseg(mbuf)->next = new_mbuf;
        mbuf->nb_segs += 1;
    }
    rte_memcpy(tail_addr, append_addr, append_len);
    return 0;
}

/*
 * dpdk_virtio_from_vm_rx - receive packets from a virtio client so that
 * the packets can be handed to vrouter for forwarding. the virtio client is
 * usually a VM.
 *
 * Returns the number of packets received from the virtio.
 */
static int
dpdk_virtio_from_vm_rx(void *port, struct rte_mbuf **pkts, uint32_t max_pkts)
{
    struct dpdk_virtio_reader *p = (struct dpdk_virtio_reader *)port;
    vr_dpdk_virtioq_t *vq = p->rx_virtioq;
    uint16_t vq_hard_avail_idx, i;
    uint16_t avail_pkts, next_desc_idx, next_avail_idx;
    struct vring_desc *desc;
    char *pkt_addr, *tail_addr;
    struct rte_mbuf *mbuf;
    uint32_t pkt_len, nb_pkts = 0;
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

    /* Unsigned subtraction gives the right result even with wrap around. */
    avail_pkts = vq_hard_avail_idx - vq->vdv_last_used_idx;
    avail_pkts = RTE_MIN(avail_pkts, max_pkts);
    if (unlikely(avail_pkts == 0)) {
        DPDK_UDEBUG(VROUTER, &vq->vdv_hash, "%s: queue %p has no packets\n",
                    __func__, vq);
        return 0;
    }

    DPDK_UDEBUG(VROUTER, &vq->vdv_hash, "%s: queue %p AVAILABLE %u packets\n",
            __func__, vq, avail_pkts);
    for (i = 0; i < avail_pkts; i++) {
        uint32_t header_len = 0;
        /* Allocate a mbuf. */
        mbuf = rte_pktmbuf_alloc(vr_dpdk.rss_mempool);
        if (unlikely(mbuf == NULL)) {
            p->nb_nombufs++;
            DPDK_UDEBUG(VROUTER, &vq->vdv_hash, "%s: queue %p no_mbufs=%"PRIu64"\n",
                    __func__, vq, p->nb_nombufs);
            break;
        }

        next_avail_idx = (vq->vdv_last_used_idx + i) & (vq->vdv_size - 1);
        next_desc_idx = vq->vdv_avail->ring[next_avail_idx];
        /*
         * Move the (chain of) descriptors to the vdv_used list. The used
         * index will, however, only be updated at the end of the loop.
         */
        vq->vdv_used->ring[next_avail_idx].id = next_desc_idx;
        vq->vdv_used->ring[next_avail_idx].len = 0;

        desc = &vq->vdv_desc[next_desc_idx];
        pkt_len = desc->len;
        pkt_addr = vr_dpdk_guest_phys_to_host_virt(vru_cl, desc->addr);
        /* Check the descriptor is sane. */
        if (unlikely(desc->len < vq->vdv_hlen ||
                desc->addr == 0 || pkt_addr == NULL)) {
            goto free_mbuf;
        }
        mbuf->tso_segsz = 0;
        /* Now pkt_addr points to the virtio_net_hdr. */
        if (((struct virtio_net_hdr *)pkt_addr)->flags & VIRTIO_NET_HDR_F_NEEDS_CSUM)
                mbuf->ol_flags |= PKT_RX_IP_CKSUM_BAD;
        if (((struct virtio_net_hdr *)pkt_addr)->gso_type == VIRTIO_NET_HDR_GSO_TCPV4) {
                mbuf->ol_flags |= PKT_RX_GSO_TCP4;
                mbuf->tso_segsz = ((struct virtio_net_hdr *)pkt_addr)->gso_size;
        } else if (((struct virtio_net_hdr *)pkt_addr)->gso_type == VIRTIO_NET_HDR_GSO_TCPV6) {
                mbuf->ol_flags |= PKT_RX_GSO_TCP6;
                mbuf->tso_segsz = ((struct virtio_net_hdr *)pkt_addr)->gso_size;
        }

        /* Skip virtio_net_hdr  */
        if (likely(desc->flags & VRING_DESC_F_NEXT &&
                pkt_len == vq->vdv_hlen)) {
            DPDK_UDEBUG(VROUTER, &vq->vdv_hash, "%s: queue %p pkt %u F_NEXT\n",
                __func__, vq, i);
            desc = &vq->vdv_desc[desc->next];
            pkt_len = desc->len;
            pkt_addr = vr_dpdk_guest_phys_to_host_virt(vru_cl, desc->addr);
        } else {
            DPDK_UDEBUG(VROUTER, &vq->vdv_hash, "%s: queue %p pkt %u no F_NEXT\n",
                __func__, vq, i);
            pkt_addr += vq->vdv_hlen;
            pkt_len -= vq->vdv_hlen;
        }
        /* Now pkt_addr points to the packet data. */
        if (mbuf->tso_segsz == 0) {
            tail_addr = rte_pktmbuf_append(mbuf, pkt_len);
            /* Check we ready to copy the data. */
            if (unlikely(desc->addr == 0 || pkt_addr == NULL)) {
                goto free_mbuf;
            } else if (unlikely(tail_addr == NULL)) {
                /* If insufficient tailroom, create a chained mbuf and copy the data */
                if (unlikely(dpdk_virtio_create_chained_mbuf(mbuf, pkt_addr, pkt_len) < 0)) {
                    goto free_mbuf;
                }
            } else {
                /* No chaining - Just Copy first descriptor data. */
                rte_memcpy(tail_addr, pkt_addr, pkt_len);
            }
        } else {
            header_len = dpdk_virtio_get_ip_tcp_hdr_len(pkt_addr, pkt_len);
            if (unlikely(dpdk_virtio_create_mss_sized_mbuf_chain(mbuf,
                            mbuf->tso_segsz, pkt_addr, pkt_len, header_len) < 0)) {
                goto free_mbuf;
            }
        }

        /*
         * Gather mbuf from several virtio buffers.
         */
        while (unlikely(desc->flags & VRING_DESC_F_NEXT)) {
            desc = &vq->vdv_desc[desc->next];
            pkt_len = desc->len;
            pkt_addr = vr_dpdk_guest_phys_to_host_virt(vru_cl, desc->addr);
            if (mbuf->tso_segsz == 0) {
                tail_addr = rte_pktmbuf_append(mbuf, pkt_len);
                /* Check we ready to copy the data. */
                if (unlikely(desc->addr == 0 || pkt_addr == NULL)) {
                    goto free_mbuf;
                } else if (unlikely(tail_addr == NULL)) {
                    /* If insufficient tailroom, create a chained mbuf and copy the data */
                    if (unlikely(dpdk_virtio_create_chained_mbuf(mbuf, pkt_addr, pkt_len) < 0)) {
                        goto free_mbuf;
                    }
                } else {
                    /* No chaining - Just append next descriptor(s) data. */
                    rte_memcpy(tail_addr, pkt_addr, pkt_len);
                }
            } else {
                if (unlikely(dpdk_virtio_create_mss_sized_mbuf_chain(mbuf,
                                mbuf->tso_segsz, pkt_addr, pkt_len, header_len) < 0)) {
                    goto free_mbuf;
                }

            }
        }

        pkts[nb_pkts] = mbuf;
        nb_pkts++;
        continue;

    free_mbuf:
        DPDK_UDEBUG(VROUTER, &vq->vdv_hash, "%s: queue %p DROP desc->addr %p "
            "pkt_addr %p tail_addr %p len %d\n",
            __func__, vq, desc->addr, pkt_addr, tail_addr, pkt_len);
        DPDK_VIRTIO_READER_STATS_PKTS_DROP_ADD(p, 1);
        rte_pktmbuf_free(mbuf);
    }

    /*
     * Do not call the guest if there are no descriptors processed.
     *
     * If there are no free mbufs on host, the TX queue in guest gets
     * filled up. This makes the guest kernel to switch to interrupt mode
     * and clear the VRING_AVAIL_F_NO_INTERRUPT flag.
     *
     * Meanwhile the host polls the virtio queue, sees the available
     * descriptors and interrupts the guest. Those interrupts get unhandled by
     * the guest virtio driver, so after 100K of the interrupts the IRQ get
     * reported and disabled by the guest kernel.
     */
    if (likely(i > 0)) {
        vq->vdv_last_used_idx += i;
        rte_wmb();
        vq->vdv_used->idx += i;
        RTE_LOG_DP(DEBUG, VROUTER,
                "%s: vif %d vq %p vdv_last_used_idx %d vdv_used->idx %u vdv_avail->idx %u\n",
                __func__, vq->vdv_vif_idx, vq, vq->vdv_last_used_idx,
                vq->vdv_used->idx, vq->vdv_avail->idx);

        /* Call guest if required. */
        if (unlikely(!(vq->vdv_avail->flags & VRING_AVAIL_F_NO_INTERRUPT))) {
            p->nb_syscalls++;
            eventfd_write(vq->vdv_callfd, 1);
        }
    }

    DPDK_UDEBUG(VROUTER, &vq->vdv_hash, "%s: queue %p RETURNS %u pkts\n",
            __func__, vq, nb_pkts);

    DPDK_VIRTIO_READER_STATS_PKTS_IN_ADD(p, nb_pkts);

    return nb_pkts;
}

#ifdef RTE_PORT_STATS_COLLECT

#define DPDK_VIRTIO_WRITER_STATS_PKTS_IN_ADD(port, val) \
        port->stats.n_pkts_in += val
#define DPDK_VIRTIO_WRITER_STATS_PKTS_DROP_ADD(port, val) \
        port->stats.n_pkts_drop += val

#else

#define DPDK_VIRTIO_WRITER_STATS_PKTS_IN_ADD(port, val)
#define DPDK_VIRTIO_WRITER_STATS_PKTS_DROP_ADD(port, val)

#endif

static inline int32_t __attribute__((always_inline))
dpdk_virtio_dev_to_vm_tx_burst_simple(struct dpdk_virtio_writer *p, 
        vr_dpdk_virtioq_t *vq, uint16_t res_base_idx, uint16_t res_end_idx, 
        struct rte_mbuf **pkts, uint32_t count, uint8_t mrg_hdr)
{
    struct vring_desc *desc;
    struct rte_mbuf *buff;
    /* The virtio_hdr is initialised to 0. */
    struct virtio_net_hdr_mrg_rxbuf virtio_hdr = {{0, 0, 0, 0, 0, 0}, 1};
    uint64_t buff_addr = 0;
    uint64_t buff_hdr_addr = 0;
    uint32_t head[VR_DPDK_VIRTIO_TX_BURST_SZ];
    uint32_t head_idx, packet_success = 0;
    uint16_t res_cur_idx;
    uint8_t virtio_hdr_len;
    vr_uvh_client_t *vru_cl;

    vru_cl = vr_dpdk_virtio_get_vif_client(vq->vdv_vif_idx);
    if (unlikely(vru_cl == NULL))
        return 0;

    res_cur_idx = res_base_idx;
    RTE_LOG_DP(DEBUG, VROUTER, "%s: Current Index %d| End Index %d\n",
            __func__, res_cur_idx, res_end_idx);

    /* Prefetch available ring to retrieve indexes. */
    rte_prefetch0(&vq->vdv_avail->ring[res_cur_idx & (vq->vdv_size - 1)]);

    /* Retrieve all of the head indexes first to avoid caching issues. */
    for (head_idx = 0; head_idx < count; head_idx++)
        head[head_idx] = vq->vdv_avail->ring[(res_cur_idx + head_idx) &
                    (vq->vdv_size - 1)];

    virtio_hdr_len = (mrg_hdr)? sizeof(struct virtio_net_hdr_mrg_rxbuf):
                                sizeof(struct virtio_net_hdr);

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
            && !mrg_hdr && (desc->len == sizeof(struct virtio_net_hdr))) {
            /*
             * TODO: verify that desc->next is sane below.
             */
            desc = &vq->vdv_desc[desc->next];
            /* Buffer address translation. */
            buff_addr = (uintptr_t)vr_dpdk_guest_phys_to_host_virt(vru_cl, desc->addr);
        } else {
            vb_offset += virtio_hdr_len;
            hdr = 1;
        }

        pkt_len = rte_pktmbuf_pkt_len(buff);
        data_len = rte_pktmbuf_data_len(buff);
        len_to_cpy = RTE_MIN(data_len,
            hdr ? desc->len - virtio_hdr_len : desc->len);
        while (total_copied < pkt_len) {
            /* Copy mbuf data to buffer */
            rte_memcpy((void *)(uintptr_t)(buff_addr + vb_offset),
                rte_pktmbuf_mtod_offset(buff, const void *, offset),
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
                           virtio_hdr_len; 
        else
            vq->vdv_used->ring[res_cur_idx & (vq->vdv_size - 1)].len =
                            pkt_len + virtio_hdr_len; 

        res_cur_idx++;
        packet_success++;

        /* TODO: in DPDK 2.1 we do not copy the header
        if (unlikely(uncompleted_pkt == 1))
            continue;
        */
        rte_memcpy((void *)(uintptr_t)buff_hdr_addr,
            (const void *)&virtio_hdr, virtio_hdr_len);

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
    RTE_LOG_DP(DEBUG, VROUTER, "%s: vif %d vq %p last_used_idx %d used->idx %d\n",
            __func__, vq->vdv_vif_idx, vq, vq->vdv_last_used_idx, vq->vdv_used->idx);

    /* flush used->idx update before we read avail->flags. */
    rte_mb();

    /* Kick the guest if necessary. */
    if (unlikely(!(vq->vdv_avail->flags & VRING_AVAIL_F_NO_INTERRUPT))) {
        p->nb_syscalls++;
        eventfd_write(vq->vdv_callfd, 1);
    }
    return count;
}

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
    uint16_t res_base_idx, res_end_idx, avail_idx, free_entries;
    uint8_t success = 0;

    if (unlikely(vq->vdv_ready_state == VQ_NOT_READY))
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

    return dpdk_virtio_dev_to_vm_tx_burst_simple(p, vq,
                   res_base_idx, res_end_idx,
                   pkts, count, !VIRTIO_HDR_MRG_RXBUF);
}

static inline uint32_t __attribute__((always_inline))
copy_from_mbuf_to_vring(vr_dpdk_virtioq_t *vq, vr_uvh_client_t *vru_cl, uint16_t res_base_idx,
    uint16_t res_end_idx, struct vq_buf_vector *buf_vec,
    struct virtio_net_hdr_mrg_rxbuf* virtio_hdr,
    struct rte_mbuf *pkt)
{
    uint32_t vec_idx = 0;
    uint32_t entry_success = 0;
    uint16_t cur_idx = res_base_idx;
    uint64_t vb_addr = 0;
    uint64_t vb_hdr_addr = 0;
    uint32_t seg_offset = 0;
    uint32_t vb_offset = 0;
    uint32_t seg_avail;
    uint32_t vb_avail;
    uint32_t cpy_len, entry_len;

    if (pkt == NULL)
        return 0;

    RTE_LOG_DP(DEBUG, VROUTER, "%s: Current Index %d| "
        "End Index %d\n",
        __func__, cur_idx, res_end_idx);

    /*
     * Convert from gpa to vva
     * (guest physical addr -> vhost virtual addr)
     */
    vb_addr = (uintptr_t)vr_dpdk_guest_phys_to_host_virt(vru_cl,
                                                        buf_vec[vec_idx].buf_addr);
    vb_hdr_addr = vb_addr;

    /* Prefetch buffer address. */
    rte_prefetch0((void *)(uintptr_t)vb_addr);

    RTE_LOG_DP(DEBUG, VROUTER, "%s RX: Num merge buffers %d\n",
        __func__, virtio_hdr->num_buffers);

    rte_memcpy((void *)(uintptr_t)vb_hdr_addr,
        (const void *)virtio_hdr, vq->vdv_hlen);

    seg_avail = rte_pktmbuf_data_len(pkt);
    vb_offset = vq->vdv_hlen;
    vb_avail = buf_vec[vec_idx].buf_len - vq->vdv_hlen;

    entry_len = vq->vdv_hlen;

    if (vb_avail == 0) {
        uint32_t desc_idx =
            buf_vec[vec_idx].desc_idx;

        if ((vq->vdv_desc[desc_idx].flags
            & VRING_DESC_F_NEXT) == 0) {
            /* Update vdv_used ring with vdv_desc information */
            vq->vdv_used->ring[cur_idx & (vq->vdv_size - 1)].id
                = buf_vec[vec_idx].desc_idx;
            vq->vdv_used->ring[cur_idx & (vq->vdv_size - 1)].len
                = entry_len;

            entry_len = 0;
            cur_idx++;
            entry_success++;
        }

        vec_idx++;
        vb_addr = (uintptr_t)vr_dpdk_guest_phys_to_host_virt(vru_cl,
                                                          buf_vec[vec_idx].buf_addr);

        /* Prefetch buffer address. */
        rte_prefetch0((void *)(uintptr_t)vb_addr);
        vb_offset = 0;
        vb_avail = buf_vec[vec_idx].buf_len;
    }

    cpy_len = RTE_MIN(vb_avail, seg_avail);

    while (cpy_len > 0) {
        /* Copy mbuf data to vring buffer */
        rte_memcpy((void *)(uintptr_t)(vb_addr + vb_offset),
            rte_pktmbuf_mtod_offset(pkt, const void *, seg_offset),
            cpy_len);

        seg_offset += cpy_len;
        vb_offset += cpy_len;
        seg_avail -= cpy_len;
        vb_avail -= cpy_len;
        entry_len += cpy_len;

        if (seg_avail != 0) {
            /*
             * The virtio buffer in this vring
             * entry reach to its end.
             * But the segment doesn't complete.
             */
            if ((vq->vdv_desc[buf_vec[vec_idx].desc_idx].flags &
                VRING_DESC_F_NEXT) == 0) {
                /* Update vdv_used ring with vdv_desc information */
                vq->vdv_used->ring[cur_idx & (vq->vdv_size - 1)].id
                    = buf_vec[vec_idx].desc_idx;
                vq->vdv_used->ring[cur_idx & (vq->vdv_size - 1)].len
                    = entry_len;
                entry_len = 0;
                cur_idx++;
                entry_success++;
            }

            vec_idx++;
            vb_addr = (uintptr_t)vr_dpdk_guest_phys_to_host_virt(vru_cl,
                                                        buf_vec[vec_idx].buf_addr);
            vb_offset = 0;
            vb_avail = buf_vec[vec_idx].buf_len;
            cpy_len = RTE_MIN(vb_avail, seg_avail);
        } else {
            /*
             * This current segment complete, need continue to
             * check if the whole packet complete or not.
             */
            pkt = pkt->next;
            if (pkt != NULL) {
                /*
                 * There are more segments.
                 */
                if (vb_avail == 0) {
                    /*
                     * This current buffer from vring is
                     * vdv_used up, need fetch next buffer
                     * from buf_vec.
                     */
                    uint32_t desc_idx =
                        buf_vec[vec_idx].desc_idx;

                    if ((vq->vdv_desc[desc_idx].flags &
                        VRING_DESC_F_NEXT) == 0) {
                        uint16_t wrapped_idx =
                            cur_idx & (vq->vdv_size - 1);
                        /*
                         * Update vdv_used ring with the
                         * descriptor information
                         */
                        vq->vdv_used->ring[wrapped_idx].id
                            = desc_idx;
                        vq->vdv_used->ring[wrapped_idx].len
                            = entry_len;
                        entry_success++;
                        entry_len = 0;
                        cur_idx++;
                    }

                    /* Get next buffer from buf_vec. */
                    vec_idx++;
                    vb_addr = (uintptr_t)vr_dpdk_guest_phys_to_host_virt(vru_cl,
                                                    buf_vec[vec_idx].buf_addr);
                    vb_avail =
                        buf_vec[vec_idx].buf_len;
                    vb_offset = 0;
                }

                seg_offset = 0;
                seg_avail = rte_pktmbuf_data_len(pkt);
                cpy_len = RTE_MIN(vb_avail, seg_avail);
            } else {
                /*
                 * This whole packet completes.
                 */
                /* Update vdv_used ring with vdv_desc information */
                vq->vdv_used->ring[cur_idx & (vq->vdv_size - 1)].id
                    = buf_vec[vec_idx].desc_idx;
                vq->vdv_used->ring[cur_idx & (vq->vdv_size - 1)].len
                    = entry_len;
                entry_success++;
                break;
            }
        }
    }

    return entry_success;
}

static inline void __attribute__((always_inline))
update_secure_len(vr_dpdk_virtioq_t *vq, uint32_t id,
    uint32_t *secure_len, struct vq_buf_vector *buf_vec, uint32_t *vec_idx)
{
    uint16_t wrapped_idx = id & (vq->vdv_size - 1);
    uint32_t idx = vq->vdv_avail->ring[wrapped_idx];
    uint8_t next_desc;
    uint32_t len = *secure_len;
    uint32_t vec_id = *vec_idx;

    do {
        next_desc = 0;
        len += vq->vdv_desc[idx].len;
        buf_vec[vec_id].buf_addr = vq->vdv_desc[idx].addr;
        buf_vec[vec_id].buf_len = vq->vdv_desc[idx].len;
        buf_vec[vec_id].desc_idx = idx;
        vec_id++;

        if (vq->vdv_desc[idx].flags & VRING_DESC_F_NEXT) {
            idx = vq->vdv_desc[idx].next;
            next_desc = 1;
        }
    } while (next_desc);

    *secure_len = len;
    *vec_idx = vec_id;
}

static inline uint32_t __attribute__((always_inline))
dpdk_virtio_dev_to_vm_tx_burst_mergeable(struct dpdk_virtio_writer *p,
        vr_dpdk_virtioq_t *vq, struct rte_mbuf **pkts, uint32_t count)
{
    uint32_t pkt_idx = 0, start_idx = 0, entry_success = 0, simple_count;
    uint16_t avail_idx;
    uint16_t res_base_idx, res_cur_idx;
    uint8_t success = 0;
    vr_uvh_client_t *vru_cl;
    struct vq_buf_vector buf_vec[VR_BUF_VECTOR_MAX];

    if (unlikely(vq->vdv_ready_state == VQ_NOT_READY))
        return 0;

    vru_cl = vr_dpdk_virtio_get_vif_client(vq->vdv_vif_idx);
    if (unlikely(vru_cl == NULL))
        return 0;

    count = RTE_MIN((uint32_t)VR_DPDK_VIRTIO_TX_BURST_SZ, count);

    if (count == 0)
        return 0;

    /* Check if we can call -
     * dpdk_virtio_dev_to_vm_tx_burst_simple() for some/all pkts
     */
    do {
        res_base_idx = vq->vdv_last_used_idx_res;
        res_cur_idx = res_base_idx;
        avail_idx = *((volatile uint16_t *)&vq->vdv_avail->idx);
        for (pkt_idx = 0; pkt_idx < count; pkt_idx++) {
            uint32_t pkt_len = pkts[pkt_idx]->pkt_len + vq->vdv_hlen;
            if (unlikely(res_cur_idx == avail_idx)) {
                RTE_LOG_DP(DEBUG, VROUTER,
                    "Failed "
                    "to get enough vdv_desc from "
                    "vring\n");
                count = pkt_idx;
                break;
            } else {
                uint8_t next_desc;
                uint16_t wrapped_idx = res_cur_idx & (vq->vdv_size - 1);
                uint32_t len = 0, idx = vq->vdv_avail->ring[wrapped_idx];
                do {
                    next_desc = 0;
                    len += vq->vdv_desc[idx].len;
                    if (vq->vdv_desc[idx].flags & VRING_DESC_F_NEXT) {
                        idx = vq->vdv_desc[idx].next;
                        next_desc = 1;
                    }
                    if (len > pkt_len)
                        break;
                }while (next_desc);
                if (len < pkt_len)
                    break;
                res_cur_idx++;
            }
        }

        /* If there are no packets to pass to
         * dpdk_virtio_dev_to_vm_tx_burst_simple() function, break 
         */
        if (pkt_idx == 0)
            break;

        success = rte_atomic16_cmpset(&vq->vdv_last_used_idx_res,
                res_base_idx, res_cur_idx);
    } while (unlikely(success == 0));

    if (pkt_idx) {
        simple_count = dpdk_virtio_dev_to_vm_tx_burst_simple(p, vq,
                                    res_base_idx, res_cur_idx,
                                    pkts, pkt_idx, VIRTIO_HDR_MRG_RXBUF);
        if (simple_count < pkt_idx)
            return simple_count;
    }

    start_idx = pkt_idx;
    for (pkt_idx = start_idx; pkt_idx < count; pkt_idx++) {
        struct virtio_net_hdr_mrg_rxbuf virtio_hdr = {
            {0, 0, 0, 0, 0, 0}, 0};
        uint32_t pkt_len = pkts[pkt_idx]->pkt_len + vq->vdv_hlen;

        do {
            /*
             * As many data cores may want access to available
             * buffers, they need to be reserved.
             */
            uint32_t secure_len = 0;
            uint32_t vec_idx = 0;

            res_base_idx = vq->vdv_last_used_idx_res;
            res_cur_idx = res_base_idx;

            do {
                avail_idx = *((volatile uint16_t *)&vq->vdv_avail->idx);
                if (unlikely(res_cur_idx == avail_idx)) {
                    RTE_LOG_DP(DEBUG, VROUTER,
                        "Failed "
                        "to get enough vdv_desc from "
                        "vring\n");
                    return pkt_idx;
                } else {
                    update_secure_len(vq, res_cur_idx, &secure_len, buf_vec, &vec_idx);
                    res_cur_idx++;
                }
            } while (pkt_len > secure_len);

            /* vq->vdv_last_used_idx_res is atomically updated. */
            success = rte_atomic16_cmpset(&vq->vdv_last_used_idx_res,
                            res_base_idx,
                            res_cur_idx);
        } while (success == 0);

        /* Fill the virtio hdr */
        virtio_hdr.num_buffers = res_cur_idx - res_base_idx;
        if (pkts[pkt_idx]->ol_flags & PKT_RX_GSO_TCP4) {
            virtio_hdr.hdr.gso_type = VIRTIO_NET_HDR_GSO_TCPV4;
            virtio_hdr.hdr.gso_size = pkts[pkt_idx]->tso_segsz;
        } else if (pkts[pkt_idx]->ol_flags & PKT_RX_GSO_TCP6) {
            virtio_hdr.hdr.gso_type = VIRTIO_NET_HDR_GSO_TCPV6;
            virtio_hdr.hdr.gso_size = pkts[pkt_idx]->tso_segsz;
        }

        entry_success = copy_from_mbuf_to_vring(vq, vru_cl, res_base_idx,
            res_cur_idx, buf_vec, &virtio_hdr, pkts[pkt_idx]);

        rte_compiler_barrier();

        /*
         * Wait until it's our turn to add our buffer
         * to the vdv_used ring.
         */
        while (unlikely(vq->vdv_last_used_idx != res_base_idx))
            rte_pause();

        *(volatile uint16_t *)&vq->vdv_used->idx += entry_success;
        vq->vdv_last_used_idx = res_cur_idx;

        /* flush vdv_used->idx update before we read vdv_avail->flags. */
        rte_mb();

        /* Kick the guest if necessary. */
        if (unlikely(!(vq->vdv_avail->flags & VRING_AVAIL_F_NO_INTERRUPT))) {
            p->nb_syscalls++;
            eventfd_write(vq->vdv_callfd, 1);
        }
    }

    return count;
}

void
vr_dpdk_set_vhost_send_func(unsigned int vif_idx, uint32_t mrg)
{
    int i;
    vr_dpdk_virtioq_t *vq;

    if (vif_idx >= VR_MAX_INTERFACES) {
        return;
    }

    for (i = 0; i < VR_DPDK_VIRTIO_MAX_QUEUES*2; i++) {
        if (i & 1) {
            vq = &vr_dpdk_virtio_rxqs[vif_idx][i/2];
        } else {
            vq = &vr_dpdk_virtio_txqs[vif_idx][i/2];
        }

        if (mrg) {
            vq->vdv_send_func = dpdk_virtio_dev_to_vm_tx_burst_mergeable;
            vq->vdv_hlen = sizeof(struct virtio_net_hdr_mrg_rxbuf);
        } else {
            vq->vdv_send_func = dpdk_virtio_dev_to_vm_tx_burst;
            vq->vdv_hlen = sizeof(struct virtio_net_hdr);
        }
    }
}

static inline void
dpdk_virtio_send_burst(struct dpdk_virtio_writer *p)
{
    uint32_t nb_tx = 0;
    int i;

    if (likely(p->tx_buf_count)) {
        /*
         * prefetch the tx buffer to be sent
         * This will avoid large cpu cycles in the
         * dpdk_virtio_dev_to_vm_tx_burst_mergeable()
         */
        for (i=0;i<p->tx_buf_count;i++)
            rte_prefetch0((void *)p->tx_buf[i]);
        if (likely(p->tx_virtioq->vdv_send_func != NULL)) {
            nb_tx = p->tx_virtioq->vdv_send_func(p, p->tx_virtioq,
                            p->tx_buf, p->tx_buf_count);
        }

        DPDK_VIRTIO_WRITER_STATS_PKTS_DROP_ADD(p, p->tx_buf_count - nb_tx);
        /* dpdk_virtio_dev_to_vm_tx_burst() does not free any mbufs */
        while (likely(p->tx_buf_count)) {
            p->tx_buf_count--;
            p->tx_mbufs -= p->tx_buf[p->tx_buf_count]->nb_segs;
            rte_pktmbuf_free(p->tx_buf[p->tx_buf_count]);
        }
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
    const unsigned lcore_id = rte_lcore_id();
    struct vr_dpdk_lcore *lcore = NULL;

    if (lcore_id >= VR_DPDK_FWD_LCORE_ID) {
        lcore = vr_dpdk.lcores[lcore_id];
        p->last_pkt_tx = lcore->lcore_fwd_loops;
    }

    p->tx_buf[p->tx_buf_count++] = pkt;
    p->tx_mbufs += pkt->nb_segs;
    DPDK_VIRTIO_WRITER_STATS_PKTS_IN_ADD(p, 1);

    if (unlikely(p->tx_mbufs >= VR_DPDK_VIRTIO_TX_BURST_SZ)) {
        dpdk_virtio_send_burst(p);
        if (lcore) {
            p->last_pkt_tx_flush = lcore->lcore_fwd_loops;
        }
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
dpdk_virtio_to_vm_flush(void *port)
{
    struct dpdk_virtio_writer *p = (struct dpdk_virtio_writer *)port;
    unsigned lcore_id;
    struct vr_dpdk_lcore *lcore = NULL;

    if (p->tx_buf_count == 0) {
        return 0;
    }

    lcore_id = rte_lcore_id();
    if (lcore_id >= VR_DPDK_FWD_LCORE_ID) {
        lcore = vr_dpdk.lcores[lcore_id];
    }

    if (lcore) {
        /*
         * Flush the TX queue if it has been a while since it was last done OR
         * if there are packets in the queue and no packets have been enqueued
         * for a short while. The latter condition helps to reduce latency in
         * case there isn't a lot of traffic on the queue.
         */
        if ((lcore->lcore_fwd_loops - p->last_pkt_tx_flush) <
                    VR_DPDK_TX_FLUSH_LOOPS) {
            if ((lcore->lcore_fwd_loops - p->last_pkt_tx) <
                    VR_DPDK_TX_IDLE_LOOPS) {
                return 0;
            }
        }
    }

    dpdk_virtio_send_burst(p);
    if (lcore) {
        p->last_pkt_tx_flush = lcore->lcore_fwd_loops;
    }

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

    /* Reset the queue. We reset only those values we analyze in
     * uvhm_check_vring_ready()
     */
    vq->vdv_desc = NULL;
    if (vq->vdv_callfd) {
        close(vq->vdv_callfd);
        vq->vdv_callfd = 0;
    }

    return 0;
}

/*
 * vr_dpdk_virtio_recover_vring_base - recovers the vring base from the shared
 * memory after vRouter crash.
 *
 * Returns 0 on success, -1 otherwise.
 */
int
vr_dpdk_virtio_recover_vring_base(unsigned int vif_idx, unsigned int vring_idx)
{
    vr_dpdk_virtioq_t *vq;

    if ((vif_idx >= VR_MAX_INTERFACES)
        || (vring_idx >= (2 * VR_DPDK_VIRTIO_MAX_QUEUES))) {
        return -1;
    }

    if (vring_idx & 1) {
        vq = &vr_dpdk_virtio_rxqs[vif_idx][vring_idx/2];
    } else {
        vq = &vr_dpdk_virtio_txqs[vif_idx][vring_idx/2];
    }

    if (vq->vdv_used) {
        /* Reading base index from the shared memory. */
        if (vq->vdv_last_used_idx != vq->vdv_used->idx) {
            RTE_LOG(INFO, UVHOST, "    recovering vring base %d -> %d\n",
                    vq->vdv_last_used_idx, vq->vdv_used->idx);
            vr_dpdk_virtio_set_vring_base(vif_idx, vring_idx, vq->vdv_used->idx);
        }
    }

    return 0;
}

/*
 * vr_dpdk_set_vring_addr - Sets the address of the virtio descriptor and
 * available/used rings based on messages sent by the vhost client.
 *
 * Returns 0 on success, -1 otherwise.
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

    if (vq->vdv_hlen == 0) {
        struct vr_interface *vif;
        vif = __vrouter_get_interface(vrouter_get(0), vq->vdv_vif_idx);
        if (vif && (vif->vif_flags & VIF_FLAG_MRG_RXBUF)) {
            vq->vdv_send_func = dpdk_virtio_dev_to_vm_tx_burst_mergeable;
            vq->vdv_hlen = sizeof(struct virtio_net_hdr_mrg_rxbuf);
        } else {
            vq->vdv_send_func = dpdk_virtio_dev_to_vm_tx_burst;
            vq->vdv_hlen = sizeof(struct virtio_net_hdr);
        }
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
