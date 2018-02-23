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
 * vr_dpdk_knidev.c -- DPDK KNI device
 *
 */

#include "vr_dpdk.h"
#include "vr_packet.h"

#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_kni.h>
#include <rte_malloc.h>

#if (RTE_VERSION >= RTE_VERSION_NUM(17, 2, 0, 0))
#define VROUTER_KNI_ADDR_CHECK 1
#define vr_elt_va_start 0
#define vr_elt_va_end 1
#define vr_elt_va_status 2
#endif

/*
 * KNI Reader
 */
#ifdef RTE_PORT_STATS_COLLECT

#define DPDK_KNIDEV_READER_STATS_PKTS_IN_ADD(port, val) \
    port->stats.n_pkts_in += val
#define DPDK_KNIDEV_READER_STATS_PKTS_DROP_ADD(port, val) \
    port->stats.n_pkts_drop += val

#else

#define DPDK_KNIDEV_READER_STATS_PKTS_IN_ADD(port, val)
#define DPDK_KNIDEV_READER_STATS_PKTS_DROP_ADD(port, val)

#endif

struct dpdk_knidev_reader {
    struct rte_port_in_stats stats;

    struct rte_kni *kni;
};

struct dpdk_knidev_reader_params {
    /* Pointer to preallocated KNI */
    struct rte_kni *kni;
};

static void *
dpdk_knidev_reader_create(void *params, int socket_id)
{
    struct dpdk_knidev_reader_params *conf =
            (struct dpdk_knidev_reader_params *) params;
    struct dpdk_knidev_reader *port;

    /* Check input parameters */
    if (conf == NULL) {
        RTE_LOG(ERR, PORT, "%s: params is NULL\n", __func__);
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
    port->kni = conf->kni;

    return port;
}

static int
dpdk_knidev_reader_rx(void *port, struct rte_mbuf **pkts, uint32_t n_pkts)
{
    struct dpdk_knidev_reader *p =
        (struct dpdk_knidev_reader *) port;
    uint32_t nb_rx;

    nb_rx = rte_kni_rx_burst(p->kni, pkts, n_pkts);
    DPDK_KNIDEV_READER_STATS_PKTS_IN_ADD(p, nb_rx);

    return nb_rx;
}

static int
dpdk_knidev_reader_free(void *port)
{
    if (port == NULL) {
        RTE_LOG(ERR, PORT, "%s: port is NULL\n", __func__);
        return -EINVAL;
    }

    rte_free(port);

    return 0;
}

static int
dpdk_knidev_reader_stats_read(void *port,
    struct rte_port_in_stats *stats, int clear)
{
    struct dpdk_knidev_reader *p =
        (struct dpdk_knidev_reader *) port;

    if (stats != NULL)
        memcpy(stats, &p->stats, sizeof(p->stats));

    if (clear)
        memset(&p->stats, 0, sizeof(p->stats));

    return 0;
}

/*
 * KNI Writer
 */
#ifdef RTE_PORT_STATS_COLLECT

#define DPDK_KNIDEV_WRITER_STATS_PKTS_IN_ADD(port, val) \
    port->stats.n_pkts_in += val
#define DPDK_KNIDEV_WRITER_STATS_PKTS_DROP_ADD(port, val) \
    port->stats.n_pkts_drop += val

#else

#define DPDK_KNIDEV_WRITER_STATS_PKTS_IN_ADD(port, val)
#define DPDK_KNIDEV_WRITER_STATS_PKTS_DROP_ADD(port, val)

#endif

struct dpdk_knidev_writer {
    struct rte_port_out_stats stats;

    struct rte_mbuf *tx_buf[2 * VR_DPDK_TX_BURST_SZ];
    uint32_t tx_burst_sz;
    uint16_t tx_buf_count;
    uint64_t bsz_mask;
    struct rte_kni *kni;
};

struct dpdk_knidev_writer_params {
    /* Pointer to preallocated KNI */
    struct rte_kni *kni;
    /* Recommended burst size */
    uint32_t tx_burst_sz;
};

static void *
dpdk_knidev_writer_create(void *params, int socket_id)
{
    struct dpdk_knidev_writer_params *conf =
            (struct dpdk_knidev_writer_params *) params;
    struct dpdk_knidev_writer *port;

    /* Check input parameters */
    if ((conf == NULL) ||
        (conf->tx_burst_sz == 0) ||
        (conf->tx_burst_sz > VR_DPDK_TX_BURST_SZ) ||
        (!rte_is_power_of_2(conf->tx_burst_sz))) {
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
    port->kni = conf->kni;
    port->tx_burst_sz = conf->tx_burst_sz;
    port->tx_buf_count = 0;
    port->bsz_mask = 1LLU << (conf->tx_burst_sz - 1);

    return port;
}

static inline void
send_burst(struct dpdk_knidev_writer *p)
{
    uint32_t nb_tx;

    nb_tx = rte_kni_tx_burst(p->kni, p->tx_buf, p->tx_buf_count);

    DPDK_KNIDEV_WRITER_STATS_PKTS_DROP_ADD(p, p->tx_buf_count - nb_tx);
    for ( ; nb_tx < p->tx_buf_count; nb_tx++) {
        /* TODO: a separate counter for this drop */
        vr_dpdk_pfree(p->tx_buf[nb_tx], NULL, VP_DROP_INTERFACE_DROP);
    }

    p->tx_buf_count = 0;
}

#ifdef VROUTER_KNI_ADDR_CHECK
/*
 The rte_mempool_mem_iter callback routine for inspecting
 mempool pointers to find a start/end address of a contiguous
 memory region
 */
static void mempool_info_cb(struct rte_mempool *mp,
       void *opaque, struct rte_mempool_memhdr *memhdr,
       unsigned index)
{
       uintptr_t *info = opaque;

       /* Stop iteration ...*/
       if (info[vr_elt_va_status] || (memhdr == NULL))
               return;

       /* This is the first link */
       if (info[vr_elt_va_start] == 0 && info[vr_elt_va_end] == 0) {
               info[vr_elt_va_start] = (uintptr_t)memhdr->addr;
               info[vr_elt_va_end] = (uintptr_t)(info[vr_elt_va_start] + memhdr->len);
               return;
       }

       /* This is the link before head block */
       if (info[vr_elt_va_end] == (uintptr_t)memhdr->addr) {
               info[vr_elt_va_end] += memhdr->len;
               return;
       }

       /* This is the link down last block */
       if (info[vr_elt_va_start] == (uintptr_t)(memhdr->addr + memhdr->len)) {
               info[vr_elt_va_start] -= memhdr->len;
               return;
       }


       /* mempool is not contiguous. */
       info[vr_elt_va_status] = (uintptr_t)1;
}

/**
 * Check if the provided address is inside mempool memory region
 *
 * @return
 *   1: (true) if the provided address is out of range
     0: (false) if the provided address is in range
 */
static int addr_out_range(struct rte_mempool *mp, uintptr_t addr)
{
    uintptr_t info[vr_elt_va_status + 1];

       memset(&info, 0, sizeof(info));
       rte_mempool_mem_iter(mp, mempool_info_cb, &info);
       if ((addr < info[vr_elt_va_start]) ||
               (addr > info[vr_elt_va_end])) {
               return true;
       }
       return false;
}
#endif

static int
dpdk_knidev_writer_tx(void *port, struct rte_mbuf *pkt)
{
    struct dpdk_knidev_writer *p = (struct dpdk_knidev_writer *) port;
    struct rte_mbuf *pkt_copy;

    /*
     * KNI kernel module uses a trick to speed up packet processing. It takes
     * a physical address of a memory pool, converts it to the kernel virtual
     * address with phys_to_virt() and saves the address.
     *
     * Then in kni_net_rx_normal() instead of using phys_to_virt() per each
     * packet, KNI just calculates the difference between the previously
     * converted physical address of the given mempool and the packets
     * physical address.
     *
     * It works well for the mbufs from the same mempool. It also works fine
     * with any mempool allocated from the same physically contiguous memory
     * segment.
     *
     * As soon as we get a mempool allocated from another memory segment, the
     * difference calculations fail and thus we might have a crash.
     *
     * So we make sure the packet is from the RSS mempool. If not, we make
     * a copy to the RSS mempool.
     */
#if (RTE_VERSION == RTE_VERSION_NUM(2, 1, 0, 0))
    if (unlikely(pkt->pool != vr_dpdk.rss_mempool ||
            /* Check indirect mbuf's data is within the RSS mempool. */
            rte_pktmbuf_mtod(pkt, uintptr_t) < vr_dpdk.rss_mempool->elt_va_start ||
            rte_pktmbuf_mtod(pkt, uintptr_t) > vr_dpdk.rss_mempool->elt_va_end
            )) {
#else
    if (unlikely(pkt->pool != vr_dpdk.rss_mempool
#ifdef VROUTER_KNI_ADDR_CHECK
        || addr_out_range(vr_dpdk.rss_mempool, rte_pktmbuf_mtod(pkt, uintptr_t))
#endif
        )) {
#endif
        struct vr_packet *vr_pkt = vr_dpdk_mbuf_to_pkt(pkt);
        pkt_copy = vr_dpdk_pktmbuf_copy(pkt, vr_dpdk.rss_mempool);
        /* The original mbuf is no longer needed. */
        vr_dpdk_pfree(pkt, vr_pkt->vp_if, VP_DROP_CLONED_ORIGINAL);

        if (unlikely(pkt_copy == NULL)) {
            DPDK_KNIDEV_WRITER_STATS_PKTS_DROP_ADD(p, 1);
            return -1;
        }

        pkt = pkt_copy;
    }

    p->tx_buf[p->tx_buf_count++] = pkt;
    DPDK_KNIDEV_WRITER_STATS_PKTS_IN_ADD(p, 1);
    if (p->tx_buf_count >= p->tx_burst_sz)
        send_burst(p);

    return 0;
}

static int
dpdk_knidev_writer_flush(void *port)
{
    struct dpdk_knidev_writer *p = (struct dpdk_knidev_writer *) port;

    if (p->tx_buf_count > 0)
        send_burst(p);

    return 0;
}

static int
dpdk_knidev_writer_free(void *port)
{
    if (port == NULL) {
        RTE_LOG(ERR, PORT, "%s: port is NULL\n", __func__);
        return -EINVAL;
    }

    dpdk_knidev_writer_flush(port);
    rte_free(port);

    return 0;
}

static int
dpdk_knidev_writer_stats_read(void *port,
    struct rte_port_out_stats *stats, int clear)
{
    struct dpdk_knidev_writer *p =
        (struct dpdk_knidev_writer *) port;

    if (stats != NULL)
        memcpy(stats, &p->stats, sizeof(p->stats));

    if (clear)
        memset(&p->stats, 0, sizeof(p->stats));

    return 0;
}

/*
 * Summary of KNI operations
 */
struct rte_port_in_ops dpdk_knidev_reader_ops = {
    .f_create = dpdk_knidev_reader_create,
    .f_free = dpdk_knidev_reader_free,
    .f_rx = dpdk_knidev_reader_rx,
    .f_stats = dpdk_knidev_reader_stats_read,
};

struct rte_port_out_ops dpdk_knidev_writer_ops = {
    .f_create = dpdk_knidev_writer_create,
    .f_free = dpdk_knidev_writer_free,
    .f_tx = dpdk_knidev_writer_tx,
    .f_tx_bulk = NULL, /* TODO: not implemented */
    .f_flush = dpdk_knidev_writer_flush,
    .f_stats = dpdk_knidev_writer_stats_read,
};

/* Release KNI RX queue */
static void
dpdk_kni_rx_queue_release(unsigned lcore_id,
        unsigned queue_index __attribute__((unused)),
        struct vr_interface *vif)
{
    struct vr_dpdk_lcore *lcore = vr_dpdk.lcores[lcore_id];
    struct vr_dpdk_queue *rx_queue = &lcore->lcore_rx_queues[vif->vif_idx];
    struct vr_dpdk_queue_params *rx_queue_params
                        = &lcore->lcore_rx_queue_params[vif->vif_idx];

    /* free the queue */
    if (rx_queue->rxq_ops.f_free(rx_queue->q_queue_h)) {
        RTE_LOG(ERR, VROUTER, "    error freeing lcore %u KNI device RX queue\n",
                    lcore_id);
    }

    /* reset the queue */
    vrouter_put_interface(rx_queue->q_vif);
    memset(rx_queue, 0, sizeof(*rx_queue));
    memset(rx_queue_params, 0, sizeof(*rx_queue_params));
}

/* Init KNI RX queue */
struct vr_dpdk_queue *
vr_dpdk_kni_rx_queue_init(unsigned lcore_id, struct vr_interface *vif,
    unsigned host_lcore_id)
{
    struct vr_dpdk_lcore *lcore = vr_dpdk.lcores[lcore_id];
    const unsigned socket_id = rte_lcore_to_socket_id(lcore_id);
    uint8_t port_id = 0;
    unsigned vif_idx = vif->vif_idx;
    struct vr_dpdk_queue *rx_queue = &lcore->lcore_rx_queues[vif_idx];
    struct vr_dpdk_queue_params *rx_queue_params
                    = &lcore->lcore_rx_queue_params[vif_idx];

    if (vif->vif_type == VIF_TYPE_HOST) {
        port_id = (((struct vr_dpdk_ethdev *)(vif->vif_bridge->vif_os))->
                ethdev_port_id);
    }

    /* init queue */
    rx_queue->rxq_ops = dpdk_knidev_reader_ops;
    rx_queue->q_queue_h = NULL;
    rx_queue->q_vif = vrouter_get_interface(vif->vif_rid, vif_idx);

    /* create the queue */
    struct dpdk_knidev_reader_params reader_params = {
        .kni = vif->vif_os,
    };
    rx_queue->q_queue_h = rx_queue->rxq_ops.f_create(&reader_params, socket_id);
    if (rx_queue->q_queue_h == NULL) {
        RTE_LOG(ERR, VROUTER, "    error creating KNI device %s RX queue"
            " at eth device %" PRIu8 "\n", vif->vif_name, port_id);
        return NULL;
    }

    /* store queue params */
    rx_queue_params->qp_release_op = &dpdk_kni_rx_queue_release;

    return rx_queue;
}

/* Release KNI TX queue */
static void
dpdk_kni_tx_queue_release(unsigned lcore_id, unsigned queue_index,
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
        RTE_LOG(ERR, VROUTER, "    error freeing lcore %u KNI device TX queue\n",
                    lcore_id);
    }

    /* reset the queue */
    vrouter_put_interface(tx_queue->q_vif);
    memset(tx_queue, 0, sizeof(*tx_queue));
    memset(tx_queue_params, 0, sizeof(*tx_queue_params));
}

/* Init KNI TX queue */
struct vr_dpdk_queue *
vr_dpdk_kni_tx_queue_init(unsigned lcore_id, struct vr_interface *vif,
    unsigned host_lcore_id)
{
    struct vr_dpdk_lcore *lcore = vr_dpdk.lcores[lcore_id];
    const unsigned socket_id = rte_lcore_to_socket_id(lcore_id);
    uint8_t port_id = 0;
    unsigned vif_idx = vif->vif_idx;
    struct vr_dpdk_queue *tx_queue = &lcore->lcore_tx_queues[vif_idx][0];
    struct vr_dpdk_queue_params *tx_queue_params
                    = &lcore->lcore_tx_queue_params[vif_idx][0];
    struct vr_dpdk_ethdev *ethdev;

    if (vif->vif_type == VIF_TYPE_HOST) {
        ethdev = vif->vif_bridge->vif_os;
        if (ethdev == NULL) {
            RTE_LOG(ERR, VROUTER, "    error creating KNI device %s TX queue:"
                " bridge vif %u ethdev is not initialized\n",
                vif->vif_name, vif->vif_bridge->vif_idx);
            return NULL;
        }
        port_id = ethdev->ethdev_port_id;
    }

    /* init queue */
    tx_queue->txq_ops = dpdk_knidev_writer_ops;
    tx_queue->q_queue_h = NULL;
    tx_queue->q_vif = vrouter_get_interface(vif->vif_rid, vif_idx);

    /* create the queue */
    struct dpdk_knidev_writer_params writer_params = {
        .kni = vif->vif_os,
        .tx_burst_sz = VR_DPDK_TX_BURST_SZ,
    };
    tx_queue->q_queue_h = tx_queue->txq_ops.f_create(&writer_params, socket_id);
    if (tx_queue->q_queue_h == NULL) {
        RTE_LOG(ERR, VROUTER, "    error creating KNI device %s TX queue"
            " at eth device %" PRIu8 "\n", vif->vif_name, port_id);
        return NULL;
    }

    /* store queue params */
    tx_queue_params->qp_release_op = &dpdk_kni_tx_queue_release;

    return tx_queue;
}

/* Change KNI MTU size callback */
static int
dpdk_knidev_change_mtu(uint8_t port_id, unsigned new_mtu)
{
    struct vrouter *router = vrouter_get(0);
    struct vr_interface *vif;
    int i, ret;
    uint8_t slave_port_id;
    struct vr_dpdk_ethdev *ethdev = NULL;

    if (port_id >= rte_eth_dev_count()) {
        RTE_LOG(ERR, VROUTER,
                "Error changing eth device %"PRIu8" MTU: invalid eth device\n",
                port_id);
        return -EINVAL;
    }

    /*
     * TODO: DPDK bond PMD does not implement mtu_set op, so we need to
     * set the MTU manually for all the slaves.
     */
    /* Bond vif uses first slave port ID. */
    if (router->vr_eth_if)
        ethdev = (struct vr_dpdk_ethdev *)router->vr_eth_if->vif_os;

    if (ethdev && vr_dpdk_ethdev_bond_port_match(port_id, ethdev)) {
        RTE_LOG(INFO, VROUTER, "Changing bond eth device %" PRIu8 " MTU\n",
                ethdev->ethdev_port_id);

        rte_eth_devices[ethdev->ethdev_port_id].data->mtu = new_mtu;
        for (i = 0; i < ethdev->ethdev_nb_slaves; i++) {
            slave_port_id = ethdev->ethdev_slaves[i];
            RTE_LOG(INFO, VROUTER,
                    "    changing bond member eth device %" PRIu8 " MTU to %u\n",
                    slave_port_id, new_mtu);

            ret =  rte_eth_dev_set_mtu(slave_port_id, new_mtu);
            if (ret < 0) {
                /*
                 * Do not return error as some NICs (such as X710) do not allow setting 
                 * the MTU while the NIC is up and running. The max_rx_pkt_len is anyway
                 * set to support jumbo frames, so continue further here to set vif_mtu.
                 */
                RTE_LOG(DEBUG, VROUTER,
                        "    error changing bond member eth device %" PRIu8 " MTU: %s (%d)\n",
                        slave_port_id, rte_strerror(-ret), -ret);
            }
        }
    } else {
        RTE_LOG(INFO, VROUTER, "Changing eth device %" PRIu8 " MTU to %u\n",
                port_id, new_mtu);

        ret =  rte_eth_dev_set_mtu(port_id, new_mtu);
        if (ret < 0) {
            /*
             * Do not return error as some NICs (such as X710) do not allow setting 
             * the MTU while the NIC is up and running. The max_rx_pkt_len is anyway
             * set to support jumbo frames, so continue further here to set vif_mtu.
             */
            RTE_LOG(DEBUG, VROUTER,
                    "Error changing eth device %" PRIu8 " MTU: %s (%d)\n",
                    port_id, rte_strerror(-ret), -ret);
        }
    }

    /* On success, inform vrouter about new MTU */
    for (i = 0; i < router->vr_max_interfaces; i++) {
        vif = __vrouter_get_interface(router, i);
        if (vif && (vif->vif_type == VIF_TYPE_PHYSICAL)) {
           /* Ethernet header size */
           new_mtu += sizeof(struct vr_eth);
           if (vr_dpdk.vlan_tag != VLAN_ID_INVALID) {
               /* 802.1q header size */
               new_mtu += sizeof(uint32_t);
           }
           vif->vif_mtu = new_mtu;
           if (vif->vif_bridge)
               vif->vif_bridge->vif_mtu = new_mtu;
        }
    }

    return 0;
}

/* Configure KNI state callback */
static int
dpdk_knidev_config_network_if(uint8_t port_id, uint8_t if_up)
{
    struct vrouter *router = vrouter_get(0);
    struct vr_dpdk_ethdev *ethdev = NULL;
    int ret = 0;

    if (port_id >= rte_eth_dev_count() || port_id >= RTE_MAX_ETHPORTS) {
        RTE_LOG(ERR, VROUTER, "%s: Invalid eth device %" PRIu8 "\n",
                __func__, port_id);
        return -EINVAL;
    }

    if (router->vr_eth_if)
        ethdev = (struct vr_dpdk_ethdev *)router->vr_eth_if->vif_os;

    if (ethdev && vr_dpdk_ethdev_bond_port_match(port_id, ethdev))
        port_id = ethdev->ethdev_port_id;

    RTE_LOG(INFO, VROUTER, "Configuring eth device %" PRIu8 " %s\n",
                    port_id, if_up ? "UP" : "DOWN");

    if (if_up)
        ret = rte_eth_dev_start(port_id);
    else
        rte_eth_dev_stop(port_id);

    if (ret < 0) {
        RTE_LOG(ERR, VROUTER, "Configuring eth device %" PRIu8 " UP "
                    "failed (%d)\n", port_id, ret);
    }

    return ret;
}

/*
 * vr_dpdk_knidev_init - initializes Kernel Network Interface device using
 * specified Ethernet device port.
 *
 * Returns 0 on success, < 0 otherwise.
 */
int
vr_dpdk_knidev_init(uint8_t port_id, struct vr_interface *vif)
{
    int i;
    struct rte_eth_dev_info dev_info;
    struct rte_kni_conf kni_conf;
    struct rte_kni_ops kni_ops;
    struct rte_kni *kni;
    struct rte_config *rte_conf = rte_eal_get_configuration();

    /* Probe KNI. */
    if (vr_dpdk.kni_state == 0) {
        /* Check if the KNI is available. */
        if (access("/dev/kni", R_OK | W_OK)) {
            vr_dpdk.kni_state = -1;
        } else {
            RTE_LOG(INFO, VROUTER,
                "    initializing KNI with %d maximum interfaces\n",
                VR_DPDK_MAX_KNI_INTERFACES);
            rte_kni_init(VR_DPDK_MAX_KNI_INTERFACES);
            vr_dpdk.kni_state = 1;
        }
    }

    if (vr_dpdk.kni_state == -1) {
        RTE_LOG(INFO, VROUTER, "    KNI is not available\n");
        return -ENOTSUP;
    }

    /* Check if port is valid. */
    if (!rte_eth_dev_is_valid_port(port_id)) {
        RTE_LOG(ERR, VROUTER, "    error initializing KNI device %s: invalid eth device %"
                PRIu8"\n", vif->vif_name, port_id);
        return -EINVAL;
    }

    /* get eth device info */
    memset(&dev_info, 0, sizeof(dev_info));
    rte_eth_dev_info_get(port_id, &dev_info);

    /* create KNI configuration */
    memset(&kni_conf, 0, sizeof(kni_conf));
    strncpy(kni_conf.name, (char *)vif->vif_name, sizeof(kni_conf.name) - 1);

    kni_conf.addr = dev_info.pci_dev->addr;
    kni_conf.id = dev_info.pci_dev->id;
    kni_conf.group_id = port_id;
    kni_conf.mbuf_size = vr_packet_sz;
    /*
     * Due to DPDK commit 41a6ebd, now to prevent packet reordering in KNI
     * we have to bind KNI kernel thread to a first online unused CPU.
     */
    for (i = 0; i < RTE_MAX_LCORE; i++) {
        if (lcore_config[i].detected
                && rte_conf->lcore_role[VR_DPDK_FWD_LCORE_ID + i] == ROLE_OFF) {
            kni_conf.force_bind = 1;
            kni_conf.core_id = i;
            RTE_LOG(INFO, VROUTER, "    bind KNI kernel thread to CPU %d\n", i);
            break;
        }
    }

    /* KNI options
     *
     * Changing state of the KNI interface can change state of the physical
     * interface. This is useful for the vhost, but not for the VLAN
     * forwarding interface.
     */
    if (vif->vif_type == VIF_TYPE_VLAN) {
        memset(&kni_ops, 0, sizeof(kni_ops));
    } else {
        kni_ops.port_id = port_id;
        kni_ops.change_mtu = dpdk_knidev_change_mtu;
        kni_ops.config_network_if = dpdk_knidev_config_network_if;
    }

    /* allocate KNI device */
    kni = rte_kni_alloc(vr_dpdk.rss_mempool, &kni_conf, &kni_ops);
    if (kni == NULL) {
        RTE_LOG(ERR, VROUTER, "    error allocating KNI device %s"
            " at eth device %" PRIu8 "\n", vif->vif_name, port_id);
        return -ENOMEM;
    }

    /* store pointer to KNI for further use */
    vif->vif_os = kni;

    /* add interface to the table of KNIs */
    for (i = 0; i < VR_DPDK_MAX_KNI_INTERFACES; i++) {
        if (vr_dpdk.knis[i] == NULL) {
            vr_dpdk.knis[i] = vif->vif_os;
            break;
        }
    }

    return 0;
}

/*
 * vr_dpdk_knidev_release - release KNI interface and remove it from the
 * global list.
 * Returns 0 on success, < 0 otherwise.
 */
int
vr_dpdk_knidev_release(struct vr_interface *vif)
{
    int i;
    struct rte_kni *kni = vif->vif_os;

    RTE_LOG(INFO, VROUTER, "    releasing vif %u KNI device %s\n",
            vif->vif_idx, vif->vif_name);

    vif->vif_os = NULL;

    /* delete the interface from the table of KNIs */
    for (i = 0; i < VR_DPDK_MAX_KNI_INTERFACES; i++) {
        if (vr_dpdk.knis[i] == kni) {
            vr_dpdk.knis[i] = NULL;
            break;
        }
    }
    rte_wmb();

    return rte_kni_release(kni);
}

/* Handle all KNIs attached */
void
vr_dpdk_knidev_all_handle(void)
{
    int i;

    vr_dpdk_if_lock();
    for (i = 0; i < VR_DPDK_MAX_KNI_INTERFACES; i++) {
        if (vr_dpdk.knis[i] != NULL)
            rte_kni_handle_request(vr_dpdk.knis[i]);
    }
    vr_dpdk_if_unlock();
}
