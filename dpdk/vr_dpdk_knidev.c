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
#include <stdio.h>
#include <unistd.h>

#include <rte_malloc.h>

#include "vr_dpdk.h"

/*
 * KNI Reader
 */
struct dpdk_knidev_reader {
    struct rte_kni *kni;
    struct vr_interface *vif;
};

struct dpdk_knidev_reader_params {
    /* Pointer to preallocated KNI */
    struct rte_kni *kni;
    struct vr_interface *vif;
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
            CACHE_LINE_SIZE, socket_id);
    if (port == NULL) {
        RTE_LOG(ERR, PORT, "%s: Failed to allocate port\n", __func__);
        return NULL;
    }

    /* Initialization */
    port->kni = conf->kni;
    port->vif = conf->vif;

    return port;
}

static int
dpdk_knidev_reader_rx(void *port, struct rte_mbuf **pkts, uint32_t n_pkts)
{
    struct dpdk_knidev_reader *p =
        (struct dpdk_knidev_reader *) port;

    return rte_kni_rx_burst(p->kni, pkts, n_pkts);
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

/*
 * KNI Writer
 */
struct dpdk_knidev_writer {
    struct rte_mbuf *tx_buf[2 * RTE_PORT_IN_BURST_SIZE_MAX];
    uint32_t tx_burst_sz;
    uint16_t tx_buf_count;
    uint64_t bsz_mask;
    struct rte_kni *kni;
    struct vr_interface *vif;
};

struct dpdk_knidev_writer_params {
    /* Pointer to preallocated KNI */
    struct rte_kni *kni;
    struct vr_interface *vif;
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
        (conf->tx_burst_sz > RTE_PORT_IN_BURST_SIZE_MAX) ||
        (!rte_is_power_of_2(conf->tx_burst_sz))) {
        RTE_LOG(ERR, PORT, "%s: Invalid input parameters\n", __func__);
        return NULL;
    }

    /* Memory allocation */
    port = rte_zmalloc_socket("PORT", sizeof(*port),
            CACHE_LINE_SIZE, socket_id);
    if (port == NULL) {
        RTE_LOG(ERR, PORT, "%s: Failed to allocate port\n", __func__);
        return NULL;
    }

    /* Initialization */
    port->kni = conf->kni;
    port->vif = conf->vif;
    port->tx_burst_sz = conf->tx_burst_sz;
    port->tx_buf_count = 0;
    port->bsz_mask = 1LLU << (conf->tx_burst_sz - 1);

    return port;
}

static inline void
send_burst(struct dpdk_knidev_writer *p)
{
    uint32_t nb_tx, i;
    struct vr_interface_stats *stats;

    nb_tx = rte_kni_tx_burst(p->kni, p->tx_buf, p->tx_buf_count);

    for (i = 0; i < nb_tx; i++) {
        stats = vif_get_stats(p->vif, vr_dpdk_mbuf_to_pkt(p->tx_buf[i])->vp_cpu);
        stats->vis_enqpackets++;
    }

    for ( ; nb_tx < p->tx_buf_count; nb_tx++)
        vif_drop_pkt(p->vif, vr_dpdk_mbuf_to_pkt(p->tx_buf[nb_tx]), 0, VP_DROP_ENQUEUE_FAIL);

    p->tx_buf_count = 0;
}

static int
dpdk_knidev_writer_tx(void *port, struct rte_mbuf *pkt)
{
    struct dpdk_knidev_writer *p = (struct dpdk_knidev_writer *) port;

    p->tx_buf[p->tx_buf_count++] = pkt;
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
        RTE_LOG(ERR, PORT, "%s: Port is NULL\n", __func__);
        return -EINVAL;
    }

    dpdk_knidev_writer_flush(port);
    rte_free(port);

    return 0;
}

/*
 * Summary of KNI operations
 */
struct rte_port_in_ops dpdk_knidev_reader_ops = {
    .f_create = dpdk_knidev_reader_create,
    .f_free = dpdk_knidev_reader_free,
    .f_rx = dpdk_knidev_reader_rx,
};

struct rte_port_out_ops dpdk_knidev_writer_ops = {
    .f_create = dpdk_knidev_writer_create,
    .f_free = dpdk_knidev_writer_free,
    .f_tx = dpdk_knidev_writer_tx,
    .f_tx_bulk = NULL, /* TODO: not implemented */
    .f_flush = dpdk_knidev_writer_flush,
};

/* Release KNI RX queue */
static void
dpdk_kni_rx_queue_release(unsigned lcore_id, struct vr_interface *vif)
{
    struct vr_dpdk_lcore *lcore = vr_dpdk.lcores[lcore_id];
    struct vr_dpdk_queue *rx_queue = &lcore->lcore_rx_queues[vif->vif_idx];
    struct vr_dpdk_queue_params *rx_queue_params
                        = &lcore->lcore_rx_queue_params[vif->vif_idx];

    /* free the queue */
    if (rx_queue->rxq_ops.f_free(rx_queue->q_queue_h)) {
        RTE_LOG(ERR, VROUTER, "\terror freeing lcore %u KNI device RX queue\n",
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
    rx_queue->rxq_burst_size = VR_DPDK_KNI_RX_BURST_SZ;
    rx_queue->q_vif = vrouter_get_interface(vif->vif_rid, vif_idx);

    /* create the queue */
    struct dpdk_knidev_reader_params reader_params = {
        .kni = vif->vif_os,
        .vif = vif,
    };
    rx_queue->q_queue_h = rx_queue->rxq_ops.f_create(&reader_params, socket_id);
    if (rx_queue->q_queue_h == NULL) {
        RTE_LOG(ERR, VROUTER, "\terror creating KNI device %s RX queue at eth device %"
            PRIu8 "\n", vif->vif_name, port_id);
        return NULL;
    }

    /* store queue params */
    rx_queue_params->qp_release_op = &dpdk_kni_rx_queue_release;

    return rx_queue;
}

/* Release KNI TX queue */
static void
dpdk_kni_tx_queue_release(unsigned lcore_id, struct vr_interface *vif)
{
    struct vr_dpdk_lcore *lcore = vr_dpdk.lcores[lcore_id];
    struct vr_dpdk_queue *tx_queue = &lcore->lcore_tx_queues[vif->vif_idx];
    struct vr_dpdk_queue_params *tx_queue_params
                        = &lcore->lcore_tx_queue_params[vif->vif_idx];

    tx_queue->txq_ops.f_tx = NULL;
    rte_wmb();

    /* flush and free the queue */
    if (tx_queue->txq_ops.f_free(tx_queue->q_queue_h)) {
        RTE_LOG(ERR, VROUTER, "\terror freeing lcore %u KNI device TX queue\n",
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
    struct vr_dpdk_queue *tx_queue = &lcore->lcore_tx_queues[vif_idx];
    struct vr_dpdk_queue_params *tx_queue_params
                    = &lcore->lcore_tx_queue_params[vif_idx];

    if (vif->vif_type == VIF_TYPE_HOST) {
        port_id = (((struct vr_dpdk_ethdev *)(vif->vif_bridge->vif_os))->
                ethdev_port_id);
    }

    /* init queue */
    tx_queue->txq_ops = dpdk_knidev_writer_ops;
    tx_queue->q_queue_h = NULL;
    tx_queue->q_vif = vrouter_get_interface(vif->vif_rid, vif_idx);

    /* create the queue */
    struct dpdk_knidev_writer_params writer_params = {
        .kni = vif->vif_os,
        .tx_burst_sz = VR_DPDK_KNI_TX_BURST_SZ,
        .vif = vif,
    };
    tx_queue->q_queue_h = tx_queue->txq_ops.f_create(&writer_params, socket_id);
    if (tx_queue->q_queue_h == NULL) {
        RTE_LOG(ERR, VROUTER, "\terror creating KNI device %s TX queue at eth device %"
            PRIu8 "\n", vif->vif_name, port_id);
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
    int i = 0;
    uint8_t ethdev_port_id;
    int ret = 0;

    RTE_LOG(INFO, VROUTER, "Change MTU of eth device %" PRIu8 " to %u\n",
                    port_id, new_mtu);
    if (port_id >= rte_eth_dev_count()) {
        RTE_LOG(ERR, VROUTER, "Invalid eth device %" PRIu8 "\n", port_id);
        return -EINVAL;
    }

    ret =  rte_eth_dev_set_mtu(port_id, new_mtu);

    if (ret < 0) {
        RTE_LOG(ERR, VROUTER, "Change MTU of eth device %" PRIu8 " to %u"
                        " failed (%d)\n", port_id, new_mtu, ret);
    }
    else { /* On success, inform vrouter about new MTU */
        vr_dpdk_if_lock();
        for (i = 0; i < router->vr_max_interfaces; i++) {
            vif = __vrouter_get_interface(router, i);
            if (vif && (vif->vif_type == VIF_TYPE_PHYSICAL)) {
                ethdev_port_id = (((struct vr_dpdk_ethdev *)(vif->vif_os))->
                            ethdev_port_id);
                if (ethdev_port_id == port_id) {
                    vif->vif_mtu = new_mtu;
                    if (vif->vif_bridge)
                        vif->vif_bridge->vif_mtu = new_mtu;
                }
            }
        }
        vr_dpdk_if_unlock();
    }

    return ret;
}


/* Configure KNI state callback */
static int
dpdk_knidev_config_network_if(uint8_t port_id, uint8_t if_up)
{
    int ret = 0;

    RTE_LOG(INFO, VROUTER, "Configuring eth device %" PRIu8 " %s\n",
                    port_id, if_up ? "UP" : "DOWN");
    if (port_id >= rte_eth_dev_count() || port_id >= RTE_MAX_ETHPORTS) {
        RTE_LOG(ERR, VROUTER, "Invalid eth device %" PRIu8 "\n", port_id);
        return -EINVAL;
    }

    vr_dpdk_if_lock();
    if (if_up)
        ret = rte_eth_dev_start(port_id);
    else
        rte_eth_dev_stop(port_id);
    vr_dpdk_if_unlock();

    if (ret < 0) {
        RTE_LOG(ERR, VROUTER, "Configuring eth device %" PRIu8 " UP"
                    "failed (%d)", port_id, ret);
    }

    return ret;
}

/* Init KNI */
int
vr_dpdk_knidev_init(struct vr_interface *vif)
{
    uint8_t port_id;
    struct vr_dpdk_ethdev *ethdev;
    struct rte_eth_dev_info dev_info;
    struct rte_kni_conf kni_conf;
    struct rte_kni *kni;

    if (vif->vif_type == VIF_TYPE_HOST) {
        ethdev = (struct vr_dpdk_ethdev *)(vif->vif_bridge->vif_os);
        /* TODO: in test scripts ethdev is null here */
        if (ethdev)
            port_id = ethdev->ethdev_port_id;
        else
            /* ...so we use os_idx instead */
            port_id = vif->vif_os_idx;
    } else if (vif->vif_type == VIF_TYPE_MONITORING) {
            /*
             * DPDK numerates all the detected Ethernet devices starting from 0.
             * So we might get into an issue if we have no eth devices at all
             * or we have few eth ports and don't what to use the first one.
             */
            port_id = 0; /* TODO: we always use DPDK port 0 */
    } else {
        RTE_LOG(ERR, VROUTER, "\tunknown KNI interface addition"
                "type %d os index %d\n", vif->vif_type, vif->vif_os_idx);
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
    kni_conf.mbuf_size = VR_DPDK_MAX_PACKET_SZ;

    /* KNI options */
    struct rte_kni_ops kni_ops = {
        .port_id = port_id,
        .change_mtu = dpdk_knidev_change_mtu,
        .config_network_if = dpdk_knidev_config_network_if,
    };

    /* allocate KNI device */
    kni = rte_kni_alloc(vr_dpdk.rss_mempool, &kni_conf, &kni_ops);
    if (kni == NULL) {
        RTE_LOG(ERR, VROUTER, "\terror allocation KNI device %s at eth device %"
                PRIu8 "\n", vif->vif_name, port_id);
        return -ENOMEM;
    }

    /* store pointer to KNI for further use */
    vif->vif_os = kni;

    return 0;
}

/* Release KNI */
int
vr_dpdk_knidev_release(struct vr_interface *vif)
{
    struct rte_kni *kni = vif->vif_os;

    vif->vif_os = NULL;
    rte_wmb();
    return rte_kni_release(kni);
}

/* Handle all KNIs attached */
void
vr_dpdk_knidev_all_handle(void)
{
    struct vrouter *router = vrouter_get(0);
    int i;
    struct vr_interface *vif;

    for (i = 0; i < router->vr_max_interfaces; i++) {
        vif = __vrouter_get_interface(router, i);
        if (vif && (vif->vif_type == VIF_TYPE_HOST
                    || vif->vif_type == VIF_TYPE_MONITORING))
            rte_kni_handle_request((struct rte_kni *)vif->vif_os);
    }
}
