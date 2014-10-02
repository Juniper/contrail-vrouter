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
            CACHE_LINE_SIZE, socket_id);
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

    for ( ; nb_tx < p->tx_buf_count; nb_tx++)
        rte_pktmbuf_free(p->tx_buf[nb_tx]);

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

/* Init KNI RX queue */
struct vr_dpdk_rx_queue *
vr_dpdk_kni_rx_queue_init(unsigned lcore_id, struct vr_interface *vif,
    unsigned host_lcore_id)
{
    struct vr_dpdk_lcore *lcore = vr_dpdk.lcores[lcore_id];
    const unsigned socket_id = rte_lcore_to_socket_id(lcore_id);
    uint8_t port_id = vif->vif_os_idx;
    unsigned vif_idx = vif->vif_idx;
    struct vr_dpdk_rx_queue *rx_queue = &lcore->lcore_rx_queues[vif_idx];

    RTE_LOG(DEBUG, VROUTER, "%s: lcore_id=%u  host_lcore_id=%u\n", __func__,
        lcore_id, host_lcore_id);

    /* init queue */
    memcpy(&rx_queue->rxq_ops, &dpdk_knidev_reader_ops,
        sizeof(struct rte_port_in_ops));
    rx_queue->rxq_queue_h = NULL;
    rx_queue->rxq_burst_size = VR_DPDK_KNI_RX_BURST_SZ;
    rx_queue->rxq_vif = vrouter_get_interface(vif->vif_rid, vif_idx);

    /* create the queue */
    struct dpdk_knidev_reader_params rx_queue_params = {
        .kni = vif->vif_os,
    };
    rx_queue->rxq_queue_h = rx_queue->rxq_ops.f_create(&rx_queue_params, socket_id);
    if (rx_queue->rxq_queue_h == NULL) {
        RTE_LOG(ERR, VROUTER, "\terror creating KNI device %s RX queue at eth device %" PRIu8 "\n",
            vif->vif_name, port_id);
        return NULL;
    }

    return rx_queue;
}

/* Init KNI TX queue */
struct vr_dpdk_tx_queue *
vr_dpdk_kni_tx_queue_init(unsigned lcore_id, struct vr_interface *vif,
    unsigned host_lcore_id)
{
    struct vr_dpdk_lcore *lcore = vr_dpdk.lcores[lcore_id];
    const unsigned socket_id = rte_lcore_to_socket_id(lcore_id);
    uint8_t port_id = vif->vif_os_idx;
    unsigned vif_idx = vif->vif_idx;
    struct vr_dpdk_tx_queue *tx_queue = &lcore->lcore_tx_queues[vif_idx];

    RTE_LOG(DEBUG, VROUTER, "%s: lcore_id=%u  host_lcore_id=%u\n", __func__,
        lcore_id, host_lcore_id);

    /* init queue */
    memcpy(&tx_queue->txq_ops, &dpdk_knidev_writer_ops,
        sizeof(struct rte_port_out_ops));
    tx_queue->txq_queue_h = NULL;
    tx_queue->txq_vif = vrouter_get_interface(vif->vif_rid, vif_idx);

    /* create the queue */
    struct dpdk_knidev_writer_params tx_queue_params = {
        .kni = vif->vif_os,
        .tx_burst_sz = VR_DPDK_KNI_TX_BURST_SZ,
    };
    tx_queue->txq_queue_h = tx_queue->txq_ops.f_create(&tx_queue_params, socket_id);
    if (tx_queue->txq_queue_h == NULL) {
        RTE_LOG(ERR, VROUTER, "\terror creating KNI device %s TX queue at eth device %" PRIu8 "\n",
            vif->vif_name, port_id);
        return NULL;
    }

    return tx_queue;
}

/* Change KNI MTU size callback */
static int
dpdk_knidev_change_mtu(uint8_t portid, unsigned new_mtu)
{
    /* TODO: not implemented */
    if (portid >= rte_eth_dev_count()) {
        RTE_LOG(ERR, VROUTER, "Invalid eth device %d\n", portid);
        return -EINVAL;
    }

    RTE_LOG(INFO, VROUTER, "Change MTU of eth device %d to %u\n", portid, new_mtu);

    return 0;
}


/* Configure KNI state callback */
static int
dpdk_knidev_config_network_if(uint8_t portid, uint8_t if_up)
{
    RTE_LOG(INFO, VROUTER, "Configuring eth device %d %s\n",
                    (int)portid, if_up ? "UP" : "DOWN");
    if (portid >= rte_eth_dev_count() || portid >= RTE_MAX_ETHPORTS) {
        RTE_LOG(ERR, VROUTER, "Invalid eth device %d\n", portid);
        return -EINVAL;
    }

    /* TODO: not implemented */

    return 0;
}

/* Init KNI */
int
vr_dpdk_knidev_init(struct vr_interface *vif)
{
    uint8_t port_id = vif->vif_os_idx;
    struct rte_eth_dev_info dev_info;
    struct rte_kni_conf kni_conf;
    struct rte_kni *kni;

    /* get eth device info */
    memset(&dev_info, 0, sizeof(dev_info));
    rte_eth_dev_info_get(port_id, &dev_info);

    /* create KNI configuration */
    memset(&kni_conf, 0, sizeof(kni_conf));
    strncpy(kni_conf.name, (char *)vif->vif_name, sizeof(kni_conf.name));

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
    kni = rte_kni_alloc(vr_dpdk.pktmbuf_pool, &kni_conf, &kni_ops);
    if (kni == NULL) {
        RTE_LOG(ERR, VROUTER, "\terror allocation KNI device %s at eth device %" PRIu8 "\n",
                vif->vif_name, port_id);
        return -ENOMEM;
    }

    /* store pointer to KNI for further use */
    vif->vif_os = kni;

    return 0;
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
        if (vif && vif->vif_os)
            rte_kni_handle_request((struct rte_kni *)vif->vif_os);
    }
}
