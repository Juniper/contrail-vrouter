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
 * vr_dpdk.c -- misc DPDK ETH and KNI functions
 *
 */
#include <stdio.h>
#include <unistd.h>

#include <urcu-qsbr.h>

#include "vr_dpdk.h"

static struct rte_eth_conf port_conf = {
    .rxmode = {
        .header_split   = 0,    /* Header Split disabled */
        .hw_ip_checksum = 0,    /* IP checksum offload disabled */
        .hw_vlan_filter = 0,    /* VLAN filtering disabled */
        .jumbo_frame    = 0,    /* Jumbo Frame Support disabled */
        .hw_strip_crc   = 0,    /* CRC stripped by hardware */
    },
    .txmode = {
        .mq_mode = ETH_MQ_TX_NONE,
    },
};

/* RX and TX Prefetch, Host, and Write-back threshold values should be
 * carefully set for optimal performance. Consult the network
 * controller's datasheet and supporting DPDK documentation for guidance
 * on how these parameters should be set.
 */
/* RX ring configuration */
static const struct rte_eth_rxconf rx_conf = {
    .rx_thresh = {
        .pthresh = 8,   /* Ring prefetch threshold */
        .hthresh = 8,   /* Ring host threshold */
        .wthresh = 4,   /* Ring writeback threshold */
    },
    .rx_free_thresh = 0,    /* Immediately free RX descriptors */
};

/*
 * These default values are optimized for use with the Intel(R) 82599 10 GbE
 * Controller and the DPDK ixgbe PMD. Consider using other values for other
 * network controllers and/or network drivers.
 */
/* TX ring configuration */
static const struct rte_eth_txconf tx_conf = {
    .tx_thresh = {
        .pthresh = 36,  /* Ring prefetch threshold */
        .hthresh = 0,   /* Ring host threshold */
        .wthresh = 0,   /* Ring writeback threshold */
    },
    .tx_free_thresh = 0,    /* Use PMD default values */
    .tx_rs_thresh = 0,      /* Use PMD default values */
};

static void
dpdk_burst_free(struct rte_mbuf **pkts, unsigned num)
{
    unsigned i;

    for (i = 0; i < num; i++) {
        rte_pktmbuf_free(pkts[i]);
    }
}

/* Send a burst to VRouter */
static inline void
dpdk_burst_vroute(unsigned nb_rx, struct rte_mbuf *pkt_burst[VR_DPDK_PKT_BURST_SZ],
    struct vr_interface *vif, const char *name, unsigned port_id)
{
    /* packet iterator */
    unsigned i;
    /* loop packet pointer */
    struct vr_packet *pkt;

    /* if we have no vrouter interface attached */
    if (unlikely(NULL == vif)) {
        dpdk_burst_free(pkt_burst, nb_rx);
        RTE_LOG(ERR, VROUTER, "No VRouter interface attached "
            "to %s %u\n", name, port_id);
    } else  {
        RTE_LOG(DEBUG, VROUTER, "%s: RX %u packet(s) from %s %u\n",
             __func__, nb_rx, name, port_id);
        for (i = 0; i < nb_rx; i++) {
#ifdef VR_DPDK_RX_PKT_DUMP
            rte_pktmbuf_dump(pkt_burst[i], 0x60);
#endif
            rte_prefetch0(vr_dpdk_mbuf_to_pkt(pkt_burst[i]));
            rte_prefetch0(rte_pktmbuf_mtod(pkt_burst[i], void *));

            /* convert mbuf to vr_packet */
            pkt = vr_dpdk_packet_get(pkt_burst[i], vif);
            /* transmit the packet to vrouter */
            vif->vif_rx(vif, pkt, VLAN_ID_INVALID);
        }
    }

    return;
}

void
dpdk_burst_rx(unsigned nb_rx, struct rte_mbuf *pkt_burst[VR_DPDK_PKT_BURST_SZ],
        struct vr_interface *vif, const char *name, unsigned port_id)
{
    dpdk_burst_vroute(nb_rx, pkt_burst, vif, name, port_id);
    return;
}

/* Read a burst from eth and KNI interfaces and transmit it to VRouter */
unsigned
vr_dpdk_port_rx(struct vif_port *port)
{
    /* number of packets read */
    unsigned nb_rx, nb_kni_rx = 0;
    /* pointers to mbufs read */
    struct rte_mbuf *pkt_burst[VR_DPDK_PKT_BURST_SZ];
    /* ethdev port ID */
    unsigned port_id = port->vip_id;
    /* pointer to vrouter interface */
    struct vr_interface *eth_vif = port->vip_vif;
    struct vr_interface *kni_vif = port->vip_kni_vif;
    /* pointer to KNI */
    struct rte_kni *kni = port->vip_kni;

    /* always read from ethernet port queue 0 */
    nb_rx = rte_eth_rx_burst(port_id, 0, pkt_burst, VR_DPDK_PKT_BURST_SZ);
    if (likely(nb_rx)) {
        /* transmit to vrouter */
        dpdk_burst_vroute(nb_rx, pkt_burst, eth_vif, "port", port_id);
    }

    /* the same for the KNI attached */
    if (unlikely(NULL != kni)) {
        nb_kni_rx = rte_kni_rx_burst(kni, pkt_burst, VR_DPDK_PKT_BURST_SZ);

        /* we do not expect many packets from KNI */
        if (unlikely(nb_kni_rx > 0)) {
            /* transmit to vrouter */
            dpdk_burst_vroute(nb_kni_rx, pkt_burst, kni_vif, "KNI", port_id);
        }
    }

    rcu_quiescent_state();

    return nb_rx + nb_kni_rx;
}

/* Handle all KNIs attached */
void
vr_dpdk_all_knis_handle(void)
{
    /* number of ports */
    const unsigned nb_ports = rte_eth_dev_count();
    /* loop iterator */
    int i;
    /* loop port pointer */
    struct vif_port *port;
    /* loop pointer to KNI structure */
    struct rte_kni *kni;

    /* for all RX ports */
    for (i = 0; i < nb_ports; i++) {
        port = &vr_dpdk.ports[i];

        /* handle KNI attached */
        kni = port->vip_kni;
        if (unlikely(NULL != kni)) {
            /* unused ports marked with null lcore context */
            if (likely(NULL != port->vip_lcore_ctx)) {
                rte_kni_handle_request(kni);
            }
        }
    } /* for all RX queues */
}

/* Drain all ports */
inline void
vr_dpdk_all_ports_drain(struct lcore_ctx *lcore_ctx)
{
    /* number of TX ports */
    const unsigned nb_tx_ports = rte_eth_dev_count();
    /* loop iterator */
    int i;
    /* loop port pointer */
    struct vif_port *port;

    /* for all TX ports */
    for (i = 0; i < nb_tx_ports; i++) {
        port = &vr_dpdk.ports[i];
        /* unused ports marked with NULL lcore context */
        if (likely(NULL != port->vip_lcore_ctx)) {
            /* drain TX queues */
            vr_dpdk_eth_tx_queue_drain(port, lcore_ctx);
            if (unlikely(port->vip_kni != NULL)) {
                rte_rmb();
                /* RTE_LOG(DEBUG, VROUTER, "lcore %u main loop KNI drain\n", lcore_id); */
                vr_dpdk_kni_tx_queue_drain(port, lcore_ctx);
            }
        }
    }
}

/* Read bursts from all the ports assigned and transmit those
 * packets to VRouter
 */
inline void
vr_dpdk_all_ports_poll(struct lcore_ctx *lcore_ctx)
{
    /* number of RX ports */
    const unsigned nb_rx_ports = lcore_ctx->lcore_nb_rx_ports;
    /* loop iterator */
    int i;
    /* loop port pointer */
    struct vif_port *port;
    /* total number of packets read */
    unsigned sum_rx = 0;

    /* for all RX ports in list */
    for (i = 0; i < nb_rx_ports; i++) {
        port = lcore_ctx->lcore_rx_ports[i];

        /* unused ports marked with null */
        if (likely(NULL != port)) {
            rte_prefetch0(port);
            sum_rx += vr_dpdk_port_rx(port);
        }
    } /* for all ports in list */

    /* sleep if no packets received */
    if (unlikely(!sum_rx)) {
        usleep(VR_DPDK_NO_PACKETS_US);
    }
}

/*
 * pktmbuf constructor with vr_packet support
 */
void
vr_dpdk_pktmbuf_init(struct rte_mempool *mp,
         __attribute__((unused)) void *opaque_arg,
         void *_m,
         __attribute__((unused)) unsigned i)
{
    struct rte_mbuf *m = _m;
    struct vr_packet *pkt;
    rte_pktmbuf_init(mp, opaque_arg, _m, i);

    /* decrease rte packet size to fit vr_packet struct */
    m->buf_len -= sizeof(struct vr_packet);
    RTE_VERIFY(0 < m->buf_len);

    /* basic vr_packet initialization */
    pkt = vr_dpdk_mbuf_to_pkt(m);
    pkt->vp_head = (unsigned char *)m->buf_addr;
    pkt->vp_end = m->buf_len;
}

static int
dpdk_kni_change_mtu(uint8_t portid, unsigned new_mtu)
{
    /* TODO: not implemented */
    struct rte_eth_conf conf;
    unsigned nb_rx_queue, nb_tx_queue;
    int ret;

    if (portid >= rte_eth_dev_count()) {
        RTE_LOG(ERR, VROUTER, "Invalid port id %d\n", portid);
        return -EINVAL;
    }

    RTE_LOG(INFO, VROUTER, "Change MTU of port %d to %u\n", portid, new_mtu);

    return 0;
}


static int
dpdk_kni_config_network_interface(uint8_t portid, uint8_t if_up)
{
    int ret = 0;

    RTE_LOG(INFO, VROUTER, "Configuring port %d %s\n",
                    (int)portid, if_up ? "UP" : "DOWN");
    if (portid >= rte_eth_dev_count() || portid >= RTE_MAX_ETHPORTS) {
        RTE_LOG(ERR, VROUTER, "Invalid port id %d\n", portid);
        return -EINVAL;
    }

    /* TODO: not implemented */

    return 0;
}

inline int
vr_dpdk_ring_create(unsigned port_id, struct rte_ring **ring, const char *port_name)
{
    int ret;
    char ring_name[IFNAMSIZ];

    /* check if already created */
    if (NULL != *ring)
        return 0;

    RTE_LOG(INFO, VROUTER, "\tcreating %s %u TX ring\n",
        port_name, port_id);
    ret = snprintf(ring_name, sizeof(ring_name), "ring_%s%u",
            port_name, port_id);
    if (ret >= sizeof(ring_name)) {
        RTE_LOG(ERR, VROUTER, "Could not create ring name for "
            "%s%u (%d)\n", port_name, port_id, ret);
        return -ENOMEM;
    }
    /* create multi-producer multi-consumer ring */
    *ring = rte_ring_create(ring_name, VR_DPDK_TX_RING_SZ, SOCKET_ID_ANY, 0);
    if (!(*ring)) {
        RTE_LOG(ERR, VROUTER, "Could not create ring for "
            "%s%u (%d)\n", port_name, port_id, errno);
        return -ENOMEM;
    }
    return 0;
}


int
vr_dpdk_kni_init(unsigned port_id, struct vr_interface *vif)
{
    int ret;
    struct rte_eth_dev_info dev_info;
    struct rte_kni_conf kni_conf;
    struct vif_port *port = &vr_dpdk.ports[port_id];
    struct rte_kni *kni;

    /* get device info */
    memset(&dev_info, 0, sizeof(dev_info));
    rte_eth_dev_info_get(port_id, &dev_info);

    /* create KNI configuration */
    memset(&kni_conf, 0, sizeof(kni_conf));
    strncpy(kni_conf.name, vif->vif_name, sizeof(kni_conf.name));

    kni_conf.addr = dev_info.pci_dev->addr;
    kni_conf.id = dev_info.pci_dev->id;
    kni_conf.group_id = port_id;
    kni_conf.mbuf_size = VR_DPDK_MAX_PACKET_SZ;

    /* KNI options */
    struct rte_kni_ops kni_ops = {
        .port_id = port_id,
        .change_mtu = dpdk_kni_change_mtu,
        .config_network_if = dpdk_kni_config_network_interface,
    };

    /* create KNI interface */
    kni = rte_kni_alloc(vr_dpdk.pktmbuf_pool,
        &kni_conf, &kni_ops);
    if (kni == NULL) {
        ret = -errno;
        goto err;
    }
    /* store vif for feature reference */
    port->vip_kni_vif = vif;

    /* create KNI ring */
    ret = vr_dpdk_ring_create(port_id, &(port->vip_kni_ring), "vhost");
    if (ret) {
        rte_kni_release(kni);
        goto err;
    }

    rte_wmb();

    port->vip_kni = kni;
    /* update vif OS index */
    vif->vif_os_idx = if_nametoindex(vif->vif_name);

    return 0;
err:
    RTE_LOG(ERR, VROUTER, "Error creating KNI %s (%d)\n",
                            kni_conf.name, ret);
    return ret;
}

int
vr_dpdk_port_init(uint8_t port_id)
{
    int ret;
    struct ether_addr mac;
    struct rte_eth_dev_info dev_info;
    unsigned tx_index, nb_tx, lcore_id;
    struct vif_port *port = &vr_dpdk.ports[port_id];
    struct vr_interface *vif = port->vip_vif;

    rte_eth_macaddr_get(port_id, &mac);
    RTE_LOG(INFO, VROUTER, "Initialising port %u MAC " MAC_FORMAT " ...\n",
                (unsigned)port_id, MAC_VALUE(mac.addr_bytes));
    fflush(stdout);

    /* Get device info to find out the number of hardware TX queues */
    memset(&dev_info, 0, sizeof(dev_info));
    rte_eth_dev_info_get(port_id, &dev_info);

    /* Use up to nb_lcores TX queues */
    nb_tx = RTE_MIN(dev_info.max_tx_queues, vr_dpdk.nb_lcores);
    ret = rte_eth_dev_configure(port_id, 1, nb_tx, &port_conf);
    if (ret < 0) {
        RTE_LOG(ERR, VROUTER, "Could not configure port%u (%d)\n",
                    (unsigned)port_id, ret);
        goto fail;
    }

    /* check if the device supports checksum offloading */
    if (DEV_TX_OFFLOAD_IPV4_CKSUM & dev_info.tx_offload_capa) {
        vif->vif_flags |= VIF_FLAG_TX_CSUM_OFFLOAD;
    }

    ret = rte_eth_rx_queue_setup(port_id, 0, VR_DPDK_NB_RXD,
        rte_eth_dev_socket_id(port_id), &rx_conf, vr_dpdk.pktmbuf_pool);
    if (ret < 0) {
        RTE_LOG(ERR, VROUTER, "Could not setup up RX queue for "
                "port%u (%d)\n", (unsigned)port_id, ret);
        goto fail;
    }

    for (tx_index = 0; tx_index < nb_tx; tx_index++) {
        ret = rte_eth_tx_queue_setup(port_id, tx_index, VR_DPDK_NB_TXD,
            rte_eth_dev_socket_id(port_id), &tx_conf);
        if (ret < 0) {
            RTE_LOG(ERR, VROUTER, "Could not setup up TX queue %u for "
                "port%u (%d)\n", tx_index, (unsigned)port_id, ret);
            goto fail;
        }
    }

    ret = rte_eth_dev_start(port_id);
    if (ret < 0) {
        RTE_LOG(ERR, VROUTER, "Could not start port%u (%d)\n",
                        (unsigned)port_id, ret);
        goto fail;
    }

    /* TODO: promisc mode */
    /* KNI generates random MACs for e1000e NICs, so we need this
     * option enabled for the development on servers with those NICs
     */
    /* rte_eth_promiscuous_enable(port_id); */

    /* Save the number of TX queues */
    port->vip_nb_tx = nb_tx;

    /* Create TX ring if necessary */
    if (vr_dpdk.nb_lcores > nb_tx) {
        RTE_LOG(WARNING, VROUTER, "\tthere are more lcores than port TX queues "
            "(%u > %u)\n", vr_dpdk.nb_lcores, nb_tx);
        if (unlikely(vr_dpdk_ring_create(port_id,
            &vr_dpdk.ports[port_id].vip_tx_ring, "port"))) {
            return -ENOMEM;
        }
    }

    return 0;
fail:
    return -EFAULT;
}

/* Increase number of errors (dropped packets) on interface */
/* TODO: update drop reasons */
static void
dpdk_tx_errors_inc(struct vr_interface *vif, unsigned drops)
{
    /* pointer to vif statistics */
    struct vr_interface_stats *vis;

    RTE_VERIFY(NULL != vif);

    vis = &vif->vif_stats[rte_lcore_id()];
    RTE_VERIFY(NULL != vis);

    vis->vis_oerrors += drops;
}

/* Burst TX mbufs to KNI interface or free mbufs */
static int
dpdk_kni_burst_tx(struct vr_interface *vif, struct rte_kni *kni,
    struct rte_mbuf **tx_pkts, unsigned nb_pkts)
{
    int ret = rte_kni_tx_burst(kni, tx_pkts, nb_pkts);
    if (unlikely(ret < nb_pkts)) {
        dpdk_tx_errors_inc(vif, nb_pkts - ret);
        do {
            rte_pktmbuf_free(tx_pkts[ret]);
        } while (++ret < nb_pkts);
        return -1;
    }
    return 0;
}

/* Burst TX ring to KNI interface or free mbufs */
static int
dpdk_kni_ring_tx(struct vr_interface*vif, struct rte_kni *kni, struct rte_ring *ring)
{
    struct rte_mbuf *pkt_burst[VR_DPDK_PKT_BURST_SZ];
    int nb_tx;

    do {
        nb_tx = rte_ring_dequeue_burst(ring, (void *)&pkt_burst[0],
            VR_DPDK_PKT_BURST_SZ);
        if (unlikely(nb_tx > 0)) {
            dpdk_kni_burst_tx(vif, kni,
                pkt_burst, nb_tx);
        }
    } while (unlikely(rte_ring_count(ring)));

    return 0;
}

/* Burst TX mbufs to ethdev or free mbufs */
static int
dpdk_eth_burst_tx(struct vr_interface *vif, unsigned port_id, unsigned queue_id,
    struct rte_mbuf **tx_pkts, unsigned nb_pkts)
{
    int ret = rte_eth_tx_burst(port_id, queue_id,
        tx_pkts, nb_pkts);
    if (unlikely(ret < nb_pkts)) {
        dpdk_tx_errors_inc(vif, nb_pkts - ret);
        do {
            rte_pktmbuf_free(tx_pkts[ret]);
        } while (++ret < nb_pkts);
        return -1;
    }
    return 0;
}

/* Burst TX ring to ethdev or free mbufs */
static int
dpdk_eth_ring_tx(struct vr_interface *vif, unsigned port_id, unsigned queue_id,
    struct rte_ring *ring)
{
    struct rte_mbuf *pkt_burst[VR_DPDK_PKT_BURST_SZ];
    int nb_tx;

    do {
        nb_tx = rte_ring_dequeue_burst(ring, (void *)&pkt_burst[0],
            VR_DPDK_PKT_BURST_SZ);
        if (likely(nb_tx > 0)) {
            dpdk_eth_burst_tx(vif, port_id, queue_id,
                pkt_burst, nb_tx);
        }
    } while (unlikely(rte_ring_count(ring)));

    return 0;
}

/* Add an mbuf burst to the ring or free the mbufs */
static void
dpdk_burst_enqueue(struct vr_interface *vif, struct rte_ring *ring, struct rte_mbuf **pkts,
    unsigned nb_pkts)
{
    int ret = rte_ring_enqueue_burst(ring, (void **)pkts, nb_pkts);
    if (unlikely(ret < nb_pkts)) {
        dpdk_tx_errors_inc(vif, nb_pkts - ret);
        do {
            rte_pktmbuf_free(pkts[ret]);
        } while (++ret < nb_pkts);
    }
}

/* Drain eth TX queue */
int
vr_dpdk_eth_tx_queue_drain(struct vif_port *port, struct lcore_ctx *lcore_ctx)
{
    struct vr_interface *vif = port->vip_vif;
    unsigned port_id = port->vip_id;
    struct rte_ring *tx_ring = port->vip_tx_ring;
    int tx_index = lcore_ctx->lcore_tx_index[port_id];
    struct rte_mbuf **tx_burst = lcore_ctx->lcore_port_tx[port_id];
    unsigned nb_tx_burst = lcore_ctx->lcore_port_tx_len[port_id];

    RTE_VERIFY(NULL != lcore_ctx);

    if ((vif->vif_type == VIF_TYPE_AGENT) &&
            (vif->vif_transport == VIF_TRANSPORT_SOCKET)) {
        vr_dpdk_packet_tx(port);
        return 0;
    }


    if (likely(NULL == tx_ring)) {
        /* if we have no ring -> just transmit the burst */
        RTE_VERIFY(0 <= tx_index);
        if (likely(nb_tx_burst)) {
            dpdk_eth_burst_tx(port->vip_vif, port_id, tx_index, tx_burst, nb_tx_burst);
        }
    } else {
        /* if we have ring -> enqueue pointers there */
        if (likely(nb_tx_burst)) {
            dpdk_burst_enqueue(port->vip_vif, tx_ring, tx_burst, nb_tx_burst);
        }
        if (likely(-1 != tx_index)) {
            /* transmit the queue */
            if (likely(rte_ring_count(tx_ring))) {
                dpdk_eth_ring_tx(port->vip_vif, port_id, tx_index, tx_ring);
            }
        }
    }

    /* reset burst size */
    lcore_ctx->lcore_port_tx_len[port_id] = 0;

    return 0;
}

/* Drain KNI TX queue */
int
vr_dpdk_kni_tx_queue_drain(struct vif_port *port, struct lcore_ctx *lcore_ctx)
{
    unsigned port_id = port->vip_id;
    struct rte_ring *tx_ring = port->vip_kni_ring;
    int tx_index = lcore_ctx->lcore_tx_index[port_id];
    struct rte_kni *kni = port->vip_kni;
    struct rte_mbuf **tx_burst = lcore_ctx->lcore_kni_tx[port_id];
    unsigned nb_tx_burst = lcore_ctx->lcore_kni_tx_len[port_id];

    RTE_VERIFY(NULL != lcore_ctx);
    RTE_VERIFY(NULL != kni);

    if (likely(NULL == tx_ring)) {
        /* if we have no ring -> just transmit the burst */
        RTE_VERIFY(0 <= tx_index);
        if (unlikely(nb_tx_burst)) {
            dpdk_kni_burst_tx(port->vip_kni_vif, kni, tx_burst, nb_tx_burst);
        }
    } else {
        /* if we have ring -> enqueue pointers there */
        if (unlikely(nb_tx_burst)) {
            dpdk_burst_enqueue(port->vip_kni_vif, tx_ring, tx_burst, nb_tx_burst);
        }
        if (unlikely(-1 != tx_index)) {
            /* transmit the queue */
            if (unlikely(rte_ring_count(tx_ring))) {
                dpdk_kni_ring_tx(port->vip_kni_vif, kni, tx_ring);
            }
        }
    }

    /* reset burst size */
    lcore_ctx->lcore_kni_tx_len[port_id] = 0;

    return 0;
}
