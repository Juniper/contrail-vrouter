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
 * vr_dpdk_interface.c -- vRouter interface callbacks
 *
 */

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <stdbool.h>
#include <net/if.h>

#include "vr_queue.h"
#include "vr_dpdk.h"
#include "vr_dpdk_usocket.h"


/* Add fabric interface */
static int
dpdk_fabric_if_add(struct vr_interface *vif)
{
    uint8_t port_id = vif->vif_os_idx;
    int ret;
    struct ether_addr mac_addr;
    struct rte_eth_dev_info dev_info;
    uint16_t nb_rx_queues, nb_tx_queues;

    /* get interface MAC address */
    memset(&mac_addr, 0, sizeof(mac_addr));
    rte_eth_macaddr_get(port_id, &mac_addr);

    RTE_LOG(INFO, VROUTER, "Adding vif %u eth device %" PRIu8 " MAC " MAC_FORMAT "\n",
                vif->vif_idx, port_id, MAC_VALUE(mac_addr.addr_bytes));

    /* check if ethdev is already added */
    if (vr_dpdk.eth_devs[vif->vif_os_idx] != NULL) {
        RTE_LOG(ERR, VROUTER, "\terror adding eth device %s: already exists\n",
                vif->vif_name);
        return -EEXIST;
    }

    /* get device info to find out the number of hardware TX queues */
    memset(&dev_info, 0, sizeof(dev_info));
    rte_eth_dev_info_get(port_id, &dev_info);

    /* use no more queues than lcores */
    nb_rx_queues = RTE_MIN(RTE_MIN(dev_info.max_rx_queues, vr_dpdk.nb_lcores),
                    VR_DPDK_MAX_RX_QUEUES);
    nb_tx_queues = RTE_MIN(RTE_MIN(dev_info.max_tx_queues, vr_dpdk.nb_lcores),
                    VR_DPDK_MAX_TX_QUEUES);

    /* init eth device */
    ret = vr_dpdk_ethdev_init(vif, nb_rx_queues, nb_tx_queues);
    if (ret != 0)
        return ret;

    /* add interface to the table of eth devices */
    vr_dpdk.eth_devs[vif->vif_os_idx] = &rte_eth_devices[vif->vif_os_idx];

    /* schedule RX/TX queues */
    return vr_dpdk_lcore_if_schedule(vif, nb_rx_queues, &vr_dpdk_eth_rx_queue_init,
            nb_tx_queues, &vr_dpdk_eth_tx_queue_init);
}

/* Add vhost interface */
static int
dpdk_vhost_if_add(struct vr_interface *vif)
{
    uint8_t port_id = vif->vif_os_idx;
    int ret;
    struct ether_addr mac_addr;

    /* get interface MAC address */
    memset(&mac_addr, 0, sizeof(mac_addr));
    rte_eth_macaddr_get(port_id, &mac_addr);

    RTE_LOG(INFO, VROUTER, "Adding vif %u KNI device %s at eth device %" PRIu8
                " MAC " MAC_FORMAT "\n",
                vif->vif_idx, vif->vif_name, port_id, MAC_VALUE(mac_addr.addr_bytes));

    /* check if KNI is already added */
    if (vr_dpdk.knis[vif->vif_idx] != NULL) {
        RTE_LOG(ERR, VROUTER, "\terror adding KNI device %s: already exist\n",
                vif->vif_name);
        return -EEXIST;
    }

    /* init KNI */
    ret = vr_dpdk_knidev_init(vif);
    if (ret != 0)
        return ret;

    /* add interface to the table of KNIs */
    vr_dpdk.knis[vif->vif_idx] = vif->vif_os;

    /* add interface to the table of vHosts */
    vr_dpdk.vhosts[vif->vif_idx] = vrouter_get_interface(vif->vif_rid, vif->vif_idx);

    /* schedule KNI queues */
    return vr_dpdk_lcore_if_schedule(vif, 1, &vr_dpdk_kni_rx_queue_init,
            1, &vr_dpdk_kni_tx_queue_init);
}

/* vRouter callback */
static int
dpdk_if_add(struct vr_interface *vif)
{
    int ret = 0;

    if ((vif->vif_type == VIF_TYPE_AGENT) &&
            (vif->vif_transport == VIF_TRANSPORT_SOCKET)) {
        ret = dpdk_packet_socket_init();
        if (ret)
            return ret;

        vr_usocket_attach_vif(vr_dpdk.packet_transport, vif);
        return 0;
    }

    /* get interface name */
    if (vif->vif_flags & VIF_FLAG_PMD) {
        /* check DPDK port index */
        if (vif->vif_os_idx >= rte_eth_dev_count()) {
            RTE_LOG(ERR, VROUTER, "Invalid eth device index %u (must be less than %u)\n",
                (unsigned)vif->vif_os_idx, (unsigned)rte_eth_dev_count());
            return -ENOENT;
        }
    } else {
        RTE_LOG(ERR, VROUTER, "Error adding interface %s:\n"
            "\tThis version of vRouter supports DPDK eth devices only.\n"
            "\tPlease use an eth device index and --pmd flag instead.\n",
                vif->vif_name);
        return -EFAULT;
    } /* VIF_FLAG_PMD */

    if (vif_is_fabric(vif) || vif_is_tap(vif)) {
        return dpdk_fabric_if_add(vif);
    }
    else if (vif_is_vhost(vif)) {
        return dpdk_vhost_if_add(vif);
    }

    RTE_LOG(ERR, VROUTER, "Unknown interface type %hu\n", vif->vif_type);
    return -EFAULT;
}

static int
dpdk_if_del(struct vr_interface *vif)
{
    if ((vif->vif_type == VIF_TYPE_AGENT) &&
            (vif->vif_transport == VIF_TRANSPORT_SOCKET))
        dpdk_packet_socket_close();

    return 0;
}

/* vRouter callback */
static int
dpdk_if_del_tap(struct vr_interface *vif)
{
    /* TODO: not implemented */
    return 0;
}


/* vRouter callback */
static int
dpdk_if_add_tap(struct vr_interface *vif)
{
    /* TODO: not implemented */
    return 0;
}

static inline void
dpdk_hw_checksum_at_offset(struct vr_packet *pkt, unsigned offset)
{
    struct rte_mbuf *m = vr_dpdk_pkt_to_mbuf(pkt);
    struct vr_ip *iph = (struct vr_ip *)pkt_data_at_offset(pkt, offset);
    unsigned iph_len = iph->ip_hl * 4;
    struct vr_tcp *tcph;
    struct vr_udp *udph;

    RTE_VERIFY(0 < offset);

    /* calculate IP checksum */
    m->ol_flags |= PKT_TX_IP_CKSUM;
    /* Note: Intel NICs need the checksum set to zero
     * and proper l2/l3 lens to be set.
     */
    iph->ip_csum = 0;
    m->pkt.vlan_macip.f.l2_len = offset - rte_pktmbuf_headroom(m);
    m->pkt.vlan_macip.f.l3_len = iph_len;

    RTE_LOG(DEBUG, VROUTER, "Inner offset: l2_len = %d, l3_len = %d\n",
        (int)m->pkt.vlan_macip.f.l2_len,
        (int)m->pkt.vlan_macip.f.l3_len);

    /* calculate TCP/UDP checksum */
    if (iph->ip_proto == VR_IP_PROTO_TCP) {
        m->ol_flags |= PKT_TX_TCP_CKSUM;
        tcph = (struct vr_tcp *)pkt_data_at_offset(pkt, offset + iph_len);
        tcph->tcp_csum = 0;

    } else if (iph->ip_proto == VR_IP_PROTO_UDP) {
        m->ol_flags |= PKT_TX_UDP_CKSUM;
        udph = (struct vr_udp *)pkt_data_at_offset(pkt, offset + iph_len);
        udph->udp_csum = 0;
    }
}

static inline void
dpdk_sw_checksum_at_offset(struct vr_packet *pkt, unsigned offset)
{
    /* pointer to IP header */
    struct vr_ip *iph = (struct vr_ip *)pkt_data_at_offset(pkt, offset);

    RTE_VERIFY(0 < offset);

    /* calculate IP checksum */
    iph->ip_csum = vr_ip_csum(iph);

    /* TODO: TCP/UDP checksums */
}

static inline void
dpdk_hw_checksum(struct vr_packet *pkt)
{
    /* if a tunnel */
    if (VP_TYPE_IPOIP == pkt->vp_type) {
        /* calculate outer checksum in soft */
        /* TODO: vlan support */
        dpdk_sw_checksum_at_offset(pkt,
            pkt->vp_data + sizeof(struct ether_hdr));
        /* calculate inner checksum in hardware */
        dpdk_hw_checksum_at_offset(pkt,
               pkt_get_inner_network_header_off(pkt));
    } else {
        /* normal IP packet */
        /* TODO: vlan support */
        dpdk_hw_checksum_at_offset(pkt,
            pkt->vp_data + sizeof(struct ether_hdr));
    }
}


static inline void
dpdk_sw_checksum(struct vr_packet *pkt)
{
    /* if a tunnel */
    if (VP_TYPE_IPOIP == pkt->vp_type) {
        /* calculate outer checksum */
        /* TODO: vlan support */
        dpdk_sw_checksum_at_offset(pkt,
            pkt->vp_data + sizeof(struct ether_hdr));
        /* calculate inner checksum */
        dpdk_sw_checksum_at_offset(pkt,
               pkt_get_inner_network_header_off(pkt));
    } else {
        /* normal IP packet */
        /* TODO: vlan support */
        dpdk_sw_checksum_at_offset(pkt,
            pkt->vp_data + sizeof(struct ether_hdr));
    }
}

/* TX packet callback */
static int
dpdk_if_tx(struct vr_interface *vif, struct vr_packet *pkt)
{
    const unsigned lcore_id = rte_lcore_id();
    struct vr_dpdk_lcore * const lcore = vr_dpdk.lcores[lcore_id];
    struct rte_mbuf *m = vr_dpdk_pkt_to_mbuf(pkt);
    unsigned vif_idx = vif->vif_idx;
    struct vr_dpdk_tx_queue *tx_queue = &lcore->lcore_tx_queues[vif_idx];

    RTE_LOG(DEBUG, VROUTER,"%s: TX packet to interface %s\n", __func__,
        vif->vif_name);

    /* reset mbuf data pointer and length */
    m->pkt.data = pkt_data(pkt);
    m->pkt.data_len = pkt_head_len(pkt);
    /* TODO: use pkt_len instead? */
    m->pkt.pkt_len = pkt_head_len(pkt);

    /* TODO: Checksums
     * With DPDK pktmbufs we don't know if the checksum is incomplete,
     * i.e. there is no direct equivalent of skb->ip_summed field.
     *
     * So we just rely on VP_FLAG_CSUM_PARTIAL flag here, assuming
     * the flag is set when we need to calculate inner or outer packet
     * checksum.
     *
     * This is not elegant and need to be addressed.
     * See dpdk/app/test-pmd/csumonly.c for more checksum examples
     */
    if (unlikely(pkt->vp_flags & VP_FLAG_CSUM_PARTIAL)) {
        /* if NIC supports checksum offload */
        if(vif->vif_flags & VIF_FLAG_TX_CSUM_OFFLOAD)
            dpdk_hw_checksum(pkt);
        else
            dpdk_sw_checksum(pkt);
    } else if(VP_TYPE_IPOIP == pkt->vp_type) {
        /* always calculate outer checksum for tunnels */
        /* if NIC supports checksum offload */
        if(vif->vif_flags & VIF_FLAG_TX_CSUM_OFFLOAD) {
            /* TODO: vlan support */
            dpdk_hw_checksum_at_offset(pkt,
                pkt->vp_data + sizeof(struct ether_hdr));
        } else {
            /* TODO: vlan support */
            dpdk_sw_checksum_at_offset(pkt,
                pkt->vp_data + sizeof(struct ether_hdr));
        }
    }

#ifdef VR_DPDK_TX_PKT_DUMP
    rte_pktmbuf_dump(m, 0x60);
#endif

    tx_queue->txq_ops.f_tx(tx_queue->txq_queue_h, m);

    return 0;
}

static int
dpdk_if_rx(struct vr_interface *vif, struct vr_packet *pkt)
{
    const unsigned lcore_id = rte_lcore_id();
    struct vr_dpdk_lcore * const lcore = vr_dpdk.lcores[lcore_id];
    struct rte_mbuf *m = vr_dpdk_pkt_to_mbuf(pkt);
    unsigned vif_idx = vif->vif_idx;
    struct vr_dpdk_tx_queue *tx_queue = &lcore->lcore_tx_queues[vif_idx];

    RTE_LOG(DEBUG, VROUTER,"%s: TX packet to interface %s\n", __func__,
        vif->vif_name);

    /* reset mbuf data pointer and length */
    m->pkt.data = pkt_data(pkt);
    m->pkt.data_len = pkt_head_len(pkt);
    /* TODO: use pkt_len instead? */
    m->pkt.pkt_len = pkt_head_len(pkt);

#ifdef VR_DPDK_TX_PKT_DUMP
    rte_pktmbuf_dump(m, 0x60);
#endif

    tx_queue->txq_ops.f_tx(tx_queue->txq_queue_h, m);

    return 0;
}

static int
dpdk_if_get_settings(struct vr_interface *vif,
        struct vr_interface_settings *settings)
{
    /* TODO: not implemented */
    settings->vis_speed = 1000;
    settings->vis_duplex = 1;
    return 0;
}

static unsigned int
dpdk_if_get_mtu(struct vr_interface *vif)
{
    uint8_t port_id;
    uint16_t mtu;

    port_id = vif->vif_os_idx;

    if (rte_eth_dev_get_mtu(port_id, &mtu) == 0)
        return mtu;

    return vif->vif_mtu;
}

static void
dpdk_if_unlock(void)
{
    /* TODO: not implemented */
    return;
}

static void
dpdk_if_lock(void)
{
    /* TODO: not implemented */
    return;
}

struct vr_host_interface_ops dpdk_interface_ops = {
    .hif_lock           =    dpdk_if_lock,      /* not implemented */
    .hif_unlock         =    dpdk_if_unlock,    /* not implemented */
    .hif_add            =    dpdk_if_add,
    .hif_del            =    dpdk_if_del,       /* not implemented */
    .hif_add_tap        =    dpdk_if_add_tap,   /* not implemented */
    .hif_del_tap        =    dpdk_if_del_tap,   /* not implemneted */
    .hif_tx             =    dpdk_if_tx,
    .hif_rx             =    dpdk_if_rx,
    .hif_get_settings   =    dpdk_if_get_settings, /* always returns speed 1000 duplex 1 */
    .hif_get_mtu        =    dpdk_if_get_mtu,
};

void
vr_host_vif_init(struct vrouter *router)
{
    return;
}

struct vr_host_interface_ops *
vr_host_interface_init(void)
{
    return &dpdk_interface_ops;
}

void
vr_host_interface_exit(void)
{
    return;
}
