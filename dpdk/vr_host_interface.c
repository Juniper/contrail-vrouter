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
 * vr_host_interface.c -- DPDK specific handling of vrouter interfaces
 *
 */

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <net/if.h>

#include "vr_dpdk.h"

static struct rte_pci_device *
dpdk_pci_dev_get(struct rte_pci_addr *pci)
{
    struct rte_pci_device *dev;

    TAILQ_FOREACH(dev, &pci_device_list, next)
        if ((dev->addr.domain == pci->domain) &&
            (dev->addr.bus == pci->bus) &&
            (dev->addr.devid == pci->devid) &&
            (dev->addr.function == pci->function))
            return dev;

    return NULL;
}

static struct rte_eth_dev *
dpdk_eth_dev_get(struct rte_pci_device *dev)
{
    unsigned i;

    for (i=0; i< rte_eth_dev_count(); i++)
        if (rte_eth_devices[i].pci_dev == dev)
            return &rte_eth_devices[i];
    rte_panic("No port found for device " PCI_PRI_FMT,
                    dev->addr.domain, dev->addr.bus,
                    dev->addr.devid, dev->addr.function);
}

static uint8_t
dpdk_port_id_get(struct rte_pci_device *dev)
{
    return dpdk_eth_dev_get(dev)->data->port_id;
}

static int
dpdk_phys_if_add(struct vr_interface *vif)
{
    struct rte_pci_addr pci;
    struct rte_pci_device *dev;
    uint8_t port_id;
    struct vif_port *port;
    struct rte_eth_dev *eth;

    if (vif->vif_flags & VIF_FLAG_PMD) {
        /* use DPDK port */
        port_id = vif->vif_os_idx;
        eth = &rte_eth_devices[port_id];
        port = &vr_dpdk.ports[port_id];
    } else {
        RTE_LOG(ERR, VROUTER, "Error adding physical interface %s\n"
            "This version of vRouter only supports DPDK ports.\n",
            "Please use port index and --pmd flag.\n",
            vif->vif_name);
        return -EFAULT;
    } /* VIF_FLAG_PMD */

    strncpy(port->vip_name, vif->vif_name, sizeof(port->vip_name));
    port->vip_id = port_id;
    port->vip_addr = pci;
    port->vip_eth = eth;
    vif->vif_os = port;
    port->vip_vif = vif;

    if (unlikely(vr_dpdk_port_init(port_id)))
        return -ENOLINK;

    return 0;
}

static int
dpdk_kni_if_add(struct vr_interface *vif)
{
    int port_id = vif->vif_os_idx;

    RTE_LOG(INFO, VROUTER, "Initialising KNI interface for port %u ...\n", port_id);

    /* add KNI to DPDK ports only */
    if (!(vif->vif_flags & VIF_FLAG_PMD)) {
        RTE_LOG(ERR, VROUTER, "Please use --pmd option to specify"
               " DPDK port index\n");
        return -ENOENT;
    }

    vif->vif_os = &vr_dpdk.ports[port_id];
    /* add new KNI interface */
    return vr_dpdk_kni_init(port_id, vif);
}

static int
dpdk_pcap_if_add(struct vr_interface *vif)
{
    RTE_LOG(ERR, VROUTER, "Tap interfaces are not supported\n");
    return -EINVAL;
}

/* Schedule vif to one of the lcores */
static void
dpdk_vif_schedule(struct vr_interface *vif)
{
    int i;
    unsigned lcore_id;
    struct lcore_ctx *lcore_ctx;
    struct lcore_ctx *min_lcore_ctx;
    unsigned min_lcore_id = RTE_MAX_LCORE;
    unsigned min_nb_rx_ports = RTE_MAX_ETHPORTS;
    struct vif_port *port = vif->vif_os;
    unsigned port_id = port->vip_id;
    unsigned tx_index, nb_tx;

    /* find an lcore with the least number of ports assigned */
    RTE_LCORE_FOREACH(lcore_id) {
        lcore_ctx = &vr_dpdk.lcores[lcore_id];
        if (lcore_ctx->lcore_nb_rx_ports < min_nb_rx_ports) {
            min_nb_rx_ports = lcore_ctx->lcore_nb_rx_ports;
            min_lcore_id = lcore_id;
        }
    }
    if (unlikely(RTE_MAX_LCORE == min_lcore_id)) {
        RTE_LOG(ERR, VROUTER, "Error assigning port to lcore\n");
        return;
    }
    min_lcore_ctx = &vr_dpdk.lcores[min_lcore_id];

    RTE_LOG(INFO, VROUTER, "Assigning port %u to lcore %u:\n",
        port_id, min_lcore_id);

    /* Assign hardware queues to lcores */
    tx_index = 0;
    nb_tx = port->vip_nb_tx;
    lcore_id = min_lcore_id;
    do {
        lcore_ctx = &vr_dpdk.lcores[lcore_id];
        if (tx_index < nb_tx) {
            lcore_ctx->lcore_tx_index[port_id] = tx_index;
            RTE_LOG(INFO, VROUTER, "\tlcore %u - TX queue %u\n",
                lcore_id, tx_index);
            tx_index++;
        } else {
            lcore_ctx->lcore_tx_index[port_id] = -1;
            RTE_LOG(INFO, VROUTER, "\tlcore %u - TX ring\n", lcore_id);
        }
        /* do not skip master lcore but wrap */
        lcore_id = rte_get_next_lcore(lcore_id, 0, 1);
    } while (lcore_id != min_lcore_id);

    /* find an empty port slot in the array */
    for (i = 0; i < min_nb_rx_ports; i++) {
        if (unlikely(NULL == min_lcore_ctx->lcore_rx_ports[i]))
            /* empty slot found */
            break;
    }
    /* increase number of ports if nescessary */
    if (i == min_lcore_ctx->lcore_nb_rx_ports)
        min_lcore_ctx->lcore_nb_rx_ports++;



    /* add port to the lcore list */
    rte_wmb();
    min_lcore_ctx->lcore_rx_ports[i] = port;
    port->vip_lcore_ctx = min_lcore_ctx;
}

static int
dpdk_if_add(struct vr_interface *vif)
{
    int ret = 0;

    /* get interface name */
    if (vif->vif_flags & VIF_FLAG_PMD) {
        if (vif->vif_os_idx >= rte_eth_dev_count()) {
            RTE_LOG(ERR, VROUTER, "DPDK port index is out of range %u\n",
                            vif->vif_os_idx);
            return -ENOENT;
        }
    } else {
        if (if_indextoname(vif->vif_os_idx, vif->vif_name) == NULL) {
            RTE_LOG(ERR, VROUTER, "No interface with index %u\n",
                            vif->vif_os_idx);
            return -ENOENT;
        }
    }

    if (vif_is_fabric(vif)) {
        ret = dpdk_phys_if_add(vif);
    }
    else if (vif_is_tap(vif)) {
        if (vif->vif_flags & VIF_FLAG_PMD)
            ret = dpdk_phys_if_add(vif);
        else
            ret = dpdk_pcap_if_add(vif);
    }
    else if (vif_is_vhost(vif)) {
        /* do not schedule KNI interface */
        return dpdk_kni_if_add(vif);
    }
    else {
        RTE_LOG(ERR, VROUTER, "Unknown interface type %hu\n",
            vif->vif_type);
    }

    /* return error if any */
    if (unlikely(ret))
        return ret;

    /* schedule new port to one of the cores */
    dpdk_vif_schedule(vif);

    return 0;
}

static int
dpdk_if_del(struct vr_interface *vif)
{
    /* TODO: not implemented */
    return 0;
}

static int
dpdk_if_del_tap(struct vr_interface *vif)
{
    /* TODO: not implemented */
    return 0;
}


static int
dpdk_if_add_tap(struct vr_interface *vif)
{
    /* TODO: not implemented */
    return 0;
}

static inline void
dpdk_hw_checksum_at_offset(struct vr_packet *pkt, unsigned offset)
{
    /* pointer to mbuf */
    struct rte_mbuf *m = vr_dpdk_pkt_to_mbuf(pkt);
    /* pointer to IP header */
    struct vr_ip *iph = (struct vr_ip *)pkt_data_at_offset(pkt, offset);
    /* size of IP header */
    unsigned iph_len = iph->ip_hl * 4;
    /* pointer to TCP header */
    struct vr_tcp *tcph;
    /* pointer to UDP header */
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
        RTE_LOG(DEBUG, VROUTER,"%s: tunnel\n",  __func__);
        /* calculate outer checksum in soft */
        /* TODO: vlan support */
        dpdk_sw_checksum_at_offset(pkt,
            pkt->vp_data + sizeof(struct ether_hdr));
        /* calculate inner checksum in hardware */
        dpdk_hw_checksum_at_offset(pkt,
               pkt_get_inner_network_header_off(pkt));
    } else {
        RTE_LOG(DEBUG, VROUTER,"%s: normal IP\n",  __func__);
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
        RTE_LOG(DEBUG, VROUTER,"%s: tunnel\n",  __func__);
        /* calculate outer checksum */
        /* TODO: vlan support */
        dpdk_sw_checksum_at_offset(pkt,
            pkt->vp_data + sizeof(struct ether_hdr));
        /* calculate inner checksum */
        dpdk_sw_checksum_at_offset(pkt,
               pkt_get_inner_network_header_off(pkt));
    } else {
        RTE_LOG(DEBUG, VROUTER,"%s: normal IP\n",  __func__);
        /* normal IP packet */
        /* TODO: vlan support */
        dpdk_sw_checksum_at_offset(pkt,
            pkt->vp_data + sizeof(struct ether_hdr));
    }
}

static int
dpdk_if_tx(struct vr_interface *vif, struct vr_packet *pkt)
{
    /* currect lcore id */
    const unsigned lcore_id = rte_lcore_id();
    /* current lcore context */
    struct lcore_ctx * const lcore_ctx = &vr_dpdk.lcores[lcore_id];
    /* pointer to vif_port structure */
    struct vif_port * const port = (struct vif_port *)vif->vif_os;
    /* port index */
    const unsigned port_id = port->vip_id;
    /* pointer to mbuf */
    struct rte_mbuf *m = vr_dpdk_pkt_to_mbuf(pkt);
    /* tx burst */
    struct rte_mbuf ** const tx_burst = lcore_ctx->lcore_port_tx[port_id];
    /* tx burst size */
    unsigned nb_tx_burst = lcore_ctx->lcore_port_tx_len[port_id];

    RTE_VERIFY(nb_tx_burst < VR_DPDK_PKT_BURST_SZ);

    RTE_LOG(DEBUG, VROUTER,"%s: TX %u packet(s) to port %hhu\n",
         __func__, nb_tx_burst + 1, port_id);

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
        if(vif->vif_flags & VIF_FLAG_TX_CSUM_OFFLOAD) {
            dpdk_hw_checksum(pkt);
        } else {
            dpdk_sw_checksum(pkt);
        }
    } else if(VP_TYPE_IPOIP == pkt->vp_type) {
        /* always calculate outer checksum for tunnels */
        /* if NIC supports checksum offload */
        if(vif->vif_flags & VIF_FLAG_TX_CSUM_OFFLOAD) {
            RTE_LOG(DEBUG, VROUTER,"%s: tunnel HW outer checksum\n",
                 __func__);
            /* TODO: vlan support */
            dpdk_hw_checksum_at_offset(pkt,
                pkt->vp_data + sizeof(struct ether_hdr));
        } else {
            RTE_LOG(DEBUG, VROUTER,"%s: tunnel SW outer checksum\n",
                 __func__);
            /* TODO: vlan support */
            dpdk_sw_checksum_at_offset(pkt,
                pkt->vp_data + sizeof(struct ether_hdr));
        }
    }

#ifdef VR_DPDK_TX_PKT_DUMP
    rte_pktmbuf_dump(m, 0x60);
#endif
    /* Burst tx to eth */
    tx_burst[nb_tx_burst++] = m;

    /* update burst size */
    lcore_ctx->lcore_port_tx_len[port_id] = nb_tx_burst;

    if (unlikely(VR_DPDK_PKT_BURST_SZ == nb_tx_burst)) {
        RTE_LOG(DEBUG, VROUTER, "lcore %u %s drain\n", lcore_id, __func__);
        /* drain eth TX queue */
        return vr_dpdk_eth_tx_queue_drain(port, lcore_ctx);
    }

    return 0;
}

static int
dpdk_if_rx(struct vr_interface *vif, struct vr_packet *pkt)
{
    /* currect lcore id */
    const unsigned lcore_id = rte_lcore_id();
    /* current lcore context */
    struct lcore_ctx * const lcore_ctx = &vr_dpdk.lcores[lcore_id];
    /* pointer to vif_port structure */
    struct vif_port * const port = (struct vif_port *)vif->vif_os;
    /* port index */
    const unsigned port_id = port->vip_id;
    /* mbuf */
    struct rte_mbuf *m = vr_dpdk_pkt_to_mbuf(pkt);
    /* tx burst */
    struct rte_mbuf ** const tx_burst = lcore_ctx->lcore_kni_tx[port_id];
    /* tx burst size */
    unsigned nb_tx_burst = lcore_ctx->lcore_kni_tx_len[port_id];

    RTE_VERIFY(nb_tx_burst < VR_DPDK_PKT_BURST_SZ);

    RTE_LOG(DEBUG, VROUTER,"%s: TX %u packet(s) to KNI %hhu\n",
         __func__, nb_tx_burst + 1, port_id);

    /* reset mbuf data pointer and length */
    m->pkt.data = pkt_data(pkt);
    m->pkt.data_len = pkt_head_len(pkt);
    /* TODO: use pkt_len instead? */
    m->pkt.pkt_len = pkt_head_len(pkt);

    /* Burst tx to KNI */
    tx_burst[nb_tx_burst++] = m;
    /* update burst size */
    lcore_ctx->lcore_kni_tx_len[port_id] = nb_tx_burst;

    if (unlikely(VR_DPDK_PKT_BURST_SZ == nb_tx_burst)) {
        RTE_LOG(DEBUG, VROUTER, "lcore %u main loop KNI drain\n", lcore_id);
        /* drain KNI TX queue */
        return vr_dpdk_kni_tx_queue_drain(port, lcore_ctx);
    } 

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
    u_int16_t mtu;
    struct vif_port *port = (struct vif_port *)vif->vif_os;

    if (port) {
        if (0 == rte_eth_dev_get_mtu(port->vip_id, &mtu))
            return mtu;
    }
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

