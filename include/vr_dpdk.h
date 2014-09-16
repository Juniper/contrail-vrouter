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
 * vr_dpdk.h -- vRouter/DPDK definitions
 *
 */

#ifndef _VR_DPDK_H_
#define _VR_DPDK_H_

#include <net/if.h>

#include "vr_os.h"

#include <rte_config.h>
#include <rte_pci.h>
#include <rte_version.h>
#include <rte_kni.h>
#include <rte_ethdev.h>

#define RTE_LOGTYPE_VROUTER RTE_LOGTYPE_USER1
#undef RTE_LOG_LEVEL
#define RTE_LOG_LEVEL RTE_LOG_INFO
/*
 * Debug options:
 *
#define RTE_LOG_LEVEL RTE_LOG_DEBUG
#define VR_DPDK_NETLINK_DEBUG
#define VR_DPDK_NETLINK_PKT_DUMP
#define VR_DPDK_RX_PKT_DUMP
#define VR_DPDK_TX_PKT_DUMP
 */

/* Max size of a single packet */
#define VR_DPDK_MAX_PACKET_SZ   2048
/* Number of bytes needed for each mbuf */
#define VR_DPDK_MBUF_SZ \
    (VR_DPDK_MAX_PACKET_SZ + sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM \
        + sizeof(struct vr_packet))
/* How many packets to read from NIC in one go */
#define VR_DPDK_PKT_BURST_SZ    32
/* Number of hardware RX ring descriptors */
#define VR_DPDK_NB_RXD          256
/* Number of hardware TX ring descriptors */
#define VR_DPDK_NB_TXD          512
/* Number of mbufs in software TX ring */
#define VR_DPDK_TX_RING_SZ      2048
/* Number of mbufs in mempool */
#define VR_DPDK_MPOOL_SZ        8192
/* How many objects (mbufs) to keep in per-lcore mempool cache */
#define VR_DPDK_MPOOL_CACHE_SZ  VR_DPDK_PKT_BURST_SZ*16
/* NetLink buffer size */
#define VR_DPDK_NL_BUF_SZ       0x2000
/* Use timer to measure drains (slower, but should improve latency) */
/* #define VR_DPDK_USE_TIMER 1 */
/* TX drain timeout (in loops or US if USE_TIMER defined) */
#define VR_DPDK_TX_DRAIN_LOOPS  5
#define VR_DPDK_TX_DRAIN_US     100
/* Sleep time in US if no ports attached */
#define VR_DPDK_NO_PORTS_US     100000
/* Sleep time in US if no packets received */
#define VR_DPDK_NO_PACKETS_US   100
/* Timers handling periodicity in US */
#define VR_DPDK_TIMER_US        100
/* KNI handling periodicity in US */
#define VR_DPDK_KNI_US          100
/* Lcore ID to create timers on */
#define VR_DPDK_TIMER_LCORE_ID  0

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

#ifndef PAGE_SIZE
#define PAGE_SIZE               4096
#endif

/*
 * VRouter/DPDK Data Structures
 * ============================
 *
 * Global variable vr_dpdk (type dpdk_global) consist of:
 *   pointer to mempool
 *   array or ports (type vif_port)
 *   array of lcore contexts (type lcore_ctx)
 *
 * We use DPDK port ID as an index to array of ports:
 *   port = &vr_dpdk.ports[dpdk_port_id];
 * We use lcore ID as an index to array of lcore contexts:
 *   lcore_ctx = &vr_dpdk.lcores[rte_lcore_id()];
 *
 *
 * Every port (type vif_port) has the following:
 *   port name (for PMD ports it's just a string of port ID)
 *   port PCI addr
 *   DPDK port ID
 *   pointer to DPDK port structure rte_eth_dev
 *   pointer to VRouter interface assigned to the port
 *     Note: VRouter interface has a vif_os field pointing back
 *           to this port structure
 *   number of port hardware TX queues
 *   pointer to port TX ring or NULL if every lcore got its HW queue
 *   pointer to KNI structure or NULL if port has no KNI attached
 *   pointer to VRouter interface assigned to the KNI
 *     Note: VRouter interface has a vif_os field pointing back
 *           to this port structure
 *   pointer to KNI TX ring or NULL if we have just one lcore
 *   pointer to lcore context or NULL if the port is not assigned to an lcore
 *
 * Lcore context (type lcore_ctx) consist of:
 *   number of RX ports assigned to the lcore (i.e. number of elements
 *     in the following list
 *   list of RX ports assigned to the lcore or NULL if port was removed
 *   array of TX burst queues for each DPDK port
 *   number of mbufs for each port in the burst
 *   array of TX burst queues for each KNI interface
 *   number of mbufs for each KNI in the burst
 *   hardware TX queue index or -1 if there is no index assigned, so
 *     we have to use a ring to enqueue the packets
 */

struct lcore_ctx;
struct vif_port {
    /* vif port name */
    char vip_name[IFNAMSIZ];
    /* port PCI address */
    struct rte_pci_addr vip_addr;
    /* ethdev port ID */
    uint8_t vip_id;
    /* pointer to eth port */
    struct rte_eth_dev *vip_eth;
    /* pointer to the VRouter interface */
    struct vr_interface *vip_vif;
    /* number of hardware TX queues */
    unsigned vip_nb_tx;
    /* TX ring */
    struct rte_ring *vip_tx_ring;
    /* pointer to KNI interface or NULL */
    struct rte_kni *vip_kni;
    /* pointer to KNI VRouter interface or NULL */
    struct vr_interface *vip_kni_vif;
    /* KNI TX ring */
    struct rte_ring *vip_kni_ring;
    /* assigned lcore context or NULL if the port is not assigned
     * to an lcore */
    struct lcore_ctx *vip_lcore_ctx;
    /* TODO: unbind port on exit flag (unstable, kernel panics at exit) */
    bool vip_binded;
} __rte_cache_aligned;


struct lcore_ctx {
    /* number of RX ports assigned to the lcore */
    volatile int lcore_nb_rx_ports;
    /* list of RX ports assigned to the lcore or NULL if port was removed */
    struct vif_port *lcore_rx_ports[RTE_MAX_ETHPORTS];
    /* TX burst queues for each DPDK port */
    struct rte_mbuf *lcore_port_tx[RTE_MAX_ETHPORTS][VR_DPDK_PKT_BURST_SZ];
    /* TX burst queue size for each DPDK port */
    unsigned lcore_port_tx_len[RTE_MAX_ETHPORTS];
    /* KNI TX burst queues for each DPDK port with KNI attached */
    struct rte_mbuf *lcore_kni_tx[RTE_MAX_ETHPORTS][VR_DPDK_PKT_BURST_SZ];
    /* KNI TX burst queue size for each port */
    unsigned lcore_kni_tx_len[RTE_MAX_ETHPORTS];
    /* hardware TX queue indexes for each DPDK port or -1 to use ring */
    int lcore_tx_index[RTE_MAX_ETHPORTS];
} __rte_cache_aligned;

struct dpdk_global {
    /* pointer to memory pool */
    struct rte_mempool * pktmbuf_pool;
    /* number of lcores available (excluding master lcore) */
    unsigned nb_lcores;
    /* table of ports */
    struct vif_port ports[RTE_MAX_ETHPORTS];
    /* table of lcore contexts */
    struct lcore_ctx lcores[RTE_MAX_LCORE];
    /* global stop flag */
    rte_atomic32_t stop_flag;
    /* NetLink socket handler */
    int netlink_sock;
    /* NetLink message buffer */
    uint8_t netlink_buf[VR_DPDK_NL_BUF_SZ];
    /* KNI thread ID */
    pthread_t kni_thread;
    /* timer thread ID */
    pthread_t timer_thread;
    /* NetLink thread ID */
    pthread_t netlink_thread;
};

extern struct dpdk_global vr_dpdk;

/*
 * rte_mbuf <=> vr_packet conversion
 *
 * We use the tailroom to store vr_packet structure:
 *     struct rte_mbuf + headroom + data + tailroom + struct vr_packet
 *
 * rte_mbuf: *buf_addr(buf_len) + headroom + *pkt.data(data_len) + tailroom
 *
 * rte_mbuf->buf_addr = rte_mbuf + sizeof(rte_mbuf)
 * rte_mbuf->buf_len = elt_size - sizeof(rte_mbuf) - sizeof(vr_packet)
 * rte_mbuf->pkt.data = rte_mbuf->buf_addr + RTE_PKTMBUF_HEADROOM
 *
 *
 * vr_packet: *vp_head + headroom + vp_data(vp_len) + vp_tail + tailroom
 *                + vp_end
 *
 * vr_packet->vp_head = rte_mbuf->buf_addr (set in mbuf constructor)
 * vr_packet->vp_data = rte_mbuf->pkt.data - rte_mbuf->buf_addr
 * vr_packet->vp_len  = rte_mbuf->pkt.data_len
 * vr_packet->vp_tail = vr_packet->vp_data + vr_packet->vp_len
 * vr_packet->vp_end  = rte_mbuf->buf_len (set in mbuf constructor)
 */
static inline struct rte_mbuf *
vr_dpdk_pkt_to_mbuf(struct vr_packet *pkt)
{
    return (struct rte_mbuf *)((uintptr_t)pkt->vp_head - sizeof(struct rte_mbuf));
}
static inline struct vr_packet *
vr_dpdk_mbuf_to_pkt(struct rte_mbuf *mbuf)
{
    return (struct vr_packet *)((uintptr_t)mbuf->buf_addr + mbuf->buf_len);
}

/*
 * vr_dpdk_mbuf_reset - if the mbuf changes, possibley due to
 * pskb_may_pull, reset fields of the pkt structure that point at
 * the mbuf fields.
 */
static inline void
vr_dpdk_mbuf_reset(struct vr_packet *pkt)
{
    struct rte_mbuf *mbuf = vr_dpdk_pkt_to_mbuf(pkt);

    pkt->vp_head = mbuf->buf_addr;
    pkt->vp_data = mbuf->pkt.data - mbuf->buf_addr;
    pkt->vp_len = mbuf->pkt.data_len;
    pkt->vp_tail = pkt->vp_data + pkt->vp_len;
    pkt->vp_end = mbuf->buf_len;
}

/* Convert internal packet fields */
struct vr_packet * vr_dpdk_packet_get(struct rte_mbuf *m, struct vr_interface *vif);
/* Overrided mempool mbuf constructor (DPDK callback) */
void vr_dpdk_pktmbuf_init(struct rte_mempool *mp, void *opaque_arg, void *_m,
    unsigned i);
/* Handle NetLink connection */
int vr_dpdk_netlink_handle(void);
/* Close NetLink socket */
void vr_dpdk_netlink_sock_close(void);
/* Init NetLink socket */
int vr_dpdk_netlink_sock_init(void);

/* Init DPDK port */
int vr_dpdk_port_init(uint8_t port);

/* Read bursts from all the ports assigned and transmit those
 * packets to VRouter
 */
void vr_dpdk_all_ports_poll(struct lcore_ctx *lcore_ctx);
/* Drain all ports */
void vr_dpdk_all_ports_drain(struct lcore_ctx *lcore_ctx);
/* Handle all KNIs attached */
void vr_dpdk_all_knis_handle(void);
/* Read a burst from eth and KNI interfaces and transmit it to VRouter */
unsigned vr_dpdk_port_rx(struct vif_port *port);

/* Drain eth TX queue */
int vr_dpdk_eth_tx_queue_drain(struct vif_port *port, struct lcore_ctx *lcore_ctx);
/* Drain KNI TX queue */
int vr_dpdk_kni_tx_queue_drain(struct vif_port *port, struct lcore_ctx *lcore_ctx);

/* Run-time bind DPDK port */
int vr_dpdk_port_bind(struct rte_pci_addr *pci, const char *ifname);
/* Run-time unbind DPDK port */
int vr_dpdk_port_unbind(struct rte_pci_addr *pci);

#endif /*_VR_DPDK_H_ */
