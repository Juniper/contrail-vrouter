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
#include <sys/queue.h>

#include "vr_os.h"

#include <rte_config.h>
#include <rte_pci.h>
#include <rte_version.h>
#include <rte_kni.h>
#include <rte_ethdev.h>
#include <rte_port.h>

#define RTE_LOGTYPE_VROUTER         RTE_LOGTYPE_USER1
#undef RTE_LOG_LEVEL
#define RTE_LOG_LEVEL               RTE_LOG_INFO
/*
 * Debug options:
 *
#define RTE_LOG_LEVEL               RTE_LOG_DEBUG
#define VR_DPDK_NETLINK_DEBUG
#define VR_DPDK_NETLINK_PKT_DUMP
#define VR_DPDK_RX_PKT_DUMP
#define VR_DPDK_TX_PKT_DUMP
 */

/* lcore mask */
#define VR_DPDK_LCORE_MASK          "0x3f"
/* Number of service lcores */
#define VR_DPDK_NB_SERVICE_LCORES   2
/* Minimum number of lcores */
#define VR_DPDK_MIN_LCORES          2
/* Memory to allocate at startup in MB */
#define VR_DPDK_MAX_MEM             "256"
/* Use hardware filters (Flow Director) */
#define VR_DPDK_USE_HW_FILTERS      true
/* Promisc mode
 * KNI generates random MACs for e1000e NICs, so we need this
 * option enabled for the development on servers with those NICs
 */
#define VR_DPDK_ENABLE_PROMISC      false
/* Maximum number of hardware RX queues to use for RSS and filtering
 * (limited by NIC and number of per queue TX/RX descriptors) */
#define VR_DPDK_MAX_NB_RX_QUEUES    11
/* Maximum number of hardware TX queues to use (limited by the number of lcores) */
#define VR_DPDK_MAX_NB_TX_QUEUES    4
/* Maximum number of hardware RX queues to use for RSS (limited by the number of lcores) */
#define VR_DPDK_MAX_NB_RSS_QUEUES   4
/* Number of hardware RX ring descriptors */
#define VR_DPDK_NB_RXD              256
/* Number of hardware TX ring descriptors */
#define VR_DPDK_NB_TXD              512
/* Offset to MPLS label for hardware filters */
#define VR_DPDK_MPLS_OFFSET         (VR_ETHER_HLEN          \
                                    + sizeof(struct vr_ip)  \
                                    + sizeof(struct vr_udp))
/* Maximum number of rings per lcore (maximum is VR_MAX_INTERFACES*RTE_MAX_LCORE) */
#define VR_DPDK_MAX_RINGS           (VR_MAX_INTERFACES*2)
/* Max size of a single packet */
#define VR_DPDK_MAX_PACKET_SZ       2048
/* Number of bytes needed for each mbuf */
#define VR_DPDK_MBUF_SZ             (VR_DPDK_MAX_PACKET_SZ      \
                                    + sizeof(struct rte_mbuf)   \
                                    + RTE_PKTMBUF_HEADROOM      \
                                    + sizeof(struct vr_packet))
/* How many packets to read/write from/to queue in one go */
#define VR_DPDK_MAX_BURST_SZ        RTE_PORT_IN_BURST_SIZE_MAX
#define VR_DPDK_ETH_RX_BURST_SZ     32
#define VR_DPDK_ETH_TX_BURST_SZ     32
#define VR_DPDK_KNI_RX_BURST_SZ     32
#define VR_DPDK_KNI_TX_BURST_SZ     32
#define VR_DPDK_RING_RX_BURST_SZ    32
#define VR_DPDK_RING_TX_BURST_SZ    32
/* Number of mbufs in TX ring */
#define VR_DPDK_TX_RING_SZ          (VR_DPDK_MAX_BURST_SZ*2)
/* Number of mbufs in mempool */
#define VR_DPDK_MPOOL_SZ            8192
/* How many objects (mbufs) to keep in per-lcore mempool cache */
#define VR_DPDK_MPOOL_CACHE_SZ      (VR_DPDK_MAX_BURST_SZ*8)
/* Use timer to measure flushes (slower, but should improve latency) */
#define VR_DPDK_USE_TIMER           false
/* TX flush timeout (in loops or US if USE_TIMER defined) */
#define VR_DPDK_TX_FLUSH_LOOPS      5
#define VR_DPDK_TX_FLUSH_US         100
/* Lcore ID to create timers on */
#define VR_DPDK_TIMER_LCORE_ID      0
/* Sleep time in US if there are no queues to poll */
#define VR_DPDK_SLEEP_NO_QUEUES_US  10000
/* Sleep (in US) or yield if no packets received (use 0 to disable) */
#define VR_DPDK_SLEEP_NO_PACKETS_US 10
#define VR_DPDK_YIELD_NO_PACKETS    0
/* Timers handling periodicity in US */
#define VR_DPDK_SLEEP_TIMER_US      100
/* KNI handling periodicity in US */
#define VR_DPDK_SLEEP_KNI_US        500
/* Sleep time in US for service lcore */
#define VR_DPDK_SLEEP_SERVICE_US    100

/*
 * VRouter/DPDK Data Structures
 * ============================
 *
 * Changes since the initial commit:
 *   lcore_ctx -> vr_dpdk_lcore
 *   vif_port -> vr_dpdk_rx_queue
 *
 * TODO: update the description
 */

struct vr_dpdk_rx_queue {
    /* single-linked list */
    SLIST_ENTRY(vr_dpdk_rx_queue) rxq_next;
    /* RX queue operators */
    struct rte_port_in_ops rxq_ops;
    /* queue handler */
    void *rxq_queue_h;
    /* RX burst size */
    uint16_t rxq_burst_size;
    /* pointer to vRouter interface */
    struct vr_interface *rxq_vif;
};

struct vr_dpdk_tx_queue {
    /* single-linked list */
    SLIST_ENTRY(vr_dpdk_tx_queue) txq_next;
    /* TX queue operators */
    struct rte_port_out_ops txq_ops;
    /* queue handler */
    void *txq_queue_h;
    /* pointer to vRouter interface */
    struct vr_interface *txq_vif;
};

struct vr_dpdk_ring_to_push {
    /* ring pointer */
    struct rte_ring *rtp_tx_ring;
    /* TX queue pointer */
    struct vr_dpdk_tx_queue *rtp_tx_queue;
};

SLIST_HEAD(vr_dpdk_rx_slist, vr_dpdk_rx_queue);
SLIST_HEAD(vr_dpdk_tx_slist, vr_dpdk_tx_queue);

struct vr_dpdk_lcore {
    /* global stop flag */
    rte_atomic16_t lcore_stop_flag;
    /* pointer to memory pool */
    struct rte_mempool *pktmbuf_pool;
    /* number of RX queues assigned to the lcore (for the scheduler) */
    uint16_t lcore_nb_rx_queues;
    /* RX queues head */
    struct vr_dpdk_rx_slist lcore_rx_head;
    /* list of RX queues */
    struct vr_dpdk_rx_queue lcore_rx_queues[VR_MAX_INTERFACES];
    /* TX queues head */
    struct vr_dpdk_tx_slist lcore_tx_head;
    /* table of TX queues */
    struct vr_dpdk_tx_queue lcore_tx_queues[VR_MAX_INTERFACES];
    /* number of rings to push for the lcore */
    uint16_t lcore_nb_rings_to_push;
    /* list of rings to push */
    struct vr_dpdk_ring_to_push lcore_rings_to_push[VR_DPDK_MAX_RINGS];
    /* number of free rings available for the lcore */
    uint16_t lcore_nb_free_rings;
    /* list of free rings */
    struct rte_ring *lcore_free_rings[VR_DPDK_MAX_RINGS];
};

/* Hardware RX queue state */
enum vr_dpdk_queue_state {
    /* The queue is free to use for RSS or filtering */
    VR_DPDK_QUEUE_FREE_STATE,
    /* The queue is being used for RSS */
    VR_DPDK_QUEUE_RSS_STATE,
    /* The queue is being used for filtering */
    VR_DPDK_QUEUE_FILTER_STATE
};

/* Ethdev configuration */
struct vr_dpdk_ethdev {
    /* Pointer to ethdev or NULL if the device is not used */
    struct rte_eth_dev *ethdev_ptr;
    /* Number of HW RX queues (limited by NIC hardware) */
    uint16_t ethdev_nb_rx_queues;
    /* Number of HW TX queues (limited by the nb of lcores) */
    uint16_t ethdev_nb_tx_queues;
    /* Number of HW RX queues used for RSS (limited by the nb of lcores) */
    uint16_t ethdev_nb_rss_queues;
    /* Hardware RX queue states */
    enum vr_dpdk_queue_state ethdev_queue_states[VR_DPDK_MAX_NB_RX_QUEUES];
};

struct vr_dpdk_global {
    /* pointer to memory pool */
    struct rte_mempool *pktmbuf_pool;
    /* number of forwarding lcores */
    unsigned nb_fwd_lcores;
    /* table of pointers to forwarding lcore */
    struct vr_dpdk_lcore *lcores[RTE_MAX_LCORE];
    /* global stop flag */
    rte_atomic16_t stop_flag;
    /* NetLink socket handler */
    void *netlink_sock;
    void *flow_table;
    /* Packet socket */
    struct rte_ring *packet_ring;
    void *packet_transport;
    unsigned packet_lcore_id;
    /* Event socket */
    void *event_sock;
    /* KNI thread ID */
    pthread_t kni_thread;
    /* timer thread ID */
    pthread_t timer_thread;
    /* table of KNIs */
    struct rte_kni *knis[VR_MAX_INTERFACES];
    /* table of vHosts */
    struct vr_interface *vhosts[VR_MAX_INTERFACES];
    /* table of ethdevs */
    struct vr_dpdk_ethdev ethdevs[RTE_MAX_ETHPORTS];
};

extern struct vr_dpdk_global vr_dpdk;

/* Init RX queue operation */
typedef struct vr_dpdk_rx_queue *
    (*vr_dpdk_rx_queue_init_op)(unsigned lcore_id, struct vr_interface *vif,
        unsigned queue_or_lcore_id);
/* Init TX queue operation */
typedef struct vr_dpdk_tx_queue *
    (*vr_dpdk_tx_queue_init_op)(unsigned lcore_id, struct vr_interface *vif,
        unsigned queue_or_lcore_id);

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

/*
 * dpdk_vrouter.c
 */
/* pktmbuf constructor with vr_packet support */
void vr_dpdk_pktmbuf_init(struct rte_mempool *mp, void *opaque_arg, void *_m, unsigned i);

/*
 * vr_dpdk_ethdev.c
 */
/* Init eth RX queue */
struct vr_dpdk_rx_queue *
vr_dpdk_eth_rx_queue_init(unsigned lcore_id, struct vr_interface *vif,
    unsigned rx_queue_id);
/* Init eth TX queue */
struct vr_dpdk_tx_queue *
vr_dpdk_eth_tx_queue_init(unsigned lcore_id, struct vr_interface *vif,
    unsigned tx_queue_id);
/* Init ethernet device */
int vr_dpdk_ethdev_init(struct vr_interface *vif);

/*
 * vr_dpdk_flow_mem.c
 */
int vr_dpdk_flow_mem_init(void);
int vr_dpdk_flow_init(void);

/*
 * vr_dpdk_host.c
 */
int vr_dpdk_host_init(void);
void vr_dpdk_host_exit(void);
/* Convert internal packet fields */
struct vr_packet * vr_dpdk_packet_get(struct rte_mbuf *m, struct vr_interface *vif);

/*
 * vr_dpdk_knidev.c
 */
/* Init KNI */
int vr_dpdk_knidev_init(struct vr_interface *vif);
/* Init KNI RX queue */
struct vr_dpdk_rx_queue *
vr_dpdk_kni_rx_queue_init( unsigned lcore_id, struct vr_interface *vif,
    unsigned host_lcore_id);
/* Init KNI TX queue */
struct vr_dpdk_tx_queue *
vr_dpdk_kni_tx_queue_init( unsigned lcore_id, struct vr_interface *vif,
    unsigned host_lcore_id);
/* Handle all KNIs attached */
void vr_dpdk_knidev_all_handle(void);

/*
 * vr_dpdk_lcore.c
 */
/* Launch lcore main loop */
int vr_dpdk_lcore_launch(void *dummy);
/* Schedule an interface */
int vr_dpdk_lcore_if_schedule(struct vr_interface *vif, unsigned least_used_id,
    uint16_t nb_rx_queues, vr_dpdk_rx_queue_init_op rx_queue_init_op,
    uint16_t nb_tx_queues, vr_dpdk_tx_queue_init_op tx_queue_init_op);
/* Returns the least used lcore or RTE_MAX_LCORE */
unsigned vr_dpdk_lcore_least_used_get(void);

/*
 * vr_dpdk_netlink.c
 */
void dpdk_netlink_exit(void);
int dpdk_netlink_init(void);
int dpdk_netlink_receive(void *usockp, char *nl_buf, unsigned int nl_len);
int dpdk_netlink_io(void);

/*
 * vr_dpdk_packet.c
 */
int vr_dpdk_packet_tx(void);
int dpdk_packet_socket_init(void);
void dpdk_packet_socket_close(void);
int dpdk_packet_io(void);

/*
 * vr_dpdk_ringdev.c
 */
/* Init ring RX queue */
struct vr_dpdk_rx_queue *
vr_dpdk_ring_rx_queue_init(unsigned lcore_id, struct vr_interface *vif,
    unsigned host_lcore_id);
/* Init ring TX queue */
struct vr_dpdk_tx_queue *
vr_dpdk_ring_tx_queue_init(unsigned lcore_id, struct vr_interface *vif,
    unsigned host_lcore_id);

#endif /*_VR_DPDK_H_ */
