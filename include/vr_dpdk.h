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
 * vr_dpdk.h -- vRouter/DPDK definitions
 *
 */

#ifndef _VR_DPDK_H_
#define _VR_DPDK_H_

#include "vr_os.h"
#include "vr_interface.h"
#include "vr_packet.h"

#include <sys/queue.h>

#include <rte_config.h>
#include <rte_port.h>
#include <rte_port_ring.h>

extern struct vr_interface_stats *vif_get_stats(struct vr_interface *,
        unsigned short);

/*
 * Use RTE_LOG_DEBUG to enable debug logs.
 * See more debug options below.
 */
#undef RTE_LOG_LEVEL
#define RTE_LOG_LEVEL               RTE_LOG_INFO

/*
 * By default all the logtypes are enabled.
 * Use VR_DPDK_LOGTYPE_DISABLE option below to disable some of the types.
 */
#define RTE_LOGTYPE_VROUTER         RTE_LOGTYPE_USER1
#define RTE_LOGTYPE_USOCK           RTE_LOGTYPE_USER2
#define RTE_LOGTYPE_UVHOST          RTE_LOGTYPE_USER3
#define RTE_LOGTYPE_DPCORE          RTE_LOGTYPE_USER4
#define VR_DPDK_LOGTYPE_DISABLE     (0)

/*
 * Debug options:
 *
#define RTE_LOG_LEVEL               RTE_LOG_DEBUG
#define VR_DPDK_LOGTYPE_DISABLE     (RTE_LOGTYPE_USOCK | RTE_LOGTYPE_UVHOST)
#define VR_DPDK_NETLINK_DEBUG
#define VR_DPDK_NETLINK_PKT_DUMP
#define VR_DPDK_USOCK_DUMP
#define VR_DPDK_RX_PKT_DUMP
#define VR_DPDK_TX_PKT_DUMP
#define VR_DPDK_PKT_DUMP_VIF_FILTER(vif) (vif->vif_type == VIF_TYPE_AGENT \
                                        || vif->vif_type == VIF_TYPE_VIRTUAL)
 */

/* Default lcore mask. Used only when sched_getaffinity() is failed */
#define VR_DPDK_DEF_LCORE_MASK      0xf
/* Memory to allocate at startup in MB */
#define VR_DPDK_MAX_MEM             "512"
/* Number of memory channels to use */
#define VR_DPDK_MAX_MEMCHANNELS     "4"
/* Use UDP source port hashing */
#define VR_DPDK_USE_MPLS_UDP_ECMP   true
/* Use hardware filtering (Flow Director) */
#define VR_DPDK_USE_HW_FILTERING    false
/* KNI generates random MACs for e1000e NICs, so we need this
 * option enabled for the development on servers with those NICs */
#define VR_DPDK_ENABLE_PROMISC      false
/* Maximum number of hardware RX queues to use for RSS and filtering
 * (limited by NIC and number of per queue TX/RX descriptors) */
#define VR_DPDK_MAX_NB_RX_QUEUES    11
/* Maximum number of hardware TX queues to use (limited by the number of lcores) */
#define VR_DPDK_MAX_NB_TX_QUEUES    5
/* Maximum number of hardware RX queues to use for RSS (limited by the number of lcores) */
#define VR_DPDK_MAX_NB_RSS_QUEUES   4
/* Maximum number of bond members per ethernet device */
#define VR_DPDK_BOND_MAX_SLAVES     6
/* Maximum RETA table size */
#define VR_DPDK_MAX_RETA_SIZE       ETH_RSS_RETA_SIZE_128
#define VR_DPDK_MAX_RETA_ENTRIES    (VR_DPDK_MAX_RETA_SIZE/RTE_RETA_GROUP_SIZE)
/* Number of hardware RX ring descriptors */
#define VR_DPDK_NB_RXD              256
/* Number of hardware TX ring descriptors */
#define VR_DPDK_NB_TXD              512
/* Offset to MPLS label for hardware filtering (in 16-bit word units) */
#define VR_DPDK_MPLS_OFFSET         ((VR_ETHER_HLEN             \
                                    + sizeof(struct vr_ip)      \
                                    + sizeof(struct vr_udp))/2)
/* Maximum number of rings per lcore (maximum is VR_MAX_INTERFACES*VR_MAX_CPUS) */
#define VR_DPDK_MAX_RINGS           (VR_MAX_INTERFACES*2)
/* Maximum number of bond interfaces per lcore */
#define VR_DPDK_MAX_BONDS           2
/* Max size of a single packet */
#define VR_DPDK_MAX_PACKET_SZ       2048
/* Number of bytes needed for each mbuf */
#define VR_DPDK_MBUF_SZ             (VR_DPDK_MAX_PACKET_SZ      \
                                    + sizeof(struct rte_mbuf)   \
                                    + RTE_PKTMBUF_HEADROOM      \
                                    + sizeof(struct vr_packet))
/* Size of direc mbuf used for fragmentation. It needs a headroom as it holds
 * the IP headers of the fragments and we have to prepend an outer (tunnel)
 * header. */
#define VR_DPDK_FRAG_DIRECT_MBUF_SZ     (sizeof(struct rte_mbuf)    \
                                         + RTE_PKTMBUF_HEADROOM)
/* Size of indirect mbufs used for fragmentation. These mbufs holds only a
 * pointer to the data in other mbufs, thus they don't need any additional
 * buffer size. */
#define VR_DPDK_FRAG_INDIRECT_MBUF_SZ   (sizeof(struct rte_mbuf))
/* How many packets to read/write from/to queue in one go */
#define VR_DPDK_RX_BURST_SZ         32
#define VR_DPDK_TX_BURST_SZ         32
/* Number of mbufs in virtio mempool */
#define VR_DPDK_VIRTIO_MEMPOOL_SZ   4096
/* How many objects (mbufs) to keep in per-lcore virtio mempool cache */
#define VR_DPDK_VIRTIO_MEMPOOL_CACHE_SZ (VR_DPDK_VIRTIO_RX_BURST_SZ*8)
/* Number of mbufs in RSS mempool */
#define VR_DPDK_RSS_MEMPOOL_SZ      16384
/* How many objects (mbufs) to keep in per-lcore RSS mempool cache */
#define VR_DPDK_RSS_MEMPOOL_CACHE_SZ    (VR_DPDK_RX_BURST_SZ*8)
/* Number of mbufs in FRAG_DIRECT mempool */
#define VR_DPDK_FRAG_DIRECT_MEMPOOL_SZ     4096
/* How many objects (mbufs) to keep in per-lcore FRAG_DIRECT mempool cache */
#define VR_DPDK_FRAG_DIRECT_MEMPOOL_CACHE_SZ    (VR_DPDK_RX_BURST_SZ*8)
/* Number of mbufs in FRAG_INDIRECT mempool */
#define VR_DPDK_FRAG_INDIRECT_MEMPOOL_SZ     4096
/* How many objects (mbufs) to keep in per-lcore FRAG_INDIRECT mempool cache */
#define VR_DPDK_FRAG_INDIRECT_MEMPOOL_CACHE_SZ    (VR_DPDK_RX_BURST_SZ*8)
/* Number of VM mempools */
#define VR_DPDK_MAX_VM_MEMPOOLS     (VR_DPDK_MAX_NB_RX_QUEUES*2)
/* Number of mbufs in VM mempool */
#define VR_DPDK_VM_MEMPOOL_SZ       1024
/* How many objects (mbufs) to keep in per-lcore VM mempool cache */
#define VR_DPDK_VM_MEMPOOL_CACHE_SZ (VR_DPDK_RX_BURST_SZ*8)
/* Number of mbufs in TX ring */
#define VR_DPDK_TX_RING_SZ          (VR_DPDK_TX_BURST_SZ*2)
/* RX ring minimum number of pointers to transfer (cache line / size of ptr) */
#define VR_DPDK_RX_RING_CHUNK_SZ    1
/* Number of mbufs in lcore RX ring.
 * Must be bigger than mempool size due to the headers and other mempools */
#define VR_DPDK_RX_RING_SZ          (VR_DPDK_RSS_MEMPOOL_SZ*2)
/* Use timer to measure flushes (slower, but should improve latency) */
#define VR_DPDK_USE_TIMER           false
/* TX flush timeout (in loops or US if USE_TIMER defined) */
#define VR_DPDK_TX_FLUSH_LOOPS      5
#define VR_DPDK_TX_FLUSH_US         100
/*
 * Bond TX timeout (in ms)
 * Receive and transmit functions must be invoked on bonded
 * interface at least 10 times per second or LACP will not
 * work correctly
 */
#define VR_DPDK_BOND_TX_MS          100
/* Sleep time in US if there are no queues to poll */
#define VR_DPDK_SLEEP_NO_QUEUES_US  10000
/* Sleep (in US) or yield if no packets received (use 0 to disable) */
#define VR_DPDK_SLEEP_NO_PACKETS_US 0
#define VR_DPDK_YIELD_NO_PACKETS    1
/* Timers handling periodicity in US */
#define VR_DPDK_SLEEP_TIMER_US      100
/* KNI handling periodicity in US */
#define VR_DPDK_SLEEP_KNI_US        500
/* Sleep time in US for service lcore */
#define VR_DPDK_SLEEP_SERVICE_US    100
/* Invalid port ID */
#define VR_DPDK_INVALID_PORT_ID     0xFF
/* Invalid queue ID */
#define VR_DPDK_INVALID_QUEUE_ID    0xFFFF
/* Socket connection retry timeout in seconds (use power of 2) */
#define VR_DPDK_RETRY_CONNECT_SECS  64
/* Maximum number of KNI devices (vhost0 + monitoring) */
#define VR_DPDK_MAX_KNI_INTERFACES  5
/* String buffer size (for logs and EAL arguments) */
#define VR_DPDK_STR_BUF_SZ          512
/* Log timestamp format */
#define VR_DPDK_TIMESTAMP           "%F %T"
/* Maximum number of fragments allowed after IP fragmentation. Set to 7 to
 * allow for standard jumbo frame size (9000 / 1500 = 6) + 1 additional segment
 * for outer headers. */
#define VR_DPDK_FRAG_MAX_IP_FRAGS   7

/*
 * DPDK LCore IDs
 */
enum {
    VR_DPDK_NETLINK_LCORE_ID,
    VR_DPDK_KNI_LCORE_ID,
    VR_DPDK_TIMER_LCORE_ID,
    VR_DPDK_UVHOST_LCORE_ID,
    /* packet lcore has TX queues, so it should be at the end of the list */
    VR_DPDK_PACKET_LCORE_ID,
    /* the actual number of forwarding lcores depends on affinity mask */
    VR_DPDK_FWD_LCORE_ID
};

/*
 * VRouter/DPDK Data Structures
 * ============================
 *
 * Changes since the initial commit:
 *   lcore_ctx -> vr_dpdk_lcore
 *   vif_port -> vr_dpdk_queue
 *
 * TODO: update the description
 */

/* Init queue operation */
typedef struct vr_dpdk_queue *
    (*vr_dpdk_queue_init_op)(unsigned lcore_id, struct vr_interface *vif,
        unsigned queue_or_lcore_id);
/* Release queue operation */
typedef void
    (*vr_dpdk_queue_release_op)(unsigned lcore_id, struct vr_interface *vif);

struct vr_dpdk_queue {
    SLIST_ENTRY(vr_dpdk_queue) q_next;
    union {
        /* DPDK TX queue operators */
        struct rte_port_out_ops txq_ops;
        /* DPDK RX queue operators */
        struct rte_port_in_ops rxq_ops;
    };
    /* Queue handler */
    void *q_queue_h;
    /* Pointer to vRouter interface */
    struct vr_interface *q_vif;
};

/* We store the queue params in the separate structure to increase CPU
 * cache hit rate
 */
struct vr_dpdk_queue_params {
    /* Pointer to release function */
    vr_dpdk_queue_release_op qp_release_op;
    /* Extra queue params */
    union {
        struct {
            struct rte_ring *ring_p;
            unsigned host_lcore_id;
        } qp_ring;
        struct {
            uint8_t port_id;
            uint16_t queue_id;
        } qp_ethdev;
    };
};

struct vr_dpdk_ring_to_push {
    /* Ring pointer */
    struct rte_ring *rtp_tx_ring;
    /* TX queue pointer */
    struct vr_dpdk_queue *rtp_tx_queue;
};

SLIST_HEAD(vr_dpdk_q_slist, vr_dpdk_queue);

/* Lcore commands */
enum vr_dpdk_lcore_cmd {
    /* No command */
    VR_DPDK_LCORE_NO_CMD = 0,
    /* Stop and exit the lcore loop */
    VR_DPDK_LCORE_STOP_CMD,
    /* Remove RX queue */
    VR_DPDK_LCORE_RX_RM_CMD,
    /* Remove TX queue */
    VR_DPDK_LCORE_TX_RM_CMD,
};

struct vr_dpdk_lcore {
    /**********************************************************************/
    /* Frequently used fields */
    /* RX queues head */
    struct vr_dpdk_q_slist lcore_rx_head;
    /* TX queues head */
    struct vr_dpdk_q_slist lcore_tx_head;
    /* Number of rings to push for the lcore */
    volatile uint16_t lcore_nb_rings_to_push;
    /* Number of bond queues to TX */
    volatile uint16_t lcore_nb_bonds_to_tx;
    /* Number of hardware RX queues assigned to the lcore (for the scheduler) */
    uint16_t lcore_nb_rx_queues;
    /* Lcore command */
    rte_atomic16_t lcore_cmd;
    /* Lcore command param */
    rte_atomic32_t lcore_cmd_param;
    /* Event FD to wake up UVHost
     * TODO: refactor to use either event_sock or event FD
     */
    int lcore_event_fd;
    /* Event socket */
    void *lcore_event_sock;
    /* RX ring */
    struct rte_ring *lcore_rx_ring;

    /**********************************************************************/
    /* Big and less frequently used fields */
    /* Table of RX queues */
    struct vr_dpdk_queue lcore_rx_queues[VR_MAX_INTERFACES];
    /* Table of TX queues */
    struct vr_dpdk_queue lcore_tx_queues[VR_MAX_INTERFACES] __rte_cache_aligned;
    /* List of rings to push */
    struct vr_dpdk_ring_to_push lcore_rings_to_push[VR_DPDK_MAX_RINGS] __rte_cache_aligned;
    /* List of bond queue params to TX LACP packets periodically */
    struct vr_dpdk_queue_params *lcore_bonds_to_tx[VR_DPDK_MAX_BONDS] __rte_cache_aligned;
    /* Table of RX queue params */
    struct vr_dpdk_queue_params lcore_rx_queue_params[VR_MAX_INTERFACES] __rte_cache_aligned;
    /* Table of TX queue params */
    struct vr_dpdk_queue_params lcore_tx_queue_params[VR_MAX_INTERFACES] __rte_cache_aligned;
};

/* Hardware RX queue state */
enum vr_dpdk_queue_state {
    /* No queue available */
    VR_DPDK_QUEUE_NONE,
    /* The queue is ready to use for RSS or filtering */
    VR_DPDK_QUEUE_READY_STATE,
    /* The queue is being used for RSS */
    VR_DPDK_QUEUE_RSS_STATE,
    /* The queue is being used for filtering */
    VR_DPDK_QUEUE_FILTERING_STATE
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
    /* Actual size of ethdev RETA */
    uint16_t ethdev_reta_size;
    /* DPDK port ID */
    uint8_t ethdev_port_id;
    /* The device is a bond if the number of slaves is > 0 */
    int8_t ethdev_nb_slaves;
    /* List of slaves port IDs */
    uint8_t ethdev_slaves[VR_DPDK_BOND_MAX_SLAVES];
    /* Hardware RX queue states */
    uint8_t ethdev_queue_states[VR_DPDK_MAX_NB_RX_QUEUES];
    /* Pointers to memory pools */
    struct rte_mempool *ethdev_mempools[VR_DPDK_MAX_NB_RX_QUEUES];
};

struct vr_dpdk_global {
    /**********************************************************************/
    /* Frequently used fields */
    /* Pointer to main (RSS) memory pool */
    struct rte_mempool *rss_mempool;
    /* Packet socket ring */
    struct rte_ring *packet_ring;
    /* Global stop flag */
    rte_atomic16_t stop_flag;
    /* VLAN tag */
    uint16_t vlan_tag;
    /* Number of forwarding lcores */
    unsigned nb_fwd_lcores;
    /* Table of pointers to forwarding lcore
     * Must be at the end of the cache line 1 */
    struct vr_dpdk_lcore *lcores[VR_MAX_CPUS];

    /**********************************************************************/
    /* Big and less frequently used fields */
    /* Number of free memory pools */
    uint16_t nb_free_mempools;
    /* NetLink socket handler */
    void *netlink_sock;
    void *flow_table;
    /* Packet socket */
    void *packet_transport;
    /* Interface configuration mutex
     * ATM we use it just to synchronize access between the NetLink interface
     * and kernel KNI events. The datapath is not affected. */
    pthread_mutex_t if_lock;
    /* Pointer to IP fragmentation memory pool (direct) */
    struct rte_mempool *frag_direct_mempool;
    /* Pointer to IP fragmentation memory pool (indirect) */
    struct rte_mempool *frag_indirect_mempool;
    /* List of free memory pools */
    struct rte_mempool *free_mempools[VR_DPDK_MAX_VM_MEMPOOLS] __rte_cache_aligned;
    /* List of KNI interfaces to handle KNI requests */
    struct rte_kni *knis[VR_DPDK_MAX_KNI_INTERFACES] __rte_cache_aligned;
    /* Table of monitoring redirections (for vifdump) */
    uint16_t monitorings[VR_MAX_INTERFACES] __rte_cache_aligned;
    /* Table of ethdevs */
    struct vr_dpdk_ethdev ethdevs[RTE_MAX_ETHPORTS] __rte_cache_aligned;
};

extern struct vr_dpdk_global vr_dpdk;

/**
 *  Enable sent/received/dropped packets statistics
 */
#define DPDK_KNIDEV_WRITER_STATS_COLLECT    1
#define DPDK_KNIDEV_READER_STATS_COLLECT    1
#define DPDK_VIRTIO_WRITER_STATS_COLLECT    1
#define DPDK_VIRTIO_READER_STATS_COLLECT    1

/**
 * dpdk_port_out_stats_update
 *
 * Updates counters for:
 *  - packets enqueued to the interface successfully.
 *  - packets which have been dropped during .f_tx() or .f_flush().
 *  If we write to ring instead of NIC's queue, count it as a ring enqueue.
 *
 * port_stats is updated by .f_tx() and .f_flush().
 * vr_stats is returned by vif_get_stats().
 */
static inline void
dpdk_port_out_stats_update(struct vr_dpdk_queue *txq,
                            struct rte_port_out_stats *port_stats,
                            struct vr_interface_stats *vr_stats)
{
    if (!port_stats || !vr_stats)
        return;

    if (likely(txq->txq_ops.f_stats != NULL)) {
        txq->txq_ops.f_stats(txq->q_queue_h, port_stats, 0);

        /**
         * It does not matter if we check equality of .f_tx of .f_flush here,
         * equality of .f_txs implies equality of .f_flushes.
         */
        if (txq->txq_ops.f_tx == rte_port_ring_writer_ops.f_tx) {
            vr_stats->vis_iftxrngenqpkts = port_stats->n_pkts_in;
            vr_stats->vis_iftxrngenqdrops = port_stats->n_pkts_drop;
        } else {
            vr_stats->vis_ifenqpkts = port_stats->n_pkts_in;
            vr_stats->vis_ifenqdrops = port_stats->n_pkts_drop;
        }
    }
}

/**
 * dpdk_port_in_stats_update
 *
 * Updates counters for:
 *  - packets dequeued from the interface successfully.
 *  - packets which have been dropped during .f_rx().
 *
 * port_stats is updated by .f_rx().
 * vr_stats is returned by vif_get_stats().
 */
static inline void
dpdk_port_in_stats_update(struct vr_dpdk_queue *rxq,
                            struct rte_port_in_stats *port_stats,
                            struct vr_interface_stats *vr_stats)
{
    if (!port_stats || !vr_stats)
        return;

    if (likely(rxq->rxq_ops.f_stats != NULL)) {
        rxq->rxq_ops.f_stats(rxq->q_queue_h, port_stats, 0);

        /**
         * We don't use .f_rx for rings, so no need to check.
         */
        vr_stats->vis_ifdeqpkts = port_stats->n_pkts_in;
        vr_stats->vis_ifdeqdrops = port_stats->n_pkts_drop;
    }
}

/*
 * rte_mbuf <=> vr_packet conversion
 *
 * The vr_packet structure is right after the rte_mbuf:
 *     struct rte_mbuf + struct vr_packet + headroom + data + tailroom
 *
 * rte_mbuf: *buf_addr(buf_len) + headroom + data_off(data_len) + tailroom
 *
 * rte_mbuf->buf_addr = rte_mbuf + sizeof(rte_mbuf) + sizeof(vr_packet)
 * rte_mbuf->buf_len = elt_size - sizeof(rte_mbuf) - sizeof(vr_packet)
 * rte_mbuf->data_off = RTE_PKTMBUF_HEADROOM
 *
 *
 * vr_packet: *vp_head + headroom + vp_data(vp_len) + vp_tail + tailroom
 *                + vp_end
 *
 * vr_packet->vp_head = rte_mbuf->buf_addr (set in mbuf constructor)
 * vr_packet->vp_data = rte_mbuf->data_off
 * vr_packet->vp_len  = rte_mbuf->data_len
 * vr_packet->vp_tail = vr_packet->vp_data + vr_packet->vp_len
 * vr_packet->vp_end  = rte_mbuf->buf_len (set in mbuf constructor)
 */
static inline struct rte_mbuf *
vr_dpdk_pkt_to_mbuf(struct vr_packet *pkt)
{
    return (struct rte_mbuf *)((uintptr_t)pkt - sizeof(struct rte_mbuf));
}
static inline struct vr_packet *
vr_dpdk_mbuf_to_pkt(struct rte_mbuf *mbuf)
{
    return (struct vr_packet *)((uintptr_t)mbuf + sizeof(struct rte_mbuf));
}

/*
 * vr_dpdk_mbuf_reset - if the mbuf changes, possibley due to
 * pskb_may_pull, reset fields of the pkt structure that point at
 * the mbuf fields.
 * Note: we do not reset pkt->data here
 */
static inline void
vr_dpdk_mbuf_reset(struct vr_packet *pkt)
{
    struct rte_mbuf *mbuf = vr_dpdk_pkt_to_mbuf(pkt);

    pkt->vp_head = mbuf->buf_addr;
    pkt->vp_tail = rte_pktmbuf_headroom(mbuf) + mbuf->data_len;
    pkt->vp_end = mbuf->buf_len;
    pkt->vp_len = pkt->vp_tail - pkt->vp_data;

    return;
}

/*
 * dpdk_vrouter.c
 */
/* pktmbuf constructor with vr_packet support */
void vr_dpdk_pktmbuf_init(struct rte_mempool *mp, void *opaque_arg, void *_m, unsigned i);
/* Check if the stop flag is set */
int vr_dpdk_is_stop_flag_set(void);
/* Called by user space vhost server at exit */
void vr_dpdk_exit_trigger(void);

/*
 * vr_dpdk_ethdev.c
 */
/* Init eth RX queue */
struct vr_dpdk_queue *
vr_dpdk_ethdev_rx_queue_init(unsigned lcore_id, struct vr_interface *vif,
    unsigned rx_queue_id);
/* Init eth TX queue */
struct vr_dpdk_queue *
vr_dpdk_ethdev_tx_queue_init(unsigned lcore_id, struct vr_interface *vif,
    unsigned tx_queue_id);
/* Init ethernet device */
int vr_dpdk_ethdev_init(struct vr_dpdk_ethdev *);
/* Release ethernet device */
int vr_dpdk_ethdev_release(struct vr_dpdk_ethdev *);
/* Get free queue ID */
uint16_t vr_dpdk_ethdev_ready_queue_id_get(struct vr_interface *vif);
/* Add hardware filter */
int vr_dpdk_ethdev_filter_add(struct vr_interface *vif, uint16_t queue_id,
    unsigned dst_ip, unsigned mpls_label);
/* Init hardware filtering */
int vr_dpdk_ethdev_filtering_init(struct vr_interface *vif, struct vr_dpdk_ethdev *ethdev);
/* Init RSS */
int vr_dpdk_ethdev_rss_init(struct vr_dpdk_ethdev *ethdev);
/* Emulate smart NIC RX for a burst of mbufs
 * Returns:
 *     0  if at least one mbuf has been hashed by NIC, so there is
 *        no need to emulate RSS
 *     1  if the RSS need to be emulated
 */
int vr_dpdk_ethdev_rx_emulate(struct vr_interface *vif, struct rte_mbuf *pkts[VR_DPDK_RX_BURST_SZ],
    uint32_t nb_pkts);

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
void vr_dpdk_pfree(struct rte_mbuf *mbuf, unsigned short reason);
/* Retry socket connection */
int vr_dpdk_retry_connect(int sockfd, const struct sockaddr *addr,
                            socklen_t alen);
/* Generates unique log message */
int vr_dpdk_ulog(uint32_t level, uint32_t logtype, uint32_t *last_hash,
                    const char *format, ...);
#if (RTE_LOG_LEVEL == RTE_LOG_DEBUG)
#define DPDK_DEBUG_VAR(v) v
#define DPDK_UDEBUG(t, h, ...)                          \
    (void)(((RTE_LOGTYPE_ ## t & rte_logs.type)) ?      \
    vr_dpdk_ulog(RTE_LOG_DEBUG,                         \
        RTE_LOGTYPE_ ## t, h, # t ": " __VA_ARGS__) : 0)
#else
#define DPDK_DEBUG_VAR(v)
#define DPDK_UDEBUG(t, h, ...)
#endif

/*
 * vr_dpdk_interface.c
 */
/* Lock interface operations */
static inline int vr_dpdk_if_lock()
{ return pthread_mutex_lock(&vr_dpdk.if_lock); }
/* Unlock interface operations */
static inline int vr_dpdk_if_unlock()
{ return pthread_mutex_unlock(&vr_dpdk.if_lock); }

/*
 * vr_dpdk_knidev.c
 */
/* Init KNI */
int vr_dpdk_knidev_init(uint8_t port_id, struct vr_interface *vif);
/* Release KNI */
int vr_dpdk_knidev_release(struct vr_interface *vif);
/* Init KNI RX queue */
struct vr_dpdk_queue *
vr_dpdk_kni_rx_queue_init(unsigned lcore_id, struct vr_interface *vif,
    unsigned host_lcore_id);
/* Init KNI TX queue */
struct vr_dpdk_queue *
vr_dpdk_kni_tx_queue_init(unsigned lcore_id, struct vr_interface *vif,
    unsigned host_lcore_id);
/* Handle all KNIs attached */
void vr_dpdk_knidev_all_handle(void);

/*
 * vr_dpdk_packet.c
 */
void vr_dpdk_packet_wakeup(void);
int dpdk_packet_socket_init(void);
void dpdk_packet_socket_close(void);
int dpdk_packet_io(void);

/*
 * vr_dpdk_lcore.c
 */
/* Launch lcore main loop */
int vr_dpdk_lcore_launch(void *dummy);
/* Schedule an interface */
int vr_dpdk_lcore_if_schedule(struct vr_interface *vif, unsigned least_used_id,
    uint16_t nb_rx_queues, vr_dpdk_queue_init_op rx_queue_init_op,
    uint16_t nb_tx_queues, vr_dpdk_queue_init_op tx_queue_init_op);
/* Unschedule an interface */
void vr_dpdk_lcore_if_unschedule(struct vr_interface *vif);
/* Schedule an MPLS label queue */
int vr_dpdk_lcore_mpls_schedule(struct vr_interface *vif, unsigned dst_ip,
    unsigned mpls_label);
/* Returns the least used lcore or VR_MAX_CPUS */
unsigned vr_dpdk_lcore_least_used_get(void);
/* Flush TX queues */
static inline void
vr_dpdk_lcore_flush(struct vr_dpdk_lcore *lcore)
{
    struct vr_dpdk_queue *tx_queue;
    const unsigned lcore_id = rte_lcore_id();
    struct rte_port_out_stats port_stats;
    struct vr_interface_stats *vr_stats;

    SLIST_FOREACH(tx_queue, &lcore->lcore_tx_head, q_next) {
        tx_queue->txq_ops.f_flush(tx_queue->q_queue_h);
        /**
         * Don't update stats if we write to agent interface, as it does
         * not use rte_port_out_stats structure.
         */
        if (tx_queue->q_vif->vif_type != VIF_TYPE_AGENT) {
            vr_stats = vif_get_stats(tx_queue->q_vif, lcore_id);
            dpdk_port_out_stats_update(tx_queue, &port_stats, vr_stats);
        }
    }
}
/* Hash and distribute mbufs */
void
vr_dpdk_lcore_distribute(struct vr_interface *vif, struct rte_mbuf *pkts[VR_DPDK_RX_BURST_SZ],
    uint32_t nb_pkts);
/* Send a burst of mbufs to vRouter */
void
vr_dpdk_lcore_vroute(struct vr_interface *vif, struct rte_mbuf *pkts[VR_DPDK_RX_BURST_SZ],
    uint32_t nb_pkts);
/* Handle an IPC command */
int
vr_dpdk_lcore_cmd_handle(struct vr_dpdk_lcore *lcore);
/* Post an lcore command */
void
vr_dpdk_lcore_cmd_post_all(uint16_t cmd, uint32_t cmd_param);


/*
 * vr_dpdk_netlink.c
 */
void dpdk_netlink_exit(void);
int dpdk_netlink_init(void);
int dpdk_netlink_receive(void *usockp, char *nl_buf, unsigned int nl_len);
int dpdk_netlink_io(void);

/*
 * vr_dpdk_ringdev.c
 */
/* Allocates a new ring */
struct rte_ring *
vr_dpdk_ring_allocate(unsigned host_lcore_id, char *ring_name,
    unsigned vr_dpdk_tx_ring_sz, unsigned flags);
/* Init ring RX queue */
struct vr_dpdk_queue *
vr_dpdk_ring_rx_queue_init(unsigned lcore_id, struct vr_interface *vif,
    unsigned host_lcore_id);
/* Init ring TX queue */
struct vr_dpdk_queue *
vr_dpdk_ring_tx_queue_init(unsigned lcore_id, struct vr_interface *vif,
    unsigned host_lcore_id);
void dpdk_ring_to_push_add(unsigned lcore_id, struct rte_ring *tx_ring,
    struct vr_dpdk_queue *tx_queue);

void
dpdk_ring_to_push_remove(unsigned lcore_id, struct rte_ring *tx_ring);

#endif /*_VR_DPDK_H_ */
