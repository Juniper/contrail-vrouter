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
#include "vr_dpdk_compat.h"
#include "vr_interface.h"
#include "vr_packet.h"
#include "vr_fragment.h"

#include <sys/queue.h>

#include <urcu-qsbr.h>

#include <rte_config.h>
#include <rte_port.h>
#include <rte_ip.h>
#include <rte_port_ring.h>
#include <rte_ethdev.h>

extern struct vr_interface_stats *vif_get_stats(struct vr_interface *,
        unsigned short);
extern int dpdk_vlan_forwarding_if_add(void);
extern unsigned int vr_flow_hold_limit;
extern int no_huge_set;
extern unsigned vr_packet_sz;

/*
 * Use RTE_LOG_DEBUG to enable debug logs.
 * See more debug options below.
 */
#undef RTE_LOG_LEVEL
#ifdef COMPILE_DEBUG_LOGS
#define RTE_LOG_LEVEL               RTE_LOG_DEBUG
#else
#define RTE_LOG_LEVEL               RTE_LOG_INFO
#endif

/*
 * By default all the logtypes are enabled.
 * Use VR_DPDK_LOGTYPE_DISABLE option below to disable some of the types.
 */
#define RTE_LOGTYPE_VROUTER         RTE_LOGTYPE_USER1
#define RTE_LOGTYPE_USOCK           RTE_LOGTYPE_USER2
#define RTE_LOGTYPE_UVHOST          RTE_LOGTYPE_USER3
#define RTE_LOGTYPE_DPCORE          RTE_LOGTYPE_USER4
/* Disable the rest (undefined) logtypes */
#define VR_DPDK_LOGTYPE_DISABLE     (RTE_LOGTYPE_USER5 | RTE_LOGTYPE_USER6 | \
                                     RTE_LOGTYPE_USER7 | RTE_LOGTYPE_USER8)

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
/* Default memory size to allocate at startup (in MBs) */
#define VR_DPDK_DEF_MEM             "1024"
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
#define VR_DPDK_MAX_NB_TX_QUEUES    64
/* bnxt NIC only supports 8 TX queues */
#define VR_DPDK_MAX_NB_TX_Q_BNXT    8
/* bnxt and enic only support 9022 size jumbo frames */
#define VT_DPDK_MAX_RX_PKT_LEN_9022 9022
/*
 * Special value for number of queues to indicate that each
 * packet forwarding core should be assigned one queue
 */
#define VR_DPDK_ONE_QUEUE_PER_CORE  ((uint16_t)-1)
/* Maximum number of hardware RX queues to use for RSS (limited by the number of lcores) */
#define VR_DPDK_MAX_NB_RSS_QUEUES   16
/* Maximum number of bond members per ethernet device */
#define VR_DPDK_BOND_MAX_SLAVES     6
/* Maximum RETA table size */
#define VR_DPDK_MAX_RETA_SIZE       ETH_RSS_RETA_SIZE_512
#define VR_DPDK_MAX_RETA_ENTRIES    (VR_DPDK_MAX_RETA_SIZE/RTE_RETA_GROUP_SIZE)
/* Number of hardware RX ring descriptors per queue */
#define VR_DPDK_NB_RXD              128
/* Number of hardware TX ring descriptors per queue */
#define VR_DPDK_NB_TXD              128
/* Offset to MPLS label for hardware filtering (in 16-bit word units) */
#define VR_DPDK_MPLS_OFFSET         ((VR_ETHER_HLEN             \
                                    + sizeof(struct vr_ip)      \
                                    + sizeof(struct vr_udp))/2)
/* Maximum number of rings per lcore (maximum is VR_MAX_INTERFACES*VR_MAX_CPUS) */
#define VR_DPDK_MAX_RINGS           (VR_MAX_INTERFACES*2)
/* Maximum number of bond interfaces per lcore */
#define VR_DPDK_MAX_BONDS           2
/* Max size of a single packet used by default */
#define VR_DEF_MAX_PACKET_SZ        (9 * 1024)
/* Number of bytes needed for each mbuf header */
#define VR_DPDK_MBUF_HDR_SZ         (sizeof(struct rte_mbuf)   \
                                    + sizeof(struct vr_packet) \
                                    + RTE_PKTMBUF_HEADROOM)
/* Size of direc mbuf used for fragmentation. It needs a headroom as it holds
 * the IP headers of the fragments and we have to prepend an outer (tunnel)
 * header. */
#define VR_DPDK_FRAG_DIRECT_MBUF_SZ     (sizeof(struct rte_mbuf)    \
                                         + 2*RTE_PKTMBUF_HEADROOM)
/* Size of indirect mbufs used for fragmentation. These mbufs holds only a
 * pointer to the data in other mbufs, thus they don't need any additional
 * buffer size. */
#define VR_DPDK_FRAG_INDIRECT_MBUF_SZ   (sizeof(struct rte_mbuf))
/* How many packets to read/write from/to queue in one go */
#define VR_DPDK_RX_BURST_SZ         32
#define VR_DPDK_TX_BURST_SZ         32
/* Default Number of mbufs in RSS mempool */
#define VR_DEF_MEMPOOL_SZ           (16 * 1024)
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
/* Number of mbufs in TX rings (like ring to push, socket, VLAN rings etc */
#define VR_DPDK_TX_RING_SZ          (VR_DPDK_TX_BURST_SZ*32)
/* RX ring minimum number of pointers to transfer (cache line / size of ptr) */
#define VR_DPDK_RX_RING_CHUNK_SZ    1
/* Number of mbufs in lcore RX ring (we retry in case enqueue fails) */
#define VR_DPDK_RX_RING_SZ          1024
/* Number of retries to enqueue packets */
#define VR_DPDK_RETRY_NUM           1
/* Delay between retries */
#define VR_DPDK_RETRY_US            15
/* Use timer to measure flushes (slower, but should improve latency) */
#define VR_DPDK_USE_TIMER           false
/* TX flush timeout (in loops or US if USE_TIMER defined) */
#define VR_DPDK_TX_FLUSH_LOOPS      16
/* TX idle timeout - if packets are not sent to a VM for this many
 * forwarding loops, its TX queue can be flushed if it is not
 * empty (to reduce latency).
 */
#define VR_DPDK_TX_IDLE_LOOPS       5
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
/* Sleep (in US) no packets received on any TAP devs (use 0 to disable) */
#define VR_DPDK_TAPDEV_SLEEP_NO_PACKETS_US 500
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
#define VR_DPDK_MAX_KNI_INTERFACES  16
/* Maximum number of TAP devices (vhost0 + monitoring) */
#define VR_DPDK_MAX_TAP_INTERFACES  16
/* String buffer size (for logs and EAL arguments) */
#define VR_DPDK_STR_BUF_SZ          512
/* Log timestamp format */
#define VR_DPDK_TIMESTAMP           "%F %T"
/* Maximum number of fragments allowed after IP fragmentation. Set to 7 to
 * allow for standard jumbo frame size (9000 / 1500 = 6) + 1 additional segment
 * for outer headers. */
#define VR_DPDK_FRAG_MAX_IP_FRAGS   7
#define VR_DPDK_FRAG_MAX_IP_SEGS    128
#define VR_DPDK_VLAN_FWD_DEF_NAME   "vfw0"
/*
 * Use IO lcores:
 *   true  - IO lcores distribute packet among forwarding lcores
 *   false - forwarding lcores distribute among other forwarding lcores
 */
#define VR_DPDK_USE_IO_LCORES       false
/*
 * Whether IO lcore share CPUs with forwarding lcores
 *   true  - each IO lcore has an affinity mask of all the forwarding
 *           lcores it distributes packets to
 *           Example: if core mask is 0xf and FWD_LCORES_PER_IO is 2,
 *             there are will be 4 forwarding lcores: 7@0,8@1,9@2,10@3
 *             and 2 shared IO lcores: 3@(0,1),4@(2,3)
 *   false - IO lcore has a dedicated CPU core
 *           Example: if core mask is 0x3f and FWD_LCORES_PER_IO is 2,
 *             there are will be 4 forwarding lcores: 7@1,8@2,9@4,10@5
 *             and 2 dedicated IO lcores: 3@0,4@3
 */
#define VR_DPDK_SHARED_IO_LCORES    false
/*
 * Create IO lcore for the specified number of forwarding lcores.
 * The maximum number of IO lcores is limited by IO lcore IDs below.
 */
#define VR_DPDK_FWD_LCORES_PER_IO   3

/*
 * Number of open fds needed for vrouter (other than one uvhost fd per
 * interface)
 */
#define VR_DPDK_NUM_FDS    512

/* Maximum number of HOLD entries in flow table */
#define VR_DPDK_MAX_FLOW_TABLE_HOLD_COUNT 1000
/* Maximum number of mbufs in fragment assembler. */
#define VR_DPDK_MAX_FRAGMENT_ELEMENTS     1024ULL
/*
 * SR-IOV virtual function PMD name suffix.
 * Note: only rte_ixgbevf_pmd was tested.
 */
#if (RTE_VERSION == RTE_VERSION_NUM(2, 1, 0, 0))
#define VR_DPDK_VF_PMD_SFX "vf_pmd"
#define RTE_LOG_DP RTE_LOG
#else
#define VR_DPDK_VF_PMD_SFX "_vf"
#endif

/*
 * DPDK LCore IDs
 */
enum {
    VR_DPDK_KNITAP_LCORE_ID = 0,
    VR_DPDK_TIMER_LCORE_ID,
    VR_DPDK_UVHOST_LCORE_ID,
    /*
     * The actual number of IO lcores depends on the number of
     * forwarding lcores.
     */
    VR_DPDK_IO_LCORE_ID,
    VR_DPDK_IO_LCORE_ID2,
    VR_DPDK_IO_LCORE_ID3,
    VR_DPDK_IO_LCORE_ID4,
    VR_DPDK_LAST_IO_LCORE_ID,
    /* [PACKET_ID..FWD_ID) lcores have TX queues, but no RX queues */
    VR_DPDK_PACKET_LCORE_ID,
    VR_DPDK_NETLINK_LCORE_ID,
    /* The actual number of forwarding lcores depends on affinity mask. */
    VR_DPDK_FWD_LCORE_ID,
};

/* Maximum number of IO lcores */
#define VR_DPDK_MAX_IO_LORES (VR_DPDK_LAST_IO_LCORE_ID - VR_DPDK_IO_LCORE_ID + 1)


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

struct vr_dpdk_rcu_cb_data {
    struct rcu_head rcd_rcu;
    vr_defer_cb rcd_user_cb;
    struct vrouter *rcd_router;
    unsigned char rcd_user_data[0];
};

/* Init queue operation */
typedef struct vr_dpdk_queue *
    (*vr_dpdk_queue_init_op)(unsigned lcore_id, struct vr_interface *vif,
        unsigned queue_or_lcore_id);
/* Release queue operation */
typedef void
    (*vr_dpdk_queue_release_op)(unsigned lcore_id, unsigned queue_index,
            struct vr_interface *vif);

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
    /* Enabled/disabled (whether polled by lcores) */
    bool enabled;
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
    /* Command arguments are being published */
    VR_DPDK_LCORE_IN_PROGRESS_CMD,
    /* Stop and exit the lcore loop */
    VR_DPDK_LCORE_STOP_CMD,
    /* Remove RX queue */
    VR_DPDK_LCORE_RX_RM_CMD,
    /* Remove TX queue */
    VR_DPDK_LCORE_TX_RM_CMD,
    /* Call RCU callback */
    VR_DPDK_LCORE_RCU_CMD,
    /* TX queue disable/enable command */
    VR_DPDK_LCORE_TX_QUEUE_SET_CMD,
    /* RX queue disable/enable command */
    VR_DPDK_LCORE_RX_QUEUE_SET_CMD,
};

struct gro_ctrl {
    int     gro_queued;
    int     gro_flushed;
    int     gro_bad_csum;
    int     gro_cnt;
    int     gro_flows;
    int     gro_flush_inactive_flows;

    struct rte_hash *gro_tbl_v4_handle;
    struct rte_hash *gro_tbl_v6_handle;
};

struct vr_dpdk_lcore_rx_queue_remove_arg {
    unsigned int vif_id;
    bool clear_f_rx;
    bool free_arg;
};

struct vr_dpdk_lcore {
    /**********************************************************************/
    /* Frequently used fields */
    /* RX queues head */
    struct vr_dpdk_q_slist lcore_rx_head;
    /* TX queues head */
    struct vr_dpdk_q_slist lcore_tx_head;
    /* Forwarding lcore: number of rings to push for the lcore */
    volatile uint16_t lcore_nb_rings_to_push;
    /* Forwarding lcore: number of bond queues to TX */
    volatile uint16_t lcore_nb_bonds_to_tx;
    /* Number of hardware RX queues assigned to the lcore (for the scheduler) */
    uint16_t lcore_nb_rx_queues;
    /* Lcore command */
    volatile uint16_t lcore_cmd;
    /* Lcore command arguments */
    volatile uint64_t lcore_cmd_arg;
    /* RX ring with packets from other lcores (i.e. for MPLSoGRE). */
    struct rte_ring *lcore_rx_ring;
    /* RX ring with packets from IO lcore. */
    struct rte_ring *lcore_io_rx_ring;
    /* Number of forwarding loops */
    u_int64_t lcore_fwd_loops;
    /* Flag controlling the assembler work */
    bool do_fragment_assembly;
    /* GRO ctrl structure */
    struct gro_ctrl gro;

    /**********************************************************************/
    /* Big and less frequently used fields */
    /* Number of lcores to distribute packets to */
    uint16_t lcore_nb_dst_lcores;
    /* List of forwarding lcore indexes based on VR_DPDK_FWD_LCORE_ID */
    uint16_t lcore_dst_lcore_idxs[VR_MAX_CPUS];
    /* Table of RX queues */
    struct vr_dpdk_queue lcore_rx_queues[VR_MAX_INTERFACES];
    /* Table of TX queues */
    struct vr_dpdk_queue *lcore_tx_queues[VR_MAX_INTERFACES] __rte_cache_aligned;
    /* List of rings to push */
    struct vr_dpdk_ring_to_push lcore_rings_to_push[VR_DPDK_MAX_RINGS] __rte_cache_aligned;
    /* List of bond queue params to TX LACP packets periodically */
    struct vr_dpdk_queue_params *lcore_bonds_to_tx[VR_DPDK_MAX_BONDS] __rte_cache_aligned;
    /* Table of RX queue params */
    struct vr_dpdk_queue_params lcore_rx_queue_params[VR_MAX_INTERFACES] __rte_cache_aligned;
    /* Table of TX queue params */
    struct vr_dpdk_queue_params *lcore_tx_queue_params[VR_MAX_INTERFACES] __rte_cache_aligned;
    /*
     * number of queues/lcore - basically one hardware queue + rings
     * to other cores that hosts each hardware queue
     *
     * If hardware queueing is supported, num_tx_queues_per_lcore will
     * be equal to the number of queues that the agent wants to use.
     * The number of queues that the agent wants to use is set in the
     * vr_interface structure (vif_num_hw_queues). agent will read its
     * configuration file and tell vRouter the queue numbers it wants
     * to use (and hence the number of queues) and set this information
     * in vif_hw_queues
     */
    uint16_t num_tx_queues_per_lcore[VR_MAX_INTERFACES];
    /* for each vif, the first hardware queue that is tied to this lcore */
    int16_t lcore_hw_queue[VR_MAX_INTERFACES];
    /*
     * given a hardware queue, the index to the array of vr_dpdk_queue.
     * Enables us to get the queue faster
     */
    int16_t *lcore_hw_queue_to_dpdk_index[VR_MAX_INTERFACES];
    void (*fragment_assembly_func)(void *arg);
    void *fragment_assembly_arg;
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

struct vif_queue_dpdk_data {
    int16_t vqdd_queue_to_lcore[VR_DPDK_MAX_NB_TX_QUEUES];
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

/* Tapdev configuration. */
struct vr_dpdk_tapdev {
    /* Tapdev file descriptor. */
    volatile int tapdev_fd;
    /* RX ring. */
    struct rte_ring *tapdev_rx_ring;
    /* TX rings (single-producer single-consumer) */
    struct rte_ring *tapdev_tx_rings[RTE_MAX_LCORE];
    /* Pointer to vif. */
    struct vr_interface *tapdev_vif;
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
    /* We are use it in unittest application (vtest) for vlan
     * adding workaround for virtual interfaces. */
    uint16_t vtest_vlan;
    /* Number of forwarding lcores */
    uint16_t nb_fwd_lcores;
    /* Number of IO lcores */
    uint16_t nb_io_lcores;
    /* Packet lcore event socket
     * TODO: refactor to use event FD
     */
    void *packet_event_sock;
    /* NetLink lcore event socket */
    void *netlink_event_sock;
    /* Event FD to wake up UVHost */
    int uvhost_event_fd;

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
    void *bridge_table;
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
    /* Table of tapdevs. */
    struct vr_dpdk_tapdev tapdevs[VR_DPDK_MAX_TAP_INTERFACES] __rte_cache_aligned;
    /* netlink socket to listen to link up/down and mtu change notifications */
    volatile int tap_nl_fd;
    /* VLAN forwarding interface name */
    char vlan_name[VR_INTERFACE_NAME_LEN];
    /* VLAN forwarding interface ring */
    struct rte_ring *vlan_ring;
    /* VLAN forwarding device pointer. */
    void *vlan_dev;
    /* VLAN forwarding interface vif. */
    struct vr_interface *vlan_vif;
    /* Dedicated IO lcore for SR-IOV VF. */
    unsigned vf_lcore_id;
    /*
     * KNI global state flag:
     *  0 - initial state
     *  1 - KNI is enabled
     * -1 - KNI is not available, so TAP interfaces are used instead
     */
    int kni_state;
};

extern struct vr_dpdk_global vr_dpdk;
extern struct rte_eth_conf ethdev_conf;

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
/* A packet mbuf pool constructor with vr_packet support */
void vr_dpdk_pktmbuf_pool_init(struct rte_mempool *mp, void *opaque_arg);
/* The packet mbuf constructor with vr_packet support */
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
int vr_dpdk_ethdev_init(struct vr_dpdk_ethdev *, struct rte_eth_conf *);
/* Release ethernet device */
int vr_dpdk_ethdev_release(struct vr_dpdk_ethdev *);
/* Get free queue ID */
uint16_t vr_dpdk_ethdev_ready_queue_id_get(struct vr_interface *vif);

#if VR_DPDK_USE_HW_FILTERING
/* Add hardware filter */
int vr_dpdk_ethdev_filter_add(struct vr_interface *vif, uint16_t queue_id,
    unsigned dst_ip, unsigned mpls_label);
/* Init hardware filtering */
int vr_dpdk_ethdev_filtering_init(struct vr_interface *vif, struct vr_dpdk_ethdev *ethdev);
#endif

/* Init RSS */
int vr_dpdk_ethdev_rss_init(struct vr_dpdk_ethdev *ethdev);
/*
 * vr_dpdk_ethdev_rx_emulate - emulate smart NIC RX:
 *  - strip VLAN tags for packets received from fabric interface
 *  - calculate RSS hash if it is not present
 *  - recalculate RSS hash for MPLSoGRE packets
 *
 * Returns 0 on no hash changes, otherwise a bitmask of mbufs to distribute.
 */
uint64_t vr_dpdk_ethdev_rx_emulate(struct vr_interface *vif,
    struct rte_mbuf *pkts[VR_DPDK_RX_BURST_SZ], uint32_t *nb_pkts);
/* Check if port_id is a bond slave. */
bool vr_dpdk_ethdev_bond_port_match(uint8_t port_id, struct vr_dpdk_ethdev *ethdev);

int vr_dpdk_table_mem_init(unsigned int, unsigned int, unsigned long,
        unsigned int, unsigned long);
int vr_dpdk_flow_init(void);
int vr_dpdk_bridge_init(void);

/*
 * vr_dpdk_host.c
 */
int vr_dpdk_host_init(void);
void vr_dpdk_host_exit(void);
/* Convert internal packet fields */
struct vr_packet * vr_dpdk_packet_get(struct rte_mbuf *m, struct vr_interface *vif);
void vr_dpdk_pfree(struct rte_mbuf *mbuf, struct vr_interface *vif, unsigned short reason);
/* Retry socket connection */
int vr_dpdk_retry_connect(int sockfd, const struct sockaddr *addr,
                            socklen_t alen);
/* Generates unique log message */
int vr_dpdk_ulog(uint32_t level, uint32_t logtype, uint32_t *last_hash,
                    const char *format, ...);
#if (RTE_LOG_LEVEL == RTE_LOG_DEBUG)
#define DPDK_DEBUG_VAR(v) v
#define DPDK_UDEBUG(t, h, ...)                          \
    (void)(((RTE_LOG_DEBUG <= RTE_LOG_LEVEL) &&         \
        (RTE_LOG_DEBUG <= rte_logs.level) &&            \
        (RTE_LOGTYPE_ ## t & rte_logs.type)) ?          \
    vr_dpdk_ulog(RTE_LOG_DEBUG,                         \
        RTE_LOGTYPE_ ## t, h, # t ": " __VA_ARGS__) : 0)
#else
#define DPDK_DEBUG_VAR(v)
#define DPDK_UDEBUG(t, h, ...)
#endif
/* Helper to adjust TCP MSS */
void dpdk_adjust_tcp_mss(struct tcphdr *tcph, unsigned short overlay_len,
                            unsigned char iph_len);
/* Creates a copy of the given packet mbuf */
struct rte_mbuf *
vr_dpdk_pktmbuf_copy(struct rte_mbuf *md, struct rte_mempool *mp);
struct rte_mbuf *
vr_dpdk_pktmbuf_copy_mon(struct rte_mbuf *md, struct rte_mempool *mp);

/*
 * vr_dpdk_interface.c
 */
/* Lock interface operations */
static inline int vr_dpdk_if_lock()
{ return pthread_mutex_lock(&vr_dpdk.if_lock); }
/* Unlock interface operations */
static inline int vr_dpdk_if_unlock()
{ return pthread_mutex_unlock(&vr_dpdk.if_lock); }
uint16_t dpdk_get_ether_header_len(const void *data);

/*
 * vr_dpdk_tapdev.c
 */
/* Init TAP device. */
int vr_dpdk_tapdev_init(struct vr_interface *vif);
/* Release TAP device. */
int vr_dpdk_tapdev_release(struct vr_interface *vif);
/* Init TAP RX queue. */
struct vr_dpdk_queue *
vr_dpdk_tapdev_rx_queue_init(unsigned lcore_id, struct vr_interface *vif,
    unsigned queue_id);
/* Init TAP TX queue. */
struct vr_dpdk_queue *
vr_dpdk_tapdev_tx_queue_init(unsigned lcore_id, struct vr_interface *vif,
    unsigned queue_id);
/* RX/TX to/from all the TAP devices. */
uint64_t vr_dpdk_tapdev_rxtx(void);
/* RX a burst of packets from the TAP device. */
unsigned vr_dpdk_tapdev_rx_burst(struct vr_dpdk_tapdev *, struct rte_mbuf **,
        unsigned num);
/* Dequeue a burst of packets from the TAP device. */
unsigned vr_dpdk_tapdev_dequeue_burst(struct vr_dpdk_tapdev *, struct rte_mbuf **,
        unsigned num);
/* TX a burst of packets to the TAP device. */
unsigned vr_dpdk_tapdev_tx_burst(struct vr_dpdk_tapdev *, struct rte_mbuf **,
        unsigned num);
/* Enqueue a burst of packets to the TAP device. */
unsigned vr_dpdk_tapdev_enqueue_burst(struct vr_dpdk_tapdev *, struct rte_mbuf **,
        unsigned num);
void vr_dpdk_tapdev_handle_notifications(void);

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
void vr_dpdk_packet_wakeup(struct vr_interface *vif);
int dpdk_packet_socket_init(void);
void dpdk_packet_socket_close(void);
int dpdk_packet_io(void);
/* RCU callback called on packet lcore */
void vr_dpdk_packet_rcu_cb(struct rcu_head *rh);
/* Work callback called on packet lcore */
void vr_dpdk_packet_work_cb(void (*fn)(void *), void *arg);

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

    SLIST_FOREACH(tx_queue, &lcore->lcore_tx_head, q_next) {
        tx_queue->txq_ops.f_flush(tx_queue->q_queue_h);
    }
}
/*
 * Distribute mbufs among forwarding lcores using hash.rss.
 * The destination lcores are listed in lcore->lcore_dst_lcores.
 */
void
vr_dpdk_lcore_distribute(struct vr_dpdk_lcore *lcore, const bool io_lcore,
    struct vr_interface *vif, struct rte_mbuf *pkts[VR_DPDK_RX_BURST_SZ],
    uint32_t nb_pkts);
/* Pass mbufs to dp-core. */
void
vr_dpdk_lcore_vroute(struct vr_dpdk_lcore *lcore, struct vr_interface *vif,
    struct rte_mbuf *pkts[VR_DPDK_RX_BURST_SZ], uint32_t nb_pkts);
/* Handle an IPC command */
int vr_dpdk_lcore_cmd_handle(struct vr_dpdk_lcore *lcore);
/* Busy wait for a command to complete on a specific lcore */
void vr_dpdk_lcore_cmd_wait(unsigned lcore_id);
/* Post an lcore command to a specific lcore */
void
vr_dpdk_lcore_cmd_post(unsigned lcore_id, uint16_t cmd, uint64_t cmd_arg);
/* Post an lcore command to all the lcores */
void vr_dpdk_lcore_cmd_post_all(uint16_t cmd, uint64_t cmd_arg);
/* Schedule an asslembler work on an lcore */
void vr_dpdk_lcore_schedule_assembler_work(struct vr_dpdk_lcore *lcore,
        void (*fun)(void *arg), void *arg);
void dpdk_lcore_exit(unsigned lcore_id);
/*
 * vr_dpdk_netlink.c
 */
void vr_dpdk_netlink_wakeup(void);
void dpdk_netlink_exit(void);
int dpdk_netlink_init(void);
int dpdk_netlink_receive(void *usockp, char *nl_buf, unsigned int nl_len);

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
        unsigned int queue_id, unsigned host_lcore_id);
void dpdk_ring_to_push_add(unsigned lcore_id, struct rte_ring *tx_ring,
    struct vr_dpdk_queue *tx_queue);

void
dpdk_ring_to_push_remove(unsigned lcore_id, struct rte_ring *tx_ring);

/*
 * vr_dpdk_fragment_assembler.c
 */
int dpdk_fragment_assembler_init(void);
void dpdk_fragment_assembler_exit(void);
int dpdk_fragment_assembler_enqueue(struct vrouter *router,
        struct vr_packet *pkt, struct vr_forwarding_md *fmd);
void dpdk_fragment_assembler_table_scan(void *);
void dpdk_gro_free_all_flows(struct vr_dpdk_lcore *lcore);
void dpdk_gro_flush_all_inactive(struct vr_dpdk_lcore *lcore);
int dpdk_gro_process(struct vr_packet *pkt, struct vr_interface *vif, bool l2_pkt);
int dpdk_segment_packet(struct vr_packet *pkt, struct rte_mbuf *mbuf_in, 
                struct rte_mbuf **mbuf_out, const unsigned short out_num, 
                const unsigned short mss_size, bool do_outer_ip_csum);
uint16_t dpdk_ipv4_udptcp_cksum(struct rte_mbuf *m, 
                       const struct ipv4_hdr *ipv4_hdr, 
                       uint8_t *l4_hdr);
uint16_t dpdk_ipv6_udptcp_cksum(struct rte_mbuf *m, 
                       const struct ipv6_hdr *ipv6_hdr,
                       uint8_t *l4_hdr);
int dpdk_check_rx_mrgbuf_disable(void);

/*
 * Get bond interface port id by drv_name
 */
uint8_t dpdk_find_port_id_by_drv_name(void);

#endif /*_VR_DPDK_H_ */
