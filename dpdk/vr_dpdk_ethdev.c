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
 * vr_dpdk_ethdev.c -- DPDK ethernet device
 *
 */

#include "vr_dpdk.h"

#include <vr_mpls.h>
#include "cust_rte_mbuf.h"

#include <rte_eth_bond.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_hash_crc.h>
#include <rte_ip.h>
#include <rte_port_ethdev.h>
#include <rte_udp.h>

static struct rte_eth_conf ethdev_conf = {
    .link_speed = 0,    /* ETH_LINK_SPEED_10[0|00|000], or 0 for autonegotation */
    .link_duplex = 0,   /* ETH_LINK_[HALF_DUPLEX|FULL_DUPLEX], or 0 for autonegotation */
    .rxmode = { /* Port RX configuration. */
        /* The multi-queue packet distribution mode to be used, e.g. RSS. */
        .mq_mode            = ETH_MQ_RX_RSS,
        .max_rx_pkt_len     = ETHER_MAX_LEN, /* Only used if jumbo_frame enabled */
        .header_split       = 0, /* Disable Header Split */
        .hw_ip_checksum     = 1, /* Enable IP/UDP/TCP checksum offload */
        .hw_vlan_filter     = 0, /* Disabel VLAN filter */
        .hw_vlan_strip      = 0, /* Disable VLAN strip (might be enabled with --vlan argument) */
        .hw_vlan_extend     = 0, /* Disable Extended VLAN */
        .jumbo_frame        = 0, /* Disable Jumbo Frame Receipt */
        .hw_strip_crc       = 0, /* Disable CRC stripping by hardware */
        .enable_scatter     = 0, /* Disable scatter packets rx handler */
    },
    .rx_adv_conf = {
        .rss_conf = { /* Port RSS configuration */
            .rss_key            = NULL, /* If not NULL, 40-byte hash key */
            .rss_key_len        = 0,    /* Hash key length in bytes */
            /* Hash functions to apply */
            .rss_hf             = ETH_RSS_IP | ETH_RSS_UDP | ETH_RSS_TCP,
        },
    },
    .txmode = { /* Port TX configuration. */
        .mq_mode            = ETH_MQ_TX_NONE, /* TX multi-queues mode */
        /* For i40e specifically */
        .pvid               = 0,
        .hw_vlan_reject_tagged      = 0, /* If set, reject sending out tagged pkts */
        .hw_vlan_reject_untagged    = 0, /* If set, reject sending out untagged pkts */
        .hw_vlan_insert_pvid        = 0, /* If set, enable port based VLAN insertion */
    },
    .fdir_conf = {
#if VR_DPDK_USE_HW_FILTERING
        .mode = RTE_FDIR_MODE_PERFECT,          /* Flow Director mode. */
        .status = RTE_FDIR_REPORT_STATUS,       /* How to report FDIR hash. */
#else
        .mode = RTE_FDIR_MODE_NONE,
        .status = RTE_FDIR_NO_REPORT_STATUS,
#endif
        .pballoc = RTE_FDIR_PBALLOC_64K,        /* Space for FDIR filters. */
        /* Offset of flexbytes field in RX packets (in 16-bit word units). */
        /* TODO: flow director API has changed since DPDK 1.7 */
//        .flexbytes_offset = VR_DPDK_MPLS_OFFSET,
        /* RX queue of packets matching a "drop" filter in perfect mode. */
        .drop_queue = 0,
        .flex_conf = {
        },
    },
};

/* RX and TX Prefetch, Host, and Write-back threshold values should be
 * carefully set for optimal performance. Consult the network
 * controller's datasheet and supporting DPDK documentation for guidance
 * on how these parameters should be set.
 */
/* RX ring configuration */
static const struct rte_eth_rxconf rx_queue_conf = {
    .rx_thresh = {
        .pthresh = 8,   /* Ring prefetch threshold */
        .hthresh = 8,   /* Ring host threshold */
        .wthresh = 4,   /* Ring writeback threshold */
    },
    /* Do not immediately free RX descriptors */
    .rx_free_thresh = VR_DPDK_RX_BURST_SZ,
};

/*
 * These default values are optimized for use with the Intel(R) 82599 10 GbE
 * Controller and the DPDK ixgbe PMD. Consider using other values for other
 * network controllers and/or network drivers.
 */
/* TX ring configuration */
static const struct rte_eth_txconf tx_queue_conf = {
    .tx_thresh = {
        .pthresh = 36,  /* Ring prefetch threshold */
        .hthresh = 0,   /* Ring host threshold */
        .wthresh = 0,   /* Ring writeback threshold */
    },
    .tx_free_thresh = 0,    /* Use PMD default values */
    .tx_rs_thresh = 0,      /* Use PMD default values */
    .txq_flags = 0          /* Set flags for the Tx queue */
};

/* Add hardware filter */
int
vr_dpdk_ethdev_filter_add(struct vr_interface *vif, uint16_t queue_id,
    unsigned dst_ip, unsigned mpls_label)
{
    struct vr_dpdk_ethdev *ethdev = (struct vr_dpdk_ethdev *)vif->vif_os;
    uint8_t port_id = ethdev->ethdev_port_id;
    struct rte_fdir_filter filter;
    int ret;

    /* accept 2-byte labels only */
    if (mpls_label > 0xffff)
        return -EINVAL;

    if (queue_id > VR_DPDK_MAX_NB_RX_QUEUES)
        return -EINVAL;

    memset(&filter, 0, sizeof(filter));
    filter.iptype = RTE_FDIR_IPTYPE_IPV4;
    filter.l4type = RTE_FDIR_L4TYPE_UDP;
    filter.ip_dst.ipv4_addr = dst_ip;
    filter.port_dst = rte_cpu_to_be_16((uint16_t)VR_MPLS_OVER_UDP_DST_PORT);
    filter.flex_bytes = rte_cpu_to_be_16((uint16_t)mpls_label);

    RTE_LOG(DEBUG, VROUTER, "%s: ip_dst=0x%x port_dst=%d flex_bytes=%d\n", __func__,
        (unsigned)dst_ip, (unsigned)VR_MPLS_OVER_UDP_DST_PORT, (unsigned)mpls_label);

    if (queue_id >= 0xFF) {
        RTE_LOG(ERR, VROUTER, "    error adding perfect filter for eth device %"
                PRIu8 ": queue ID %" PRIu16 " is out of range\n",
                 port_id, queue_id);
        return -EINVAL;
    }
    ret = rte_eth_dev_fdir_add_perfect_filter(port_id, &filter, (uint16_t)mpls_label,
        (uint8_t)queue_id, 0);
    if (ret == 0)
        ethdev->ethdev_queue_states[queue_id] = VR_DPDK_QUEUE_FILTERING_STATE;

    return ret;
}

/* Get a ready queue ID */
uint16_t
vr_dpdk_ethdev_ready_queue_id_get(struct vr_interface *vif)
{
    uint16_t i;
    struct vr_dpdk_ethdev *ethdev = (struct vr_dpdk_ethdev *)vif->vif_os;

    for (i = ethdev->ethdev_nb_rss_queues; i < ethdev->ethdev_nb_rx_queues; i++) {
        if (ethdev->ethdev_queue_states[i] == VR_DPDK_QUEUE_READY_STATE) {
            return i;
        }
    }
    return VR_DPDK_INVALID_QUEUE_ID;
}

/* Release ethdev RX queue */
static void
dpdk_ethdev_rx_queue_release(unsigned lcore_id, struct vr_interface *vif)
{
    struct vr_dpdk_lcore *lcore = vr_dpdk.lcores[lcore_id];
    struct vr_dpdk_queue *rx_queue = &lcore->lcore_rx_queues[vif->vif_idx];
    struct vr_dpdk_queue_params *rx_queue_params
                        = &lcore->lcore_rx_queue_params[vif->vif_idx];

    /* free the queue */
    if (rx_queue->rxq_ops.f_free(rx_queue->q_queue_h)) {
        RTE_LOG(ERR, VROUTER, "    error freeing lcore %u eth device RX queue\n",
                    lcore_id);
    }

    /* reset the queue */
    vrouter_put_interface(rx_queue->q_vif);
    memset(rx_queue, 0, sizeof(*rx_queue));
    memset(rx_queue_params, 0, sizeof(*rx_queue_params));
}

/* Init eth RX queue */
struct vr_dpdk_queue *
vr_dpdk_ethdev_rx_queue_init(unsigned lcore_id, struct vr_interface *vif,
    unsigned queue_or_lcore_id)
{
    uint16_t rx_queue_id = queue_or_lcore_id;
    uint8_t port_id;
    unsigned int vif_idx = vif->vif_idx;
    const unsigned int socket_id = rte_lcore_to_socket_id(lcore_id);

    struct vr_dpdk_ethdev *ethdev;
    struct vr_dpdk_lcore *lcore = vr_dpdk.lcores[lcore_id];
    struct vr_dpdk_queue *rx_queue = &lcore->lcore_rx_queues[vif_idx];
    struct vr_dpdk_queue_params *rx_queue_params
                    = &lcore->lcore_rx_queue_params[vif_idx];

    ethdev = (struct vr_dpdk_ethdev *)vif->vif_os;
    port_id = ethdev->ethdev_port_id;

    /* init queue */
    rx_queue->rxq_ops = rte_port_ethdev_reader_ops;
    rx_queue->q_queue_h = NULL;
    rx_queue->q_vif = vrouter_get_interface(vif->vif_rid, vif_idx);

    /* create the queue */
    struct rte_port_ethdev_reader_params reader_params = {
        .port_id = port_id,
        .queue_id = rx_queue_id,
    };
    rx_queue->q_queue_h = rx_queue->rxq_ops.f_create(&reader_params, socket_id);
    if (rx_queue->q_queue_h == NULL) {
        RTE_LOG(ERR, VROUTER, "    error creating eth device %" PRIu8
                " RX queue %" PRIu16 "\n", port_id, rx_queue_id);
        return NULL;
    }

    /* store queue params */
    rx_queue_params->qp_release_op = &dpdk_ethdev_rx_queue_release;
    rx_queue_params->qp_ethdev.queue_id = rx_queue_id;
    rx_queue_params->qp_ethdev.port_id = port_id;

    return rx_queue;
}

/* Release ethdev TX queue */
static void
dpdk_ethdev_tx_queue_release(unsigned lcore_id, struct vr_interface *vif)
{
    int i;
    struct vr_dpdk_lcore *lcore = vr_dpdk.lcores[lcore_id];
    struct vr_dpdk_queue *tx_queue = &lcore->lcore_tx_queues[vif->vif_idx];
    struct vr_dpdk_queue_params *tx_queue_params
                        = &lcore->lcore_tx_queue_params[vif->vif_idx];

    /* remove queue params from the list of bonds to TX */
    for (i = 0; i < lcore->lcore_nb_bonds_to_tx; i++) {
        if (likely(lcore->lcore_bonds_to_tx[i] == tx_queue_params)) {
            lcore->lcore_bonds_to_tx[i] = NULL;
            lcore->lcore_nb_bonds_to_tx--;
            RTE_VERIFY(lcore->lcore_nb_bonds_to_tx <= VR_DPDK_MAX_BONDS);
            /* copy the last element to the empty spot */
            lcore->lcore_bonds_to_tx[i] = lcore->lcore_bonds_to_tx[lcore->lcore_nb_bonds_to_tx];
            break;
        }
    }

    tx_queue->txq_ops.f_tx = NULL;
    rte_wmb();

    /* flush and free the queue */
    if (tx_queue->txq_ops.f_free(tx_queue->q_queue_h)) {
        RTE_LOG(ERR, VROUTER, "    error freeing lcore %u eth device TX queue\n",
                    lcore_id);
    }

    /* reset the queue */
    vrouter_put_interface(tx_queue->q_vif);
    memset(tx_queue, 0, sizeof(*tx_queue));
    memset(tx_queue_params, 0, sizeof(*tx_queue_params));
}

/* Init eth TX queue */
struct vr_dpdk_queue *
vr_dpdk_ethdev_tx_queue_init(unsigned lcore_id, struct vr_interface *vif,
    unsigned queue_or_lcore_id)
{
    uint16_t tx_queue_id = queue_or_lcore_id;
    uint8_t port_id;
    unsigned int vif_idx = vif->vif_idx;
    const unsigned int socket_id = rte_lcore_to_socket_id(lcore_id);

    struct vr_dpdk_ethdev *ethdev;
    struct vr_dpdk_lcore *lcore = vr_dpdk.lcores[lcore_id];
    struct vr_dpdk_queue *tx_queue = &lcore->lcore_tx_queues[vif_idx];
    struct vr_dpdk_queue_params *tx_queue_params
                    = &lcore->lcore_tx_queue_params[vif_idx];

    ethdev = (struct vr_dpdk_ethdev *)vif->vif_os;
    port_id = ethdev->ethdev_port_id;

    /* init queue */
    tx_queue->txq_ops = rte_port_ethdev_writer_ops;
    tx_queue->q_queue_h = NULL;
    tx_queue->q_vif = vrouter_get_interface(vif->vif_rid, vif_idx);

    /* create the queue */
    struct rte_port_ethdev_writer_params writer_params = {
        .port_id = port_id,
        .queue_id = tx_queue_id,
        .tx_burst_sz = VR_DPDK_TX_BURST_SZ,
    };
    tx_queue->q_queue_h = tx_queue->txq_ops.f_create(&writer_params, socket_id);
    if (tx_queue->q_queue_h == NULL) {
        RTE_LOG(ERR, VROUTER, "    error creating eth device %" PRIu8
                " TX queue %" PRIu16 "\n", port_id, tx_queue_id);
        return NULL;
    }

    /* store queue params */
    tx_queue_params->qp_release_op = &dpdk_ethdev_tx_queue_release;
    tx_queue_params->qp_ethdev.queue_id = tx_queue_id;
    tx_queue_params->qp_ethdev.port_id = port_id;

    /* for the queue 0 add queue params to the list of bonds to TX */
    if (ethdev->ethdev_nb_slaves > 0 && tx_queue_id == 0) {
        /* make sure queue params have been stored */
        rte_wmb();
        lcore->lcore_bonds_to_tx[lcore->lcore_nb_bonds_to_tx++] = tx_queue_params;
        RTE_VERIFY(lcore->lcore_nb_bonds_to_tx <= VR_DPDK_MAX_BONDS);
    }

    return tx_queue;
}

/* Update device info */
static void
dpdk_ethdev_info_update(struct vr_dpdk_ethdev *ethdev)
{
    struct rte_eth_dev_info dev_info;

    rte_eth_dev_info_get(ethdev->ethdev_port_id, &dev_info);

    ethdev->ethdev_nb_rx_queues = RTE_MIN(dev_info.max_rx_queues,
        VR_DPDK_MAX_NB_RX_QUEUES);
    /* [PAKCET_ID..FWD_ID) lcores have just TX queues, so we increase
     * the number of TX queues here */
    ethdev->ethdev_nb_tx_queues = RTE_MIN(RTE_MIN(dev_info.max_tx_queues,
        vr_dpdk.nb_fwd_lcores + (VR_DPDK_FWD_LCORE_ID - VR_DPDK_PACKET_LCORE_ID)),
        VR_DPDK_MAX_NB_TX_QUEUES);
    ethdev->ethdev_nb_rss_queues = RTE_MIN(RTE_MIN(ethdev->ethdev_nb_rx_queues,
        vr_dpdk.nb_fwd_lcores), VR_DPDK_MAX_NB_RSS_QUEUES);
    ethdev->ethdev_reta_size = RTE_MIN(dev_info.reta_size,
        VR_DPDK_MAX_RETA_SIZE);

    RTE_LOG(DEBUG, VROUTER, "dev_info: driver_name=%s if_index=%u"
            " max_rx_queues=%" PRIu16 " max_tx_queues=%" PRIu16
            " max_vfs=%" PRIu16 " max_vmdq_pools=%" PRIu16
            " rx_offload_capa=%" PRIx32 " tx_offload_capa=%" PRIx32 "\n",
            dev_info.driver_name, dev_info.if_index,
            dev_info.max_rx_queues, dev_info.max_tx_queues,
            dev_info.max_vfs, dev_info.max_vmdq_pools,
            dev_info.rx_offload_capa, dev_info.tx_offload_capa);

#if !VR_DPDK_USE_HW_FILTERING
    /* use RSS queues only */
    ethdev->ethdev_nb_rx_queues = ethdev->ethdev_nb_rss_queues;
#else
    /* we use just RSS queues if the device does not support RETA */
    if (ethdev->ethdev_reta_size == 0)
        ethdev->ethdev_nb_rx_queues = ethdev->ethdev_nb_rss_queues;
#endif

    return;
}

/* Setup ethdev hardware queues */
static int
dpdk_ethdev_queues_setup(struct vr_dpdk_ethdev *ethdev)
{
    int ret, i;
    uint8_t port_id = ethdev->ethdev_port_id;
    struct rte_mempool *mempool;

    /* configure RX queues */
    RTE_LOG(DEBUG, VROUTER, "%s: nb_rx_queues=%u nb_tx_queues=%u\n",
        __func__, (unsigned)ethdev->ethdev_nb_rx_queues,
            (unsigned)ethdev->ethdev_nb_tx_queues);

    for (i = 0; i < VR_DPDK_MAX_NB_RX_QUEUES; i++) {
        if (i < ethdev->ethdev_nb_rss_queues) {
            mempool = vr_dpdk.rss_mempool;
            ethdev->ethdev_queue_states[i] = VR_DPDK_QUEUE_RSS_STATE;
        } else if (i < ethdev->ethdev_nb_rx_queues) {
            if (vr_dpdk.nb_free_mempools == 0) {
                RTE_LOG(ERR, VROUTER, "    error assigning mempool to eth device %"
                    PRIu8 " RX queue %d\n", port_id, i);
                return -ENOMEM;
            }
            vr_dpdk.nb_free_mempools--;
            mempool = vr_dpdk.free_mempools[vr_dpdk.nb_free_mempools];
            ethdev->ethdev_queue_states[i] = VR_DPDK_QUEUE_READY_STATE;
        } else {
            ethdev->ethdev_queue_states[i] = VR_DPDK_QUEUE_NONE;
            continue;
        }

        ret = rte_eth_rx_queue_setup(port_id, i, VR_DPDK_NB_RXD,
            SOCKET_ID_ANY, &rx_queue_conf, mempool);
        if (ret < 0) {
            /* return mempool to the list */
            if (mempool != vr_dpdk.rss_mempool)
                vr_dpdk.nb_free_mempools++;
            RTE_LOG(ERR, VROUTER, "    error setting up eth device %" PRIu8 " RX queue %d"
                    ": %s (%d)\n", port_id, i, rte_strerror(-ret), -ret);
            return ret;
        }
        /* map RX queue to stats counter ignoring any errors */
        rte_eth_dev_set_rx_queue_stats_mapping(port_id, i, i);

        /* save queue mempool pointer */
        ethdev->ethdev_mempools[i] = mempool;
    }
    i = ethdev->ethdev_nb_rx_queues - ethdev->ethdev_nb_rss_queues;
    RTE_LOG(INFO, VROUTER, "    setup %d RSS queue(s) and %d filtering queue(s)\n",
        (int)ethdev->ethdev_nb_rss_queues, i);

    /* configure TX queues */
    for (i = 0; i < ethdev->ethdev_nb_tx_queues; i++) {
        ret = rte_eth_tx_queue_setup(port_id, i, VR_DPDK_NB_TXD,
            SOCKET_ID_ANY, &tx_queue_conf);
        if (ret < 0) {
            RTE_LOG(ERR, VROUTER, "    error setting up eth device %" PRIu8 " TX queue %d"
                    ": %s (%d)\n", port_id, i, rte_strerror(-ret), -ret);
            return ret;
        }
        /* map TX queue to stats counter ignoring any errors */
        rte_eth_dev_set_tx_queue_stats_mapping(port_id, i, i);
    }
    return 0;
}

static void
dpdk_ethdev_reta_show(uint8_t port_id, uint16_t reta_size)
{
    int nb_entries = reta_size/RTE_RETA_GROUP_SIZE;
    struct rte_eth_rss_reta_entry64 reta_entries[nb_entries];
    struct rte_eth_rss_reta_entry64 *reta;
    uint16_t i, idx, shift;
    int ret, entry;

    for (entry = 0; entry < nb_entries; entry++) {
        reta = &reta_entries[entry];

        /* reset RSS redirection table */
        memset(reta, 0, sizeof(*reta));
        reta->mask = 0xffffffffffffffffULL;
    }

    ret = rte_eth_dev_rss_reta_query(port_id, reta_entries, reta_size);
    if (ret != 0) {
        RTE_LOG(ERR, VROUTER, "Error getting RSS RETA info: %s (%d)\n",
            rte_strerror(ret), ret);
        return;
    }

    for (i = 0; i < reta_size; i++) {
        idx = i / RTE_RETA_GROUP_SIZE;
        shift = i % RTE_RETA_GROUP_SIZE;
        if (!(reta_entries[idx].mask & (1ULL << shift)))
            continue;
        RTE_LOG(DEBUG, VROUTER, "        hash index=%u, queue=%u\n",
                    i, reta_entries[idx].reta[shift]);
    }
}

/* Init RSS */
int
vr_dpdk_ethdev_rss_init(struct vr_dpdk_ethdev *ethdev)
{
    int ret, i, j, entry;
    uint8_t port_id = ethdev->ethdev_port_id;
    int nb_entries = ethdev->ethdev_reta_size/RTE_RETA_GROUP_SIZE;
    struct rte_eth_rss_reta_entry64 reta_entries[VR_DPDK_MAX_RETA_ENTRIES];
    struct rte_eth_rss_reta_entry64 *reta;

    /* There is nothing to configure if the device does not support RETA.
     * If the device reported few RX queues earlier, we assume those
     * queues are preconfigured for RSS by default.
     */
    if (ethdev->ethdev_reta_size == 0)
        return 0;

    RTE_LOG(DEBUG, VROUTER, "%s: RSS RETA BEFORE:\n", __func__);
    dpdk_ethdev_reta_show(port_id, ethdev->ethdev_reta_size);

    for (entry = 0; entry < nb_entries; entry++) {
        reta = &reta_entries[entry];

        /* create new RSS redirection table */
        memset(reta, 0, sizeof(*reta));
        reta->mask = 0xffffffffffffffffULL;
        for (i = j = 0; i < RTE_RETA_GROUP_SIZE; i++) {
            reta->reta[i] = j++;
            if (ethdev->ethdev_queue_states[j] != VR_DPDK_QUEUE_RSS_STATE)
                j = 0;
        }
    }

    /* update RSS redirection table */
    ret = rte_eth_dev_rss_reta_update(port_id, reta_entries,
                ethdev->ethdev_reta_size);

    /* no error if the device does not support RETA configuration */
    if (ret == -ENOTSUP)
        return 0;

    if (ret < 0) {
        RTE_LOG(ERR, VROUTER, "    error initializing ethdev %" PRIu8 " RSS: %s (%d)\n",
            port_id, rte_strerror(-ret), -ret);
    }

    RTE_LOG(DEBUG, VROUTER, "%s: RSS RETA AFTER:\n", __func__);
    dpdk_ethdev_reta_show(port_id, ethdev->ethdev_reta_size);

    return ret;
}

/* Init hardware filtering */
static void
dpdk_ethdev_mempools_free(struct vr_dpdk_ethdev *ethdev)
{
    int i;

    for (i = ethdev->ethdev_nb_rss_queues; i < ethdev->ethdev_nb_rx_queues; i++) {
        if (ethdev->ethdev_mempools[i] != NULL
            && ethdev->ethdev_mempools[i] != vr_dpdk.rss_mempool) {
            vr_dpdk.free_mempools[vr_dpdk.nb_free_mempools++] =
                ethdev->ethdev_mempools[i];
            ethdev->ethdev_mempools[i] = NULL;
            ethdev->ethdev_queue_states[i] = VR_DPDK_QUEUE_READY_STATE;
        }
    }
}

/* Init hardware filtering */
int
vr_dpdk_ethdev_filtering_init(struct vr_interface *vif,
        struct vr_dpdk_ethdev *ethdev)
{
    int ret;
    uint8_t port_id = ethdev->ethdev_port_id;
    struct rte_fdir_masks masks;
    struct rte_eth_fdir fdir_info;

    /* probe Flow Director */
    memset(&fdir_info, 0, sizeof(fdir_info));
    ret = rte_eth_dev_fdir_get_infos(port_id, &fdir_info);
    if (ret == 0) {
        /* enable hardware filtering */
        RTE_LOG(INFO, VROUTER, "    enable hardware filtering for ethdev %"
            PRIu8 "\n", port_id);
        vif->vif_flags |= VIF_FLAG_FILTERING_OFFLOAD;
    } else {
        vif->vif_flags &= ~VIF_FLAG_FILTERING_OFFLOAD;
        /* free filtering mempools */
        dpdk_ethdev_mempools_free(ethdev);
        /* the ethdev does not support hardware filtering - it's not an error */
        return 0;
    }

    memset(&masks, 0, sizeof(masks));
    masks.dst_ipv4_mask = 0xffffffff;
    masks.dst_port_mask = 0xffff;
    masks.flexbytes = 1;

    ret = rte_eth_dev_fdir_set_masks(port_id, &masks);
    if (ret < 0) {
        RTE_LOG(ERR, VROUTER, "    error setting ethdev %" PRIu8
            " Flow Director masks: %s (%d)\n", port_id, rte_strerror(-ret), -ret);
    }

    return ret;
}

/* Update device bond info */
static void
dpdk_ethdev_bond_info_update(struct vr_dpdk_ethdev *ethdev)
{
    int i, slave_port_id;
    int port_id = ethdev->ethdev_port_id;
    struct rte_pci_addr *pci_addr;
    struct ether_addr bond_mac, mac_addr;
    struct ether_addr lacp_mac = { .addr_bytes = {0x01, 0x80, 0xc2, 0, 0, 0x02} };

    if (rte_eth_bond_mode_get(port_id) == -1) {
        ethdev->ethdev_nb_slaves = -1;
    } else {
        ethdev->ethdev_nb_slaves = rte_eth_bond_slaves_get(port_id,
            ethdev->ethdev_slaves, sizeof(ethdev->ethdev_slaves));

        memset(&mac_addr, 0, sizeof(bond_mac));
        rte_eth_macaddr_get(port_id, &bond_mac);
        RTE_LOG(INFO, VROUTER, "    bond eth device %" PRIu8
            " configured MAC " MAC_FORMAT "\n",
            port_id, MAC_VALUE(bond_mac.addr_bytes));
        /* log out and configure bond members */
        for (i = 0; i < ethdev->ethdev_nb_slaves; i++) {
            slave_port_id = ethdev->ethdev_slaves[i];
            memset(&mac_addr, 0, sizeof(mac_addr));
            rte_eth_macaddr_get(slave_port_id, &mac_addr);
            pci_addr = &rte_eth_devices[slave_port_id].pci_dev->addr;
            RTE_LOG(INFO, VROUTER, "    bond member eth device %" PRIu8
                " PCI " PCI_PRI_FMT " MAC " MAC_FORMAT "\n",
                slave_port_id, pci_addr->domain, pci_addr->bus,
                pci_addr->devid, pci_addr->function,
                MAC_VALUE(mac_addr.addr_bytes));

            /* try to add bond mac and LACP multicast MACs */
            if (rte_eth_dev_mac_addr_add(slave_port_id, &bond_mac, 0) == 0
                && rte_eth_dev_mac_addr_add(slave_port_id, &lacp_mac, 0) == 0) {
                /* disable the promisc mode enabled by default */
                rte_eth_promiscuous_disable(ethdev->ethdev_port_id);
                RTE_LOG(INFO, VROUTER, "    bond member eth device %" PRIu8
                    " promisc mode disabled\n", slave_port_id);
            } else {
                RTE_LOG(INFO, VROUTER, "    bond member eth device %" PRIu8
                    ": unable to add MAC addresses\n", slave_port_id);
            }
        }
        /* In LACP mode all the bond members are in the promisc mode
         * by default (see bond_mode_8023ad_activate_slave()
         * But we need also to put the bond interface in promisc to get
         * the broadcasts. Seems to be a bug in bond_ethdev_rx_burst_8023ad()?
         */
        rte_eth_promiscuous_enable(port_id);
    }
}



/* Init ethernet device */
int
vr_dpdk_ethdev_init(struct vr_dpdk_ethdev *ethdev)
{
    uint8_t port_id;
    int ret;

    port_id = ethdev->ethdev_port_id;
    ethdev->ethdev_ptr = &rte_eth_devices[port_id];

    dpdk_ethdev_info_update(ethdev);

    /* enable hardware vlan stripping */
    if (vr_dpdk.vlan_tag != VLAN_ID_INVALID) {
        ethdev_conf.rxmode.hw_vlan_strip = 1;
    }
    ret = rte_eth_dev_configure(port_id, ethdev->ethdev_nb_rx_queues,
        ethdev->ethdev_nb_tx_queues, &ethdev_conf);
    if (ret < 0) {
        RTE_LOG(ERR, VROUTER, "    error configuring eth dev %" PRIu8
                ": %s (%d)\n",
            port_id, rte_strerror(-ret), -ret);
        return ret;
    }

    /* update device bond information after the device has been configured */
    dpdk_ethdev_bond_info_update(ethdev);

    ret = dpdk_ethdev_queues_setup(ethdev);
    if (ret < 0)
        return ret;

    /* Promisc mode
     * KNI generates random MACs for e1000e NICs, so we need this
     * option enabled for the development on servers with those NICs
     */
#if VR_DPDK_ENABLE_PROMISC
    rte_eth_promiscuous_enable(port_id);
#endif

    return 0;
}

/* Release ethernet device */
int
vr_dpdk_ethdev_release(struct vr_dpdk_ethdev *ethdev)
{
    ethdev->ethdev_ptr = NULL;

    dpdk_ethdev_mempools_free(ethdev);

    return 0;
}


static inline int
dpdk_mbuf_parse_udp_mpls(struct vr_udp *const udp_header,
                         uint32_t **const simple_mpls_header)
{
    /* Initial GRE header len */
     if (!udp_header || !simple_mpls_header) {
        return -1;
    }   

    *simple_mpls_header = (uint32_t *)((uintptr_t)udp_header + sizeof(struct vr_udp));

    return 0;
}

/* Parse simple MPLS header
 */
static inline int
dpdk_mbuf_parse_gre_mpls(struct vr_gre *const gre_header,
                         uint32_t **const simple_mpls_header)
{
    /* Initial GRE header len */
    uint8_t gre_header_len = 4;
     if (!gre_header || !simple_mpls_header ) {
        return -1;
    }   
    if (gre_header->gre_flags & (~(VR_GRE_FLAG_CSUM | VR_GRE_FLAG_KEY ))){
        return 1;

    }
    if (gre_header->gre_flags & VR_GRE_FLAG_CSUM) {
        gre_header_len += 4;
    }
    if (gre_header->gre_flags & VR_GRE_FLAG_KEY) {
        gre_header_len += 4;
    }
    
    *simple_mpls_header = (uint32_t *) ((uintptr_t)gre_header + gre_header_len);

    return 0;
}

/* Parse simple GRE header
 */
inline int
dpdk_mbuf_parse_ipv4_simple_gre(struct vr_ip *const ipv4_header,
                           struct vr_gre **const gre_header)
{ 
    uint64_t ipv4_len = 0;
    if (!ipv4_header || !gre_header) {
        return -1;
    } 
    ipv4_len = (ipv4_header->ip_hl) * IPV4_IHL_MULTIPLIER;

    *gre_header = (struct vr_gre *)((uintptr_t)ipv4_header + ipv4_len);
    
    return 0;
};


/*
 * Parse L4 UDP header
 */
static inline int
dpdk_mbuf_parse_ipv4_udp(struct vr_ip *const ipv4_header,
                         struct vr_udp **const udp_header )
{
    unsigned char ipv4_len = 0;
    if (!ipv4_header || !udp_header){
        return -1;
    }
    ipv4_len = ipv4_header->ip_hl * IPV4_IHL_MULTIPLIER;
    *udp_header = (struct vr_udp *)((uintptr_t)ipv4_header + ipv4_len); 

    return 0;
}
/*
 * Parse L4 TCP header
 */
static inline int
dpdk_mbuf_parse_ipv4_tcp(struct vr_ip *const ipv4_header,
                         struct vr_tcp **const tcp_header )
{
    unsigned char ipv4_len = 0;
    if (!ipv4_header || !tcp_header){
        return -1;
    }
    ipv4_len = ipv4_header->ip_hl * IPV4_IHL_MULTIPLIER;
    *tcp_header = (struct vr_tcp *)((uintptr_t)ipv4_header + ipv4_len); 
    
    return 0;
}

/* *
 * Set sum of size - pointer relative address
 * The sum value MUST be added to the address which is pointing to L2_outer pointer.
 */

static inline int
dpdk_mbuf_pointer_sum(MBUF_PTR_SUM layer, struct rte_mbuf *const mbuf, uint64_t *const ptr_sum){
    

    if (!mbuf || !ptr_sum){
        return -1;
    }
    *ptr_sum = 0;
    switch(layer){
        
        case L4_INNER:
              *ptr_sum += mbuf->l3_len;
        case L3_INNER:
              *ptr_sum += mbuf->l2_len;
        case L2_INNER:
              *ptr_sum += sizeof(uint32_t);
        case L4_OUTER:
              *ptr_sum += mbuf->outer_l3_len; 
        case L3_OUTER:
              *ptr_sum += mbuf->outer_l2_len;
        case L2_OUTER:
              *ptr_sum += 0;
        default:
              *ptr_sum += 0;
            break;;

    }

    return 0;

}

static inline int
dpdk_mbuf_parse_ethernet_ipv4(struct vr_eth *const eth_header, struct vr_ip **const ipv4_header){
   
    if (!eth_header || !ipv4_header) {
        return -1;
    } 

    *ipv4_header = (struct vr_ip*)((uintptr_t)eth_header + sizeof(struct vr_eth));
   
    /* At the moment, there is no implementation for additional proccessing. */
    
    return 0;
}
/*  !!! WARNING - NON PRODUCTION CODE !!!
 *  
 *  dpdk_mbuf_emulate_protocol_type_and_offsets
 *  
 *  We can use a mbuf structure - (tx_offload=> inner/outer header len) for 
 *  creating relative pointer address. 
 *  (http://dpdk.org/browse/dpdk/tree/lib/librte_mbuf/rte_mbuf.h#n851)
 *  
 *  Also, in the new version of DPDK (DPDK 2.1.0) is changed packet_type definition
 *  (http://dpdk.org/browse/dpdk/tree/lib/librte_mbuf/rte_mbuf.h#n784)
 *  Instead of variable packet_type I use the variable udata64
 *
 * If we combine the new features in the DPDK we can use information for easily
 *  packet parsing. 
 *  
 */
static inline int
dpdk_mbuf_emulate_protocol_type_and_offsets(struct rte_mbuf *mbuf){
    int ret = 0;

    /* 
     * Ethernet data structures
     * */
    struct vr_eth *eth_header = rte_pktmbuf_mtod(mbuf, struct vr_eth *);
    struct vr_eth *inner_ether_header = NULL;
    /* 
     * IPv4 data structures 
     * */
    struct vr_ip *ipv4_header = NULL;
    struct vr_ip *inner_ipv4_header = NULL;
    
    /*
     * L4 data structures
     **/
    struct vr_udp *udp_header = NULL;
 
    /* We dont need parse header, we only need a size of header and
     *protocol type.
     *
     * GRE data structure
     * */
    struct vr_gre *gre_header = NULL;

    /* We dont need parse header, we only need a size of header 
     *
     * MPLS data structure
     * MPLS header has 32 bit size,
     **/
    uint32_t *simple_mpls_header = NULL;
    memset(&mbuf->udata64, 0, sizeof(uint64_t));
    /* In the feature we should use `new` protocol type in a mbuf structure
        Change udata64 to packet_type

        We don't check different ethernet type, for example Synchronous Ethernet
        aka SyncE.
    */
    
    /* Outer header. */

    mbuf->udata64 |= RTE_PTYPE_L2_ETHER;
    /* Size of Ethernet header. */
    mbuf->outer_l2_len = sizeof(struct vr_eth);
    if (ntohs(eth_header->eth_proto) == VR_ETH_PROTO_IP) {

        /* In the feature we should use `new` protocol type in a mbuf structure
           Change userdata64 to packet_type. 
         */

        mbuf->udata64 |= RTE_PTYPE_L3_IPV4;    
        /* */
        ret = dpdk_mbuf_parse_ethernet_ipv4(eth_header, &ipv4_header);
        if (ret) {
            RTE_LOG(INFO, VROUTER, "Outer IPv4 parsing failed, %s\n", __func__);
            return -1;
        }
        if (ipv4_header->ip_proto == VR_IP_PROTO_GRE) {
            /* Probably MPLS over GRE */

            /* rte_mbuf.h does not contain option for MPLS over GRE
             * therefore I choose "RTE_CONTRAIL_PTYPE_TUNNEL_MPLS_GRE"
             * */

            /* In future we should use `new` protocol type in
             *  a mbuf structure
             *
             !!! Change udata64 to packet_type !!! 
             */
            mbuf->udata64 |= RTE_PTYPE_L3_IPV4_EXT;
            ret = dpdk_mbuf_parse_ipv4_simple_gre(ipv4_header, &gre_header);
            if (ret) {
                RTE_LOG(INFO, VROUTER, "Outer GRE parsing failed, %s\n", __func__);
                return -1;
            }
            mbuf->udata64 |= RTE_PTYPE_TUNNEL_GRE;
            if (ntohs(gre_header->gre_proto) == VR_GRE_PROTO_MPLS) {
                /* In case, when MPLS parsing fail or MPLS has not set BoS,
                 * len has only IP header  */
                mbuf->outer_l3_len = ((uintptr_t)gre_header - ((uintptr_t)mbuf->outer_l2_len + (uintptr_t) eth_header)); 
                /* Inner Header - probably MPLS over GRE */
                ret = dpdk_mbuf_parse_gre_mpls(gre_header, &simple_mpls_header);                

                if (ret) {
                    RTE_LOG(INFO, VROUTER, "Outer MPLS parsing failed, %s\n", __func__);
                    return -1;
                }

                /* The bottom of stack is NOT set to 1 */
                if (!(rte_cpu_to_be_32(*simple_mpls_header) & 0x100)) {
                    RTE_LOG(INFO, VROUTER, "MPLS header has not set bottom of stack to 1.\n");
                    return 1;
                }
                /* Now we can set MPLSoverGRE. */
                mbuf->udata64 |= RTE_CONTRAIL_PTYPE_TUNNEL_MPLS_GRE;
                /* In case, when everything is OK,
                 * len is set to IP header size  + GRE header size. */
                mbuf->outer_l3_len = ((uintptr_t)simple_mpls_header - ((uintptr_t)mbuf->outer_l2_len + (uintptr_t) eth_header)); 
            }
        } else if (ipv4_header->ip_proto == VR_IP_PROTO_UDP) {
            /* Probably MPLS over UDP */

            /* rte_mbuf.h does not contain option for MPLS over UDP
             * therefore I choose "RTE_CONTRAIL_PTYPE_TUNNEL_MPLS_UDP"
             * */

            mbuf->udata64 |= RTE_PTYPE_L4_UDP;
            ret = dpdk_mbuf_parse_ipv4_udp(ipv4_header, &udp_header);
            /* In case, when MPLS parsing fail or MPLS has not set BoS,
             * len is set to IP header size  */
            mbuf->outer_l3_len = ((uintptr_t)udp_header - ((uintptr_t)mbuf->l2_len) + (uintptr_t) eth_header); 
            if (ret) {
                RTE_LOG(INFO, VROUTER, "Inner UDP parsing failed, %s\n", __func__);
                return -1;
            }
            if (!vr_mpls_udp_port(ntohs(udp_header->udp_dport))) {
                RTE_LOG(INFO, VROUTER, "UDP datagram does not contain MPLS destination port.\n" );
                return 1;
            }
            ret = dpdk_mbuf_parse_udp_mpls(udp_header, &simple_mpls_header);
            if (ret) {
                RTE_LOG(INFO, VROUTER, "Outer MPLS parsing failed, %s\n", __func__);
                return -1;
            }
            mbuf->udata64 |= RTE_PTYPE_L3_IPV4_EXT;
            /* The bottom of stack is NOT set to 1 */
            if (!(rte_cpu_to_be_32(*simple_mpls_header) & 0x100)) {
                RTE_LOG(INFO, VROUTER, "MPLS has not set bottom of stack to 1.\n");
                return 1;
            } 
           /* In case, when everything is OK,
            * len is set to IP header size + UDP header size. */
            mbuf->outer_l3_len = ((uintptr_t)simple_mpls_header - ((uintptr_t)mbuf->l2_len) + (uintptr_t) eth_header); 
            mbuf->udata64 |= RTE_CONTRAIL_PTYPE_TUNNEL_MPLS_UDP;
        }
        if (!(mbuf->udata64 & RTE_PTYPE_TUNNEL_MASK & (RTE_CONTRAIL_PTYPE_TUNNEL_MPLS_UDP | RTE_CONTRAIL_PTYPE_TUNNEL_MPLS_GRE))) {
            return 1;
        }

        /* Inner L2 header */
        mbuf->udata64 |= RTE_PTYPE_INNER_L2_ETHER;
        inner_ether_header = (struct vr_eth*)((uintptr_t)simple_mpls_header
                                                           + sizeof(uint32_t));
       //14
        mbuf->l2_len = sizeof(struct vr_eth);
       
        if (inner_ether_header->eth_proto != rte_cpu_to_be_16(VR_ETH_PROTO_IP)) {
            return 1;
        }

        /* Inner L3 Header */
        mbuf->udata64 |= RTE_PTYPE_INNER_L3_IPV4;
        ret = dpdk_mbuf_parse_ethernet_ipv4(inner_ether_header, &inner_ipv4_header); 
        if (ret) {
            RTE_LOG(INFO, VROUTER, "Inner IPv4 parsing failed, %s\n", __func__);
            return -1;
        }
        if (vr_ip_fragment((struct vr_ip *)inner_ipv4_header)) {
            RTE_LOG(INFO, VROUTER, "Fragmented IP inner packet, %s\n", __func__);
            mbuf->udata64 |= RTE_PTYPE_INNER_L4_FRAG;
            return 1;
        }
          
        mbuf->l3_len = (inner_ipv4_header->ip_hl) * IPV4_IHL_MULTIPLIER; 
        return 0;

    }/* else

      TODO IPv6 
      TODO VLAN */
    return 0;
}



/* !!! Warning NON PRODUCTION CODE !!! */
static inline int
dpdk_mbuf_rss_hash(struct rte_mbuf *mbuf)
{
    struct ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
    struct ipv4_hdr *ipv4_hdr;
    uint64_t pointer_sum = 0;
    char ipv4_add[128] = {0};


    /* MPLS over GRE */ 
    if ( mbuf->udata64 & RTE_PTYPE_TUNNEL_MASK & (RTE_CONTRAIL_PTYPE_TUNNEL_MPLS_GRE)){
        RTE_LOG(INFO,VROUTER, " MPLS over GRE\n");
        
        /* outer packet */
        dpdk_mbuf_pointer_sum(L3_OUTER, mbuf, &pointer_sum);
        ipv4_hdr = (struct ipv4_hdr*)((uintptr_t)eth_hdr + (uintptr_t)pointer_sum); 
        inet_ntop(AF_INET,&ipv4_hdr->src_addr, ipv4_add,128);
        RTE_LOG(INFO, VROUTER, "ipv4_addr: %s \n", ipv4_add);
        
        /* inner packet */ 
        dpdk_mbuf_pointer_sum(L3_INNER, mbuf, &pointer_sum);
        ipv4_hdr = (struct ipv4_hdr*) ((uintptr_t) eth_hdr + (uintptr_t)pointer_sum);
        inet_ntop(AF_INET,&ipv4_hdr->src_addr, ipv4_add,128);
        RTE_LOG(INFO, VROUTER, "ipv4_addr: %s \n", ipv4_add);


    }
    return 1;
}

/* Emulate smart NIC RX for a burst of mbufs
 * Returns:
 *     0  if at least one mbuf has been hashed by NIC, so there is
 *        no need to emulate RSS
 *     1  if the RSS need to be emulated
 */
int
vr_dpdk_ethdev_rx_emulate(struct vr_interface *vif, struct rte_mbuf *pkts[VR_DPDK_RX_BURST_SZ],
    uint32_t nb_pkts)
{
    unsigned i;

    /* prefetch the mbufs */
    for (i = 0; i < nb_pkts; i++) {
        rte_prefetch0(rte_pktmbuf_mtod(pkts[i], void *));
        rte_prefetch0(rte_pktmbuf_mtod(pkts[i], uint8_t *) + RTE_CACHE_LINE_SIZE);
    }

    /* emulate VLAN stripping if needed */
    if (unlikely (vr_dpdk.vlan_tag != VLAN_ID_INVALID
            && vif_is_fabric(vif)
            && ((vif->vif_flags & VIF_FLAG_VLAN_OFFLOAD) == 0))) {
        for (i = 0; i < nb_pkts; i++) {
            rte_vlan_strip(pkts[i]);
        }
    }

    /* no RSS needed for just one lcore */
    if (unlikely(vr_dpdk.nb_fwd_lcores == 1))
        return 0;

    /* emulate RSS hash */
    for (i = 0; i < nb_pkts; i++) {
        dpdk_mbuf_emulate_protocol_type_and_offsets(pkts[i]);
        if (likely(dpdk_mbuf_rss_hash(pkts[i]) == 0)) {
            return 0;
        }
    }

    return 1;
}
