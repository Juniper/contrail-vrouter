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

/*
 * dpdk_mbuf_rss_hash - emulate RSS hash for the mbuf.
 *
 * Returns 0 if the mbuf's hash was OK, 1 if the hash was recalculated.
 *
 * TODO: add MPLSoGRE case
 */
static inline int
dpdk_mbuf_rss_hash(struct rte_mbuf *mbuf)
{
    struct ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
    struct ipv4_hdr *ipv4_hdr;
    uint64_t *ipv4_addr_ptr;
    uint32_t *l4_ptr;
    uint32_t hash = 0;
    uint8_t iph_len;

    if (likely(mbuf->ol_flags & PKT_RX_RSS_HASH)) {
        RTE_LOG(DEBUG, VROUTER, "%s: RSS hash: 0x%x (from NIC)\n",
                __func__, mbuf->hash.rss);
        return 0;
    }

    /* TODO: IPv6 support */
    /* TODO: VLAN support */
    if (likely(eth_hdr->ether_type == rte_cpu_to_be_16(ETHER_TYPE_IPv4))) {
#if (RTE_VERSION >= RTE_VERSION_NUM(2, 1, 0, 0))
        mbuf->packet_type |= RTE_PTYPE_L3_IPV4;
#endif
        ipv4_hdr = (struct ipv4_hdr *)((uintptr_t)eth_hdr
                                    + sizeof(struct ether_hdr));
        ipv4_addr_ptr = (uint64_t *)((uintptr_t)ipv4_hdr
                                    + offsetof(struct ipv4_hdr, src_addr));

        /* We use SSE4.2 CRC hash. No need to match NIC's Toeplitz hash ATM. */
        /* Hash src and dst address at a time */
        hash = rte_hash_crc_8byte(*ipv4_addr_ptr, hash);

        iph_len = (ipv4_hdr->version_ihl & IPV4_HDR_IHL_MASK) *
                    IPV4_IHL_MULTIPLIER;

        if (likely((rte_pktmbuf_data_len(mbuf) > sizeof(struct ether_hdr)
                    + iph_len
                    + sizeof(struct udp_hdr)) &&
                    !vr_ip_fragment((struct vr_ip *)ipv4_hdr))) {
            switch (ipv4_hdr->next_proto_id) {
            case IPPROTO_TCP:
#if (RTE_VERSION >= RTE_VERSION_NUM(2, 1, 0, 0))
                mbuf->packet_type |= RTE_PTYPE_L4_TCP;
#endif
                l4_ptr = (uint32_t *)((uintptr_t)ipv4_hdr + iph_len);

                hash = rte_hash_crc_4byte(*l4_ptr, hash);
                break;
            case IPPROTO_UDP:
#if (RTE_VERSION >= RTE_VERSION_NUM(2, 1, 0, 0))
                mbuf->packet_type |= RTE_PTYPE_L4_UDP;
#endif
                l4_ptr = (uint32_t *)((uintptr_t)ipv4_hdr + iph_len);

                hash = rte_hash_crc_4byte(*l4_ptr, hash);
                break;
            }
        }
        mbuf->ol_flags |= PKT_RX_RSS_HASH;
        mbuf->hash.rss = hash;
        RTE_LOG(DEBUG, VROUTER, "%s: RSS hash: 0x%x (emulated)\n",
                __func__, mbuf->hash.rss);
    }

    return 1;
}

/*
 * vr_dpdk_ethdev_rx_emulate - emulate smart NIC RX:
 *  - strip VLAN tags for packets received from fabric interface
 *  - calculate RSS hash if not present
 *  - recalculate RSS hash for MPLSoGRE packets
 *
 * Returns 0 on no hash changes, otherwise a bitmask of mbufs to distribute.
 */
uint64_t
vr_dpdk_ethdev_rx_emulate(struct vr_interface *vif,
    struct rte_mbuf *pkts[VR_DPDK_RX_BURST_SZ], uint32_t nb_pkts)
{
    unsigned i;
    uint64_t mask_to_distribute = 0;

    /* prefetch the mbufs */
    for (i = 0; i < nb_pkts; i++) {
        rte_prefetch0(rte_pktmbuf_mtod(pkts[i], uint8_t *));
        rte_prefetch0(rte_pktmbuf_mtod_offset(pkts[i], uint8_t *, RTE_CACHE_LINE_SIZE));
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
        if (unlikely(dpdk_mbuf_rss_hash(pkts[i]) != 0)) {
            mask_to_distribute |= 1ULL << i;
        }
    }

    return mask_to_distribute;
}
