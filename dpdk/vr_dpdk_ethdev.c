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
 * vr_dpdk_ethdev.c -- DPDK ethernet device
 *
 */
#include <stdio.h>
#include <unistd.h>

#include "vr_dpdk.h"

#include <rte_port_ethdev.h>

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
        .hw_vlan_strip      = 0, /* Disable VLAN strip */
        .hw_vlan_extend     = 0, /* Disable Extended VLAN */
        .jumbo_frame        = 0, /* Disable Jumbo Frame Receipt */
        .hw_strip_crc       = 0, /* Disable CRC stripping by hardware */
        .enable_scatter     = 0, /* Disable scatter packets rx handler */
    },
    .rx_adv_conf = {
        .rss_conf = { /* Port RSS configuration */
            .rss_key            = NULL, /* If not NULL, 40-byte hash key */
            .rss_key_len        = 0,    /* Hash key length in bytes */
            .rss_hf             = ETH_RSS_IP, /* Hash functions to apply */
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
#if VR_DPDK_USE_HW_FILTERS == true
        .mode = RTE_FDIR_MODE_PERFECT,          /* Flow Director mode. */
#else
        .mode = RTE_FDIR_MODE_NONE,
#endif
        .pballoc = RTE_FDIR_PBALLOC_64K,        /* Space for FDIR filters. */
        .status = RTE_FDIR_NO_REPORT_STATUS,    /* How to report FDIR hash. */
        /* Offset of flexbytes field in RX packets (in 16-bit word units). */
        .flexbytes_offset = VR_DPDK_MPLS_OFFSET,
        /* RX queue of packets matching a "drop" filter in perfect mode. */
        .drop_queue = 1,
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
    .rx_free_thresh = 0,    /* Immediately free RX descriptors */
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
    .txq_flags =            /* Set flags for the Tx queue */
        ETH_TXQ_FLAGS_NOMULTSEGS
        | ETH_TXQ_FLAGS_NOREFCOUNT
        | ETH_TXQ_FLAGS_NOVLANOFFL
        | ETH_TXQ_FLAGS_NOXSUMSCTP
        | ETH_TXQ_FLAGS_NOXSUMTCP
};

/* Init eth RX queue */
struct vr_dpdk_rx_queue *
vr_dpdk_eth_rx_queue_init(unsigned lcore_id, struct vr_interface *vif,
    unsigned rx_queue_id)
{
    struct vr_dpdk_lcore *lcore = vr_dpdk.lcores[lcore_id];
    const unsigned socket_id = rte_lcore_to_socket_id(lcore_id);
    uint8_t port_id = vif->vif_os_idx;
    unsigned vif_idx = vif->vif_idx;
    struct vr_dpdk_rx_queue *rx_queue = &lcore->lcore_rx_queues[vif_idx];

    /* init queue */
    rx_queue->rxq_ops = rte_port_ethdev_reader_ops;
    rx_queue->rxq_queue_h = NULL;
    rx_queue->rxq_burst_size = VR_DPDK_ETH_RX_BURST_SZ;
    rx_queue->rxq_vif = vrouter_get_interface(vif->vif_rid, vif_idx);

    /* create the queue */
    struct rte_port_ethdev_reader_params rx_queue_params = {
        .port_id = port_id,
        .queue_id = rx_queue_id,
    };
    rx_queue->rxq_queue_h = rx_queue->rxq_ops.f_create(&rx_queue_params, socket_id);
    if (rx_queue->rxq_queue_h == NULL) {
        RTE_LOG(ERR, VROUTER, "\terror creating eth device %" PRIu8
                " RX queue %" PRIu16 "\n", port_id, rx_queue_id);
        return NULL;
    }

    return rx_queue;
}

/* Init eth TX queue */
struct vr_dpdk_tx_queue *
vr_dpdk_eth_tx_queue_init(unsigned lcore_id, struct vr_interface *vif,
    unsigned tx_queue_id)
{
    struct vr_dpdk_lcore *lcore = vr_dpdk.lcores[lcore_id];
    const unsigned socket_id = rte_lcore_to_socket_id(lcore_id);
    uint8_t port_id = vif->vif_os_idx;
    unsigned vif_idx = vif->vif_idx;
    struct vr_dpdk_tx_queue *tx_queue = &lcore->lcore_tx_queues[vif_idx];

    /* init queue */
    tx_queue->txq_ops = rte_port_ethdev_writer_ops;
    tx_queue->txq_queue_h = NULL;
    tx_queue->txq_vif = vrouter_get_interface(vif->vif_rid, vif_idx);

    /* create the queue */
    struct rte_port_ethdev_writer_params tx_queue_params = {
        .port_id = port_id,
        .queue_id = tx_queue_id,
        .tx_burst_sz = VR_DPDK_ETH_TX_BURST_SZ,
    };
    tx_queue->txq_queue_h = tx_queue->txq_ops.f_create(&tx_queue_params, socket_id);
    if (tx_queue->txq_queue_h == NULL) {
        RTE_LOG(ERR, VROUTER, "\terror creating eth device %" PRIu8
                " TX queue %" PRIu16 "\n", port_id, tx_queue_id);
        return NULL;
    }

    return tx_queue;
}

/* Update device info */
void
dpdk_ethdev_info_update(struct vr_interface *vif)
{
    uint8_t port_id = vif->vif_os_idx;
    struct vr_dpdk_ethdev *ethdev = &vr_dpdk.ethdevs[port_id];
    struct rte_eth_dev_info dev_info;

    /* get device info */
    memset(&dev_info, 0, sizeof(dev_info));
    rte_eth_dev_info_get(port_id, &dev_info);
    ethdev->ethdev_nb_rx_queues = RTE_MIN(dev_info.max_rx_queues,
        VR_DPDK_MAX_NB_RX_QUEUES);
    ethdev->ethdev_nb_tx_queues = RTE_MIN(RTE_MIN(dev_info.max_tx_queues,
        vr_dpdk.nb_fwd_lcores), VR_DPDK_MAX_NB_TX_QUEUES);
    ethdev->ethdev_nb_rss_queues = RTE_MIN(RTE_MIN(ethdev->ethdev_nb_rx_queues,
        vr_dpdk.nb_fwd_lcores), VR_DPDK_MAX_NB_RSS_QUEUES);

    RTE_LOG(DEBUG, VROUTER, "dev_info: driver_name=%s if_index=%u max_rx_queues=%"PRIu16
        " max_vfs=%"PRIu16" max_vmdq_pools=%"PRIu16
        " rx_offload_capa=%"PRIx32" tx_offload_capa=%"PRIx32"\n",
        dev_info.driver_name, dev_info.if_index, dev_info.max_rx_queues,
        dev_info.max_vfs, dev_info.max_vmdq_pools, dev_info.rx_offload_capa,
        dev_info.tx_offload_capa);

    /* check if the device supports checksum offloading */
    if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_IPV4_CKSUM) {
        RTE_LOG(INFO, VROUTER, "\tenabling hardware TX checksum offloading for ethdev %"
            PRIu8 "\n", port_id);
        vif->vif_flags |= VIF_FLAG_TX_CSUM_OFFLOAD;
    } else {
        vif->vif_flags &= ~VIF_FLAG_TX_CSUM_OFFLOAD;
    }

#if VR_DPDK_USE_HW_FILTERS == true
    /* enable hardware filters */
    RTE_LOG(INFO, VROUTER, "\tenabling hardware filtering for ethdev %"
        PRIu8 "\n", port_id);
    vif->vif_flags |= VIF_FLAG_FILTER_OFFLOAD;
#else
    vif->vif_flags &= ~VIF_FLAG_FILTER_OFFLOAD;
    /* use RSS queues only */
    ethdev->ethdev_nb_rx_queues = ethdev->ethdev_nb_rss_queues;
#endif
}

/* Setup ethdev hardware queues */
int
dpdk_ethdev_queues_setup(struct vr_interface *vif)
{
    int ret, i;
    uint8_t port_id = vif->vif_os_idx;
    struct vr_dpdk_ethdev *ethdev = &vr_dpdk.ethdevs[port_id];

    /* reset RX queue states */
    for (i = 0; i < ethdev->ethdev_nb_rx_queues; i++) {
        if (i < ethdev->ethdev_nb_rss_queues)
            ethdev->ethdev_queue_states[i] = VR_DPDK_QUEUE_RSS_STATE;
        else
            ethdev->ethdev_queue_states[i] = VR_DPDK_QUEUE_FREE_STATE;
    }

    /* configure RX queues */
    for (i = 0; i < ethdev->ethdev_nb_rx_queues; i++) {
        ret = rte_eth_rx_queue_setup(port_id, i, VR_DPDK_NB_RXD,
            rte_eth_dev_socket_id(port_id), &rx_queue_conf, vr_dpdk.pktmbuf_pool);
        if (ret < 0) {
            RTE_LOG(ERR, VROUTER, "\terror setting up eth device %" PRIu8 " RX queue %d"
                    ": %s (%d)\n", port_id, i, strerror(-ret), -ret);
            return ret;
        }
    }

    RTE_LOG(DEBUG, VROUTER, "%s: nb_rx_queues=%u  nb_tx_queues=%u\n",
        __func__, (unsigned)ethdev->ethdev_nb_rx_queues,
            (unsigned)ethdev->ethdev_nb_tx_queues);
    /* configure TX queues */
    for (i = 0; i < ethdev->ethdev_nb_tx_queues; i++) {
        ret = rte_eth_tx_queue_setup(port_id, i, VR_DPDK_NB_TXD,
            rte_eth_dev_socket_id(port_id), &tx_queue_conf);
        if (ret < 0) {
            RTE_LOG(ERR, VROUTER, "\terror setting up eth device %" PRIu8 " TX queue %d"
                    ": %s (%d)\n", port_id, i, strerror(-ret), -ret);
            return ret;
        }
    }
    return 0;
}

/* Init RSS */
int
dpdk_ethdev_rss_init(struct vr_interface *vif)
{
    int ret, i, j;
    uint8_t port_id = vif->vif_os_idx;
    struct vr_dpdk_ethdev *ethdev = &vr_dpdk.ethdevs[port_id];
    struct rte_eth_rss_reta reta_conf;

    /* create new RSS redirection table */
    memset(&reta_conf, 0, sizeof(reta_conf));
    for (i = j = 0; i < ETH_RSS_RETA_NUM_ENTRIES; i++) {
        reta_conf.reta[i] = j++;
        if (ethdev->ethdev_queue_states[j] != VR_DPDK_QUEUE_RSS_STATE)
            j = 0;
    }

    /* update RSS redirection table */
    reta_conf.mask_lo = reta_conf.mask_hi = 0xffffffffffffffffULL;
    ret = rte_eth_dev_rss_reta_update(port_id, &reta_conf);

    /* no error if the device does not support RETA configuration */
    if (ret == -ENOTSUP)
        return 0;

    if (ret < 0) {
        RTE_LOG(ERR, VROUTER, "\terror initializing ethdev %" PRIu8 " RSS: %s (%d)\n",
            port_id, strerror(-ret), -ret);
    }

    return ret;
}

/* Init ethernet device */
int
vr_dpdk_ethdev_init(struct vr_interface *vif)
{
    /* eth dev port id */
    uint8_t port_id = vif->vif_os_idx;
    /* return value */
    int ret;
    struct vr_dpdk_ethdev *ethdev = &vr_dpdk.ethdevs[port_id];

    /* update ethdev info */
    dpdk_ethdev_info_update(vif);

    /* configure the device */
    ret = rte_eth_dev_configure(port_id, ethdev->ethdev_nb_rx_queues,
        ethdev->ethdev_nb_tx_queues, &ethdev_conf);
    if (ret < 0) {
        RTE_LOG(ERR, VROUTER, "\terror configuring eth dev %" PRIu8 ": %s (%d)\n",
            port_id, strerror(-ret), -ret);
        return ret;
    }

    /* setup hardware queues */
    ret = dpdk_ethdev_queues_setup(vif);
    if (ret < 0)
        return ret;

    /* init RSS */
    ret = dpdk_ethdev_rss_init(vif);
    if (ret < 0)
        return ret;

    /* start eth device */
    ret = rte_eth_dev_start(port_id);
    if (ret < 0) {
        RTE_LOG(ERR, VROUTER, "\terror starting eth device %" PRIu8
                ": %s (%d)\n", port_id, strerror(-ret), -ret);
        return ret;
    }

    /* Promisc mode
     * KNI generates random MACs for e1000e NICs, so we need this
     * option enabled for the development on servers with those NICs
     */
#if VR_DPDK_ENABLE_PROMISC == true
    rte_eth_promiscuous_enable(port_id);
#endif

    /* reset OS dev pointer */
    vif->vif_os = NULL;

    return 0;
}
