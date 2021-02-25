/*
 * vr_dpdk_info.c - DPDK specific callback functions for vr_info .
 *
 * Copyright (c) 2020 Juniper Networks, Inc. All rights reserved.
 */
#include <vr_os.h>
#include <vr_types.h>
#include <vr_packet.h>
#include <string.h>
#include "vr_message.h"
#include "vr_btable.h"
#include "vr_dpdk.h"
#include "vrouter.h"

#include <rte_eth_bond.h>
#include <rte_ethdev.h>
#include <rte_port_ethdev.h>
#include <rte_eth_bond_8023ad.h>
#include <rte_malloc.h>

#define SEPERATOR 70
#define LINE 200
#define MAXBITS 8

enum segments {
    RX_PACKETS,
    RX_BYTES,
    TX_PACKETS,
    TX_BYTES,
    ERRORS,
    OTHERS
};

/* NOTE: Callback API's need to be registered in vrouter/include/vr_info.h
 * under VR_INFO_REG(X) macro.
 * All callback API's should start with "dpdk_<fn.name>"
 * Register Format: X(MSG, <fn.name>) \
 *              eg: X(INFO_BOND, info_get_bond)
 */

int
dpdk_info_get_dpdk_version(VR_INFO_ARGS)
{
    extern const char *ContrailBuildInfo;

    VR_INFO_BUF_INIT();

    VI_PRINTF("DPDK version: %s\n\n", ContrailBuildInfo);
    return 0;
}

int
get_port_states(VR_INFO_ARGS, uint8_t state)
{
   VR_INFO_DEC();
   int i = 0, cur = 0;
   char *states[] = {"ACT", "TIMEOUT", "AGG", "SYNC", "COL", "DIST",
                     "DEF", "EXP"};
   uint8_t orig_state = state;
   char port_states[LINE] = "";

   /* Iterating through each bit */
   while (i <= MAXBITS){
       if ((1 & state) && (cur < LINE)){
           cur += snprintf(port_states + cur, LINE - cur, "%s ", states[i]);
       }
       state  = state >> 1;
       i++;
   }
   VI_PRINTF("\tport state: %d (%s) \n\n", orig_state, port_states);
   return 0;
}

static int
dpdk_bond_mode_8023ad(VR_INFO_ARGS, int port_id)
{
    VR_INFO_DEC();
    int ret;
    char *lacp_rate[] = {"slow", "fast"};

    VI_PRINTF("802.3ad info :\n");

    VI_PRINTF("LACP Rate: %s\n", \
            lacp_rate[rte_eth_bond_lacp_rate_get(port_id)]);

    ret = rte_eth_bond_8023ad_agg_selection_get(port_id);
    switch(ret) {
        case AGG_COUNT:
            VI_PRINTF("Aggregator selection policy (ad_select): Count\n");
            break;
        case AGG_BANDWIDTH:
            VI_PRINTF("Aggregator selection policy (ad_select): Bandwidth\n");
            break;
        case AGG_STABLE:
            VI_PRINTF("Aggregator selection policy (ad_select): Stable\n");
            break;
        default:
            VI_PRINTF("Aggregator selection policy (ad_select): Null\n");
    }

    return 0;
}

static int
dpdk_bond_info_mii_status(VR_INFO_ARGS, int port_id, struct rte_eth_link *link)
{
    VR_INFO_DEC();
    char *status[] = {"DOWN", "UP"};

    VI_PRINTF("MII status: %s\n", status[link->link_status]);
    VI_PRINTF("MII Link Speed: %d\n", link->link_speed);
    VI_PRINTF("MII Polling Interval (ms): %d\n", rte_eth_bond_link_monitoring_get(port_id));
    return 0;
}

static int
dpdk_bond_info_show_slave(VR_INFO_ARGS, int port_id, struct vr_dpdk_ethdev *ethdev)
{
    VR_INFO_DEC();
    int i, ret, slave_id;
    char *lacp_rate[] = {"slow", "fast"};
    char *duplex[] = {"half", "full"};
    struct ether_addr mac_addr;
    struct rte_eth_link link;
    char name[VR_INTERFACE_NAME_LEN];
    struct rte_eth_bond_8023ad_slave_info info;

    /* Display bond slave inforamtion */
    for(i = 0; i < ethdev->ethdev_nb_slaves; i++) {
        slave_id = ethdev->ethdev_slaves[i];

        ret = rte_eth_dev_get_name_by_port(slave_id, name);
        if (ret != 0)
            RTE_LOG(ERR, VROUTER, "Error getting bond interface name\n");

        VI_PRINTF("Slave Interface(%d): %s \n", i, name);
	#if (RTE_VERSION >= RTE_VERSION_NUM(17, 11, 0, 0))
            if (strcmp(rte_eth_devices[i].device->driver->name, "net_bonding") == 0)
        	VI_PRINTF("Slave Interface Driver: %s\n", rte_eth_devices[port_id].device->driver->name);
	#else
            if (strcmp(rte_eth_devices[i].data->drv_name, "net_bonding") == 0)
        	VI_PRINTF("Slave Interface Driver: %s\n", rte_eth_devices[port_id].device->driver->name);
	#endif

        rte_eth_link_get_nowait(port_id, &link);
        ret = dpdk_bond_info_mii_status(VR_INFO_PASS_ARGS, port_id, &link);
        if(ret < 0) {
            return VR_INFO_FAILED;
        }
        ret = rte_eth_bond_8023ad_slave_info(port_id, slave_id, &info);
        if (ret == 0) {
            VI_PRINTF("Permanent HW addr:"MAC_FORMAT "\n",
                MAC_VALUE(info.actor.system.addr_bytes));
            VI_PRINTF("Aggregator ID: %d\n", info.agg_port_id);

            VI_PRINTF("Duplex: %s\n", duplex[link.link_duplex]);

            VI_PRINTF("802.3ad info\n");

            VI_PRINTF("LACP Rate: %s\n", lacp_rate[rte_eth_bond_lacp_rate_get(port_id)]);

            rte_eth_macaddr_get(port_id, &mac_addr);
            VI_PRINTF("Bond MAC addr:" MAC_FORMAT "\n\n", MAC_VALUE(mac_addr.addr_bytes));
            VI_PRINTF("Details actor lacp pdu: \n");
            VI_PRINTF("\tsystem priority: %d \n", info.actor.system_priority);
            VI_PRINTF("\tsystem mac address:"MAC_FORMAT "\n",
                MAC_VALUE(info.actor.system.addr_bytes));
            VI_PRINTF("\tport key: %d \n", info.actor.key);
            VI_PRINTF("\tport priority: %d \n", info.actor.port_priority);
            VI_PRINTF("\tport number: %d \n", info.actor.port_number);
            VI_PRINTF("\tport state: %d \n", info.actor_state);

            VI_PRINTF("Details partner lacp pdu: \n");
            VI_PRINTF("\tsystem priority: %d \n", info.partner.system_priority);
            VI_PRINTF("\tsystem mac address:"MAC_FORMAT "\n",
                MAC_VALUE(info.partner.system.addr_bytes));
            VI_PRINTF("\tport key: %d \n", info.partner.key);
            VI_PRINTF("\tport priority: %d \n", info.partner.port_priority);
            VI_PRINTF("\tport number: %d \n", info.partner.port_number);
            VI_PRINTF("\tport state: %d \n\n", info.partner_state);
       }
       else {
            VI_PRINTF("\n");
        }
    }
    return 0;
}

static int
dpdk_bond_info_show_master(VR_INFO_ARGS, int port_id,
        struct vr_dpdk_ethdev *ethdev)
{
    VR_INFO_DEC();
    int ret, bond_mode,slave_id;
    struct rte_eth_link link;
    struct rte_eth_bond_8023ad_slave_info info;

    /* Get bond mode */
    bond_mode = rte_eth_bond_mode_get(port_id);
    switch(bond_mode) {
        case BONDING_MODE_ROUND_ROBIN:
            VI_PRINTF("Bonding Mode: Round Robin\n");
            break;
        case BONDING_MODE_ACTIVE_BACKUP:
            VI_PRINTF("Bonding Mode: Active Backup\n");
            break;
        case BONDING_MODE_BALANCE:
            VI_PRINTF("Bonding Mode: Balance\n");
            break;
        case BONDING_MODE_BROADCAST:
            VI_PRINTF("Bonding Mode: Broadcast\n");
            break;
        case BONDING_MODE_8023AD:
            VI_PRINTF("Bonding Mode: 802.3AD Dynamic Link Aggregation\n");
            break;
        case BONDING_MODE_TLB:
            VI_PRINTF("Bonding Mode: Adaptive TLB(Trnasmit Load Balancing)\n");
            break;
        case BONDING_MODE_ALB:
            VI_PRINTF("Bonding Mode: Adaptive Load Balancing(Tx/Rx)\n");
            break;
        default:
            VI_PRINTF("Bonding Mode: None\n");
    }

    /* Transmit Hash Policy */
    ret = rte_eth_bond_xmit_policy_get(port_id);
    switch(ret) {
        case BALANCE_XMIT_POLICY_LAYER2:
            VI_PRINTF("Transmit Hash Policy: Layer 2 (Ethernet MAC)\n");
            break;
        case BALANCE_XMIT_POLICY_LAYER23:
            VI_PRINTF("Transmit Hash Policy: Layer 2+3 (Ethernet MAC + "
                    "IP Addresses) transmit load balancing\n");
            break;
        case BALANCE_XMIT_POLICY_LAYER34:
            VI_PRINTF("Transmit Hash Policy: Layer 3+4 (IP Addresses + "
                    "UDP Ports) transmit load balancing\n");
            break;
        default:
            VI_PRINTF("Transmit Hash Policy: None\n");
    }

    rte_eth_link_get_nowait(port_id, &link);
    ret = dpdk_bond_info_mii_status(VR_INFO_PASS_ARGS, port_id, &link);
    if(ret < 0) {
        return VR_INFO_FAILED;
    }

    VI_PRINTF("Up Delay (ms): %d\n", \
            rte_eth_bond_link_up_prop_delay_get(port_id));
    VI_PRINTF("Down Delay (ms): %d\n", \
            rte_eth_bond_link_down_prop_delay_get(port_id));

    if(bond_mode == BONDING_MODE_8023AD) {
        ret = dpdk_bond_mode_8023ad(VR_INFO_PASS_ARGS, port_id);
        if (ret < 0) {
            return VR_INFO_FAILED;
        }
    }
    slave_id = ethdev->ethdev_slaves[0];

    ret = rte_eth_bond_8023ad_slave_info(port_id, slave_id, &info);
    if (ret != 0) {
        RTE_LOG(ERR, VROUTER, "Error getting bond interface name\n");
    }

    VI_PRINTF("System priority: %d\n", info.actor.system_priority);
    VI_PRINTF("System MAC address:"MAC_FORMAT "\n", \
        MAC_VALUE(info.actor.system.addr_bytes));
    VI_PRINTF("Active Aggregator Info: \n");
    VI_PRINTF("\tAggregator ID: %d\n", info.agg_port_id);
    VI_PRINTF("\tNumber of ports: %d \n", ethdev->ethdev_nb_slaves);
    VI_PRINTF("\tActor Key: %d \n", info.actor.key);
    VI_PRINTF("\tPartner Key: %d \n", info.partner.key);
    VI_PRINTF("\tPartner Mac Address: "MAC_FORMAT "\n\n", \
        MAC_VALUE(info.partner.system.addr_bytes));
    return 0;
}

/* dpdk_info_get_bond provide the bond master & slave information */
int
dpdk_info_get_bond(VR_INFO_ARGS)
{
    uint16_t port_id;
    struct vr_dpdk_ethdev *ethdev;
    int ret;

    /* If output buffer size(--buffsz) is sent from CLI, then allocate with
     * that size else allocate with default size */
    VR_INFO_BUF_INIT();

    /* Get the port_id for master, Incase of non-bond devices, it return here */
    port_id = dpdk_find_port_id_by_drv_name();
    if (port_id == VR_DPDK_INVALID_PORT_ID) {
        RTE_LOG(ERR, VROUTER, "Port Id is invalid\n");
        return -1;
    }

    /* Get the ethdev for master port. */
    ethdev = &vr_dpdk.ethdevs[port_id];
    if (ethdev->ethdev_ptr == NULL) {
        RTE_LOG(ERR, VROUTER, "Ethdev not available\n");
    }

    VI_PRINTF("DPDK Version: %s\n", \
            rte_version());
    VI_PRINTF("No. of bond slaves: %d\n", ethdev->ethdev_nb_slaves);

    ret = dpdk_bond_info_show_master(VR_INFO_PASS_ARGS, port_id, ethdev);
    if(ret < 0) {
        return VR_INFO_FAILED;
    }

    ret = dpdk_bond_info_show_slave(VR_INFO_PASS_ARGS,port_id, ethdev);
    if(ret < 0) {
        return VR_INFO_FAILED;
    }

    return 0;
}

static int
display_lacp_conf(VR_INFO_ARGS, uint16_t port_id)
{

    VR_INFO_DEC();
    char *lacp_rate[] = {"slow","fast"};
    struct rte_eth_bond_8023ad_conf conf;

    /* Check LACP protocol is configured for the bond interface. */
    VI_PRINTF("LACP Rate: %s\n\n", \
        lacp_rate[rte_eth_bond_lacp_rate_get(port_id)]);

    rte_eth_bond_8023ad_conf_get(port_id, &conf);

    VI_PRINTF("Fast periodic (ms): %d\n", conf.fast_periodic_ms);
    VI_PRINTF("Slow periodic (ms): %d\n", conf.slow_periodic_ms);
    VI_PRINTF("Short timeout (ms): %d\n", conf.short_timeout_ms);
    VI_PRINTF("Long timeout (ms): %d\n", conf.long_timeout_ms);
    VI_PRINTF("Aggregate wait timeout (ms): %d\n", \
        conf.aggregate_wait_timeout_ms);
    VI_PRINTF("Tx period (ms): %d\n", conf.tx_period_ms);
    VI_PRINTF("Update timeout (ms): %d\n", conf.update_timeout_ms);
    VI_PRINTF("Rx marker period (ms): %d\n\n", conf.rx_marker_period_ms);
    return 0;

}

int
dpdk_info_get_lacp(VR_INFO_ARGS)
{

    uint16_t port_id, slave_id = 0;
    struct vr_dpdk_ethdev *ethdev;
    int i, ret = 0;
    char name[VR_INTERFACE_NAME_LEN] = "";
    struct rte_eth_bond_8023ad_slave_info info;
    uint64_t lacp_rx_cnt, lacp_tx_cnt;

    VR_INFO_BUF_INIT();

    /* Get the port_id for master, Incase of non-bond devices,
       it return here. */
    port_id = dpdk_find_port_id_by_drv_name();
    if (port_id == VR_DPDK_INVALID_PORT_ID) {
        RTE_LOG(ERR, VROUTER, "Port Id is invalid\n");
        return -1;
    }
    
     if (strcmp(msg_req->inbuf, "all") == 0) {
        display_lacp_conf(msg_req, port_id);

        ethdev = &vr_dpdk.ethdevs[port_id];
        if (ethdev->ethdev_ptr == NULL) {
            RTE_LOG(ERR, VROUTER, "Ethdev not available\n");
        }

        /* Displaying bond slave inforamtion */
        for (i = 0; i < ethdev->ethdev_nb_slaves; i++) {
            slave_id = ethdev->ethdev_slaves[i];

            ret = rte_eth_dev_get_name_by_port(slave_id, name);
            if (ret != 0) {
                RTE_LOG(ERR, VROUTER, "Error getting bond interface name\n");
            }

            VI_PRINTF("Slave Interface(%d): %s \n", i, name);

            ret = rte_eth_bond_8023ad_slave_info(port_id, slave_id, &info);
            if (ret == 0) {
                VI_PRINTF("Details actor lacp pdu: \n");
                ret = get_port_states(msg_req, info.actor_state);
                if (ret < 0)
                     goto err;

                VI_PRINTF("Details partner lacp pdu: \n");
                ret = get_port_states(msg_req, info.partner_state);
                if (ret < 0)
                    goto err;
            } else {
                VI_PRINTF("Link status: DOWN\n\n");
            }

        }
        VI_PRINTF("LACP Packet Statistics:\n");
        VI_PRINTF("\t\t Tx \t Rx\n");
        for (i = 0; i < ethdev->ethdev_nb_slaves; i++) {
            slave_id = ethdev->ethdev_slaves[i];

            ret = rte_eth_dev_get_name_by_port(slave_id, name);
            if (ret != 0) {
                RTE_LOG(ERR, VROUTER, "Error getting bond interface name\n");
            }

            lacp_tx_cnt = rte_eth_bond_8023ad_lacp_tx_count(slave_id, 0);
            if (lacp_tx_cnt < 0)
                return VR_INFO_FAILED;

            lacp_rx_cnt = rte_eth_bond_8023ad_lacp_rx_count(slave_id, 0);
            if (lacp_rx_cnt < 0)
                return VR_INFO_FAILED;

            VI_PRINTF("%s\t%"PRId64"\t%"PRId64"\n", name, lacp_tx_cnt, lacp_rx_cnt);
        }
        VI_PRINTF("\n");
    } else if (strcmp(msg_req->inbuf, "conf") == 0) {
        display_lacp_conf(msg_req, port_id);
    } else {
        RTE_LOG(ERR, VROUTER, "Invalid argument.\n");
        return -1;
    }
    return 0;
err:
    return ret;
}

static void
walk_cb(struct rte_mempool *mp, void *arg __rte_unused)
{
    vr_info_t *msg_req = (vr_info_t * ) arg;
    VR_INFO_DEC();

    /* redefining VR_INFO_FAILED to prevent VI_PRINTF
       to return non-void value */
    #undef VR_INFO_FAILED
    #define VR_INFO_FAILED

    /* redefining VR_INFO_MSG_TRUNC to prevent VI_PRINTF
       to return non-void value */
    #undef VR_INFO_MSG_TRUNC
    #define VR_INFO_MSG_TRUNC

    VI_PRINTF("%-20s\t", mp->name);
    VI_PRINTF("%d\t", mp->size);
    VI_PRINTF("%d\t", rte_mempool_in_use_count(mp));
    VI_PRINTF("%d\t\n", rte_mempool_avail_count(mp));

    #undef VR_INFO_FAILED
    #define VR_INFO_FAILED - 1

    #undef VR_INFO_MSG_TRUNC
    #define VR_INFO_MSG_TRUNC - 2
    return;
}

int
dpdk_info_get_mempool(VR_INFO_ARGS)
{
    int reqd_mempool = 0;
    struct rte_mempool *mp = NULL;
    struct rte_mempool_memhdr *memhdr;
    unsigned lcore_id = 0, common_count = 0, cache_count = 0, count = 0;
    size_t mem_len = 0;
    char col_names[] = "Name\t\t\tSize\tUsed\tAvailable";
    /* Adding 25 to extend the seperator a bit */
    int col_size = (sizeof(col_names) / sizeof(col_names[0])) + 25;
    char seperator[col_size];
    VR_INFO_BUF_INIT();

    if (strcmp(msg_req->inbuf, "all") == 0) {
        reqd_mempool = 1;
    }
    switch (reqd_mempool) {
    case 0:
        mp = rte_mempool_lookup(msg_req->inbuf);
        if (mp == NULL) {
            RTE_LOG(ERR, VROUTER, "Mempool name does not exists.\n");
            return -1;
        }

	VI_PRINTF("%s\n", mp->name);
        VI_PRINTF("flags = %x\n", mp->flags);
        VI_PRINTF("nb_mem_chunks = %u\n", mp->nb_mem_chunks);
        VI_PRINTF("size = %"
            PRIu32 "\n", mp->size);
        VI_PRINTF("populated_size = %"
            PRIu32 "\n", mp->populated_size);
        VI_PRINTF("header_size = %"
            PRIu32 "\n", mp->header_size);
        VI_PRINTF("elt_size = %"
            PRIu32 "\n", mp->elt_size);
        VI_PRINTF("trailer_size = %"
            PRIu32 "\n", mp->trailer_size);
        VI_PRINTF("total_obj_size = %"
            PRIu32 "\n", \
            mp->header_size + mp->elt_size + mp->trailer_size);
        VI_PRINTF("private_data_size = %"
            PRIu32 "\n", mp->private_data_size);

        STAILQ_FOREACH(memhdr, &mp->mem_list, next)
        mem_len += memhdr->len;
        if (mem_len != 0) {
            VI_PRINTF("avg bytes/object = %#Lf\n",
                (long double) mem_len / mp->size);
        }

        VI_PRINTF("Internal cache infos:\n");
        VI_PRINTF("\tcache_size=%"
            PRIu32 "\n", mp->cache_size);

	if (mp->cache_size == 0) {
            count = 0;
        } else {
            for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
                cache_count = mp->local_cache[lcore_id].len;
                if (cache_count != 0) {
                    VI_PRINTF("\tcache_count[%u]=%"
                        PRIu32 "\n", lcore_id, cache_count);
                }
                count += cache_count;
            }
        }
        VI_PRINTF("total_cache_count=%u\n", count);
        common_count = rte_mempool_ops_get_count(mp);
        if ((cache_count + common_count) > mp->size) {
            common_count = mp->size - cache_count;
        }
        VI_PRINTF("common_pool_count=%u\n\n", common_count);
        break;

    case 1:
        memset(seperator, '-', col_size);
        seperator[col_size-1] = '\0';
        VI_PRINTF("%s\n", seperator);
        VI_PRINTF("%s\n", col_names);
        VI_PRINTF("%s\n", seperator);
        rte_mempool_walk(walk_cb, msg_req);
        VI_PRINTF("\n\n");
        break;

    }
    return 0;
}

static int
display_eth_stats(VR_INFO_ARGS, struct rte_eth_stats eth_stats)
{

    VR_INFO_DEC();
    int i, queue_size;
    char seperator[SEPERATOR];

    VI_PRINTF("RX Device Packets:%"
        PRId64 ", Bytes:%"
        PRId64 ", Errors:%"
        PRId64 ", Nombufs:%"
        PRId64 "\n", eth_stats.ipackets, \
        eth_stats.ibytes, eth_stats.ierrors, eth_stats.rx_nombuf);
    VI_PRINTF("Dropped RX Packets:%"
        PRId64 "\n", eth_stats.imissed);
    VI_PRINTF("TX Device Packets:%"
        PRId64 ", Bytes:%"
        PRId64 ", Errors:%"
        PRId64 "\n", eth_stats.opackets, eth_stats.obytes, eth_stats.oerrors);

    queue_size = sizeof(eth_stats.q_ipackets) / sizeof(eth_stats.q_ipackets[0]);
    memset(seperator, '-', SEPERATOR);
    seperator[SEPERATOR-1] = '\0';

    VI_PRINTF("%s", "Queue Rx:");
    for (i = 0; i < queue_size; i++) {
        if (eth_stats.q_ipackets[i] != 0) {
            VI_PRINTF(" [%d]", i);
            VI_PRINTF("%"
                PRId64 " ", eth_stats.q_ipackets[i]);
        }
    }
    VI_PRINTF("\n");

    VI_PRINTF("%s", "      Tx:");
    for (i = 0; i < queue_size; i++) {
        if (eth_stats.q_opackets[i] != 0) {
            VI_PRINTF(" [%d]", i);
            VI_PRINTF("%"
                PRId64 " ", eth_stats.q_opackets[i]);
        }
    }
    VI_PRINTF("\n");

    VI_PRINTF("%s", "      Rx Bytes:");
    for (i = 0; i < queue_size; i++) {
        if (eth_stats.q_ibytes[i] != 0) {
            VI_PRINTF(" [%d]", i);
            VI_PRINTF("%"
                PRId64 " ", eth_stats.q_ibytes[i]);
        }
    }
    VI_PRINTF("\n");

    VI_PRINTF("%s", "      Tx Bytes:");
    for (i = 0; i < queue_size; i++) {
        if (eth_stats.q_obytes[i] != 0) {
            VI_PRINTF(" [%d]", i);
            VI_PRINTF("%"
                PRId64 " ", eth_stats.q_obytes[i]);
        }
    }
    VI_PRINTF("\n");

    VI_PRINTF("%s", "      Errors:");
    for (i = 0; i < queue_size; i++) {
        if (eth_stats.q_errors[i] != 0) {
            VI_PRINTF(" [%d]", i);
            VI_PRINTF("%"
                PRId64 " ", eth_stats.q_errors[i]);
        }
    }
    VI_PRINTF("\n");
    VI_PRINTF("%s\n\n", seperator);
    return 0;
}

int
dpdk_info_get_stats(VR_INFO_ARGS)
{

    uint16_t port_id, slave_id = 0;
    int i, ret = 0;
    struct rte_eth_stats eth_stats;
    struct vr_dpdk_ethdev *ethdev;
    char name[VR_INTERFACE_NAME_LEN] = "";
    VR_INFO_BUF_INIT();

    port_id = dpdk_find_port_id_by_drv_name();
    if (port_id == VR_DPDK_INVALID_PORT_ID) {
        RTE_LOG(ERR, VROUTER, "Port Id is invalid\n");
        return -1;
    }

    /* Get the ethdev for master port. */
    ethdev = &vr_dpdk.ethdevs[port_id];
    if (ethdev->ethdev_ptr == NULL) {
        RTE_LOG(ERR, VROUTER, "Ethdev not available\n");
    }

    if (rte_eth_stats_get(port_id, & eth_stats) != 0) {
        return -1;
    }

    if (strcmp(msg_req->inbuf, "eth") == 0) {
        VI_PRINTF("Master Info: \n");
        display_eth_stats(msg_req, eth_stats);
        /* Displaying slave stats */
        for (i = 0; i < ethdev->ethdev_nb_slaves; i++) {
            slave_id = ethdev->ethdev_slaves[i];
            ret = rte_eth_dev_get_name_by_port(slave_id, name);
            if (ret != 0) {
                RTE_LOG(ERR, VROUTER, "Error getting bond interface name\n");
                return -1;
            }
            VI_PRINTF("Slave Info(%s): \n", name);
            if (rte_eth_stats_get(slave_id, &eth_stats) != 0) {
                return -1;
            }
            display_eth_stats(msg_req, eth_stats);
        }
    } else {
        RTE_LOG(ERR, VROUTER, "Invalid argument.\n");
        return -1;
    }

    return 0;
}

static int
display_xstats(VR_INFO_ARGS, uint16_t port_id, int xstats_count, bool is_all)
{

    VR_INFO_DEC();
    struct rte_eth_xstat_name *xstats_names = NULL;
    uint64_t *values = NULL;
    int ret, i, segment_lookup[VR_DPDK_BOND_MAX_SLAVES][xstats_count],
        rpi = 0, rbi = 0, tpi = 0, tbi = 0, ei = 0, oth = 0;
    char seperator[SEPERATOR];
    memset(seperator, '-', SEPERATOR);
    seperator[SEPERATOR-1] = '\0';

    values = (uint64_t *)vr_zalloc(
                 sizeof( *values) * xstats_count, VR_INFO_REQ_OBJECT);
    if (values == NULL) {
        RTE_LOG(ERR, VROUTER, "Cannot allocate memory for xstats\n");
        return -1;
    }

    xstats_names = (struct rte_eth_xstat_name *)vr_zalloc(
                       sizeof(struct rte_eth_xstat_name) * xstats_count, VR_INFO_REQ_OBJECT);
    if (xstats_names == NULL) {
        RTE_LOG(ERR, VROUTER, "Cannot allocate memory for xstat names\n");
        goto err;
    }
    if (xstats_count != rte_eth_xstats_get_names_by_id(port_id, xstats_names,
        xstats_count, NULL)) {
        RTE_LOG(ERR, VROUTER, "Cannot get xstat names\n");
        goto err;
    }

    ret = rte_eth_xstats_get_by_id(port_id, NULL, values, xstats_count);
    if (ret < 0 || ret > xstats_count) {
        RTE_LOG(ERR, VROUTER, "Cannot get xstats\n");
        goto err;
    }

    /* Adding the indices of respective segments in segment_lookup array */
    for (i = 0; i < xstats_count; i++) {
        if (strstr(xstats_names[i].name, "rx") &&
            strstr(xstats_names[i].name, "packets")) {
            segment_lookup[RX_PACKETS][rpi++] = i;
        } else if (strstr(xstats_names[i].name, "tx") &&
              strstr(xstats_names[i].name, "packets")) {
            segment_lookup[TX_PACKETS][tpi++] = i;
        } else if (strstr(xstats_names[i].name, "rx") &&
              strstr(xstats_names[i].name, "bytes")) {
            segment_lookup[RX_BYTES][rbi++] = i;
        } else if (strstr(xstats_names[i].name, "tx") &&
              strstr(xstats_names[i].name, "bytes")) {
            segment_lookup[TX_BYTES][tbi++] = i;
        } else if (strstr(xstats_names[i].name, "errors")) {
            segment_lookup[ERRORS][ei++] = i;
        } else {
            segment_lookup[OTHERS][oth++] = i;
        }
    }

    /* Printing xstats name and value segment-wise */
    VI_PRINTF("Rx Packets: \n");
    for (i = 0; i < rpi - 1; i++) {
        if (values[segment_lookup[RX_PACKETS][i]] != 0 || is_all) {
            VI_PRINTF("\t%s: %"PRIu64 "\n",
                xstats_names[segment_lookup[RX_PACKETS][i]].name,
                values[segment_lookup[RX_PACKETS][i]]);
        }
    }
    VI_PRINTF("Tx Packets: \n");
    for (i = 0; i < tpi - 1; i++) {
        if (values[segment_lookup[TX_PACKETS][i]] != 0 || is_all) {
            VI_PRINTF("\t%s: %"PRIu64 "\n",
                xstats_names[segment_lookup[TX_PACKETS][i]].name,
                values[segment_lookup[TX_PACKETS][i]]);
        }
    }

    VI_PRINTF("Rx Bytes: \n");
    for (i = 0; i < rbi - 1; i++) {
        if (values[segment_lookup[RX_BYTES][i]] != 0 || is_all) {
            VI_PRINTF("\t%s: %"PRIu64 "\n",
                xstats_names[segment_lookup[RX_BYTES][i]].name,
                values[segment_lookup[RX_BYTES][i]]);
        }
    }
    VI_PRINTF("Tx Bytes: \n");
    for (i = 0; i < tbi - 1; i++) {
        if (values[segment_lookup[TX_BYTES][i]] != 0 || is_all) {
            VI_PRINTF("\t%s: %"PRIu64 "\n",
                xstats_names[segment_lookup[TX_BYTES][i]].name,
                values[segment_lookup[TX_BYTES][i]]);
        }
    }
    VI_PRINTF("Errors: \n");
    for (i = 0; i < ei - 1; i++) {
        if (values[segment_lookup[ERRORS][i]] != 0 || is_all) {
            VI_PRINTF("\t%s: %"PRIu64 "\n",
                xstats_names[segment_lookup[ERRORS][i]].name,
                values[segment_lookup[ERRORS][i]]);
        }
    }
    VI_PRINTF("Others: \n");
    for (i = 0; i < oth - 1; i++) {
        if (values[segment_lookup[OTHERS][i]] != 0 || is_all) {
            VI_PRINTF("\t%s: %"PRIu64 "\n",
                xstats_names[segment_lookup[OTHERS][i]].name,
                values[segment_lookup[OTHERS][i]]);
        }
    }

    VI_PRINTF("%s\n\n", seperator);
    if (values){
        vr_free(values, VR_INFO_REQ_OBJECT);
        values = NULL;
    }
    if (xstats_names){
        vr_free(xstats_names, VR_INFO_REQ_OBJECT);
        xstats_names = NULL;
    }

    return 0;

    err:
        if (values){
            vr_free(values, VR_INFO_REQ_OBJECT);
            values = NULL;
        }
        if (xstats_names){
            vr_free(xstats_names, VR_INFO_REQ_OBJECT);
            xstats_names = NULL;
        }
        return -1;
}

int
dpdk_info_get_xstats(VR_INFO_ARGS)
{

    uint16_t port_id, slave_id = 0;
    int i, reqd_interface, ret = 0, slave = 0, xstats_count = -1;
    char name[VR_INTERFACE_NAME_LEN] = "";
    struct vrouter *router = vrouter_get(0);
    struct vr_dpdk_ethdev *ethdev = NULL;
    bool is_all = false;

    VR_INFO_BUF_INIT();
    port_id = dpdk_find_port_id_by_drv_name();
    is_all = !strcmp(msg_req->inbuf, "all");

    if (port_id != VR_DPDK_INVALID_PORT_ID) {

        /* Get the ethdev for master port. */
        ethdev = &vr_dpdk.ethdevs[port_id];
        if (ethdev->ethdev_ptr == NULL) {
            RTE_LOG(ERR, VROUTER, "Ethdev not available\n");
            return -1;
        }

        if (!strcmp(msg_req->inbuf, "") || is_all) {
            reqd_interface = 0;
        } else if (!strcmp(msg_req->inbuf, "0") ||
            (atoi(msg_req->inbuf) > 0 &&
                atoi(msg_req->inbuf) <= ethdev->ethdev_nb_slaves)) {
            reqd_interface = 1;
        } else {
            RTE_LOG(ERR, VROUTER, "Invalid argument.\n");
            return -1;
        }

        xstats_count = rte_eth_xstats_get_names_by_id(port_id, NULL, 0, NULL);
        if (xstats_count < 0) {
            RTE_LOG(ERR, VROUTER, "Cannot get xstats count\n");
            return -1;
        }

	 switch (reqd_interface) {
        case 0:
            VI_PRINTF("Master Info: \n");
            display_xstats(msg_req, port_id, xstats_count, is_all);

            /* Displaying slave stats */
            for (i = 0; i < ethdev->ethdev_nb_slaves; i++) {
                slave_id = ethdev->ethdev_slaves[i];
                ret = rte_eth_dev_get_name_by_port(slave_id, name);
                if (ret != 0) {
                    RTE_LOG(ERR, VROUTER, "Error getting bond interface name\n");
                    return -1;
                }
                VI_PRINTF("Slave Info(%d):%s \n", i, name);

                xstats_count = rte_eth_xstats_get_names_by_id(slave_id, NULL, 0, NULL);
                if (xstats_count < 0) {
                    RTE_LOG(ERR, VROUTER, "Cannot get xstats count\n");
                    return -1;
                }
                display_xstats(msg_req, slave_id, xstats_count, is_all);
            }
            break;

	    case 1:
            if (!strcmp(msg_req->inbuf, "0")) {
                VI_PRINTF("Master Info: \n");
                display_xstats(msg_req, port_id, xstats_count, is_all);
            } else {
                slave = atoi(msg_req->inbuf) - 1;
                slave_id = ethdev->ethdev_slaves[slave];
                ret = rte_eth_dev_get_name_by_port(slave_id, name);
                if (ret != 0) {
                    RTE_LOG(ERR, VROUTER, "Error getting bond interface name\n");
                    return -1;
                }
                VI_PRINTF("Slave Info(%d):%s \n", slave, name);
                xstats_count = rte_eth_xstats_get_names_by_id(slave_id, NULL, 0, NULL);
                if (xstats_count < 0) {
                    RTE_LOG(ERR, VROUTER, "Cannot get xstats count\n");
                    return -1;
                }
                display_xstats(msg_req, slave_id, xstats_count, is_all);
            }
            break;
        }
    } else {
        /* if bond is not configured */
        if (strcmp(msg_req->inbuf, "") == 0 || is_all) {
            if (router->vr_eth_if) {
                ethdev = (struct vr_dpdk_ethdev* ) router->vr_eth_if->vif_os;
            }
            if (ethdev) {
                port_id = ethdev->ethdev_port_id;
            }
            xstats_count = rte_eth_xstats_get_names_by_id(port_id, NULL, 0, NULL);
            if (xstats_count < 0) {
                RTE_LOG(ERR, VROUTER, "Cannot get xstats count\n");
                return -1;
            }

            display_xstats(msg_req, port_id, xstats_count, is_all);
        } else {
            RTE_LOG(ERR, VROUTER, "Invalid argument.\n");
            return -1;
        }

	 }

    return 0;
}

int
dpdk_info_get_lcore(VR_INFO_ARGS)
{
    struct vr_dpdk_queue *rx_queue;
    struct vr_dpdk_lcore *lcore;
    unsigned char *name;
    int i;

    VR_INFO_BUF_INIT();

    VI_PRINTF("No. of forwarding lcores: %d \n", vr_dpdk.nb_fwd_lcores);

    for (i = 0; i < vr_dpdk.nb_fwd_lcores; i++) {
        VI_PRINTF("Lcore %d: \n",(VR_DPDK_FWD_LCORE_ID + i));
        lcore = vr_dpdk.lcores[VR_DPDK_FWD_LCORE_ID + i];
        SLIST_FOREACH(rx_queue, &lcore->lcore_rx_head, q_next) {
            name = rx_queue->q_vif->vif_name;
            VI_PRINTF("\tInterface: %-20s", name);
            VI_PRINTF("Queue ID: %"
                PRId16 " \n", rx_queue->vring_queue_id);
        }
        VI_PRINTF("\n");
    }

    return 0;
}

int
dpdk_info_get_app(VR_INFO_ARGS)
{

    uint16_t port_id;
    FILE *intf = NULL, *bond_file = NULL;
    char filepath[] = "/var/run/vrouter/", tempbuf[LINE], tempbuf2[LINE],
         *bond_file_line, *slave_names;
    struct vr_dpdk_ethdev *ethdev = NULL;
    struct rte_eth_dev_info dev_info;
    struct vr_dpdk_tapdev *tapdev = vr_dpdk.tapdevs;
    size_t soff;
    struct vrouter *router = vrouter_get(0);
    int i, j = 0, k = 0,rc;
    struct vr_interface *vif;
    bool monitoring_intf = false, sriov_flag = false;

    VR_INFO_BUF_INIT();

    VI_PRINTF("No. of cores: %d \n", vr_num_cpus);
    VI_PRINTF("No. of forwarding lcores: %d \n", vr_dpdk.nb_fwd_lcores);


    /* Get the port_id for master, Incase of non-bond devices,
       port_id is VR_DPDK_INVALID_PORT_ID */
    port_id = dpdk_find_port_id_by_drv_name();
    if (port_id == VR_DPDK_INVALID_PORT_ID) {
        RTE_LOG(ERR, VROUTER, "Port Id is invalid\n");
    }
    ethdev = &vr_dpdk.ethdevs[port_id];
    if (ethdev->ethdev_ptr == NULL) {
        RTE_LOG(ERR, VROUTER, "Ethdev not available\n");
    }
    snprintf(tempbuf, sizeof(tempbuf), "%s%s", filepath, "nic");
    intf = fopen(tempbuf, "r");
    if (intf == NULL){
        RTE_LOG(ERR, VROUTER, "Nic file does not exits.\n");
        return -1;
    }
    if (fgets (tempbuf, sizeof(tempbuf), intf)){
        VI_PRINTF("Fabric interface: %s", tempbuf);
        if (strstr(tempbuf, "bond")){
            snprintf(tempbuf2, strlen(tempbuf), "%s", tempbuf);
            snprintf(tempbuf, sizeof(tempbuf), "%s%s%s", filepath,
                        tempbuf2, "_bond");
            bond_file = fopen(tempbuf, "r");
            if (bond_file == NULL){
                RTE_LOG(ERR, VROUTER, "Bond file does not exists.\n");
                if(intf)
                    fclose(intf);
                return -1;
            }
            rc = fgets (tempbuf, sizeof(tempbuf), bond_file);
            bond_file_line = strtok(tempbuf, " ");
            while(j < 2){
                bond_file_line = strtok(NULL, " ");
                j++;
            }
            snprintf(tempbuf, sizeof(tempbuf), "%s", bond_file_line);
            slave_names = strtok(tempbuf, ",");
            for (i = 0; i < ethdev->ethdev_nb_slaves; i++) {
                VI_PRINTF("Slave interface(%d): %s \n", i, slave_names);
                slave_names = strtok(NULL, ",");
            }

        }
    }
    /* Display vlan information */
    if (vr_dpdk.vlan_vif){
        VI_PRINTF("Vlan vif: %s \n", vr_dpdk.vlan_vif->vif_name);
        VI_PRINTF("Vlan name: %s \n", vr_dpdk.vlan_name);
        VI_PRINTF("Vlan tag: %d \n", vr_dpdk.vlan_tag);
    }
    /* Display Ethdev information */
    if (ethdev->ethdev_ptr) {
        rte_eth_dev_info_get(port_id, &dev_info);
        VI_PRINTF("Ethdev (Master):\n");
        VI_PRINTF("\tMax rx queues: %"PRIu16"\n", dev_info.max_rx_queues);
        VI_PRINTF("\tMax tx queues: %"PRIu16"\n", dev_info.max_tx_queues);
        VI_PRINTF("\tEthdev nb rx queues: %"PRIu16"\n",
                       ethdev->ethdev_nb_rx_queues);
        VI_PRINTF("\tEthdev nb tx queues: %"PRIu16"\n",
                       ethdev->ethdev_nb_tx_queues);
        VI_PRINTF("\tEthdev nb rss queues: %"PRIu16"\n",
                       ethdev->ethdev_nb_rss_queues);
        VI_PRINTF("\tEthdev reta size: %"PRIu16"\n", ethdev->ethdev_reta_size);
        VI_PRINTF("\tEthdev port id: %"PRIu16"\n", ethdev->ethdev_port_id);
        VI_PRINTF("\tEthdev nb slaves: %d \n", ethdev->ethdev_nb_slaves);
        VI_PRINTF("\tEthdev slaves: ");
        for (i = 0; i < VR_DPDK_BOND_MAX_SLAVES; i++){
            VI_PRINTF("%"PRIu16 " ", ethdev->ethdev_slaves[i]);
        }
        VI_PRINTF("\n\n");
    }

    for (i = 0; i < ethdev->ethdev_nb_slaves; i++) {
        #if (RTE_VERSION >= RTE_VERSION_NUM(17, 11, 0, 0))
        VI_PRINTF("Ethdev (Slave %d): %s\n", i, rte_eth_devices[i].data->name);
        VI_PRINTF("\tNb rx queues: %"PRIu16"\n",
                       rte_eth_devices[i].data->nb_rx_queues);
        VI_PRINTF("\tNb tx queues: %"PRIu16"\n",
                       rte_eth_devices[i].data->nb_tx_queues);
        VI_PRINTF("\tEthdev reta size: %"PRIu16"\n\n", dev_info.reta_size);

        #else
        VI_PRINTF("Ethdev (Slave %d): %s\n", i, rte_eth_devices[i].data->name);
        VI_PRINTF("\tNb rx queues: %"PRIu16"\n",
                       rte_eth_devices[i].data->nb_rx_queues);
        VI_PRINTF("\tNb tx queues: %"PRIu16"\n",
                       rte_eth_devices[i].data->nb_tx_queues);
        VI_PRINTF("\tEthdev reta size: %"PRIu16"\n\n", dev_info.reta_size);
        #endif
    }
    /* Display Tapdev information */
    if(tapdev) {
        VI_PRINTF("Tapdev:\n");
        while (tapdev[k].tapdev_fd){
            VI_PRINTF("\tfd: %d", tapdev[k].tapdev_fd);
            if(tapdev[k].tapdev_vif) {
                VI_PRINTF("\tvif name: %s \n", tapdev[k].tapdev_vif->vif_name);
            }
            k++;
        }
    }
    VI_PRINTF("\n");

     /* Display Monitoring interfaces */
    for (i = 0; i < router->vr_max_interfaces; i++){
         if (vr_dpdk.monitorings[i] != 0 &&
                 vr_dpdk.monitorings[i] != VR_MAX_INTERFACES){
             if (!monitoring_intf){
                 VI_PRINTF("Monitorings:\n");
                 monitoring_intf = true;
             }
             vif = router->vr_interfaces[i];
             VI_PRINTF("\t%s\n", vif->vif_name);
         }
    }

    /* Display SRIOV information */
    VR_DPDK_RTE_ETH_FOREACH_DEV(i){
         rte_eth_dev_info_get(i, &dev_info);
         /* Check PMD name suffix to detect SR-IOV virtual function. */
         soff = strlen(dev_info.driver_name) - sizeof(VR_DPDK_VF_PMD_SFX) + 1;
         if (soff > 0 &&
               strncmp(dev_info.driver_name + soff, VR_DPDK_VF_PMD_SFX,
               sizeof(VR_DPDK_VF_PMD_SFX)) == 0){
             if (dev_info.max_tx_queues < vr_dpdk.nb_fwd_lcores
                    /* We also need 2 TX queues for Netlink and Packet lcores. */
                    + VR_DPDK_FWD_LCORE_ID - VR_DPDK_PACKET_LCORE_ID) {
                 if (!sriov_flag){
                     VI_PRINTF("Sriov:\n");
                     sriov_flag = true;
                 }
                 VI_PRINTF("\tLcore: %d", VR_DPDK_FWD_LCORE_ID);
                 VI_PRINTF("\tEthdev port id: %d", i);
                 VI_PRINTF("\tDriver Name: %s\n", dev_info.driver_name);
                break;
             }
         }
    }

     VI_PRINTF("\n");
    if(intf) {
        fclose(intf);
        intf = NULL;
    }

    if(bond_file) {
        fclose(bond_file);
        bond_file = NULL;
    }

    return 0;
}
