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

#include <rte_mempool.h>
#include <rte_eal_memconfig.h>

#include "rte_mempool.h"

/* NOTE: Callback API's need to be registered in vrouter/include/vr_info.h
 * under VR_INFO_REG(X) macro.
 * All callback API's should start with "dpdk_<fn.name>"
 * Register Format: X(MSG, <fn.name>) \
 *              eg: X(INFO_BOND, info_get_bond)
 */

/* dpdk_info_get_bond provide the bond master & slave information */
int
dpdk_info_get_bond(VR_INFO_ARGS)
{
    uint16_t port_id, slave_id;
    struct vr_dpdk_ethdev *ethdev;
    int ret, i;
    char *status[] = {"DOWN", "UP"};
    char *lacp_rate[] = {"slow", "fast"};
    char *duplex[] = {"half", "full"};
    struct rte_eth_link link;
    struct ether_addr mac_addr;
    char name[VR_INTERFACE_NAME_LEN];
    struct rte_eth_bond_8023ad_slave_info info;

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
    if (ethdev->ethdev_ptr == NULL)
        RTE_LOG(ERR, VROUTER, "Ethdev not available\n");


    VI_PRINTF("DPDK Version: %s\n", \
            rte_version());
    VI_PRINTF("No. of bond slaves: %d\n\n", ethdev->ethdev_nb_slaves);

    /* Get bond mode */
    ret = rte_eth_bond_mode_get(port_id);
    switch(ret) {
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
    VI_PRINTF("MII status: %s\n", status[link.link_status]);
    VI_PRINTF("MII Link Speed: %d\n", link.link_speed);
    VI_PRINTF("MII Polling Interval (ms): %d\n", \
            rte_eth_bond_link_monitoring_get(port_id));
    VI_PRINTF("Up Delay (ms): %d\n", \
            rte_eth_bond_link_up_prop_delay_get(port_id));
    VI_PRINTF("Down Delay (ms): %d\n\n", \
            rte_eth_bond_link_down_prop_delay_get(port_id));

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

    slave_id = ethdev->ethdev_slaves[0];

    ret = rte_eth_bond_8023ad_slave_info(port_id, slave_id, &info);
    if (ret != 0)
        RTE_LOG(ERR, VROUTER, "Error getting bond interface name\n");

    VI_PRINTF("System priority: %d\n", info.actor.system_priority);
    VI_PRINTF("System MAC address:" MAC_FORMAT "\n", MAC_VALUE(info.actor.system.addr_bytes));
    VI_PRINTF("Active Aggregator Info: \n");
    VI_PRINTF("\tAggregator ID: %d\n", info.agg_port_id);
    VI_PRINTF("\tNumber of ports: %d \n", ethdev->ethdev_nb_slaves);
    VI_PRINTF("\tActor Key: %d \n",  info.actor.key);
    VI_PRINTF("\tPartner Key: %d \n",  info.partner.key );
    VI_PRINTF("\tPartner Mac Address: "MAC_FORMAT "\n\n", MAC_VALUE(info.partner.system.addr_bytes));

    /* Displaying bond slave inforamtion */
    for(i = 0; i < ethdev->ethdev_nb_slaves; i++) {
        slave_id = ethdev->ethdev_slaves[i];

        ret = rte_eth_dev_get_name_by_port(slave_id, name);
        if (ret != 0)
            RTE_LOG(ERR, VROUTER, "Error getting bond interface name\n");

        ret = rte_eth_bond_8023ad_slave_info(port_id, slave_id, &info);
        if (ret != 0)
            RTE_LOG(ERR, VROUTER, "Error getting bond interface name\n");

        VI_PRINTF("Slave Interface(%d): %s \n", i, name);
        VI_PRINTF("Slave Interface Driver: %s\n", \
                rte_eth_devices[slave_id].device->driver->name);

        rte_eth_link_get_nowait(slave_id, &link);
        VI_PRINTF("MII status: %s\n", status[link.link_status]);
        VI_PRINTF("MII Link Speed: %d\n", link.link_speed);
        VI_PRINTF("Duplex: %s\n", duplex[link.link_duplex]);
        VI_PRINTF("Permanent HW addr:" MAC_FORMAT "\n", MAC_VALUE(info.actor.system.addr_bytes))
        VI_PRINTF("Aggregator ID: %d\n", info.agg_port_id)
        VI_PRINTF("MII Polling Interval (ms): %d\n", \
                rte_eth_bond_link_monitoring_get(slave_id));


        VI_PRINTF("802.3ad info: \n");

        VI_PRINTF("LACP Rate: %s\n", \
                lacp_rate[rte_eth_bond_lacp_rate_get(slave_id)]);

        rte_eth_macaddr_get(slave_id, &mac_addr);
        VI_PRINTF("Bond MAC addr:" MAC_FORMAT "\n", \
                MAC_VALUE(mac_addr.addr_bytes));

        VI_PRINTF("Details actor lacp pdu: \n");
        VI_PRINTF("\tsystem priority: %d \n", info.actor.system_priority);
        VI_PRINTF("\tsystem mac address:" MAC_FORMAT "\n", MAC_VALUE(info.actor.system.addr_bytes));
        VI_PRINTF("\tport key: %d \n", info.actor.key);
        VI_PRINTF("\tport priority: %d \n", info.actor.port_priority);
        VI_PRINTF("\tport number: %d \n", info.actor.port_number );
        VI_PRINTF("\tport state: %d \n",  info.actor_state);

        VI_PRINTF("Details partner lacp pdu: \n");
        VI_PRINTF("\tsystem priority: %d \n", info.partner.system_priority);
        VI_PRINTF("\tsystem mac address:" MAC_FORMAT "\n", MAC_VALUE(info.partner.system.addr_bytes));
        VI_PRINTF("\tport key: %d \n", info.partner.key);
        VI_PRINTF("\tport priority: %d \n", info.partner.port_priority);
        VI_PRINTF("\tport number: %d \n", info.partner.port_number );
        VI_PRINTF("\tport state: %d \n\n",  info.partner_state);


    }

    return 0;
 }


int
dpdk_info_get_lacp(VR_INFO_ARGS){

    uint16_t port_id, slave_id;
    struct vr_dpdk_ethdev *ethdev;
    int i, ret;
    char *lacp_rate[] = {"slow", "fast"};
    char name[VR_INTERFACE_NAME_LEN];
    struct rte_eth_bond_8023ad_conf conf;
    struct rte_eth_bond_8023ad_slave_info info;

    VR_INFO_BUF_INIT();

    /* Get the port_id for master, Incase of non-bond devices, it return here. */
    port_id = dpdk_find_port_id_by_drv_name();
    if (port_id == VR_DPDK_INVALID_PORT_ID) {
        RTE_LOG(ERR, VROUTER, "Port Id is invalid\n");
        return -1;
    }

    /* Check LACP protocol is configured for the bond interface. */
    VI_PRINTF("LACP Rate: %s\n\n", \
                lacp_rate[rte_eth_bond_lacp_rate_get(port_id)]);

    ret = rte_eth_bond_8023ad_conf_get(port_id, &conf);
    
    VI_PRINTF("Fast periodic (ms): %d\n" , conf.fast_periodic_ms);
    VI_PRINTF("Slow periodic (ms): %d\n", conf.slow_periodic_ms);
    VI_PRINTF("Short timeout (ms): %d\n", conf.short_timeout_ms);
    VI_PRINTF("Long timeout (ms): %d\n", conf.long_timeout_ms);
    VI_PRINTF("Aggregate wait timeout (ms): %d\n", conf.aggregate_wait_timeout_ms);
    VI_PRINTF("Tx period (ms): %d\n", conf.tx_period_ms );
    VI_PRINTF("Update timeout (ms): %d\n", conf.update_timeout_ms);
    VI_PRINTF("Rx marker period (ms): %d\n\n", conf.rx_marker_period_ms);
    
    ethdev = &vr_dpdk.ethdevs[port_id];
    if (ethdev->ethdev_ptr == NULL)
        RTE_LOG(ERR, VROUTER, "Ethdev not available\n");

    slave_id = ethdev->ethdev_slaves[0];

    ret = rte_eth_bond_8023ad_slave_info(port_id, slave_id, &info);
    if (ret != 0)
        RTE_LOG(ERR, VROUTER, "Error getting bond interface name\n");
    
    /* Displaying bond slave inforamtion */
    
    for(i = 0; i < ethdev->ethdev_nb_slaves; i++) {
        slave_id = ethdev->ethdev_slaves[i];
	
	ret = rte_eth_dev_get_name_by_port(slave_id, name);
        if (ret != 0)
            RTE_LOG(ERR, VROUTER, "Error getting bond interface name\n");
        
	ret = rte_eth_bond_8023ad_slave_info(port_id, slave_id, &info);
        if (ret != 0)
            RTE_LOG(ERR, VROUTER, "Error getting bond interface name\n");

        VI_PRINTF("Slave Interface(%d): %s \n", i, name);
	VI_PRINTF("Details actor lacp pdu: \n");
        VI_PRINTF("\tport state: %d \n",  info.actor_state);

        VI_PRINTF("Details partner lacp pdu: \n");
        VI_PRINTF("\tport state: %d \n\n",  info.partner_state);

    }
    return 0;
}

static void
walk_cb(struct rte_mempool *mp, void *arg __rte_unused)
{
    vr_info_t *msg_req = (vr_info_t *)arg;
    VR_INFO_DEC();

#undef VR_INFO_FAILED
#define VR_INFO_FAILED
    VI_PRINTF("%-20s\t", mp->name);
    VI_PRINTF("%d\t", mp->size);
    VI_PRINTF("%d\t", rte_mempool_in_use_count(mp));
    VI_PRINTF("%d\t\n", rte_mempool_avail_count(mp));

#undef VR_INFO_FAILED
#define VR_INFO_FAILED -1
        return ;

}



int
dpdk_info_get_mempool(VR_INFO_ARGS)
{
    VR_INFO_BUF_INIT();
    int reqd_mempool  = 0;
    struct rte_mempool *mp = NULL;
    struct rte_mempool_memhdr *memhdr;
    unsigned common_count;
    unsigned cache_count;
    unsigned lcore_id;
    unsigned count = 0;
    size_t mem_len = 0;
    char col_names[] = "Name\t\t\tSize\tUsed\tAvailable";
    int col_size = *(&col_names + 1) - col_names + 25;
    char seperator[col_size + 10];

    //if inbuf is not equal to summary then num = 1
    if (strcmp(msg_req->inbuf, "all")) {
	reqd_mempool = 1;
    }
    switch(reqd_mempool){
        case 0:
    	    memset(seperator , '-', col_size);
            seperator[col_size]='\0';
            VI_PRINTF("%s\n", seperator);
            VI_PRINTF("%s\n", col_names);
    	    VI_PRINTF("%s\n", seperator);
           rte_mempool_walk(walk_cb, msg_req);
           VI_PRINTF("\n\n");
           break;
        default :
            mp = rte_mempool_lookup(msg_req->inbuf);
	    if (mp == NULL)
		 RTE_LOG(ERR, VROUTER, "Mempool name does not exists.\n");

	    VI_PRINTF("%s\n", mp->name);
	    VI_PRINTF("flags = %x\n", mp->flags);
            VI_PRINTF("nb_mem_chunks = %u\n", mp->nb_mem_chunks);
            VI_PRINTF("size = %"PRIu32"\n", mp->size);
            VI_PRINTF("populated_size = %"PRIu32"\n", mp->populated_size);
            VI_PRINTF("header_size = %"PRIu32"\n", mp->header_size);
            VI_PRINTF("elt_size = %"PRIu32"\n", mp->elt_size);
            VI_PRINTF("trailer_size = %"PRIu32"\n", mp->trailer_size);
	    VI_PRINTF("total_obj_size = %"PRIu32"\n", mp->header_size + mp->elt_size + mp->trailer_size);
	    VI_PRINTF("private_data_size = %"PRIu32"\n", mp->private_data_size);

            STAILQ_FOREACH(memhdr, &mp->mem_list, next)
                mem_len += memhdr->len;
            if (mem_len != 0) {
                VI_PRINTF("avg bytes/object = %#Lf\n",(long double)mem_len / mp->size);
	    }


            VI_PRINTF("Internal cache infos:\n");
            VI_PRINTF("\tcache_size=%"PRIu32"\n", mp->cache_size);

            if (mp->cache_size == 0)
                count = 0;
	    else{
        	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
                	cache_count = mp->local_cache[lcore_id].len;
                if (cache_count != 0){
                VI_PRINTF("\tcache_count[%u]=%"PRIu32"\n", lcore_id, cache_count);}
                count += cache_count;
            }
            }
            VI_PRINTF("total_cache_count=%u\n", count);
            common_count = rte_mempool_ops_get_count(mp);
            if ((cache_count + common_count) > mp->size)
                  common_count = mp->size - cache_count;
            VI_PRINTF("common_pool_count=%u\n\n", common_count);

 }
    return 0;
}
