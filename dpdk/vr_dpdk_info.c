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
    VI_PRINTF("MII Polling Interval (ms): %d\n", \
            rte_eth_bond_link_monitoring_get(port_id));
    return 0;
}

static int
dpdk_bond_info_show_slave(VR_INFO_ARGS, int port_id ,struct vr_dpdk_ethdev *ethdev)
{
    VR_INFO_DEC();
    int i, ret, slave_id;
    char *lacp_rate[] = {"slow", "fast"};
    char *duplex[] = {"half", "full"};
    struct ether_addr mac_addr;
    struct rte_eth_link link;
    char name[VR_INTERFACE_NAME_LEN];
    struct rte_eth_bond_8023ad_slave_info info;

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

    /* Display bond slave inforamtion */
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
                rte_eth_devices[port_id].device->driver->name);

        rte_eth_link_get_nowait(port_id, &link);
        ret = dpdk_bond_info_mii_status(VR_INFO_PASS_ARGS, port_id, &link);
        if(ret < 0) {
            return VR_INFO_FAILED;
        }
        VI_PRINTF("Permanent HW addr:" MAC_FORMAT "\n", MAC_VALUE(info.actor.system.addr_bytes))
        VI_PRINTF("Aggregator ID: %d\n", info.agg_port_id)

        VI_PRINTF("Duplex: %s\n", duplex[link.link_duplex]);

        VI_PRINTF("802.3ad info\n");

        VI_PRINTF("LACP Rate: %s\n", \
                lacp_rate[rte_eth_bond_lacp_rate_get(port_id)]);

        rte_eth_macaddr_get(port_id, &mac_addr);
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

static int
dpdk_bond_info_show_master(VR_INFO_ARGS, int port_id,
        struct vr_dpdk_ethdev *ethdev)
{
    VR_INFO_DEC();
    int ret, bond_mode;
    struct rte_eth_link link;

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
    VI_PRINTF("Down Delay (ms): %d\n\n", \
            rte_eth_bond_link_down_prop_delay_get(port_id));

    if(bond_mode == BONDING_MODE_8023AD) {
        ret = dpdk_bond_mode_8023ad(VR_INFO_PASS_ARGS, port_id);
        if (ret < 0) {
            return VR_INFO_FAILED;
        }
    }
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
 *      * that size else allocate with default size */
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

    ret = dpdk_bond_info_show_slave(VR_INFO_PASS_ARGS, port_id, ethdev);
    if(ret < 0) {
        return VR_INFO_FAILED;
    }

    return 0;
 }

int 
display_lacp_conf(VR_INFO_ARGS, uint16_t port_id){
   
    VR_INFO_DEC();
    char *lacp_rate[] = {"slow", "fast"};
    struct rte_eth_bond_8023ad_conf conf;

    /* Check LACP protocol is configured for the bond interface. */
    VI_PRINTF("LACP Rate: %s\n\n", \
		lacp_rate[rte_eth_bond_lacp_rate_get(port_id)]);

    rte_eth_bond_8023ad_conf_get(port_id, &conf);

    VI_PRINTF("Fast periodic (ms): %d\n" , conf.fast_periodic_ms);
    VI_PRINTF("Slow periodic (ms): %d\n", conf.slow_periodic_ms);
    VI_PRINTF("Short timeout (ms): %d\n", conf.short_timeout_ms);
    VI_PRINTF("Long timeout (ms): %d\n", conf.long_timeout_ms);
    VI_PRINTF("Aggregate wait timeout (ms): %d\n", conf.aggregate_wait_timeout_ms);
    VI_PRINTF("Tx period (ms): %d\n", conf.tx_period_ms );
    VI_PRINTF("Update timeout (ms): %d\n", conf.update_timeout_ms);
    VI_PRINTF("Rx marker period (ms): %d\n\n", conf.rx_marker_period_ms);
    return 0;

}

int
dpdk_info_get_lacp(VR_INFO_ARGS){

    uint16_t port_id, slave_id;
    struct vr_dpdk_ethdev *ethdev;
    int i, ret;
    char name[VR_INTERFACE_NAME_LEN];
    struct rte_eth_bond_8023ad_slave_info info;

    VR_INFO_BUF_INIT();

    /* Get the port_id for master, Incase of non-bond devices, it return here. */
    port_id = dpdk_find_port_id_by_drv_name();
    if (port_id == VR_DPDK_INVALID_PORT_ID) {
	RTE_LOG(ERR, VROUTER, "Port Id is invalid\n");
	return -1;
    }

    if (strcmp(msg_req->inbuf, "all") == 0) {
        display_lacp_conf(msg_req, port_id);

	ethdev = &vr_dpdk.ethdevs[port_id];
	if (ethdev->ethdev_ptr == NULL)
	RTE_LOG(ERR, VROUTER, "Ethdev not available\n");

	slave_id = ethdev->ethdev_slaves[0];

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
     } 
     else if (strcmp(msg_req->inbuf, "conf") == 0) {
		display_lacp_conf(msg_req, port_id);}
     else {
            RTE_LOG(ERR, VROUTER, "Invalid argument.\n");
            return -1;}
    return 0;
}

static void
walk_cb(struct rte_mempool *mp, void *arg __rte_unused)
{
    vr_info_t *msg_req = (vr_info_t *)arg;
    VR_INFO_DEC();
    #undef VR_INFO_FAILED
    #define VR_INFO_FAILED

    #undef VR_INFO_MSG_TRUNC
    #define VR_INFO_MSG_TRUNC

    VI_PRINTF("%-20s\t", mp->name);
    VI_PRINTF("%d\t", mp->size);
    VI_PRINTF("%d\t", rte_mempool_in_use_count(mp));
    VI_PRINTF("%d\t\n", rte_mempool_avail_count(mp));

    #undef VR_INFO_FAILED
    #define VR_INFO_FAILED -1

    #undef VR_INFO_MSG_TRUNC
    #define VR_INFO_MSG_TRUNC -2
    return ;
}



int
dpdk_info_get_mempool(VR_INFO_ARGS)
{
    VR_INFO_BUF_INIT();
    int reqd_mempool = 1;
    struct rte_mempool *mp = NULL;
    struct rte_mempool_memhdr *memhdr;
    unsigned common_count;
    unsigned cache_count;
    unsigned lcore_id;
    unsigned count = 0;
    size_t mem_len = 0;
    char col_names[] = "Name\t\t\tSize\tUsed\tAvailable";
    int col_size = (sizeof(col_names) / sizeof(col_names[0])) + 25;
    char seperator[col_size + 10];

    if (strcmp(msg_req->inbuf, "all") == 0) {
	reqd_mempool = 0;
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
        case 1:
            mp = rte_mempool_lookup(msg_req->inbuf);
	    if (mp == NULL){
		 RTE_LOG(ERR, VROUTER, "Mempool name does not exists.\n");
		 return -1;
	    }

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
	    break;

    }
    return 0;
}


int
display_eth_stats(VR_INFO_ARGS, struct rte_eth_stats eth_stats){
    
    VR_INFO_DEC();
    int i, queue_size;
    char seperator[100];

    VI_PRINTF("RX Device Packets:%"PRId64", Bytes:%"PRId64", Errors:%"PRId64", Nombufs:%"PRId64"\n", eth_stats.ipackets, eth_stats.ibytes, eth_stats.ierrors, eth_stats.rx_nombuf);
    VI_PRINTF("Dropped RX Packets:%"PRId64"\n", eth_stats.imissed);
    VI_PRINTF("TX Device Packets:%"PRId64", Bytes:%"PRId64", Errors:%"PRId64"\n", eth_stats.opackets, eth_stats.obytes, eth_stats.oerrors);
 
    queue_size =  sizeof(eth_stats.q_ipackets) / sizeof(eth_stats.q_ipackets[0]);
    memset(seperator , '-', 60);
    seperator[60]='\0';
    
    VI_PRINTF("%s", "Queue Rx:");
    for(i = 0; i<queue_size; i++){
        if(eth_stats.q_ipackets[i] != 0){
            VI_PRINTF(" [%d]", i);
            VI_PRINTF("%"PRId64" ", eth_stats.q_ipackets[i]);}
    }
    VI_PRINTF("\n");

    VI_PRINTF("%s", "      Tx:");
    for(i = 0; i<queue_size; i++){
        if(eth_stats.q_opackets[i] != 0){
            VI_PRINTF(" [%d]", i);
            VI_PRINTF("%"PRId64" ", eth_stats.q_opackets[i]);}
    }
    VI_PRINTF("\n");

    VI_PRINTF("%s", "      Rx Bytes:");
    for(i = 0; i<queue_size; i++){
        if(eth_stats.q_ibytes[i] != 0){
            VI_PRINTF(" [%d]", i);
            VI_PRINTF("%"PRId64" ", eth_stats.q_ibytes[i]);}
    }
    VI_PRINTF("\n");

    VI_PRINTF("%s", "      Tx Bytes:");
    for(i = 0; i<queue_size; i++){
        if(eth_stats.q_obytes[i] != 0){
            VI_PRINTF(" [%d]", i);
            VI_PRINTF("%"PRId64" ", eth_stats.q_obytes[i]);}
    }
    VI_PRINTF("\n");

    VI_PRINTF("%s", "      Errors:");
    for(i = 0; i<queue_size; i++){
        if(eth_stats.q_errors[i] != 0){
            VI_PRINTF(" [%d]", i);
            VI_PRINTF("%"PRId64" ", eth_stats.q_errors[i]);}
    }
    VI_PRINTF("\n");
    VI_PRINTF("%s\n\n", seperator);
    return 0;
}


int 
display_xstats(VR_INFO_ARGS, uint16_t port_id, char xstats_arg[]){
    
    VR_INFO_DEC();
    struct rte_eth_xstat_name *xstats_names;
    uint64_t *values;
    int xstats_count, ret, i, rx_packets[100], rx_bytes[100], tx_packets[100], tx_bytes[100], errors[100], others[100], rpi = 0, rbi = 0, tpi = 0, tbi = 0, ei = 0, oth = 0;
    char seperator[100];
    memset(rx_packets, -1, 90*sizeof(rx_packets[0]));
    memset(tx_packets, -1, 90*sizeof(tx_packets[0]));
    memset(rx_bytes, -1, 90*sizeof(rx_bytes[0]));
    memset(tx_bytes, -1, 90*sizeof(tx_bytes[0]));
    memset(errors, -1, 90*sizeof(errors[0]));
    memset(others, -1, 90*sizeof(others[0]));
    memset(seperator , '-', 70);
    seperator[70]='\0';

    xstats_count = rte_eth_xstats_get_names_by_id(port_id, NULL, 0, NULL);
    if(xstats_count < 0) {
        RTE_LOG(ERR, VROUTER, "Cannot get xstats count\n");
        return -1;
    }
    values = malloc(sizeof(*values) * xstats_count);
    if(values == NULL) {
        RTE_LOG(ERR, VROUTER, "Cannot allocate memory for xstats\n");
        return -1;
    }

    xstats_names = malloc(sizeof(struct rte_eth_xstat_name) * xstats_count);
    if(xstats_names == NULL) {
        RTE_LOG(ERR, VROUTER, "Cannot allocate memory for xstat names\n");
        free(values);
        return -1;
    }
    if(xstats_count != rte_eth_xstats_get_names_by_id(port_id, xstats_names, xstats_count, NULL)) {
        RTE_LOG(ERR, VROUTER, "Cannot get xstat names\n");
        goto err;
        return -1;
    }

    ret = rte_eth_xstats_get_by_id(port_id, NULL, values, xstats_count);
    if(ret < 0 || ret > xstats_count) {
        RTE_LOG(ERR, VROUTER, "Cannot get xstats\n");
        goto err;
        return -1;
    }

    if(strcmp(xstats_arg, "all") == 0){
    for(i = 0; i < xstats_count; i++){
         if (strstr(xstats_names[i].name, "rx") && strstr(xstats_names[i].name, "packets"))
	     rx_packets[rpi++] = i;
         else if(strstr(xstats_names[i].name, "tx") && strstr(xstats_names[i].name, "packets"))
	     tx_packets[tpi++] = i;
         else if(strstr(xstats_names[i].name, "rx") && strstr(xstats_names[i].name, "bytes"))
             rx_bytes[rbi++] = i;
         else if(strstr(xstats_names[i].name, "tx") && strstr(xstats_names[i].name, "bytes"))
             tx_bytes[tbi++] = i;
         else if(strstr(xstats_names[i].name, "errors"))
             errors[ei++] = i;
         else{
	     	others[oth++] = i;
	 }
    } }
    else{
    for(i = 0; i < xstats_count; i++){
         if (strstr(xstats_names[i].name, "rx") && strstr(xstats_names[i].name, "packets") && values[i]!=0)
             rx_packets[rpi++] = i;
         else if(strstr(xstats_names[i].name, "tx") && strstr(xstats_names[i].name, "packets") && values[i]!=0)
             tx_packets[tpi++] = i;
         else if(strstr(xstats_names[i].name, "rx") && strstr(xstats_names[i].name, "bytes") && values[i]!=0)
             rx_bytes[rbi++] = i;
         else if(strstr(xstats_names[i].name, "tx") && strstr(xstats_names[i].name, "bytes") && values[i]!=0)
             tx_bytes[tbi++] = i;
         else if(strstr(xstats_names[i].name, "errors") && values[i]!=0)
             errors[ei++] = i;
         else{
             if(values[i]!=0)
                   others[oth++] = i; }
         }
     }
     VI_PRINTF("Rx Packets: \n");
     for(i=0; i<90; i++){
     	if(rx_packets[i]!=-1)
	    VI_PRINTF("\t%s: %"PRIu64"\n", xstats_names[rx_packets[i]].name, values[rx_packets[i]]);
     }
     VI_PRINTF("Tx Packets: \n");
     for(i=0; i<90; i++){
        if(tx_packets[i]!=-1)
            VI_PRINTF("\t%s: %"PRIu64"\n", xstats_names[tx_packets[i]].name, values[tx_packets[i]]);
     }
     VI_PRINTF("Rx Bytes: \n");
     for(i=0; i<90; i++){
        if(rx_bytes[i]!=-1)
            VI_PRINTF("\t%s: %"PRIu64"\n", xstats_names[rx_bytes[i]].name, values[rx_bytes[i]]);
     }
     VI_PRINTF("Tx Bytes: \n");
     for(i=0; i<90; i++){
        if(tx_bytes[i]!=-1)
            VI_PRINTF("\t%s: %"PRIu64"\n", xstats_names[tx_bytes[i]].name, values[tx_bytes[i]]);
     }
     VI_PRINTF("Errors: \n");
     for(i=0; i<90; i++){
        if(errors[i]!=-1)
            VI_PRINTF("\t%s: %"PRIu64"\n", xstats_names[errors[i]].name, values[errors[i]]);
     }
     VI_PRINTF("Others: \n");
     for(i=0; i<90; i++){
        if(others[i]!=-1)
            VI_PRINTF("\t%s: %"PRIu64"\n", xstats_names[others[i]].name, values[others[i]]);
     }

    if(strcmp(xstats_arg, "") == 0 || strcmp(xstats_arg, "all") == 0)
    	VI_PRINTF("%s\n", seperator);
    
    VI_PRINTF("\n\n");   

err:
    free(values);
    free(xstats_names);

    return 0;
}

int
dpdk_info_get_stats(VR_INFO_ARGS){

    uint16_t port_id, slave_id;
    int i, ret;
    struct rte_eth_stats eth_stats;
    struct vr_dpdk_ethdev *ethdev;
    char name[VR_INTERFACE_NAME_LEN];
    VR_INFO_BUF_INIT();

    port_id = dpdk_find_port_id_by_drv_name();
    if(port_id == VR_DPDK_INVALID_PORT_ID) {
        RTE_LOG(ERR, VROUTER, "Port Id is invalid\n");
        return -1;
    }

    /* Get the ethdev for master port. */
    ethdev = &vr_dpdk.ethdevs[port_id];
    if(ethdev->ethdev_ptr == NULL)
        RTE_LOG(ERR, VROUTER, "Ethdev not available\n");

    if(rte_eth_stats_get(port_id, &eth_stats) != 0)
        return -1;
    if(strcmp(msg_req->inbuf, "eth") == 0){
        VI_PRINTF("Master Info: \n");
        display_eth_stats(msg_req, eth_stats);
        /* Displaying slave stats */
        for(i = 0; i < ethdev->ethdev_nb_slaves; i++) {
            slave_id = ethdev->ethdev_slaves[i];
            ret = rte_eth_dev_get_name_by_port(slave_id, name);
            if(ret != 0){
                RTE_LOG(ERR, VROUTER, "Error getting bond interface name\n");
                return -1;
            }
            VI_PRINTF("Slave Info(%s): \n", name);
            if(rte_eth_stats_get(slave_id, &eth_stats) != 0)
	        return -1;
            display_eth_stats(msg_req, eth_stats);
        }
     }
     else{
         RTE_LOG(ERR, VROUTER, "Invalid argument.\n");
	 return -1;            	
     }
     
     return 0;
}

int
dpdk_info_get_xstats(VR_INFO_ARGS){
   
    uint16_t port_id, slave_id;
    int i, ret, reqd_interface;
    struct rte_eth_stats eth_stats;
    char name[VR_INTERFACE_NAME_LEN];
    struct vrouter *router = vrouter_get(0);
    struct vr_dpdk_ethdev *ethdev = NULL;

    VR_INFO_BUF_INIT();
    port_id = dpdk_find_port_id_by_drv_name();
    if (port_id != VR_DPDK_INVALID_PORT_ID) {
 
    if (strcmp(msg_req->inbuf, "") == 0 || strcmp(msg_req->inbuf, "all") == 0) {
        reqd_interface = 0;
    }
    else if(strcmp(msg_req->inbuf, "0") == 0){
        reqd_interface = 1;
    }
    else if(strcmp(msg_req->inbuf, "1") == 0){
        reqd_interface = 2;
    }
    else if(strcmp(msg_req->inbuf, "2") == 0){
        reqd_interface = 3;
    }
    else if(strcmp(msg_req->inbuf, "3") == 0){
        reqd_interface = 4;
    }
    else if(strcmp(msg_req->inbuf, "4") == 0){
        reqd_interface = 5;
    }
    else if(strcmp(msg_req->inbuf, "5") == 0){
        reqd_interface = 6;
    }
    else if(strcmp(msg_req->inbuf, "6") == 0){
        reqd_interface = 7;
    }
    else{
        RTE_LOG(ERR, VROUTER, "Invalid argument.\n");
        return -1;
    }

    /* Get the ethdev for master port. */
    ethdev = &vr_dpdk.ethdevs[port_id];
    if (ethdev->ethdev_ptr == NULL){
        RTE_LOG(ERR, VROUTER, "Ethdev not available\n");
        return -1;
    }

    if (rte_eth_stats_get(port_id, &eth_stats) != 0)
               return -1;

    switch(reqd_interface){
        case 0:
                VI_PRINTF("Master Info: \n");
                display_xstats(msg_req, port_id, msg_req->inbuf);
                /* Displaying slave stats */
                for(i = 0; i < ethdev->ethdev_nb_slaves; i++) {
                    slave_id = ethdev->ethdev_slaves[i];
                    ret = rte_eth_dev_get_name_by_port(slave_id, name);
                    if (ret != 0){
                        RTE_LOG(ERR, VROUTER, "Error getting bond interface name\n");
                        return -1;
                    }
                    VI_PRINTF("Slave Info(%d):%s \n", i, name);
                    display_xstats(msg_req, slave_id, msg_req->inbuf);
                 }
                 break;        
	case 1:
                VI_PRINTF("Master Info: \n");
                display_xstats(msg_req, port_id, msg_req->inbuf);
                break;
        case 2:
                if (ethdev->ethdev_nb_slaves > 0){
                slave_id = ethdev->ethdev_slaves[0];
                ret = rte_eth_dev_get_name_by_port(slave_id, name);
                if (ret != 0){
                     RTE_LOG(ERR, VROUTER, "Error getting bond interface name\n");
                     return -1;
                }
                VI_PRINTF("Slave Info(0):%s \n", name);
                display_xstats(msg_req, slave_id, msg_req->inbuf);}
                else{
                    RTE_LOG(ERR, VROUTER, "There are only %d slaves available.\n", ethdev->ethdev_nb_slaves);
                    return -1;    
		}
                break;
        case 3:
		if (ethdev->ethdev_nb_slaves > 1){
                slave_id = ethdev->ethdev_slaves[1];
                ret = rte_eth_dev_get_name_by_port(slave_id, name);
                if (ret != 0){
                     RTE_LOG(ERR, VROUTER, "Error getting bond interface name\n");
                     return -1;
                }
                VI_PRINTF("Slave Info(1):%s \n", name);
                display_xstats(msg_req, slave_id, msg_req->inbuf);}
		else{
                    RTE_LOG(ERR, VROUTER, "There are only %d slaves available.\n", ethdev->ethdev_nb_slaves);
                    return -1;
                }
		break;
        case 4:
                if (ethdev->ethdev_nb_slaves > 2){
		slave_id = ethdev->ethdev_slaves[2];
                ret = rte_eth_dev_get_name_by_port(slave_id, name);
                if (ret != 0){
                     RTE_LOG(ERR, VROUTER, "Error getting bond interface name\n");
                     return -1;
                }
                VI_PRINTF("Slave Info(2):%s \n", name);
                display_xstats(msg_req, slave_id,msg_req->inbuf);}
		else{
                    RTE_LOG(ERR, VROUTER, "There are only %d slaves available.\n", ethdev->ethdev_nb_slaves);
                    return -1;
                }
                break;
        case 5:
		if (ethdev->ethdev_nb_slaves > 3){
                slave_id = ethdev->ethdev_slaves[3];
                ret = rte_eth_dev_get_name_by_port(slave_id, name);
                if (ret != 0){
                     RTE_LOG(ERR, VROUTER, "Error getting bond interface name\n");
                     return -1;
                }
                VI_PRINTF("Slave Info(3):%s \n", name);
                display_xstats(msg_req, slave_id,msg_req->inbuf);}
		else{
                    RTE_LOG(ERR, VROUTER, "There are only %d slaves available.\n", ethdev->ethdev_nb_slaves);
                    return -1;
                }
                break;
        case 6:
		if (ethdev->ethdev_nb_slaves > 4){
                slave_id = ethdev->ethdev_slaves[4];
                ret = rte_eth_dev_get_name_by_port(slave_id, name);
                if (ret != 0){
                     RTE_LOG(ERR, VROUTER, "Error getting bond interface name\n");
                     return -1;
                }
                VI_PRINTF("Slave Info(4):%s \n", name);
                display_xstats(msg_req, slave_id,msg_req->inbuf);}
		else{
                    RTE_LOG(ERR, VROUTER, "There are only %d slaves available.\n", ethdev->ethdev_nb_slaves);
                    return -1;
                }
                break;
        case 7:
		if (ethdev->ethdev_nb_slaves > 5){
                slave_id = ethdev->ethdev_slaves[5];
                ret = rte_eth_dev_get_name_by_port(slave_id, name);
                if (ret != 0){
                     RTE_LOG(ERR, VROUTER, "Error getting bond interface name\n");
                     return -1;
                }
                VI_PRINTF("Slave Info(5):%s \n", name);
                display_xstats(msg_req, slave_id, msg_req->inbuf);}
                else{
	            RTE_LOG(ERR, VROUTER, "There are only %d slaves available.\n", ethdev->ethdev_nb_slaves);
	            return -1;
                }
                break;
    }
    }
    else{
        // if bond is not configured
        if (strcmp(msg_req->inbuf, "") == 0 || strcmp(msg_req->inbuf, "all") == 0) {
            if (router->vr_eth_if)                              
                ethdev = (struct vr_dpdk_ethdev *)router->vr_eth_if->vif_os;         
                if (ethdev)          
                    port_id = ethdev->ethdev_port_id;	

                display_xstats(msg_req, port_id, msg_req->inbuf);
        }
        else{
            RTE_LOG(ERR, VROUTER, "Invalid argument.\n");
            return -1; 
        }
    }

    return 0;
}

int
dpdk_info_get_lcore(VR_INFO_ARGS){

    struct vrouter *router = vrouter_get(0);
    struct vr_interface *vif;
    struct vr_dpdk_queue *rx_queue;     
    struct vr_dpdk_lcore *lcore;
    unsigned char *name;
    int i, intf=0;
    
    VR_INFO_BUF_INIT();

    VI_PRINTF("No. of forwarding lcores: %d \n", vr_dpdk.nb_fwd_lcores);
    for (i = 0; i < router->vr_max_interfaces; i++) {                               
         vif = router->vr_interfaces[i];                                         
         if(vif)
             intf++;		
    }
    VI_PRINTF("No. of interfaces: %d \n", intf);
    
    for (i=0; i<vr_dpdk.nb_fwd_lcores; i++){
        VI_PRINTF("Lcore %d: \n",i);
        lcore = vr_dpdk.lcores[VR_DPDK_FWD_LCORE_ID + i];
        SLIST_FOREACH(rx_queue, &lcore->lcore_rx_head, q_next) {
             name = rx_queue->q_vif->vif_name;
             VI_PRINTF("\tInterface: %-20s", name);
             VI_PRINTF("Queue ID: %"PRId16" \n", rx_queue->vring_queue_id);
        }
       VI_PRINTF("\n");
    }


    return 0;
}                                                                       
