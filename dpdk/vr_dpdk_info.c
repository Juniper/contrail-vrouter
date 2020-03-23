/*
 * vr_pkt_droplog.c -- Log drop packet information.
 *
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */
#include <vr_os.h>
#include <vr_types.h>
#include <vr_packet.h>
#include "vr_message.h"
#include "vr_btable.h"
#include "vr_dpdk.h"
#include "vr_dpdk_info.h"

#include <rte_eth_bond.h>
#include <rte_ethdev.h>
#include <rte_port_ethdev.h>
#include <rte_eth_bond_8023ad.h>
#include <rte_malloc.h>

#define VR_DPDK_BOND_INFO_BUF_SIZE 4096

/* dpdk_info_get_bond provide the bond master & slave information */
int
dpdk_info_get_bond(DPDK_INFO_ARGS)
{
    uint16_t port_id;
    struct vr_dpdk_ethdev *ethdev;
    int ret, i;
    char *status[] = {"DOWN", "UP"};
    char *lacp_rate[] = {"slow", "fast"};
    char *duplex[] = {"half", "full"};
    struct rte_eth_link link;
    struct ether_addr mac_addr;
    char name[VR_INTERFACE_NAME_LEN];


    DPDK_INFO_BUF_INIT(VR_DPDK_BOND_INFO_BUF_SIZE);

    /* Get the port_id for master, Incase of non-bond devices, it return here. */
    port_id = dpdk_find_port_id_by_drv_name();
    if (port_id == VR_DPDK_INVALID_PORT_ID) {
        RTE_LOG(ERR, VROUTER, "Port Id is invalid\n");
        return -1;
    }

    /* Get the devdev for master port. */
    ethdev = &vr_dpdk.ethdevs[port_id];
    if (ethdev->ethdev_ptr == NULL)
        RTE_LOG(ERR, VROUTER, "Ethdev not available\n");


    DI_PRINTF("DPDK Version: %s\n", \
            rte_version());
    DI_PRINTF("No. of bond slaves: %d\n", ethdev->ethdev_nb_slaves);

    /* Get bond mode */
    ret = rte_eth_bond_mode_get(port_id);
    switch(ret) {
        case BONDING_MODE_ROUND_ROBIN:
            DI_PRINTF("Bonding Mode: Round Robin\n");
            break;
        case BONDING_MODE_ACTIVE_BACKUP:
            DI_PRINTF("Bonding Mode: Active Backup\n");
            break;
        case BONDING_MODE_BALANCE:
            DI_PRINTF("Bonding Mode: Balance\n");
            break;
        case BONDING_MODE_BROADCAST:
            DI_PRINTF("Bonding Mode: Broadcast\n");
            break;
        case BONDING_MODE_8023AD:
            DI_PRINTF("Bonding Mode: 802.3AD Dynamic Link Aggregation\n");
            break;
        case BONDING_MODE_TLB:
            DI_PRINTF("Bonding Mode: Adaptive TLB(Trnasmit Load Balancing)\n");
            break;
        case BONDING_MODE_ALB:
            DI_PRINTF("Bonding Mode: Adaptive Load Balancing(Tx/Rx)\n");
            break;
        default:
            DI_PRINTF("Bonding Mode: None\n");
    }

    /* Transmit Hash Policy */
    ret = rte_eth_bond_xmit_policy_get(port_id);
    switch(ret) {
        case BALANCE_XMIT_POLICY_LAYER2:
            DI_PRINTF("Transmit Hash Policy: Layer 2 (Ethernet MAC)\n");
            break;
        case BALANCE_XMIT_POLICY_LAYER23:
            DI_PRINTF("Transmit Hash Policy: Layer 2+3 (Ethernet MAC + "
                    "IP Addresses) transmit load balancing\n");
            break;
        case BALANCE_XMIT_POLICY_LAYER34:
            DI_PRINTF("Transmit Hash Policy: Layer 3+4 (IP Addresses + "
                    "UDP Ports) transmit load balancing\n");
            break;
        default:
            DI_PRINTF("Transmit Hash Policy: None\n");
    }

    rte_eth_link_get_nowait(port_id, &link);
    DI_PRINTF("MII status: %s\n", status[link.link_status]);
    DI_PRINTF("MII Link Speed: %d\n", link.link_speed);
    DI_PRINTF("MII Polling Interval (ms): %d\n", \
            rte_eth_bond_link_monitoring_get(port_id));
    DI_PRINTF("Up Delay (ms): %d\n", \
            rte_eth_bond_link_up_prop_delay_get(port_id));
    DI_PRINTF("Down Delay (ms): %d\n", \
            rte_eth_bond_link_down_prop_delay_get(port_id));

    DI_PRINTF("802.3ad info :\n");

    DI_PRINTF("LACP Rate: %s\n", \
            lacp_rate[rte_eth_bond_lacp_rate_get(port_id)]);

    ret = rte_eth_bond_8023ad_agg_selection_get(port_id);
    switch(ret) {
        case AGG_COUNT:
            DI_PRINTF("Aggregator selection policy (ad_select): Count\n\n");
            break;
        case AGG_BANDWIDTH:
            DI_PRINTF("Aggregator selection policy (ad_select): Bandwidth\n\n");
            break;
        case AGG_STABLE:
            DI_PRINTF("Aggregator selection policy (ad_select): Stable\n\n");
            break;
        default:
            DI_PRINTF("Aggregator selection policy (ad_select): Null\n\n");
    }

    /* Displaying bond slave inforamtion */
    for(i = 0; i < ethdev->ethdev_nb_slaves; i++) {
        port_id = ethdev->ethdev_slaves[i];

        ret = rte_eth_dev_get_name_by_port(port_id, name);
        if (ret != 0)
            RTE_LOG(ERR, VROUTER, "Error getting bond interface name\n");

        DI_PRINTF("Slave Interface(%d): %s \n", i, name);
        DI_PRINTF("Slave Interface Driver: %s\n", \
                rte_eth_devices[port_id].device->driver->name);

        rte_eth_link_get_nowait(port_id, &link);
        DI_PRINTF("MII status: %s\n", status[link.link_status]);
        DI_PRINTF("MII Link Speed: %d\n", link.link_speed);
        DI_PRINTF("MII Polling Interval (ms): %d\n", \
                rte_eth_bond_link_monitoring_get(port_id));

        DI_PRINTF("Duplex: %s\n", duplex[link.link_duplex]);

        DI_PRINTF("802.3ad info\n");

        DI_PRINTF("LACP Rate: %s\n", \
                lacp_rate[rte_eth_bond_lacp_rate_get(port_id)]);

        rte_eth_macaddr_get(port_id, &mac_addr);
        DI_PRINTF("Bond MAC addr:" MAC_FORMAT "\n\n", \
                MAC_VALUE(mac_addr.addr_bytes));
    }
 
    return 0;
 }
 

