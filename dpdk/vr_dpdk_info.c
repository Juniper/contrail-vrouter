/*
 * vr_dpdk_info.c - DPDK specific callback functions for vr_info .
 *
 * Copyright (c) 2020 Juniper Networks, Inc. All rights reserved.
 */
#include <vr_os.h>
#include <vr_types.h>
#include <vr_packet.h>
#include "vr_message.h"
#include "vr_btable.h"
#include "vr_dpdk.h"
#include "vrouter.h"

#include <rte_eth_bond.h>
#include <rte_ethdev.h>
#include <rte_port_ethdev.h>
#include <rte_eth_bond_8023ad.h>
#include <rte_malloc.h>

/* NOTE: Callback API's need to be registered in vrouter/include/vr_info.h
 * under VR_INFO_REG(X) macro.
 * All callback API's should start with "dpdk_<fn.name>"
 * Register Format: X(MSG, <fn.name>) \
 *              eg: X(INFO_BOND, info_get_bond)
 */

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
            VI_PRINTF("Aggregator selection policy (ad_select): Count\n\n");
            break;
        case AGG_BANDWIDTH:
            VI_PRINTF("Aggregator selection policy (ad_select): Bandwidth\n\n");
            break;
        case AGG_STABLE:
            VI_PRINTF("Aggregator selection policy (ad_select): Stable\n\n");
            break;
        default:
            VI_PRINTF("Aggregator selection policy (ad_select): Null\n\n");
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
dpdk_bond_info_show_slave(VR_INFO_ARGS, struct vr_dpdk_ethdev *ethdev)
{
    VR_INFO_DEC();
    int i, ret, port_id;
    char *lacp_rate[] = {"slow", "fast"};
    char *duplex[] = {"half", "full"};
    struct ether_addr mac_addr;
    struct rte_eth_link link;
    char name[VR_INTERFACE_NAME_LEN];

    /* Display bond slave inforamtion */
    for(i = 0; i < ethdev->ethdev_nb_slaves; i++) {
        port_id = ethdev->ethdev_slaves[i];

        ret = rte_eth_dev_get_name_by_port(port_id, name);
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

        VI_PRINTF("Duplex: %s\n", duplex[link.link_duplex]);

        VI_PRINTF("802.3ad info\n");

        VI_PRINTF("LACP Rate: %s\n", lacp_rate[rte_eth_bond_lacp_rate_get(port_id)]);

        rte_eth_macaddr_get(port_id, &mac_addr);
        VI_PRINTF("Bond MAC addr:" MAC_FORMAT "\n\n", MAC_VALUE(mac_addr.addr_bytes));
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
    VI_PRINTF("Down Delay (ms): %d\n", \
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

    ret = dpdk_bond_info_show_slave(VR_INFO_PASS_ARGS, ethdev);
    if(ret < 0) {
        return VR_INFO_FAILED;
    }

    return 0;
 }
