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
 * vr_dpdk_interface.c -- vRouter interface callbacks
 *
 */

#include "vr_dpdk.h"
#include "vr_dpdk_netlink.h"
#include "vr_dpdk_usocket.h"
#include "vr_dpdk_virtio.h"

#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_ip_frag.h>
#include <rte_ip.h>
#include <rte_port_ethdev.h>

#if (RTE_VERSION == RTE_VERSION_NUM(2, 1, 0, 0))
#include <rte_eth_af_packet.h>
#endif

#include <linux/if_tun.h>
#include <net/if_arp.h>
#include <sys/ioctl.h>

static void
dpdk_vif_queue_free(struct vr_interface *vif)
{
    unsigned int lcore, i;
    struct vr_dpdk_lcore *lcore_p;

    i = lcore = VR_DPDK_FWD_LCORE_ID;
    do {
        lcore_p = vr_dpdk.lcores[i];
        if (lcore_p->lcore_tx_queues[vif->vif_idx]) {
            vr_free(lcore_p->lcore_tx_queues[vif->vif_idx],
                    VR_INTERFACE_QUEUE_OBJECT);
            lcore_p->lcore_tx_queues[vif->vif_idx] = NULL;
        }

        if (lcore_p->lcore_tx_queue_params[vif->vif_idx]) {
            vr_free(lcore_p->lcore_tx_queue_params[vif->vif_idx],
                    VR_INTERFACE_QUEUE_OBJECT);
            lcore_p->lcore_tx_queue_params[vif->vif_idx] = NULL;
        }

        if (lcore_p->lcore_hw_queue_to_dpdk_index[vif->vif_idx]) {
            vr_free(lcore_p->lcore_hw_queue_to_dpdk_index[vif->vif_idx],
                    VR_INTERFACE_QUEUE_OBJECT);
            lcore_p->lcore_hw_queue_to_dpdk_index[vif->vif_idx] = NULL;
        }

        lcore_p->num_tx_queues_per_lcore[vif->vif_idx] = 0;

        i = rte_get_next_lcore(i, 1, 1);
    } while (i != lcore);

    if (vif->vif_queue_host_data) {
        vr_free(vif->vif_queue_host_data, VR_INTERFACE_QUEUE_OBJECT);
        vif->vif_queue_host_data = NULL;
    }

    return;
}

static int
dpdk_vif_queue_setup(struct vr_interface *vif)
{
    int16_t vif_max_queue = -1;
    uint16_t num_tx_queues_per_lcore;
    unsigned int lcore, i;

    struct vr_dpdk_lcore *lcore_p;
    struct vif_queue_dpdk_data *q_data;

    if (vif->vif_num_hw_queues) {
        num_tx_queues_per_lcore = vif->vif_num_hw_queues;
        for (i = 0; i < vif->vif_num_hw_queues; i++) {
            if (vif->vif_hw_queues[i] > vif_max_queue) {
                vif_max_queue = vif->vif_hw_queues[i];
            }
        }

        q_data = vif->vif_queue_host_data;
        if (!q_data) {
            vif->vif_queue_host_data = vr_malloc(sizeof(*q_data),
                    VR_INTERFACE_QUEUE_OBJECT);
            if (!vif->vif_queue_host_data) {
                goto unwind;
            }

            q_data = (struct vif_queue_dpdk_data *)vif->vif_queue_host_data;
            memset(q_data->vqdd_queue_to_lcore, -1,
                    VR_DPDK_MAX_NB_TX_QUEUES * sizeof(int16_t));
        }
    } else {
        num_tx_queues_per_lcore = 1;
    }

    lcore = VR_DPDK_FWD_LCORE_ID;
    do {
        if (lcore >= VR_DPDK_PACKET_LCORE_ID) {
            lcore_p = vr_dpdk.lcores[lcore];
            lcore_p->lcore_hw_queue[vif->vif_idx] = -1;
            lcore_p->lcore_tx_queues[vif->vif_idx] =
                vr_zalloc(num_tx_queues_per_lcore * sizeof(struct vr_dpdk_queue),
                        VR_INTERFACE_QUEUE_OBJECT);
            if (!lcore_p->lcore_tx_queues) {
                goto unwind;
            }

            lcore_p->lcore_tx_queue_params[vif->vif_idx] =
                vr_zalloc(num_tx_queues_per_lcore *
                        sizeof(struct vr_dpdk_queue_params),
                        VR_INTERFACE_QUEUE_OBJECT);
            if (!lcore_p->lcore_tx_queue_params) {
                goto unwind;
            }
            lcore_p->num_tx_queues_per_lcore[vif->vif_idx] =
                num_tx_queues_per_lcore;

            if (vif_max_queue > 0) {
                lcore_p->lcore_hw_queue_to_dpdk_index[vif->vif_idx] =
                    (int16_t *)vr_zalloc(sizeof(int16_t) * (vif_max_queue + 1),
                            VR_INTERFACE_QUEUE_OBJECT);
                if (!lcore_p->lcore_hw_queue_to_dpdk_index[vif->vif_idx]) {
                    goto unwind;
                }
            }
        }

        lcore = rte_get_next_lcore(lcore, 1, 1);
    } while (lcore != VR_DPDK_FWD_LCORE_ID);

    return 0;

unwind:
    dpdk_vif_queue_free(vif);
    return -ENOMEM;
}

/*
 * dpdk_virtual_if_add - add a virtual (virtio) interface to vrouter.
 * Returns 0 on success, < 0 otherwise.
 */
static int
dpdk_virtual_if_add(struct vr_interface *vif)
{
    int ret;
    uint16_t nrxqs, ntxqs;

    RTE_LOG(INFO, VROUTER, "Adding vif %u (gen. %u) virtual device %s\n",
                vif->vif_idx, vif->vif_gen, vif->vif_name);

    nrxqs = vr_dpdk_virtio_nrxqs(vif);
    /* virtio TX is thread safe, so we assign TX queue to each lcore */
    ntxqs = (uint16_t)-1;

    ret = dpdk_vif_queue_setup(vif);
    if (ret)
        return ret;

    ret = vr_dpdk_lcore_if_schedule(vif, vr_dpdk_lcore_least_used_get(),
                nrxqs, &vr_dpdk_virtio_rx_queue_init,
                ntxqs, &vr_dpdk_virtio_tx_queue_init);
    if (ret) {
        return ret;
    }

    /*
     * When something goes wrong, vr_netlink_uvhost_vif_add() returns
     * non-zero value. Then we return this value here. It is handled by
     * dp-core and dpdk_virtual_if_del() is called, so there is no need
     * to do it manually here.
     *
     * Check dp-core/vf_interface.c:eth_drv_add() for reference.
     */
    return vr_netlink_uvhost_vif_add(vif->vif_name, vif->vif_idx, vif->vif_gen,
                                     nrxqs, ntxqs, vif->vif_vhostuser_mode);
}

/*
 * dpdk_virtual_vlan_if_add - add a virtual VLAN interface to vRouter.
 * Returns 0 on success, < 0 otherwise.
 */
static int
dpdk_virtual_vlan_if_add(struct vr_interface *vif)
{

    RTE_LOG(INFO, VROUTER, "Adding vif %u (gen. %u) virtual VLAN(o/i) %u/%u device %s\n",
                vif->vif_idx, vif->vif_gen, vif->vif_ovlan_id, vif->vif_vlan_id,
                vif->vif_name);
    RTE_LOG(INFO, VROUTER, "    parent vif %u device %s\n",
                vif->vif_parent->vif_idx, vif->vif_parent->vif_name);

    return 0;
}

/*
 * dpdk_virtual_if_del - deletes a virtual (virtio) interface from vrouter.
 * Returns 0 on success, -1 otherwise.
 */
static int
dpdk_virtual_if_del(struct vr_interface *vif)
{
    int ret;

    RTE_LOG(INFO, VROUTER, "Deleting vif %u virtual device\n",
                vif->vif_idx);

    vr_dpdk_lcore_if_unschedule(vif);
    ret = vr_netlink_uvhost_vif_del(vif->vif_idx);
    if (ret) {
        RTE_LOG(ERR, VROUTER, "Error deleting vif %u virtual device %s\n",
                vif->vif_idx, vif->vif_name);
    }

    dpdk_vif_queue_free(vif);

    return ret;
}

/*
 * dpdk_virtual_vlan_if_del - deletes a virtual VLAN interface from vRouter.
 * Returns 0 on success, < 0 otherwise.
 */
static int
dpdk_virtual_vlan_if_del(struct vr_interface *vif)
{
    RTE_LOG(INFO, VROUTER, "Deleting vif %u virtual VLAN(o/i) %u/%u device\n",
                vif->vif_idx, vif->vif_ovlan_id, vif->vif_vlan_id);

    return 0;
}

static inline void
dpdk_dbdf_to_pci(unsigned int dbdf,
        struct rte_pci_addr *address)
{
    address->domain = (dbdf >> 16);
    address->bus = (dbdf >> 8) & 0xff;
    address->devid = (dbdf >> 3) & 0x1f;
    address->function = (dbdf & 0x7);

    return;
}

static inline unsigned
dpdk_pci_to_dbdf(struct rte_pci_addr *address)
{
    return address->domain << 16
        | address->bus << 8
        | address->devid
        | address->function;
}

/* mirrors the function used in bonding */
static inline uint8_t
dpdk_find_port_id_by_pci_addr(const struct rte_pci_addr *addr)
{
    uint8_t i;
    struct rte_pci_addr *eth_pci_addr;

    for (i = 0; i < rte_eth_dev_count(); i++) {
#if (RTE_VERSION >= RTE_VERSION_NUM(17, 2, 0, 0))
        if (rte_eth_devices[i].data == NULL)
#else
        if (rte_eth_devices[i].pci_dev == NULL)
#endif
            continue;
#if (RTE_VERSION >= RTE_VERSION_NUM(17, 2, 0, 0))
        if (rte_eth_devices[i].device != NULL) {
            eth_pci_addr = &(RTE_DEV_TO_PCI(rte_eth_devices[i].device)->addr);
            RTE_LOG_DP(DEBUG, VROUTER, "count %d eth_pci_addr %x %x %x %x \n",
                i, eth_pci_addr->bus, eth_pci_addr->devid,
                eth_pci_addr->domain, eth_pci_addr->function);
            RTE_LOG_DP(DEBUG, VROUTER, "count %d addr %x %x %x %x \n",
                i, addr->bus, addr->devid,
                addr->domain, addr->function);
            if (addr->bus == eth_pci_addr->bus &&
                addr->devid == eth_pci_addr->devid &&
                addr->domain == eth_pci_addr->domain &&
                addr->function == eth_pci_addr->function) {
                return i;
            }
        } else {
            if (strcmp(rte_eth_devices[i].data->drv_name, "net_bonding") == 0)
                return i;
        }
#else
        eth_pci_addr = &(rte_eth_devices[i].pci_dev->addr);
        if (addr->bus == eth_pci_addr->bus &&
            addr->devid == eth_pci_addr->devid &&
            addr->domain == eth_pci_addr->domain &&
            addr->function == eth_pci_addr->function) {
            return i;
        }
#endif
    }

    return VR_DPDK_INVALID_PORT_ID;
}

#if (RTE_VERSION >= RTE_VERSION_NUM(17, 2, 0, 0))
uint8_t
dpdk_find_port_id_by_drv_name(void)
{
    uint8_t i;

    for (i = 0; i < rte_eth_dev_count(); i++) {
        if (rte_eth_devices[i].data == NULL)
            continue;

        if (strcmp(rte_eth_devices[i].data->drv_name, "net_bonding") == 0)
            return i;
    }

    return VR_DPDK_INVALID_PORT_ID;
}
#endif

static inline void
dpdk_find_pci_addr_by_port(struct rte_pci_addr *addr, uint8_t port_id)
{
#if (RTE_VERSION >= RTE_VERSION_NUM(17, 2, 0, 0))
    rte_memcpy(addr, &(RTE_DEV_TO_PCI(rte_eth_devices[port_id].device)->addr), sizeof(struct rte_pci_addr));
#else
    rte_memcpy(addr, &rte_eth_devices[port_id].pci_dev->addr, sizeof(struct rte_pci_addr));
#endif
}

static inline void
dpdk_set_addr_vlan_filter_strip(uint32_t port_id, struct vr_interface *vif)
{
    uint32_t i, ret;
    uint8_t *port_id_ptr;
    int port_num = 0;
    struct vr_dpdk_ethdev *ethdev = &vr_dpdk.ethdevs[port_id];

    port_id_ptr = (ethdev->ethdev_nb_slaves == -1)?
                   &ethdev->ethdev_port_id:ethdev->ethdev_slaves;

    do {
        /*
         * TODO: vf_lcore_id check for SR-IOV VF should be a per-interface
         * check to handle the case where a bond has a VF and a PF in it.
         */

        /*
         * Set the MAC address of slave interfaces. Doing it from the bond driver in
         * DPDK doesn't seem to work on SR-IOV VFs.
         */
        if ((ethdev->ethdev_nb_slaves != -1) && vr_dpdk.vf_lcore_id) {
            ret = rte_eth_dev_default_mac_addr_set(*port_id_ptr,
                    (struct ether_addr *)vif->vif_mac);
            if (ret == 0) {
                RTE_LOG(INFO, VROUTER, "Bond slave port %d now uses vif MAC "
                        MAC_FORMAT "\n",
                        *port_id_ptr, MAC_VALUE(vif->vif_mac));
            } else {
                RTE_LOG(ERR, VROUTER, "Error setting vif MAC to bond slave port %d: "
                        "%s (%d)\n",
                        *port_id_ptr, rte_strerror(-ret), -ret);
            }
        }

        if ((vr_dpdk.vlan_tag != VLAN_ID_INVALID) && vr_dpdk.vf_lcore_id) {
            ret = rte_eth_dev_set_vlan_offload(*port_id_ptr, ETH_VLAN_FILTER_OFFLOAD);
            if (ret) {
                RTE_LOG(INFO, VROUTER, "Error %d enabling vlan offload on port %d\n",
                        ret, *port_id_ptr);
            } else {
                RTE_LOG(INFO, VROUTER, "Enabled vlan offload on port %d\n",
                        *port_id_ptr);
            }

            ret = rte_eth_dev_vlan_filter(*port_id_ptr, vr_dpdk.vlan_tag, 1);
            if (ret) {
                RTE_LOG(INFO, VROUTER, "Error %d enabling vlan %d on port %d\n",
                        ret, vr_dpdk.vlan_tag, *port_id_ptr);
            } else {
                RTE_LOG(INFO, VROUTER, "Enabled vlan %d on port %d\n",
                        vr_dpdk.vlan_tag, *port_id_ptr);
            }
        }

        for (i=0; i< rte_eth_devices[*port_id_ptr].data->nb_rx_queues; i++)
        {
            if (vif->vif_flags & VIF_FLAG_VLAN_OFFLOAD) {
                rte_eth_dev_set_vlan_strip_on_queue(*port_id_ptr, i, 1);
            }
        }
        port_num++;
        port_id_ptr++;
    } while (port_num < ethdev->ethdev_nb_slaves);
}

/*
 * vr_ethdev_inner_cksum_capable - check if the NIC is capable of calculating the
 * inner checksum in an overlay packet. ixgbe and i40e (and their VFs)support it,
 * so handle the cases where the physical interface is one of these or a bond with
 * these NICs.
 *
 * Returns 1 if capable and 9 if not.
 */
static int
vr_ethdev_inner_cksum_capable(struct vr_dpdk_ethdev *ethdev)
{
    struct rte_eth_dev_info dev_info;
    uint8_t *port_id_ptr;
    int port_num = 0;

    port_id_ptr = (ethdev->ethdev_nb_slaves == -1)?
                   &ethdev->ethdev_port_id:ethdev->ethdev_slaves;

    do {
        rte_eth_dev_info_get(*port_id_ptr, &dev_info);
        if (dev_info.driver_name) {
            if ((strncmp(dev_info.driver_name, "net_ixgbe",
                        strlen("net_ixgbe")) != 0) && 
                (strncmp(dev_info.driver_name, "net_i40e",
                        strlen("net_i40e")) != 0)) {
                    return 0; 
            } 
        } else {
            return 0;
        }

        port_num++;
        port_id_ptr++;
    } while (port_num < ethdev->ethdev_nb_slaves); 

    return 1;
}

void
dpdk_vif_attach_ethdev(struct vr_interface *vif,
        struct vr_dpdk_ethdev *ethdev)
{
    struct ether_addr mac_addr;
    struct rte_eth_dev_info dev_info;
    int ret;

    vif->vif_os = (void *)ethdev;

    rte_eth_dev_info_get(ethdev->ethdev_port_id, &dev_info);
    if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_IPV4_CKSUM
        && dev_info.tx_offload_capa & DEV_TX_OFFLOAD_UDP_CKSUM
        && dev_info.tx_offload_capa & DEV_TX_OFFLOAD_TCP_CKSUM
        && vr_ethdev_inner_cksum_capable(ethdev)) {
        vif->vif_flags |= VIF_FLAG_TX_CSUM_OFFLOAD;
    } else {
        vif->vif_flags &= ~VIF_FLAG_TX_CSUM_OFFLOAD;
    }

    if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_VLAN_INSERT
        && dev_info.rx_offload_capa & DEV_RX_OFFLOAD_VLAN_STRIP) {
        /*
         * Enabling vlan offload causes performance degradation, possibly
         * dut to a DPDK library issue, so don't set VIF_FLAG_VLAN_OFFLOAD
         */
    } else {
        vif->vif_flags &= ~VIF_FLAG_VLAN_OFFLOAD;
    }

    /*
     * Do not want to overwrite what agent had sent.
     * Set only if the address is null.
     */
    memset(&mac_addr, 0, sizeof(mac_addr));
    if (memcmp(vif->vif_mac, mac_addr.addr_bytes, ETHER_ADDR_LEN) == 0) {
        rte_eth_macaddr_get(ethdev->ethdev_port_id, &mac_addr);
        memcpy(vif->vif_mac, mac_addr.addr_bytes, ETHER_ADDR_LEN);
    } else {
        /*
         * On some hardware (e100e, virtual functions, etc) the MAC is random,
         * so we check if vif and NIC MACs are match and set the NIC MAC.
         */
        rte_eth_macaddr_get(ethdev->ethdev_port_id, &mac_addr);
        if (memcmp(vif->vif_mac, mac_addr.addr_bytes, ETHER_ADDR_LEN) != 0) {
            /* No match, so set vif MAC to NIC. */
            ret = rte_eth_dev_default_mac_addr_set(ethdev->ethdev_port_id,
                    (struct ether_addr *)vif->vif_mac);
            if (ret == 0) {
                RTE_LOG(INFO, VROUTER, "    eth dev %s now use vif MAC "
                        MAC_FORMAT "\n",
                        vif->vif_name, MAC_VALUE(vif->vif_mac));
            } else {
                RTE_LOG(ERR, VROUTER, "    error setting vif MAC to eth dev %s: "
                        "%s (%d)\n",
                        vif->vif_name, rte_strerror(-ret), -ret);
            }
        }
    }
}

/*
 * dpdk_vlan_forwarding_if_add - add VLAN forwarding interface
 * Returns 0 on success, < 0 otherwise.
 */
int
dpdk_vlan_forwarding_if_add(void)
{
    int ret;

    RTE_LOG(INFO, VROUTER, "Adding VLAN forwarding interface %s\n",
        vr_dpdk.vlan_name);

    /* Allocate vlan vif. */
    vr_dpdk.vlan_vif = vr_zalloc(sizeof(struct vr_interface),
        VR_INTERFACE_OBJECT);
    if (!vr_dpdk.vlan_vif) {
        RTE_LOG(ERR, VROUTER, "Error allocating interface object\n");
        return -ENOMEM;
    }

    vr_dpdk.vlan_vif->vif_stats = vr_zalloc(vr_num_cpus *
            sizeof(struct vr_interface_stats), VR_INTERFACE_STATS_OBJECT);
    if (!vr_dpdk.vlan_vif->vif_stats) {
        RTE_LOG(ERR, VROUTER, "Error allocating interface stats object\n");
        return -ENOMEM;
    }

    strncpy((char *)vr_dpdk.vlan_vif->vif_name, vr_dpdk.vlan_name,
        sizeof(vr_dpdk.vlan_vif->vif_name));
    vr_dpdk.vlan_vif->vif_type = VIF_TYPE_VLAN;

    /* Probe KNI. */
    ret = vr_dpdk_knidev_init(0, vr_dpdk.vlan_vif);
    if (ret == -ENOTSUP) {
        /* Try TAP instead. */
        ret = vr_dpdk_tapdev_init(vr_dpdk.vlan_vif);
    }

    if (ret != 0) {
        RTE_LOG(ERR, VROUTER,
            "Error initializing device for VLAN forwarding interface: %s (%d)\n",
            rte_strerror(-ret), -ret);
        return ret;
    }

    /* Save device pointer needed to send packets to the interface. */
    vr_dpdk.vlan_dev = vr_dpdk.vlan_vif->vif_os;

    /*
     * Allocate a multi-producer single-consumer ring - a buffer for packets
     * waiting to be send to the forwarding interface.
     */
    vr_dpdk.vlan_ring = vr_dpdk_ring_allocate(VR_DPDK_FWD_LCORE_ID,
        vr_dpdk.vlan_name, VR_DPDK_TX_RING_SZ, RING_F_SC_DEQ);
    if (!vr_dpdk.vlan_ring) {
        RTE_LOG(ERR, VROUTER, "Error allocating ring for VLAN forwarding interface\n");
        vr_dpdk.vlan_dev = NULL;
        if (vr_dpdk.kni_state > 0)
            vr_dpdk_knidev_release(vr_dpdk.vlan_vif);
        else
            vr_dpdk_tapdev_release(vr_dpdk.vlan_vif);
        return -1;
    }

    return 0;
}

/*
 * Add af_packet virtual device to communicate with veth namespace devices.
 * The device is removed with dpdk_fabric_af_packet_if_del().
 */
static int
dpdk_af_packet_if_add(struct vr_interface *vif)
{
    int ret;
    char params[VR_DPDK_STR_BUF_SZ];
    char name[VR_INTERFACE_NAME_LEN];
    struct vr_dpdk_ethdev *ethdev;
    uint8_t port_id;
    int frame_size;

    RTE_LOG(INFO, VROUTER,
            "Adding vif %u (gen. %u) af_packet device %s\n",
            vif->vif_idx, vif->vif_gen, vif->vif_name);

    ret = snprintf(name, sizeof(name), "eth_af_packet_%d", vif->vif_idx);
    if (ret >= sizeof(name)) {
        RTE_LOG(ERR, VROUTER,
                "    error creating name for af_packet device %s\n", name);
        return ret;
    }

    /* Frame size should be a multiple of page size. */
    frame_size = (vr_packet_sz / getpagesize()) * getpagesize();

    ret = snprintf(params, sizeof(params),
                    /* TODO: Optional af_packet mmap parameters
                     * "qpairs=%d,framecnt=%d", 16, 512);
                     */
                  "iface=%s,framesz=%d,blocksz=%d",
                  vif->vif_name, frame_size, frame_size);
    if (ret >= sizeof(params)) {
        RTE_LOG(ERR, VROUTER,
                "    error creating config for af_packet device %s\n", name);
        return ret;
    }

    ret = rte_eal_vdev_init(name, params);
    if (ret < 0) {
        RTE_LOG(ERR, VROUTER,
                "    error initializing af_packet device %s\n", name);
        return ret;
    }
    port_id = (uint8_t)(rte_eth_dev_allocated(name) - rte_eth_devices);

    ethdev = &vr_dpdk.ethdevs[port_id];
    if (ethdev->ethdev_ptr != NULL) {
        RTE_LOG(ERR, VROUTER,
                "    error adding af_packet device %s: eth device %"PRIu8" already added\n",
                name, port_id);
        return -EEXIST;
    }
    ethdev->ethdev_port_id = port_id;

    ret = vr_dpdk_ethdev_init(ethdev, &ethdev_conf);
    if (ret != 0)
        return ret;

    dpdk_vif_attach_ethdev(vif, ethdev);

    ret = dpdk_vif_queue_setup(vif);
    if (ret < 0)
        return ret;

    ret = rte_eth_dev_start(port_id);
    if (ret < 0) {
        RTE_LOG(ERR, VROUTER,
                "    error starting eth device %" PRIu8": %s (%d)\n",
                port_id, rte_strerror(-ret), -ret);
        return ret;
    }

    /* schedule RX/TX queues */
    return vr_dpdk_lcore_if_schedule(vif, vr_dpdk_lcore_least_used_get(),
        ethdev->ethdev_nb_rss_queues, &vr_dpdk_ethdev_rx_queue_init,
        ethdev->ethdev_nb_tx_queues, &vr_dpdk_ethdev_tx_queue_init);
}

/*
 * vr_ethdev_conf_update - adjust the config for fabric interfaces
 * depending on the NIC. Broadcom 25G interfaces and enic only support
 * 9022 byte jumbo frames. ixgbe VFs do not allow setting max packet
 * length higher than 1518 if the PF hasn't been configured similarly,
 * so the default is set to 1518 for VFs.
 */
static void
vr_ethdev_conf_update(struct rte_eth_conf *dev_conf)
{
    int i;
    struct rte_eth_dev_info dev_info;

    if (vr_dpdk.vf_lcore_id) {
        if (dev_conf->rxmode.max_rx_pkt_len > ETHER_MAX_LEN) {
            dev_conf->rxmode.max_rx_pkt_len = ETHER_MAX_LEN;
        }
    }

    for (i = 0; i < rte_eth_dev_count(); i++)
    {
        rte_eth_dev_info_get(i, &dev_info);

        if (dev_info.driver_name) {
            if ((strncmp(dev_info.driver_name, "net_bnxt",
                       strlen("net_bnxt") + 1) == 0) ||
                (strncmp(dev_info.driver_name, "net_enic",
                       strlen("net_enic") + 1) == 0)) {
                if (dev_conf->rxmode.max_rx_pkt_len > VT_DPDK_MAX_RX_PKT_LEN_9022) {
                    dev_conf->rxmode.max_rx_pkt_len = VT_DPDK_MAX_RX_PKT_LEN_9022;
                }
            }
        }
    }

    return;
}

/* Add fabric interface */
static int
dpdk_fabric_if_add(struct vr_interface *vif)
{
    int ret;
    uint8_t port_id;
    struct rte_pci_addr pci_address;
    struct vr_dpdk_ethdev *ethdev;
    struct ether_addr mac_addr;
    struct rte_eth_conf fabric_ethdev_conf;

    memset(&pci_address, 0, sizeof(pci_address));
    memset(&mac_addr, 0, sizeof(mac_addr));
    if (vif->vif_flags & VIF_FLAG_PMD) {
        if (vif->vif_os_idx >= rte_eth_dev_count()) {
            RTE_LOG(ERR, VROUTER, "Error adding vif %u eth device %s: invalid PMD %u"
                    " (must be less than %u)\n", vif->vif_idx, vif->vif_name,
                    vif->vif_os_idx, (unsigned)rte_eth_dev_count());
            return -ENOENT;
        }

#if (RTE_VERSION >= RTE_VERSION_NUM(17, 2, 0, 0))
        port_id = dpdk_find_port_id_by_drv_name();
        if (port_id == VR_DPDK_INVALID_PORT_ID)
#endif
            port_id = vif->vif_os_idx;

        /* TODO: does not work for host interfaces
        dpdk_find_pci_addr_by_port(&pci_address, port_id);
        vif->vif_os_idx = dpdk_pci_to_dbdf(&pci_address);
        */

        rte_eth_macaddr_get(port_id, &mac_addr);
        RTE_LOG(INFO, VROUTER, "Adding vif %u (gen. %u) eth device %" PRIu8
                " (PMD) MAC " MAC_FORMAT " (vif MAC "MAC_FORMAT")\n",
            vif->vif_idx, vif->vif_gen, port_id,
            MAC_VALUE(mac_addr.addr_bytes), MAC_VALUE(vif->vif_mac));
    } else {
        dpdk_dbdf_to_pci(vif->vif_os_idx, &pci_address);
        port_id = dpdk_find_port_id_by_pci_addr(&pci_address);
        if (port_id == VR_DPDK_INVALID_PORT_ID) {
            RTE_LOG(ERR, VROUTER, "Error adding vif %u eth device %s:"
                " no port ID found for PCI " PCI_PRI_FMT "\n",
                    vif->vif_idx, vif->vif_name,
                    pci_address.domain, pci_address.bus,
                    pci_address.devid, pci_address.function);
            return -ENOENT;
        }

        rte_eth_macaddr_get(port_id, &mac_addr);
        RTE_LOG(INFO, VROUTER, "Adding vif %u (gen. %u) eth device %" PRIu8
                " PCI " PCI_PRI_FMT " MAC " MAC_FORMAT " (vif MAC "MAC_FORMAT")\n",
                vif->vif_idx, vif->vif_gen, port_id,
                pci_address.domain, pci_address.bus,
                pci_address.devid, pci_address.function,
                MAC_VALUE(mac_addr.addr_bytes), MAC_VALUE(vif->vif_mac));
    }

    ethdev = &vr_dpdk.ethdevs[port_id];
    if (ethdev->ethdev_ptr != NULL) {
        RTE_LOG(ERR, VROUTER, "    error adding eth dev %s: already added\n",
                vif->vif_name);
        return -EEXIST;
    }
    ethdev->ethdev_port_id = port_id;

    fabric_ethdev_conf = ethdev_conf;
    vr_ethdev_conf_update(&fabric_ethdev_conf);

    /* init eth device */
    ret = vr_dpdk_ethdev_init(ethdev, &fabric_ethdev_conf);
    if (ret != 0)
        return ret;

    dpdk_vif_attach_ethdev(vif, ethdev);

    ret = dpdk_vif_queue_setup(vif);
    if (ret < 0)
        return ret;

    ret = rte_eth_dev_start(port_id);
    if (ret < 0) {
        RTE_LOG(ERR, VROUTER, "    error starting eth device %" PRIu8
                ": %s (%d)\n", port_id, rte_strerror(-ret), -ret);
        return ret;
    }

    ret = vr_dpdk_ethdev_rss_init(ethdev);
    if (ret < 0)
        return ret;

    /* we need to init Flow Director after the device has started */
#if VR_DPDK_USE_HW_FILTERING
    /* init hardware filtering */
    ret = vr_dpdk_ethdev_filtering_init(vif, ethdev);
    if (ret < 0)
        return ret;
#endif

    /* Set hardware VLAN stripping */
    dpdk_set_addr_vlan_filter_strip(port_id, vif);

    /* schedule RX/TX queues */
    return vr_dpdk_lcore_if_schedule(vif, vr_dpdk_lcore_least_used_get(),
        ethdev->ethdev_nb_rss_queues, &vr_dpdk_ethdev_rx_queue_init,
        ethdev->ethdev_nb_tx_queues, &vr_dpdk_ethdev_tx_queue_init);
}

/* Delete fabric or af_packet interface */
static int
dpdk_fabric_af_packet_if_del(struct vr_interface *vif)
{
    uint8_t port_id;
    struct vr_dpdk_ethdev *ethdev;
    struct rte_eth_dev *ethdev_ptr;

    RTE_LOG(INFO, VROUTER, "Deleting vif %u %s device\n", vif->vif_idx,
            vif_is_fabric(vif) ? "eth" : "af_packet");

    /*
     * If dpdk_fabric_if_add() failed before dpdk_vif_attach_ethdev,
     * then vif->vif_os will be NULL.
     */
    if (vif->vif_os == NULL) {
        RTE_LOG(ERR, VROUTER, "    error deleting %s dev: already removed\n",
                vif_is_fabric(vif) ? "eth" : "af_packet");
        return -EEXIST;
    }

    ethdev = (struct vr_dpdk_ethdev *)(vif->vif_os);
    ethdev_ptr = ethdev->ethdev_ptr;
    port_id = ethdev->ethdev_port_id;

    /* unschedule RX/TX queues */
    vr_dpdk_lcore_if_unschedule(vif);

    rte_eth_dev_stop(port_id);

    /* af_packet release */
    if (vif_is_namespace(vif)) {
        /**
         * af_packet does not implement rte_driver.uninit() that should
         * free memory and call rte_eth_dev_release_port(). If we ever wanted
         * to move to the pcap driver, we should call rte_eth_dev_close(),
         * then rte_eth_dev_detach(). _detach() will call .uninit(), that is
         * implemented in pcap. .uninit() will free memory and call
         * _release_port().
         */
        rte_eth_dev_close(port_id);

        rte_free(ethdev_ptr->data->dev_private);
        rte_free(ethdev_ptr->data);
#if (RTE_VERSION >= RTE_VERSION_NUM(17, 2, 0, 0))
        rte_free(ethdev_ptr->device);
#else
        rte_free(ethdev_ptr->pci_dev);
#endif

        rte_eth_dev_release_port(ethdev_ptr);
    }

    dpdk_vif_queue_free(vif);

    /* release eth device */
    return vr_dpdk_ethdev_release(ethdev);
}

/* Add vhost interface */
static int
dpdk_vhost_if_add(struct vr_interface *vif)
{
    uint8_t port_id;
    int ret;
    struct ether_addr mac_addr;
    struct vr_dpdk_ethdev *ethdev;
    uint16_t nb_txqs;

    /*
     * The Agent passes xconnect fabric interface in cross_connect_idx,
     * but dp-core does not copy it into vr_interface. Instead
     * it looks for an interface with os_idx == cross_connect_idx
     * and sets vif->vif_bridge if there is such an interface.
     */
    ethdev = (struct vr_dpdk_ethdev *)(vif->vif_bridge->vif_os);
    if (ethdev == NULL) {
        RTE_LOG(ERR, VROUTER, "Error adding vif %u device %s:"
            " bridge vif %u ethdev is not initialized\n",
                vif->vif_idx, vif->vif_name, vif->vif_bridge->vif_idx);
        return -ENOENT;
    }
    port_id = ethdev->ethdev_port_id;

    /* Get interface MAC address. */
    memset(&mac_addr, 0, sizeof(mac_addr));
    rte_eth_macaddr_get(port_id, &mac_addr);

    RTE_LOG(INFO, VROUTER, "Adding vif %u (gen. %u) device %s at eth device %" PRIu8
                " MAC " MAC_FORMAT " (vif MAC " MAC_FORMAT ")\n",
                vif->vif_idx, vif->vif_gen, vif->vif_name, port_id,
                MAC_VALUE(mac_addr.addr_bytes), MAC_VALUE(vif->vif_mac));

    /* If there is a tapdev VLAN device, assign vhost0 MAC address to it */
    if (vr_dpdk.vlan_dev && (vr_dpdk.kni_state <= 0)) {
        struct ifreq ifr;
        struct vr_dpdk_tapdev *tapdev = vr_dpdk.vlan_dev;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, vr_dpdk.vlan_name, sizeof(ifr.ifr_name) - 1);
        rte_memcpy(ifr.ifr_hwaddr.sa_data, vif->vif_mac, ETHER_ADDR_LEN);
        ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
        if (ioctl(tapdev->tapdev_fd, SIOCSIFHWADDR, &ifr) < 0) {
            RTE_LOG(ERR, VROUTER, "    error assigning MAC address to %s: %s(%d)\n",
                     vr_dpdk.vlan_name, rte_strerror(errno), errno);
        } else {
            RTE_LOG(INFO, VROUTER, "    Adding MAC " MAC_FORMAT " to %s\n",
                    MAC_VALUE(vif->vif_mac), vr_dpdk.vlan_name);
        }
    }

    /*
     * KNI does not support bond interfaces and generate random MACs,
     * so we try to get a bond member instead.
     */
    if (ethdev->ethdev_nb_slaves > 0) {
        port_id = ethdev->ethdev_slaves[0];

        memset(&mac_addr, 0, sizeof(mac_addr));
        rte_eth_macaddr_get(port_id, &mac_addr);
        RTE_LOG(INFO, VROUTER, "    using bond slave eth device %" PRIu8
                " MAC " MAC_FORMAT "\n",
                port_id, MAC_VALUE(mac_addr.addr_bytes));
    }

    ret = dpdk_vif_queue_setup(vif);
    if (ret < 0)
        return ret;

    /* Probe KNI. */
    ret = vr_dpdk_knidev_init(port_id, vif);
    switch (ret) {
    case 0:
        ret = vr_dpdk_lcore_if_schedule(vif, vr_dpdk_lcore_least_used_get(),
                1, &vr_dpdk_kni_rx_queue_init,
                1, &vr_dpdk_kni_tx_queue_init);
        break;
    case -ENOTSUP:
        /* Try TAP instead. */
        ret = vr_dpdk_tapdev_init(vif);
        if (ret != 0)
            return ret;

        /* We use few single-producer rings, so we assign TX queue to each lcore */
        nb_txqs = (uint16_t)-1;

        /* Schedule the TAP interface with 1 RX queue and unlimited TX queues. */
        ret = vr_dpdk_lcore_if_schedule(vif, vr_dpdk_lcore_least_used_get(),
                1, &vr_dpdk_tapdev_rx_queue_init,
                nb_txqs, &vr_dpdk_tapdev_tx_queue_init);
        break;
    default:
        /* Other KNI error. */
        return ret;
    }

    return ret;
}

/* Delete vhost interface */
static int
dpdk_vhost_if_del(struct vr_interface *vif)
{
    RTE_LOG(INFO, VROUTER, "Deleting vif %u device %s\n",
                vif->vif_idx, vif->vif_name);

    vr_dpdk_lcore_if_unschedule(vif);

    dpdk_vif_queue_free(vif);

    /* Release KNI or TAP device. */
    if (vr_dpdk.kni_state > 0)
        return vr_dpdk_knidev_release(vif);
    else
        return vr_dpdk_tapdev_release(vif);
}

/* Start interface monitoring */
static void
dpdk_monitoring_start(struct vr_interface *monitored_vif,
    struct vr_interface *monitoring_vif)
{
    uint8_t port_id;

    /* set monitoring redirection */
    vr_dpdk.monitorings[monitored_vif->vif_idx] = monitoring_vif->vif_idx;

    /* set vif flag */
    rte_wmb();
    monitored_vif->vif_flags |= VIF_FLAG_MONITORED;

    if(vif_is_fabric(monitored_vif)) {
        port_id = (((struct vr_dpdk_ethdev *)(monitored_vif->vif_os))->ethdev_port_id);
        rte_eth_promiscuous_enable(port_id);
    }
}

/* Stop interface monitoring */
static void
dpdk_monitoring_stop(struct vr_interface *monitored_vif,
    struct vr_interface *monitoring_vif)
{
#if !VR_DPDK_ENABLE_PROMISC
    uint8_t port_id;
#endif
    /* check if the monitored vif was reused */
    if (vr_dpdk.monitorings[monitored_vif->vif_idx] != monitoring_vif->vif_idx)
        return;

    /* clear vif flag */
    monitored_vif->vif_flags &= ~((unsigned int)VIF_FLAG_MONITORED);
    rte_wmb();

    /* clear monitoring redirection */
    vr_dpdk.monitorings[monitored_vif->vif_idx] = VR_MAX_INTERFACES;
#if !VR_DPDK_ENABLE_PROMISC
    if(vif_is_fabric(monitored_vif)) {
        port_id = (((struct vr_dpdk_ethdev *)(monitored_vif->vif_os))->ethdev_port_id);
        rte_eth_promiscuous_disable(port_id);
    }
#endif
}

/* Add monitoring interface */
static int
dpdk_monitoring_if_add(struct vr_interface *vif)
{
    int ret;
    unsigned short monitored_vif_id = vif->vif_os_idx;
    struct vr_interface *monitored_vif;
    struct vrouter *router = vrouter_get(vif->vif_rid);
    uint16_t nb_txqs;

    RTE_LOG(INFO, VROUTER, "Adding monitoring vif %u (gen. %u) device %s"
                " to monitor vif %u\n",
                vif->vif_idx, vif->vif_gen, vif->vif_name, monitored_vif_id);

    /* Check if vif exist.
     * We don't need vif reference in order to monitor it.
     * We use the VIF_FLAG_MONITORED to copy in/out packet to the
     * monitoring interface. If the monitored vif get deleted, we simply
     * get no more packets.
     */
    monitored_vif = __vrouter_get_interface(router, monitored_vif_id);
    if (!monitored_vif) {
        RTE_LOG(ERR, VROUTER, "    error getting vif to monitor:"
            " vif %u does not exist\n", monitored_vif_id);
        return -EINVAL;
    }

    ret = dpdk_vif_queue_setup(vif);
    if (ret)
        return ret;

    /*
     * TODO: we always use DPDK port 0 for monitoring KNI
     * DPDK numerates all the detected Ethernet devices starting from 0.
     * So we might only get into an issue if we have no eth devices at all
     * or we have few eth ports and don't want to use the first one.
     */

    /* Probe KNI. */
    ret = vr_dpdk_knidev_init(0, vif);
    switch (ret) {
    case 0:
        /* Write-only interface. */
        ret = vr_dpdk_lcore_if_schedule(vif, vr_dpdk_lcore_least_used_get(),
                0, NULL,
                1, &vr_dpdk_kni_tx_queue_init);
        break;
    case -ENOTSUP:
        /* Try TAP instead. */
        ret = vr_dpdk_tapdev_init(vif);
        if (ret != 0)
            return ret;

        /* We use few single-producer rings, so we assign TX queue to each lcore */
        nb_txqs = (uint16_t)-1;

        /* Schedule the TAP interface with 1 RX queue and unlimited TX queues. */
        /* Write-only interface. */
        ret = vr_dpdk_lcore_if_schedule(vif, vr_dpdk_lcore_least_used_get(),
                0, NULL,
                nb_txqs, &vr_dpdk_tapdev_tx_queue_init);
        break;
    default:
        /* Other KNI error. */
        return ret;
    }

    if (ret == 0) {
        /* Start monitoring. */
        dpdk_monitoring_start(monitored_vif, vif);
    }

    return ret;
}

/* Delete monitoring interface */
static int
dpdk_monitoring_if_del(struct vr_interface *vif)
{
    unsigned short monitored_vif_id = vif->vif_os_idx;
    struct vr_interface *monitored_vif;

    RTE_LOG(INFO, VROUTER, "Deleting monitoring vif %u device"
                " to monitor vif %u\n",
                vif->vif_idx, monitored_vif_id);

    /* check if vif exist */
    monitored_vif = __vrouter_get_interface(vrouter_get(vif->vif_rid),
                                                    monitored_vif_id);
    if (!monitored_vif) {
        RTE_LOG(ERR, VROUTER, "    error getting vif to monitor:"
            " vif %u does not exist\n", monitored_vif_id);
    } else {
        /* stop monitoring */
        dpdk_monitoring_stop(monitored_vif, vif);
    }

    vr_dpdk_lcore_if_unschedule(vif);

    dpdk_vif_queue_free(vif);

    /* Release KNI or TAP device. */
    if (vr_dpdk.kni_state > 0)
        return vr_dpdk_knidev_release(vif);
    else
        return vr_dpdk_tapdev_release(vif);
}

/* Add agent interface */
static int
dpdk_agent_if_add(struct vr_interface *vif)
{
    int ret;

    RTE_LOG(INFO, VROUTER, "Adding vif %u (gen. %u) packet device %s\n",
                vif->vif_idx, vif->vif_gen, vif->vif_name);

    /* check if packet device is already added */
    if (vr_dpdk.packet_transport != NULL) {
        RTE_LOG(ERR, VROUTER, "    error adding packet device %s: already exist\n",
            vif->vif_name);
        return -EEXIST;
    }

    /* init packet device */
    ret = dpdk_packet_socket_init();
    if (ret < 0) {
        RTE_LOG(ERR, VROUTER, "    error initializing packet socket: %s (%d)\n",
            rte_strerror(errno), errno);
        return ret;
    }

    vr_usocket_attach_vif(vr_dpdk.packet_transport, vif);

    /* No need to schedule the pkt0 at the moment, since we RX from the
     * socket and TX to the global packet_ring.
     */
    return 0;
}

/* Delete agent interface */
static int
dpdk_agent_if_del(struct vr_interface *vif)
{
    RTE_LOG(INFO, VROUTER, "Deleting vif %u packet device\n",
                vif->vif_idx);

    dpdk_packet_socket_close();

    return 0;
}

extern void vhost_remove_xconnect(void);

/* vRouter callback */
static int
dpdk_if_add(struct vr_interface *vif)
{
    if (vr_dpdk_is_stop_flag_set())
        return -EINPROGRESS;

    if (vif_is_fabric(vif)) {
        return dpdk_fabric_if_add(vif);
    } else if (vif_is_vm(vif)) {
        return dpdk_virtual_if_add(vif);
    } else if (vif_is_vlan(vif)) {
        return dpdk_virtual_vlan_if_add(vif);
    } else if (vif_is_namespace(vif)) {
        return dpdk_af_packet_if_add(vif);
    } else if (vif_is_vhost(vif)) {
        return dpdk_vhost_if_add(vif);
    } else if (vif_is_agent(vif)) {
        return dpdk_agent_if_add(vif);
    } else if (vif_is_monitoring(vif)) {
        return dpdk_monitoring_if_add(vif);
    }

    RTE_LOG(ERR, VROUTER,
            "Error adding vif %d (%s): unsupported interface type %d transport %d\n",
            vif->vif_idx, vif->vif_name, vif->vif_type, vif->vif_transport);

    return -EFAULT;
}

static int
dpdk_if_del(struct vr_interface *vif)
{
    if (vr_dpdk_is_stop_flag_set())
        return -EINPROGRESS;

    if (vif_is_fabric(vif) || vif_is_namespace(vif)) {
        return dpdk_fabric_af_packet_if_del(vif);
    } else if (vif_is_vm(vif)) {
        return dpdk_virtual_if_del(vif);
    } else if (vif_is_vlan(vif)) {
        return dpdk_virtual_vlan_if_del(vif);
    } else if (vif_is_vhost(vif)) {
        return dpdk_vhost_if_del(vif);
    } else if (vif_is_agent(vif)) {
        return dpdk_agent_if_del(vif);
    } else if (vif_is_monitoring(vif)) {
        return dpdk_monitoring_if_del(vif);
    }

    RTE_LOG(ERR, VROUTER,
            "Error deleting vif %d: unsupported interface type %d transport %d\n",
            vif->vif_idx, vif->vif_type, vif->vif_transport);

    return -EFAULT;
}

/* vRouter callback */
static int
dpdk_if_del_tap(struct vr_interface *vif)
{
    /* TODO: we untap interfaces at if_del */
    return 0;
}


/* vRouter callback */
static int
dpdk_if_add_tap(struct vr_interface *vif)
{
    /* TODO: we tap interfaces at if_add */
    return 0;
}

static int
dpdk_pkt_is_gso(struct rte_mbuf *m)
{
    /*
     * This is only for TCP4/TCP6. UDP frag offload goes through the
     * regular dpdk_fragment_packet() path
     */
    return (m->ol_flags & (PKT_RX_GSO_TCP4| PKT_RX_GSO_TCP6));
}

static inline void
dpdk_hw_checksum_at_offset(struct vr_packet *pkt, unsigned offset)
{
    struct rte_mbuf *m = vr_dpdk_pkt_to_mbuf(pkt);
    struct vr_ip *iph = NULL;
    struct vr_ip6 *ip6h = NULL;
    unsigned char iph_len = 0, iph_proto = 0;
    struct vr_tcp *tcph;
    struct vr_udp *udph;

    RTE_VERIFY(0 < offset);

    if (pkt->vp_type == VP_TYPE_IP || pkt->vp_type == VP_TYPE_IPOIP) {
        iph = (struct vr_ip *)pkt_data_at_offset(pkt, offset);
        iph_len = iph->ip_hl * 4;
        iph_proto = iph->ip_proto;
        m->ol_flags |= PKT_TX_IP_CKSUM | PKT_TX_IPV4;
        iph->ip_csum = 0;
    } else if (pkt->vp_type == VP_TYPE_IP6 || pkt->vp_type == VP_TYPE_IP6OIP) {
        ip6h = (struct vr_ip6 *)pkt_data_at_offset(pkt, offset);
        iph_len = sizeof(struct vr_ip6);
        iph_proto = ip6h->ip6_nxt;
        m->ol_flags |= PKT_TX_IPV6;
    } else {
        /* Nothing to do if the packet is neither IPv4 nor IPv6. */
        return;
    }

    /* Note: Intel NICs need the checksum set to zero
     * and proper l2/l3 lens to be set.
     */
    m->l3_len = iph_len;
    m->l2_len = offset - rte_pktmbuf_headroom(m);

    /* calculate TCP/UDP checksum */
    if (likely(iph_proto == VR_IP_PROTO_UDP)) {
        m->ol_flags |= PKT_TX_UDP_CKSUM;
        udph = (struct vr_udp *)pkt_data_at_offset(pkt, offset + iph_len);
        udph->udp_csum = 0;
        if (iph)
            udph->udp_csum = rte_ipv4_phdr_cksum((struct ipv4_hdr *)iph, m->ol_flags);
        else if (ip6h)
            udph->udp_csum = rte_ipv6_phdr_cksum((struct ipv6_hdr *)ip6h, m->ol_flags);
    } else if (likely(iph_proto == VR_IP_PROTO_TCP)) {
        m->ol_flags |= PKT_TX_TCP_CKSUM;
        tcph = (struct vr_tcp *)pkt_data_at_offset(pkt, offset + iph_len);
        tcph->tcp_csum = 0;
        if (iph)
            tcph->tcp_csum = rte_ipv4_phdr_cksum((struct ipv4_hdr *)iph, m->ol_flags);
        else if (ip6h)
            tcph->tcp_csum = rte_ipv6_phdr_cksum((struct ipv6_hdr *)ip6h, m->ol_flags);
    }
}

static inline void
dpdk_ipv4_sw_iphdr_checksum_at_offset(struct vr_packet *pkt, unsigned offset)
{
    struct vr_ip *iph;

    RTE_VERIFY(0 < offset);

    iph = (struct vr_ip *)pkt_data_at_offset(pkt, offset);
    iph->ip_csum = vr_ip_csum(iph);
}

static inline void
dpdk_sw_checksum_at_offset(struct vr_packet *pkt, unsigned offset)
{
    struct vr_ip *iph = NULL;
    struct vr_ip6 *ip6h = NULL;
    unsigned char iph_len = 0, iph_proto = 0;
    struct vr_udp *udph;
    struct vr_tcp *tcph;
    struct rte_mbuf *m = vr_dpdk_pkt_to_mbuf(pkt);

    RTE_VERIFY(0 < offset);

    if (pkt->vp_type == VP_TYPE_IP || pkt->vp_type == VP_TYPE_IPOIP) {
        iph = (struct vr_ip *)pkt_data_at_offset(pkt, offset);
        iph->ip_csum = vr_ip_csum(iph);
        iph_len = iph->ip_hl * 4;
        iph_proto = iph->ip_proto;
    } else if (pkt->vp_type == VP_TYPE_IP6 || pkt->vp_type == VP_TYPE_IP6OIP) {
        ip6h = (struct vr_ip6 *)pkt_data_at_offset(pkt, offset);
        iph_len = sizeof(struct vr_ip6);
        iph_proto = ip6h->ip6_nxt;
    } else {
        /* Nothing to do if the packet is neither IPv4 nor IPv6. */
        return;
    }

    if (iph_proto == VR_IP_PROTO_UDP) {
        udph = (struct vr_udp *)pkt_data_at_offset(pkt, offset + iph_len);
        udph->udp_csum = 0;
        if (iph)
            udph->udp_csum = dpdk_ipv4_udptcp_cksum(m, (struct ipv4_hdr *)iph, (uint8_t*)udph);
        else if (ip6h)
            udph->udp_csum = dpdk_ipv6_udptcp_cksum(m, (struct ipv6_hdr *)ip6h, (uint8_t*)udph);
    } else if (iph_proto == VR_IP_PROTO_TCP) {
        tcph = (struct vr_tcp *)pkt_data_at_offset(pkt, offset + iph_len);
        tcph->tcp_csum = 0;
        if (iph)
            tcph->tcp_csum = dpdk_ipv4_udptcp_cksum(m, (struct ipv4_hdr *)iph, (uint8_t*)tcph);
        else if (ip6h)
            tcph->tcp_csum = dpdk_ipv6_udptcp_cksum(m, (struct ipv6_hdr *)ip6h, (uint8_t*)tcph);
    }
}

static inline void
dpdk_ipv4_outer_tunnel_hw_checksum(struct vr_packet *pkt)
{
    struct rte_mbuf *m = vr_dpdk_pkt_to_mbuf(pkt);
    unsigned offset = pkt->vp_data + sizeof(struct ether_hdr);
    struct vr_ip *iph = (struct vr_ip *)pkt_data_at_offset(pkt, offset);
    unsigned iph_len = iph->ip_hl * 4;

    m->ol_flags |= PKT_TX_IP_CKSUM | PKT_TX_IPV4;
    iph->ip_csum = 0;
    m->l3_len = iph_len;
    m->l2_len = offset - rte_pktmbuf_headroom(m);
}

static inline void
dpdk_ipv4_outer_tunnel_sw_checksum(struct vr_packet *pkt)
{
    unsigned offset = pkt->vp_data + sizeof(struct ether_hdr);
    struct vr_ip *iph = (struct vr_ip *)pkt_data_at_offset(pkt, offset);

    iph->ip_csum = vr_ip_csum(iph);
}

static inline void
dpdk_hw_checksum(struct vr_packet *pkt)
{
    /* if a tunnel */
    if (vr_pkt_type_is_overlay(pkt->vp_type)) {
        /* calculate outer checksum in soft */
        dpdk_ipv4_sw_iphdr_checksum_at_offset(pkt,
            pkt->vp_data + sizeof(struct ether_hdr));
        /* calculate inner checksum in hardware */
        dpdk_hw_checksum_at_offset(pkt, pkt_get_inner_network_header_off(pkt));
    } else if (VP_TYPE_IP == pkt->vp_type || VP_TYPE_IP6 == pkt->vp_type) {
        /* normal IPv4 or IPv6 packet */
        dpdk_hw_checksum_at_offset(pkt, pkt->vp_data + sizeof(struct ether_hdr));
    }
}

static inline void
dpdk_sw_checksum(struct vr_packet *pkt, bool will_fragment)
{
    /* if a tunnel */
    if (vr_pkt_type_is_overlay(pkt->vp_type)) {
        /* calculate outer checksum */
        if (!will_fragment)
            dpdk_ipv4_sw_iphdr_checksum_at_offset(pkt,
                pkt->vp_data + sizeof(struct ether_hdr));
        /* calculate inner checksum */
        dpdk_sw_checksum_at_offset(pkt, pkt_get_inner_network_header_off(pkt));
    } else if (VP_TYPE_IP == pkt->vp_type || VP_TYPE_IP6 == pkt->vp_type) {
        /* normal IPv4 or IPv6 packet */
        dpdk_sw_checksum_at_offset(pkt, pkt->vp_data + sizeof(struct ether_hdr));
    }
}

uint16_t
dpdk_get_ether_header_len(const void *data)
{
    struct ether_hdr *eth = (struct ether_hdr *)data;

    if (eth->ether_type == rte_cpu_to_be_16(ETHER_TYPE_VLAN))
        return sizeof(struct ether_hdr) + sizeof(struct vlan_hdr);
    else
        return sizeof(struct ether_hdr);
}

/**
 * Fragment the input packet
 *
 * Please take note that the caller is responsible for freeing the input
 * packet. All output fragments are hold in mbuf chains. Since we do not
 * support the mbuf chains at the moment, there is no vr_packet structure
 * attached to the mbufs and none of the functions using the struct can not be
 * used.
 *
 * @param pkt The packet to be fragmented
 * @param mbuf_in An mbuf of the inpun packet
 * @param mbuf_out An array of mbuf pointers to hold output packets' mbufs
 * @param out_num Size of the mbuf_out array
 * @param mtu_size MTU size
 * @param do_outer_ip_csum Whether calculate the outer IP checksum (in
 * software)
 * @param lcore_id An ID of the lcore executing this function
 *
 * @return Number of output fragments (packets)
 */
static int
dpdk_fragment_packet(struct vr_packet *pkt, struct rte_mbuf *mbuf_in,
                     struct rte_mbuf **mbuf_out, const unsigned short out_num,
                     const unsigned short mtu_size, bool do_outer_ip_csum,
                     const unsigned lcore_id)
{
    int number_of_packets;
    uint16_t outer_header_len;
    struct rte_mempool *pool_direct, *pool_indirect;
    struct rte_mbuf *m;
    int i;
    unsigned char *original_header_ptr;
    uint16_t max_frag_size;

    outer_header_len = pkt_get_inner_network_header_off(pkt) -
            pkt_head_space(pkt);
    original_header_ptr = pkt_data(pkt);

    /* Get into the inner IP header */
    rte_pktmbuf_adj(mbuf_in, outer_header_len);

    /* Fragment the packet */
    pool_direct = vr_dpdk.frag_direct_mempool;
    pool_indirect = vr_dpdk.frag_indirect_mempool;

    /* Fragment with the maximum size of (MTU - outer_header_length) to leave a
     * space for the header prepended later. In addition DPDK requires that the
     * (max frag size - IP header) length is a multiple of 8, therefore the
     * calculations below. */
    max_frag_size = mtu_size - outer_header_len - sizeof(struct vr_ip);
    max_frag_size &= ~7U;
    max_frag_size += sizeof(struct vr_ip);

    number_of_packets = rte_ipv4_fragment_packet(mbuf_in, mbuf_out, out_num,
            max_frag_size, pool_direct, pool_indirect);
    if (number_of_packets < 0)
        return number_of_packets;

    /* Adjust outer and inner IP headers for each fragmented packets */
    for (i = 0; i < number_of_packets; ++i) {
        m = mbuf_out[i];

        /* Inner header operations */
        struct vr_ip *inner_ip = rte_pktmbuf_mtod(m, struct vr_ip *);
        inner_ip->ip_csum = 0;
        inner_ip->ip_csum = vr_ip_csum(inner_ip);

        /* Outer header operations */
        char *outer_header_ptr = rte_pktmbuf_prepend(m, outer_header_len);
        rte_memcpy(outer_header_ptr, original_header_ptr, outer_header_len);

        uint16_t eth_hlen = dpdk_get_ether_header_len(outer_header_ptr);
        struct vr_ip *outer_ip = (struct vr_ip *)(outer_header_ptr + eth_hlen);
        outer_ip->ip_len = rte_cpu_to_be_16(rte_pktmbuf_pkt_len(m) - eth_hlen);
        m->l2_len = mbuf_in->l2_len;
        m->l3_len = mbuf_in->l3_len;

        /* Copy inner IP id to outer. Currently, the Agent diagnostics depends
         * on that. */
        outer_ip->ip_id = inner_ip->ip_id;

        /* Adjust UDP length to match IP frament size */
        if (outer_ip->ip_proto == VR_IP_PROTO_UDP) {
            unsigned header_len = outer_ip->ip_hl * 4;
            struct vr_udp *udp = (struct vr_udp *)((char *)outer_ip +
                    header_len);
            udp->udp_length = rte_cpu_to_be_16(
                    rte_be_to_cpu_16(outer_ip->ip_len) - header_len);
        }

        /* If it is necessary to calculate (in software) IP header checksum.
         * TODO: This would not be needed if:
         * 1. We would support mbuf chains. The functions that calculate the
         * checksums, which uses vr_pkt struct could be used after fragmentation
         * 2. We would rewrite the checksumming functions to use mbufs and not
         * the vr_pkt struct, and use them after fragmentation. */
        if (do_outer_ip_csum) {
            outer_ip->ip_csum = vr_ip_csum(outer_ip);
            m->ol_flags &= ~PKT_TX_IP_CKSUM;
        }
    }

    return number_of_packets;
}

/* TX packet callback */
static int
dpdk_if_tx(struct vr_interface *vif, struct vr_packet *pkt)
{
    uint8_t queue_index;
    int ret, i;
    unsigned int vif_idx = vif->vif_idx, dpdk_queue_index;
    const unsigned int lcore_id = rte_lcore_id();

    struct vr_dpdk_lcore * const lcore = vr_dpdk.lcores[lcore_id];
    struct rte_mbuf *m = vr_dpdk_pkt_to_mbuf(pkt);
    struct vr_dpdk_queue *tx_queue;
    struct vr_dpdk_queue *monitoring_tx_queue;
    struct rte_mbuf *p_copy;
    struct vr_interface_stats *stats;
    struct rte_mbuf *mbufs_frags_out[VR_DPDK_FRAG_MAX_IP_FRAGS];
    struct rte_mbuf *mbufs_segs_out[VR_DPDK_FRAG_MAX_IP_SEGS];
    int num_of_frags = 1, num_of_segs = 1;
    bool will_fragment, will_segment;

    RTE_LOG_DP(DEBUG, VROUTER,"%s: TX packet to interface %s\n", __func__,
        vif->vif_name);

    if (pkt->vp_queue != VP_QUEUE_INVALID) {
        queue_index = pkt->vp_queue;
    } else {
        if (lcore->lcore_hw_queue[vif_idx] >= 0) {
            queue_index = lcore->lcore_hw_queue[vif_idx];
        } else {
            queue_index = 0;
        }
    }

    if (lcore->lcore_hw_queue_to_dpdk_index[vif->vif_idx]) {
        dpdk_queue_index =
            lcore->lcore_hw_queue_to_dpdk_index[vif->vif_idx][queue_index];
    } else {
        dpdk_queue_index = 0;
    }

    tx_queue = &lcore->lcore_tx_queues[vif_idx][dpdk_queue_index];
    stats = vif_get_stats(vif, lcore_id);

    /* reset mbuf data pointer and length */
    m->data_off = pkt_head_space(pkt);
    m->pkt_len = pkt_len(pkt);
    m->data_len = pkt_head_len(pkt);

    if (unlikely(vif->vif_type == VIF_TYPE_AGENT)) {
        ret = rte_ring_mp_enqueue(vr_dpdk.packet_ring, m);
        if (likely(ret == 0)) {
            stats->vis_queue_opackets++;
        } else {
            /* TODO: a separate counter for this drop */
            vr_dpdk_pfree(m, pkt->vp_if, VP_DROP_INTERFACE_DROP);
            stats->vis_queue_oerrors++;
            /* return 0 so we do not increment vif error counter */
            return 0;
        }
#ifdef VR_DPDK_TX_PKT_DUMP
#ifdef VR_DPDK_PKT_DUMP_VIF_FILTER
        if (VR_DPDK_PKT_DUMP_VIF_FILTER(vif))
#endif
        rte_pktmbuf_dump(stdout, m, 0x60);
#endif
        vr_dpdk_packet_wakeup(vif);
        return 0;
    }

    if (tx_queue == NULL) {
        vr_dpdk_pfree(m, pkt->vp_if, VP_DROP_INTERFACE_DROP);
        return 0;
    }

    /* Set a flag indicating that the packet being processed is going to be
     * fragmented as after prepending outer header it exceeds the MTU size of
     * an interface. */
    will_fragment = (vr_pkt_type_is_overlay(pkt->vp_type) &&
            vif->vif_mtu < rte_pktmbuf_pkt_len(m));

    /* Segmentation is applicable instead of fragmentation if packet has GSO enabled */
    will_segment = will_fragment && dpdk_pkt_is_gso(m);

    /*
     * With DPDK pktmbufs we don't know if the checksum is incomplete,
     * i.e. there is no direct equivalent of skb->ip_summed field.
     *
     * So we just rely on VP_FLAG_CSUM_PARTIAL flag here, assuming
     * the flag is set when we need to calculate inner or outer packet
     * checksum.
     *
     * This is not elegant and need to be addressed.
     * See dpdk/app/test-pmd/csumonly.c for more checksum examples
     */
    if (!will_segment) {
        if (unlikely(pkt->vp_flags & VP_FLAG_CSUM_PARTIAL)) {
            /* if NIC supports checksum offload */
            if (likely((vif->vif_flags & VIF_FLAG_TX_CSUM_OFFLOAD) &&
                       !will_fragment))
                /* Can not do hardware checksumming for fragmented packets */
                dpdk_hw_checksum(pkt);
            else {
                dpdk_sw_checksum(pkt, will_fragment);

                /* We could not calculate the inner checkums in hardware, but we
                 * still can do outer header in hardware. */
                if (unlikely(will_fragment &&
                            (vif->vif_flags & VIF_FLAG_TX_CSUM_OFFLOAD)))
                    dpdk_ipv4_outer_tunnel_hw_checksum(pkt);
            }

        } else if (likely(vr_pkt_type_is_overlay(pkt->vp_type))) {
            /* If NIC supports checksum offload.
             * Inner checksum is already done. Compute outer IPv4 checksum,
             * set UDP length, and zero UDP checksum.
             */
            if (likely(vif->vif_flags & VIF_FLAG_TX_CSUM_OFFLOAD)) {
                dpdk_ipv4_outer_tunnel_hw_checksum(pkt);

            } else if (likely(!will_fragment)) {
                /* if wont fragment it later */
                dpdk_ipv4_outer_tunnel_sw_checksum(pkt);
            }
        }
    }

    /* Inject ethertype and VLAN tag.
     *
     * Tag only packets that are going to be send to the physical interface,
     * to allow data transfer between compute nodes in the specified VLAN.
     *
     * VLAN tag is adjustable by user with a command line --vlan_tci parameter:
     * see dpdk_vrouter.c. If vRouter is not supposed to work in VLAN
     * (parameter was not specified), packets should not be tagged.
     *
     * --vtest_vlan parameter changes behaviour - vRouter inject packets for
     *  non fabric interfaces too (Emulates physical interface for some vlan test cases).
     *
     */
    if (unlikely(vr_dpdk.vlan_tag != VLAN_ID_INVALID && vif_is_fabric(vif)) ||
                    vr_dpdk.vtest_vlan) {
        /* set 3 PCP bits and 12 VLAN ID bits */
        m->vlan_tci = vr_dpdk.vlan_tag;
        if (pkt->vp_priority != VP_PRIORITY_INVALID)
            m->vlan_tci |= pkt->vp_priority << VR_VLAN_PRIORITY_SHIFT;

        if (unlikely((vif->vif_flags & VIF_FLAG_VLAN_OFFLOAD) == 0)) {
            /* Software VLAN TCI insert. */
            if (unlikely(pkt_push(pkt, sizeof(struct vlan_hdr)) == NULL)) {
                RTE_LOG_DP(DEBUG, VROUTER,"%s: Error inserting VLAN tag\n", __func__);
                vr_dpdk_pfree(m, pkt->vp_if, VP_DROP_INTERFACE_DROP);
                return -1;
            }
            m->l2_len += sizeof(struct vlan_hdr);
            if (unlikely(rte_vlan_insert(&m))) {
                RTE_LOG_DP(DEBUG, VROUTER,"%s: Error inserting VLAN tag\n", __func__);
                vr_dpdk_pfree(m, pkt->vp_if, VP_DROP_INTERFACE_DROP);
                return -1;
            }
        } else {
            /* Hardware VLAN TCI insert. */
            m->ol_flags |= PKT_TX_VLAN_PKT;
        }
    }

#ifdef VR_DPDK_TX_PKT_DUMP
#ifdef VR_DPDK_PKT_DUMP_VIF_FILTER
    if (VR_DPDK_PKT_DUMP_VIF_FILTER(vif))
#endif
    rte_pktmbuf_dump(stdout, m, 0x60);
#endif

    if (unlikely(will_segment)) {
        num_of_segs = dpdk_segment_packet(pkt, m, mbufs_segs_out,
                VR_DPDK_FRAG_MAX_IP_SEGS, m->tso_segsz, 
                (vif->vif_flags & VIF_FLAG_TX_CSUM_OFFLOAD));
        if (num_of_segs < 0) {
            RTE_LOG_DP(DEBUG, VROUTER, "%s: error %d during GSO of an "
                    "IP packet for interface %s on lcore %u\n", __func__,
                    num_of_segs, vif->vif_name, lcore_id);
            vr_dpdk_pfree(m, pkt->vp_if, VP_DROP_INTERFACE_DROP);
            return -1;
        }
    } else if (unlikely(will_fragment)) {
        num_of_frags = dpdk_fragment_packet(pkt, m, mbufs_frags_out,
                VR_DPDK_FRAG_MAX_IP_FRAGS, vif->vif_mtu,
                !(vif->vif_flags & VIF_FLAG_TX_CSUM_OFFLOAD), lcore_id);
        if (num_of_frags < 0) {
            RTE_LOG_DP(DEBUG, VROUTER, "%s: error %d during fragmentation of an "
                    "IP packet for interface %s on lcore %u\n", __func__,
                    num_of_frags, vif->vif_name, lcore_id);
            vr_dpdk_pfree(m, pkt->vp_if, VP_DROP_INTERFACE_DROP);
            return -1;
        }
    }

    if (unlikely(vif->vif_flags & VIF_FLAG_MONITORED)) {
        monitoring_tx_queue = &lcore->lcore_tx_queues[vr_dpdk.monitorings[vif_idx]][0];
        if (likely(monitoring_tx_queue && monitoring_tx_queue->txq_ops.f_tx)) {
            if (num_of_frags > 1) {
                int i;
                for (i=0; i < num_of_frags; i++) {
                    p_copy = vr_dpdk_pktmbuf_copy_mon(mbufs_frags_out[i], vr_dpdk.rss_mempool);
                    if (likely(p_copy != NULL)) {
                        monitoring_tx_queue->txq_ops.f_tx(monitoring_tx_queue->q_queue_h,
                                        p_copy);
                    }
                }
            } else if (num_of_segs > 1) {
                int i;
                for (i=0; i < num_of_segs; i++) {
                    p_copy = vr_dpdk_pktmbuf_copy_mon(mbufs_segs_out[i], vr_dpdk.rss_mempool);
                    if (likely(p_copy != NULL)) {
                        monitoring_tx_queue->txq_ops.f_tx(monitoring_tx_queue->q_queue_h,
                                        p_copy);
                    }
                }
            } else {
                p_copy = vr_dpdk_pktmbuf_copy_mon(m, vr_dpdk.rss_mempool);
                if (likely(p_copy != NULL)) {
                    monitoring_tx_queue->txq_ops.f_tx(monitoring_tx_queue->q_queue_h,
                                    p_copy);
                }
            }
        }
    }

    /* It is not safe to access the vr_packet structure of the original packet
     * after this point. It can be used only by drop function. The fragments
     * have no vr_packet structure attached at all so it can not be used (see
     * description for the dpdk_fragment_packet() function.
     */
    if (unlikely(num_of_frags > 1)) {
        unsigned mask = (1 << num_of_frags) - 1;

        if (likely(tx_queue->txq_ops.f_tx_bulk != NULL)) {
            tx_queue->txq_ops.f_tx_bulk(tx_queue->q_queue_h, mbufs_frags_out, mask);
            if (unlikely(lcore_id < VR_DPDK_FWD_LCORE_ID))
                tx_queue->txq_ops.f_flush(tx_queue->q_queue_h);

            /* Free the mbuf of the original packet (the one that has been
             * fragmented) */
            rte_pktmbuf_free(m);
        } else {
            RTE_LOG_DP(DEBUG, VROUTER,"%s: error TXing to interface %s: no queue "
                    "for lcore %u\n", __func__, vif->vif_name, lcore_id);
            /* Can not do vif_drop_pkt() on fragments as mbufs after IP
             * fragmentation does not have pkt structure. It is because we do
             * not support chained mbufs that are results of fragmentation. */
            for (i = 0; i < num_of_frags; ++i)
                rte_pktmbuf_free(mbufs_frags_out[i]);
            return -1;
        }
    } else if (unlikely(num_of_segs > 1)) {
        uint64_t mask = (uint64_t)((uint64_t) (1ULL << (uint64_t)num_of_segs) - 1);

        if (likely(tx_queue->txq_ops.f_tx_bulk != NULL)) {
            tx_queue->txq_ops.f_tx_bulk(tx_queue->q_queue_h, mbufs_segs_out, mask);
            if (unlikely(lcore_id < VR_DPDK_FWD_LCORE_ID))
                tx_queue->txq_ops.f_flush(tx_queue->q_queue_h);
        } else {
            RTE_LOG_DP(DEBUG, VROUTER,"%s: error TXing to interface %s: no queue "
                    "for lcore %u\n", __func__, vif->vif_name, lcore_id);
            /* Can not do vif_drop_pkt() on segments as mbufs after
             * segmentation does not have pkt structure */
            for (i = 0; i < num_of_segs; ++i)
                rte_pktmbuf_free(mbufs_segs_out[i]);

            vr_dpdk_pfree(m, pkt->vp_if, VP_DROP_INTERFACE_DROP);
            return -1;
        }
    } else {
        if (likely(tx_queue->txq_ops.f_tx != NULL)) {
            tx_queue->txq_ops.f_tx(tx_queue->q_queue_h, m);
            if (unlikely(lcore_id < VR_DPDK_FWD_LCORE_ID))
                tx_queue->txq_ops.f_flush(tx_queue->q_queue_h);
        } else {
            RTE_LOG_DP(DEBUG, VROUTER,"%s: error TXing to interface %s: no queue "
                    "for lcore %u\n", __func__, vif->vif_name, lcore_id);
            vr_dpdk_pfree(m, pkt->vp_if, VP_DROP_INTERFACE_DROP);
            return -1;
        }
    }

    return 0;
}

static int
dpdk_if_rx(struct vr_interface *vif, struct vr_packet *pkt)
{
    const unsigned lcore_id = rte_lcore_id();
    struct vr_dpdk_lcore * const lcore = vr_dpdk.lcores[lcore_id];
    struct rte_mbuf *m = vr_dpdk_pkt_to_mbuf(pkt);
    unsigned vif_idx = vif->vif_idx;
    struct vr_dpdk_queue *tx_queue;
    struct vr_dpdk_queue *monitoring_tx_queue;
    struct rte_mbuf *p_copy;

    RTE_LOG_DP(DEBUG, VROUTER,"%s: TX packet to interface %s\n", __func__,
        vif->vif_name);

    tx_queue = &lcore->lcore_tx_queues[vif_idx][0];
    /* reset mbuf data pointer and length */
    m->data_off = pkt_head_space(pkt);
    m->data_len = pkt_head_len(pkt);

#if (RTE_VERSION == RTE_VERSION_NUM(2, 1, 0, 0))
    /* TODO: we do not support mbuf chains */
    m->pkt_len = pkt_head_len(pkt);
#else
    m->pkt_len = pkt_len(pkt);
#endif

    if (unlikely(vif->vif_flags & VIF_FLAG_MONITORED)) {
        monitoring_tx_queue =
            &lcore->lcore_tx_queues[vr_dpdk.monitorings[vif_idx]][0];
        if (likely(monitoring_tx_queue && monitoring_tx_queue->txq_ops.f_tx)) {
            p_copy = vr_dpdk_pktmbuf_copy_mon(m, vr_dpdk.rss_mempool);;
            if (likely(p_copy != NULL)) {
                monitoring_tx_queue->txq_ops.f_tx(monitoring_tx_queue->q_queue_h,
                                p_copy);
            }
        }
    }

    /* For tapdev, compute the checksum of packets originating in the
     * VM and destined to the host. If offloads are enabled in the VM
     * it would not compute the checksum and the host would drop it
     */
    if (unlikely((vr_dpdk.kni_state <= 0) && vif_is_virtual(pkt->vp_if)
                  && vif_is_vhost(vif)))
        dpdk_sw_checksum_at_offset(pkt, pkt_get_network_header_off(pkt));

#ifdef VR_DPDK_TX_PKT_DUMP
#ifdef VR_DPDK_PKT_DUMP_VIF_FILTER
    if (VR_DPDK_PKT_DUMP_VIF_FILTER(vif))
#endif
    rte_pktmbuf_dump(stdout, m, 0x60);
#endif

    if (likely(tx_queue->txq_ops.f_tx != NULL)) {
        tx_queue->txq_ops.f_tx(tx_queue->q_queue_h, m);
    } else {
        RTE_LOG_DP(DEBUG, VROUTER,"%s: error TXing to interface %s: no queue for lcore %u\n",
                __func__, vif->vif_name, lcore_id);
        vr_dpdk_pfree(m, pkt->vp_if, VP_DROP_INTERFACE_DROP);
        return -1;
    }

    return 0;
}

static int
dpdk_if_get_settings(struct vr_interface *vif,
        struct vr_interface_settings *settings)
{
    uint8_t port_id = ((struct vr_dpdk_ethdev*)(vif->vif_os))->ethdev_port_id;
    struct rte_eth_link link;

    memset(&link, 0, sizeof(link));
    rte_eth_link_get_nowait(port_id, &link);
    if (link.link_speed != 0) {
        settings->vis_speed = link.link_speed;
        settings->vis_duplex = link.link_duplex == ETH_LINK_FULL_DUPLEX?
                                1 : 0;
    } else {
        /* default values */
        settings->vis_speed = 1000;
        settings->vis_duplex = 1;
    }
    return 0;
}

static unsigned int
dpdk_if_get_mtu(struct vr_interface *vif)
{
    uint8_t port_id;
    uint16_t mtu;
    unsigned l3_mtu;

    l3_mtu = vif->vif_mtu;

    if (vif->vif_type == VIF_TYPE_PHYSICAL) {
        port_id = (((struct vr_dpdk_ethdev *)(vif->vif_os))->ethdev_port_id);
        /* TODO: DPDK bond interfaces does not provide MTU (MTU is 0) */
        if (rte_eth_dev_get_mtu(port_id, &mtu) == 0 && mtu > 0)
            return mtu;

        /* Decrement Ethernet header size. */
        l3_mtu -= sizeof(struct vr_eth);
        if (vr_dpdk.vlan_tag != VLAN_ID_INVALID) {
            /* Decrement 802.1q header size. */
            l3_mtu -= sizeof(uint32_t);
        }
    }


    return l3_mtu;
}

static void
dpdk_if_unlock(void)
{
    vr_dpdk_if_unlock();
}

static void
dpdk_if_lock(void)
{
    vr_dpdk_if_lock();
}

static unsigned short
dpdk_if_get_encap(struct vr_interface *vif)
{
    return VIF_ENCAP_TYPE_ETHER;
}

/* Update port statistics */
static void
dpdk_port_stats_update(struct vr_interface *vif, unsigned lcore_id)
{
    unsigned int i;

    struct vr_interface_stats *stats;
    struct vr_dpdk_lcore *lcore;
    struct vr_dpdk_queue *queue;
    struct rte_port_in_stats rx_stats;
    struct rte_port_out_stats tx_stats;

    stats = vif_get_stats(vif, lcore_id);
    lcore = vr_dpdk.lcores[lcore_id];

    if (lcore == NULL)
        return;

    /* RX queue */
    queue = &lcore->lcore_rx_queues[vif->vif_idx];
    if (queue->q_vif == vif) {
        /* update stats */
        if (queue->rxq_ops.f_stats != NULL) {
            if (queue->rxq_ops.f_stats(queue->q_queue_h,
                &rx_stats, 0) == 0) {
                if (queue->rxq_ops.f_rx == rte_port_ring_reader_ops.f_rx) {
                    /* DPDK ports count dropped packets twice */
                    stats->vis_queue_ipackets = rx_stats.n_pkts_in - rx_stats.n_pkts_drop;
                    stats->vis_queue_ierrors = rx_stats.n_pkts_drop;
                } else {
                    /* DPDK ports count dropped packets twice */
                    stats->vis_port_ipackets = rx_stats.n_pkts_in - rx_stats.n_pkts_drop;
                    stats->vis_port_ierrors = rx_stats.n_pkts_drop;
                }
            }
        }

        /* update virtio syscalls and no mbufs counters */
        vr_dpdk_virtio_xstats_update(stats, queue);
    }

    stats->vis_queue_opackets = stats->vis_queue_oerrors = 0;
    stats->vis_port_opackets = stats->vis_port_oerrors = 0;
    /* TX queue */
    for (i = 0; i < lcore->num_tx_queues_per_lcore[vif->vif_idx]; i++) {
        queue = &lcore->lcore_tx_queues[vif->vif_idx][i];
        if (queue && (queue->q_vif == vif)) {
            /* update stats */
            if (queue->txq_ops.f_stats != NULL) {
                if (queue->txq_ops.f_stats(queue->q_queue_h,
                            &tx_stats, 0) == 0) {
                    if (queue->txq_ops.f_tx == rte_port_ring_writer_ops.f_tx) {
                        /* DPDK ports count dropped packets twice */
                        stats->vis_queue_opackets += tx_stats.n_pkts_in -
                            tx_stats.n_pkts_drop;
                        stats->vis_queue_oerrors += tx_stats.n_pkts_drop;
                    } else {
                        /* DPDK ports count dropped packets twice */
                        stats->vis_port_opackets += tx_stats.n_pkts_in -
                            tx_stats.n_pkts_drop;
                        stats->vis_port_oerrors += tx_stats.n_pkts_drop;
                    }
                }
            }

            /* update virtio syscalls counters */
            vr_dpdk_virtio_xstats_update(stats, queue);
        }
    }
}

/* For non-bonded interfaces, use the xstats from the rte_eth_xstats_get() API.
 * For bonded interfaces, this API is not available, so instead use xstats from
 * it's individual slave interfaces
 */
static void
vr_dpdk_eth_xstats_get(uint32_t port_id, struct rte_eth_stats *eth_stats)
{
    /*
     * TODO: In DPDK 2.1 ierrors includes XEC (l3_l4_xsum_error) counter.
     * The counter seems to include no check sum UDP packets. As a workaround
     * we count out the XEC from ierrors using rte_eth_xstats_get()
     */

    uint8_t *port_id_ptr;
    int port_num = 0;
    struct vr_dpdk_ethdev *ethdev = &vr_dpdk.ethdevs[port_id];
    port_id_ptr = (ethdev->ethdev_nb_slaves == -1)?
                   &ethdev->ethdev_port_id:ethdev->ethdev_slaves;
    do {
#if (RTE_VERSION < RTE_VERSION_NUM(17, 2, 0, 0))
        struct rte_eth_xstats *eth_xstats = NULL;
        int nb_xstats, i;
        nb_xstats = rte_eth_xstats_get(*port_id_ptr, eth_xstats, 0);
        if (nb_xstats > 0) {
            eth_xstats = rte_malloc("xstats",
                sizeof(*eth_xstats)*nb_xstats, 0);
            if (eth_xstats != NULL) {
                if (rte_eth_xstats_get(*port_id_ptr, eth_xstats, nb_xstats)
                        == nb_xstats) {
                    /* look for XEC counter */
                    for (i = 0; i < nb_xstats; i++) {
                        if (strncmp(eth_xstats[i].name, "l3_l4_xsum_error",
                            sizeof(eth_xstats[i].name)) == 0) {
                            eth_stats->ierrors -= eth_xstats[i].value;
                            break;
                        }
                    }
                }
                /*
                 * observed bug: in the kni code, when a memzone is allocated
                 * and used for kni, it is not zalloced. If that memory happens
                 * to be part/full of the freed memory below, then we will run
                 * into issues. For e.g a subsequent check for a particular value
                 * in the non-zalloced code fails. Hence, this workaround, which
                 * zeroes out the memory before freeing. Things seem to work.
                 */
                memset(eth_xstats, 0, sizeof(*eth_xstats)*nb_xstats);
                rte_free(eth_xstats);
            }
        }
#else
        struct rte_eth_xstat *eth_xstats = NULL;
        struct rte_eth_xstat_name *xstats_names;
        int nb_xstats, i;

        nb_xstats = rte_eth_xstats_get(*port_id_ptr, eth_xstats, 0);
        if (nb_xstats > 0) {
            xstats_names = rte_malloc("stats_name", sizeof(struct rte_eth_xstat_name) * nb_xstats, 0);
            if (xstats_names != NULL) {
                if (nb_xstats != rte_eth_xstats_get_names(*port_id_ptr,
                    xstats_names, nb_xstats)) {

                    rte_free(xstats_names);
                    return;
                }
            } else
                return;

            eth_xstats = rte_malloc("xstats",
                sizeof(struct rte_eth_xstat)*nb_xstats, 0);
            if (eth_xstats != NULL) {
                if (rte_eth_xstats_get(*port_id_ptr, eth_xstats, nb_xstats)
                        == nb_xstats) {
                    /* look for XEC counter */
                    for (i = 0; i < nb_xstats; i++) {
                        if (strncmp(xstats_names[i].name, "l3_l4_xsum_error",
                            sizeof(xstats_names[i].name)) == 0) {
                            eth_stats->ierrors -= eth_xstats[i].value;
                            break;
                        }
                    }
                }
                rte_free(eth_xstats);
            }
            rte_free(xstats_names);
        }
#endif
        port_num++;
        port_id_ptr++;
    } while (port_num < ethdev->ethdev_nb_slaves);

    /* Stats cannot go negative */
    if ((int64_t)eth_stats->ierrors < 0)
        eth_stats->ierrors = 0;
}

/* Update device statistics */
static void
dpdk_dev_stats_update(struct vr_interface *vif, unsigned lcore_id)
{
    uint8_t port_id;
    uint16_t queue_id, dpdk_queue_index, num_queues, i;

    struct vr_interface_stats *stats;
    struct vr_dpdk_lcore *lcore;
    struct vr_dpdk_queue *queue;
    struct vr_dpdk_queue_params *queue_params;
    struct vif_queue_dpdk_data *q_data =
        (struct vif_queue_dpdk_data *)vif->vif_queue_host_data;
    struct rte_eth_stats eth_stats;

    /* check if vif is a PMD */
    if (!vif_is_fabric(vif) || vif->vif_os == NULL)
        return;

    port_id = ((struct vr_dpdk_ethdev *)(vif->vif_os))->ethdev_port_id;
    if (rte_eth_stats_get(port_id, &eth_stats) != 0)
        return;

#if (RTE_VERSION >= RTE_VERSION_NUM(2, 1, 0, 0))
    vr_dpdk_eth_xstats_get(port_id, &eth_stats);
#endif

    /* per-lcore device counters */
    lcore = vr_dpdk.lcores[lcore_id];
    if (lcore == NULL)
        return;

    stats = vif_get_stats(vif, lcore_id);

    /* get lcore RX queue index */
    queue = &lcore->lcore_rx_queues[vif->vif_idx];
    if (queue->rxq_ops.f_rx == rte_port_ethdev_reader_ops.f_rx) {
        queue_params = &lcore->lcore_rx_queue_params[vif->vif_idx];
        queue_id = queue_params->qp_ethdev.queue_id;
        if (queue_id < RTE_ETHDEV_QUEUE_STAT_CNTRS) {
            stats->vis_dev_ibytes = eth_stats.q_ibytes[queue_id];
            stats->vis_dev_ipackets = eth_stats.q_ipackets[queue_id];
            stats->vis_dev_ierrors = eth_stats.q_errors[queue_id];
        }
    }

    /* get lcore TX queue index */
    if (vif->vif_hw_queues) {
        num_queues = vif->vif_num_hw_queues;
        if (!q_data)
            num_queues = 1;
    } else {
        num_queues = 1;
    }

    stats->vis_dev_obytes = stats->vis_dev_opackets = 0;
    for (i = 0; i < num_queues; i++) {
        if (vif->vif_hw_queues) {
            queue_id = vif->vif_hw_queues[i];
            if (q_data->vqdd_queue_to_lcore[queue_id] != lcore_id) {
                continue;
            }
        } else {
            queue_id = i;
        }

        if (lcore->lcore_tx_queues[vif->vif_idx]) {
            if (lcore->lcore_hw_queue_to_dpdk_index[vif->vif_idx]) {
                dpdk_queue_index =
                    lcore->lcore_hw_queue_to_dpdk_index[vif->vif_idx][queue_id];
            } else {
                dpdk_queue_index = 0;
            }

            queue = &lcore->lcore_tx_queues[vif->vif_idx][dpdk_queue_index];
            if (queue && (queue->txq_ops.f_tx == rte_port_ethdev_writer_ops.f_tx)) {
                queue_params = &lcore->lcore_tx_queue_params[vif->vif_idx][queue_id];
                queue_id = queue_params->qp_ethdev.queue_id;
                if (queue_id < RTE_ETHDEV_QUEUE_STAT_CNTRS) {
                    stats->vis_dev_obytes += eth_stats.q_obytes[queue_id];
                    stats->vis_dev_opackets += eth_stats.q_opackets[queue_id];
                }
            }
        }
    }

    if (lcore_id == 0) {
        /* use lcore 0 to store global device counters */
        stats->vis_dev_ibytes = eth_stats.ibytes;
        stats->vis_dev_ipackets = eth_stats.ipackets;
        stats->vis_dev_ierrors = eth_stats.ierrors;
        stats->vis_dev_inombufs = eth_stats.rx_nombuf;
        stats->vis_dev_obytes = eth_stats.obytes;
        stats->vis_dev_opackets = eth_stats.opackets;
        stats->vis_dev_oerrors = eth_stats.oerrors;
    }
}

/* Update interface statistics */
static void
dpdk_if_stats_update(struct vr_interface *vif, unsigned core)
{
    int i;

    if (core == (unsigned)-1) {
        /* update counters for all cores */
        for (i = 0; i < vr_num_cpus; i++) {
            dpdk_dev_stats_update(vif, i);
            dpdk_port_stats_update(vif, i);
        }
    } else if (core < vr_num_cpus) {
        /* update counters for a specific core */
        dpdk_dev_stats_update(vif, core);
        dpdk_port_stats_update(vif, core);
    }
    /* otherwise there is nothing to update */
}

struct vr_host_interface_ops dpdk_interface_ops = {
    .hif_lock           =    dpdk_if_lock,
    .hif_unlock         =    dpdk_if_unlock,
    .hif_add            =    dpdk_if_add,
    .hif_del            =    dpdk_if_del,
    .hif_add_tap        =    dpdk_if_add_tap,   /* not implemented */
    .hif_del_tap        =    dpdk_if_del_tap,   /* not implemented */
    .hif_tx             =    dpdk_if_tx,
    .hif_rx             =    dpdk_if_rx,
    .hif_get_settings   =    dpdk_if_get_settings,
    .hif_get_mtu        =    dpdk_if_get_mtu,
    .hif_get_encap      =    dpdk_if_get_encap, /* always returns VIF_ENCAP_TYPE_ETHER */
    .hif_stats_update   =    dpdk_if_stats_update,
};

void
vr_host_vif_init(struct vrouter *router)
{
    return;
}

struct vr_host_interface_ops *
vr_host_interface_init(void)
{
    return &dpdk_interface_ops;
}

void
vr_host_interface_exit(void)
{
    return;
}
