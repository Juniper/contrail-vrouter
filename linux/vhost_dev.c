/*
 * vhost_dev.c -- interface in the host OS
 *
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#include <linux/init.h>
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/if_arp.h>
#include <linux/inetdevice.h>
#include <linux/etherdevice.h>
#include <linux/types.h>
#include <net/rtnetlink.h>

#include <asm/bug.h>

#include "vr_os.h"
#include "vrouter.h"
#include "vhost.h"
#include "vr_packet.h"

/*
 * When agent dies, cross connect logic would need the list of vhost
 * interfaces which it should put in cross connect. Also, used in cases
 * when physical interface goes away from the system.
 */
struct vhost_priv **vhost_priv_db;
unsigned int vhost_num_interfaces;

extern struct vr_interface vr_reset_interface;

extern int linux_to_vr(struct vr_interface *, struct sk_buff *);

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,39))
extern rx_handler_result_t linux_rx_handler(struct sk_buff **);
#endif

static bool vhost_drv_inited;

static void vhost_ethtool_get_info(struct net_device *netdev,
	struct ethtool_drvinfo *info)
{
    strcpy(info->driver, "vrouter");
    strcpy(info->version, "N/A");
    strcpy(info->fw_version, "N/A");
    strcpy(info->bus_info, "N/A");
}

static const struct ethtool_ops vhost_ethtool_ops = {
    .get_drvinfo	= vhost_ethtool_get_info,
    .get_link		= ethtool_op_get_link,
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,39)) && defined(CONFIG_XEN)
    .get_tso		= ethtool_op_get_tso,
    .set_tso		= ethtool_op_set_tso,
    .get_flags		= ethtool_op_get_flags,
#endif
};

unsigned int
vhost_get_ip(struct vr_interface *vif)
{
    struct net_device *dev = (struct net_device *)vif->vif_os;
    struct in_device *in_dev = rcu_dereference(dev->ip_ptr);
    struct in_ifaddr *ifa;

    if (!in_dev)
        return 0;

    ifa = in_dev->ifa_list;
    if (ifa) 
        return ifa->ifa_address;

    return 0;
}

static void
vhost_dev_destructor(struct net_device *dev)
{
    free_netdev(dev);

    return;
}

static int
vhost_dev_open(struct net_device *dev)
{
    netif_start_queue(dev);

    return 0;
}

static int
vhost_dev_stop(struct net_device *dev)
{
    netif_stop_queue(dev);

    return 0;
}

static int
vhost_dev_set_mac_address(struct net_device *dev, void *addr)
{
    struct sockaddr *mac = addr;

    if (!is_valid_ether_addr(mac->sa_data))
        return -EADDRNOTAVAIL;

    memcpy(dev->dev_addr, mac->sa_data, ETH_ALEN);

    return 0;
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,39))
/*
 * this handler comes into play only for a brief moment: when the agent resets
 * vrouter, a process in which all the vifs are removed, this rx handler is
 * installed on the physical device with argument (rx_handler_data) set to the
 * vhost device
 */
rx_handler_result_t
vhost_rx_handler(struct sk_buff **pskb)
{
    struct net_device *vdev;
    struct sk_buff *skb = *pskb;

    vdev = rcu_dereference(skb->dev->rx_handler_data);
    if (!vdev) {
        kfree_skb(*pskb);
        return RX_HANDLER_CONSUMED;
    }

    if ((skb = skb_share_check(skb, GFP_ATOMIC)) == NULL)
        return RX_HANDLER_PASS;

    skb->dev = vdev;

    (void)__sync_fetch_and_add(&vdev->stats.rx_bytes, skb->len);
    (void)__sync_fetch_and_add(&vdev->stats.rx_packets, 1);


    return RX_HANDLER_ANOTHER;
}
#endif


void
vhost_del_tap_phys(struct net_device *pdev)
{
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,39))
    if (rcu_dereference(pdev->rx_handler) == vhost_rx_handler)
        netdev_rx_handler_unregister(pdev);
#else
    vr_set_vif_ptr(pdev, NULL);
#endif

    return;
}

/*
 * register an rx handler which will bypass all vrouter processing. Helpful
 * at the time of vrouter soft reset. For kernels that does not support rx
 * handler tap, the logic is handled in linux_rx_handler, albeit in an
 * inefficient way (but works :)
 */
void
vhost_tap_phys(struct net_device *vdev, struct net_device *pdev)
{
    struct vhost_priv *vp;

    if (!vdev || !pdev)
        return;

    vp = netdev_priv(vdev);
    /*
     * with vhost_attach_phys, it is possible that everything was OK except
     * that the physical went out and came back. if that is the case, do not
     * tap here
     */
    if (vp->vp_vifp)
        goto exit_tap_phys;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,39))
    /*
     * it can so happen (unlikely) that vhost is deleted from vrouter
     * before the physical, in which case we will have to unregister
     * the rx handler in physical and install the vhost_rx_handler
     */
    if (rcu_dereference(pdev->rx_handler) == linux_rx_handler)
        netdev_rx_handler_unregister(pdev);

    if (!rcu_dereference(pdev->rx_handler))
        netdev_rx_handler_register(pdev, vhost_rx_handler, (void *)vdev);

#else
    vr_set_vif_ptr(pdev, &vr_reset_interface);
#endif

exit_tap_phys:
    return;
}

void
vhost_if_del(struct net_device *dev)
{
    struct vhost_priv *vp;

    if (!dev)
        return;

    vp = netdev_priv(dev);
    vp->vp_vifp = NULL;
    if (vp->vp_phys_dev)
        vhost_tap_phys(dev, vp->vp_phys_dev);

    return;
}

void
vhost_if_add(struct vr_interface *vif)
{
    int i;
    struct net_device *dev = (struct net_device *)vif->vif_os;
    struct vhost_priv *vp = netdev_priv(dev);

    vp->vp_vifp = vif;
    if (vif->vif_type == VIF_TYPE_HOST) {
        if (vif->vif_bridge) {
            /*
             * if there already was an association, need to remove that
             */
            if ((vp->vp_phys_dev) &&
                    (vp->vp_phys_dev !=
                     ((struct net_device *)vif->vif_bridge->vif_os))) {
                vhost_del_tap_phys(vp->vp_phys_dev);
            }

            vp->vp_phys_dev =
                (struct net_device *)vif->vif_bridge->vif_os;
            strncpy(vp->vp_phys_name, vp->vp_phys_dev->name,
                    sizeof(vp->vp_phys_name));

            if (vp->vp_phys_dev->type != ARPHRD_ETHER) {
                dev->flags |= IFF_NOARP;
            } else {
                dev->flags &= ~IFF_NOARP;
            }

            if (vp->vp_db_index >= 0)
                return;

            /* ...may be a bitmap? */
            for (i = 0; i < VHOST_MAX_INTERFACES; i++)
                if (!vhost_priv_db[i])
                    break;

            if (i < VHOST_MAX_INTERFACES) {
                vp->vp_db_index = i;
                vhost_priv_db[i] = vp;
            } else {
                vr_printf("%s not added to vhost database. ",
                        vp->vp_dev->name);
                vr_printf("Cross connect will not work\n"); 
            }
        }
    }

    return;
}

void
vhost_attach_phys(struct net_device *dev)
{
    int i;
    struct vhost_priv *vp;

    if (!vhost_priv_db)
        return;

    for (i = 0; i < VHOST_MAX_INTERFACES; i++) {
        vp = vhost_priv_db[i];
        if (vp) {
            if (!strncmp(dev->name, vp->vp_phys_name, VR_INTERFACE_NAME_LEN)) {
                vp->vp_phys_dev = dev;
                vhost_tap_phys(vp->vp_dev, dev);
                break;
            }
        }
    }

    return;
}

static struct vhost_priv *
vhost_get_priv_for_phys(struct net_device *dev)
{
    int i;
    struct vhost_priv *vp;

    if (!vhost_priv_db)
        return NULL;

    for (i = 0; i < VHOST_MAX_INTERFACES; i++) {
        vp = vhost_priv_db[i];
        if (vp)
            if (vp->vp_phys_dev == dev)
                return vp;
    }

    return NULL;
}

struct net_device *
vhost_get_vhost_for_phys(struct net_device *dev)
{
    struct vhost_priv *vp;

    vp = vhost_get_priv_for_phys(dev);
    if (!vp)
        return NULL;

    return vp->vp_dev;
}

/*
 * when the vif is deleted, we need to bypass vrouter and start sending
 * packets directly to vhost interface
 */
void
vhost_if_del_phys(struct net_device *dev)
{
    struct vhost_priv *vp;

    if (!dev)
        return;

    vp = vhost_get_priv_for_phys(dev);
    if (vp)
        vhost_tap_phys(vp->vp_dev, vp->vp_phys_dev);

    return;
}

/*
 * it is quite possible that the physical interface goes away from the
 * system. when the interface goes away, we need to release the tap
 */
void
vhost_detach_phys(struct net_device *dev)
{
    struct vhost_priv *vp;

    vp = vhost_get_priv_for_phys(dev);
    if (vp) {
        /*
         * if vrouter was left uninited post reset and then the
         * physical interface went away, we need to detach the tap
         */
        vhost_del_tap_phys(vp->vp_phys_dev);
        vp->vp_phys_dev = NULL;
        return;
    }

    return;
}

void
vhost_remove_xconnect(void)
{
    int i;
    struct vhost_priv *vp;
    struct vr_interface *bridge;

    if (!vhost_priv_db)
        return;

    for (i = 0; i < VHOST_MAX_INTERFACES; i++) {
        vp = vhost_priv_db[i];
        if (vp) {
            if (vp->vp_vifp) {
                vif_remove_xconnect(vp->vp_vifp);
                if ((bridge = vp->vp_vifp->vif_bridge))
                    vif_remove_xconnect(bridge);
            }
        }
    }

    return;
}

void
vhost_xconnect(void)
{
    int i;
    struct vhost_priv *vp;
    struct vr_interface *bridge;

    if (!vhost_priv_db)
        return;

    for (i = 0; i < VHOST_MAX_INTERFACES; i++) {
        vp = vhost_priv_db[i];
        if (vp) {
            if (vp->vp_vifp) {
                vif_set_xconnect(vp->vp_vifp);
                if ((bridge = vp->vp_vifp->vif_bridge))
                    vif_set_xconnect(bridge);
            }
        }
    }

    return;
}

netdev_tx_t
vhost_dev_xmit(struct sk_buff *skb, struct net_device *dev)
{
    struct vhost_priv *vp;
    struct vr_interface *vifp;
    struct net_device *pdev;

    vp = netdev_priv(dev);
    vifp = vp->vp_vifp;
    if (!vifp) {
        if (!(pdev = vp->vp_phys_dev)) {
            (void)__sync_fetch_and_add(&dev->stats.tx_dropped, 1);
            kfree_skb(skb);
            return NETDEV_TX_OK;
        }

        skb->dev = pdev;
        dev_queue_xmit(skb);
    } else {
        linux_to_vr(vifp, skb);
    }

    (void)__sync_fetch_and_add(&dev->stats.tx_packets, 1);
    (void)__sync_fetch_and_add(&dev->stats.tx_bytes, skb->len);

    return NETDEV_TX_OK;
}

static struct net_device_ops vhost_dev_ops = {
    .ndo_open               =       vhost_dev_open,
    .ndo_stop               =       vhost_dev_stop,
    .ndo_start_xmit         =       vhost_dev_xmit,
    .ndo_set_mac_address    =       vhost_dev_set_mac_address,
};

void
vhost_setup(struct net_device *dev)
{
    struct vhost_priv *vp = netdev_priv(dev);

    /* follow the standard steps */
    random_ether_addr(dev->dev_addr);
    ether_setup(dev);

    dev->needed_headroom = sizeof(struct vr_eth) + sizeof(struct agent_hdr);
    dev->netdev_ops = &vhost_dev_ops;
    dev->destructor = vhost_dev_destructor;
#ifdef CONFIG_XEN
    dev->ethtool_ops = &vhost_ethtool_ops;
    dev->features |= NETIF_F_GRO;
#endif

    vp->vp_db_index = -1;
    vp->vp_dev = dev;
    vhost_num_interfaces++;

    return;
}

#if (LINUX_VERSION_CODE == KERNEL_VERSION(2,6,32))
static void
vhost_dellink(struct net_device *dev)
#else
static void
vhost_dellink(struct net_device *dev, struct list_head *head)
#endif
{
    struct vhost_priv *vp;

#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,6,33))
    unregister_netdevice_queue(dev, head);
#else
    unregister_netdevice(dev);
#endif

    vp = netdev_priv(dev);
    if (vp) {
        if (vp->vp_db_index >= 0)
            vhost_priv_db[vp->vp_db_index] = NULL;

        vp->vp_db_index = -1;

        if (vp->vp_phys_dev) {
            vhost_del_tap_phys(vp->vp_phys_dev);
            vp->vp_phys_dev = NULL;
        }

        vp->vp_phys_name[0] = '\0';
    }

    if (!vhost_num_interfaces)
        BUG();
    vhost_num_interfaces--;

    return;
}

static int
vhost_validate(struct nlattr *tb[], struct nlattr *data[])
{
    if (vhost_num_interfaces >= VHOST_MAX_INTERFACES)
        return -ENOMEM;

    return 0;
}

static struct rtnl_link_ops vhost_link_ops = {
    .kind       =   VHOST_KIND,
    .priv_size  =   sizeof(struct vhost_priv),
    .setup      =   vhost_setup,
    .validate   =   vhost_validate,
    .dellink    =   vhost_dellink,
};


static void
vhost_netlink_exit(void)
{
    if (vhost_drv_inited) {
        rtnl_link_unregister(&vhost_link_ops);
    }

    vhost_drv_inited = false;

    return;
}

static int
vhost_netlink_init(void)
{
    int ret;

    if (vhost_drv_inited)
        return 0;

    ret = rtnl_link_register(&vhost_link_ops);
    if (ret) {
        return ret;
    }

    vhost_drv_inited = true;

    return 0;
}

void
vhost_exit(void)
{
    vhost_netlink_exit();
    if (vhost_priv_db)
        kfree(vhost_priv_db);

    return;
}

int
vhost_init(void)
{
    if (!vhost_priv_db) {
        vhost_priv_db =
            kzalloc(sizeof(struct vhost_priv *) * VHOST_MAX_INTERFACES,
                    GFP_KERNEL);
        if (!vhost_priv_db)
            return -ENOMEM;
    }

    return vhost_netlink_init();
}
