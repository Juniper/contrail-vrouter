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
#include <linux/inetdevice.h>
#include <linux/etherdevice.h>
#include <linux/types.h>
#include <net/rtnetlink.h>

#include "vhost.h"
#include "vrouter.h"
#include "vr_packet.h"

extern int linux_to_vr(struct vr_interface *, struct sk_buff *);
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

void
vhost_if_del(struct net_device *dev)
{
    struct vhost_priv *vp;

    if (!dev)
        return;

    vp = netdev_priv(dev);
    vp->vp_vifp = NULL;

    return;
}

void
vhost_if_add(struct vr_interface *vif)
{
    struct net_device *dev = (struct net_device *)vif->vif_os;
    struct vhost_priv *vp = netdev_priv(dev);

    vp->vp_vifp = vif;

    return;
}

netdev_tx_t
vhost_dev_xmit(struct sk_buff *skb, struct net_device *dev)
{
    struct vhost_priv *vp;
    struct vr_interface *vifp;

    vp = netdev_priv(dev);
    vifp = vp->vp_vifp;
    if (!vifp) {
        (void)__sync_fetch_and_add(&dev->stats.tx_dropped, 1);
        kfree_skb(skb);
    } else {
        (void)__sync_fetch_and_add(&dev->stats.tx_packets, 1);
        (void)__sync_fetch_and_add(&dev->stats.tx_bytes, skb->len);
        linux_to_vr(vifp, skb);
    }

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
    /* follow the standard steps */
    random_ether_addr(dev->dev_addr);
    ether_setup(dev);

    dev->needed_headroom = sizeof(struct vr_eth) + sizeof(struct agent_hdr);
    dev->netdev_ops = &vhost_dev_ops;
    dev->destructor = vhost_dev_destructor;
#ifdef CONFIG_XEN
    SET_ETHTOOL_OPS(dev, &vhost_ethtool_ops);
    dev->features |= NETIF_F_GRO;
#endif
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
    vhost_if_del(dev);
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,6,33))
    unregister_netdevice_queue(dev, head);
#else
    unregister_netdevice(dev);
#endif

    return;
}

static int
vhost_validate(struct nlattr *tb[], struct nlattr *data[])
{
    return 0;
}

static int
vhost_notifier(struct notifier_block * __unused,
        unsigned long event, void *arg)
{
    struct net_device *dev = arg;

    if (event == NETDEV_UNREGISTER &&
            dev->netdev_ops == &vhost_dev_ops) {
        vhost_if_del(dev);
        return NOTIFY_OK;
    }

    return NOTIFY_DONE;
}

struct notifier_block vhost_nb = {
    .notifier_call      =   vhost_notifier,
};

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
        unregister_netdevice_notifier(&vhost_nb);
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

    ret = register_netdevice_notifier(&vhost_nb);
    if (ret)
        return ret;

    ret = rtnl_link_register(&vhost_link_ops);
    if (ret) {
        unregister_netdevice_notifier(&vhost_nb);
        return ret;
    }

    vhost_drv_inited = true;

    return 0;
}

void
vhost_exit(void)
{
    vhost_netlink_exit();
    return;
}

int
vhost_init(void)
{
    return vhost_netlink_init();
}
