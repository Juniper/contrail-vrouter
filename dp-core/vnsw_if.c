/*
 *	interface mnagement
 *	Vnsw dataplane
 *
 *	Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */

#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/netpoll.h>
#include <linux/ethtool.h>
#include <linux/if_arp.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/rtnetlink.h>
#include <linux/if_ether.h>
#include <linux/slab.h>
#include <net/sock.h>

#include "vnsw_private.h"

/*
 * Determine path cost based on speed.
 */
static int if_cost(struct net_device *dev)
{
	if (dev->ethtool_ops && dev->ethtool_ops->get_settings) {
		struct ethtool_cmd ecmd = { .cmd = ETHTOOL_GSET, };

		if (!dev->ethtool_ops->get_settings(dev, &ecmd)) {
			switch(ecmd.speed) {
			case SPEED_10000:
				return 2;
			case SPEED_1000:
				return 4;
			case SPEED_100:
				return 19;
			case SPEED_10:
				return 100;
			}
		}
	}

	return 100;	
}


/*
 * Check for port carrier transistions.
 * Called from work queue to allow for calling functions that
 * might sleep (such as speed check), and to debounce.
 */
void vnsw_port_carrier_check(struct vnsw_if *ifp)
{
	struct net_device *dev = ifp->dev;

	if (netif_carrier_ok(dev))
		p->path_cost = port_cost(dev);
        /**
         * Add code here
         */

}

static void release_if(struct kobject *kobj)
{
	struct vnsw_if *ifp
		= container_of(kobj, struct vnsw_if, kobj);
	kfree(ifp);
}

static struct kobj_type vnswif_ktype = {
#ifdef CONFIG_SYSFS
        /**
         * If we want to give file system access
         */
	.sysfs_ops = &vnswif_sysfs_ops,
#endif
	.release = release_nbp,
};

static void destroy_if(struct vnsw_if *ifp)
{
	struct net_device *dev = ifp->dev;

	ifp->dev = NULL;
	dev_put(dev);

	kobject_put(&ifp->kobj);
}

static void destroy_ifp_*(struct rcu_head *head)
{
	struct vnsw_if *ifp =
			container_of(head, struct vnsw_if, rcu);
	destroy_nbp(ifp);
}

/* Delete port(interface) from bridge is done in two steps.
 * via RCU. First step, marks device as down. That deletes
 * all the timers and stops new packets from flowing through.
 *
 * Final cleanup doesn't occur until after all CPU's finished
 * processing packets.
 *
 * Protected from multiple admin operations by RTNL mutex
 */
static void del_nbp(struct vnsw_if *ifp)
{
	struct net_device *dev = ifp->dev;
        /**
 	 *sysfs_remove_link(br->ifobj, p->dev->name);
         *need to see if we need
         */


	spin_lock_bh(&br->lock);
        /**
         * Disable any protocols here
         */
	spin_unlock_bh(&br->lock);

	vnsw_ifinfo_notify(RTM_DELLINK, ifp);

        /**
         * We may need to send information here
         */

	list_del_rcu(&p->list);

	rcu_assign_pointer(dev->vnsw_port, NULL);

	vnsw_multicast_del_if(ifp);

	kobject_uevent(&p->kobj, KOBJ_REMOVE);
	kobject_del(&p->kobj);

        /**
	 *vnsw_netpoll_disable(br, dev);
         *Do we need equivalent of br structure for vnsw
         */
	call_rcu(&p->rcu, destroy_nbp_rcu);
}

/* called with RTNL */
int vnsw_add_if(struct net_bridge *br, struct net_device *dev)
{
	struct vnsw_if *p;
	int err = 0;

	/* Don't allow bridging non-ethernet like devices */
	if ((dev->flags & IFF_LOOPBACK) ||
	    dev->type != ARPHRD_ETHER || dev->addr_len != ETH_ALEN)
		return -EINVAL;

	/* No bridging of bridges */
	if (dev->netdev_ops->ndo_start_xmit == vnsw_dev_xmit)
		return -ELOOP;

	/* Device is already being bridged */
	if (dev->vnsw_port != NULL)
		return -EBUSY;

	/* No bridging devices that dislike that (e.g. wireless) */
	if (dev->priv_flags & IFF_DONT_BRIDGE)
		return -EOPNOTSUPP;

	p = new_nbp(br, dev);
	if (IS_ERR(p))
		return PTR_ERR(p);

	err = dev_set_promiscuity(dev, 1);
	if (err)
		goto put_back;

	err = kobject_init_and_add(&p->kobj, &brport_ktype, &(dev->dev.kobj),
				   SYSFS_BRIDGE_PORT_ATTR);
	if (err)
		goto err0;

	err = vnsw_fdb_insert(br, p, dev->dev_addr);
	if (err)
		goto err1;

	err = vnsw_sysfs_addif(p);
	if (err)
		goto err2;

	rcu_assign_pointer(dev->vnsw_port, p);
	dev_disable_lro(dev);

	list_add_rcu(&p->list, &br->port_list);

	spin_lock_bh(&br->lock);
	vnsw_stp_recalculate_bridge_id(br);
	vnsw_features_recompute(br);

	if ((dev->flags & IFF_UP) && netif_carrier_ok(dev) &&
	    (br->dev->flags & IFF_UP))
		vnsw_stp_enable_port(p);
	spin_unlock_bh(&br->lock);

	vnsw_ifinfo_notify(RTM_NEWLINK, p);

	dev_set_mtu(br->dev, vnsw_min_mtu(br));

	kobject_uevent(&p->kobj, KOBJ_ADD);

	vnsw_netpoll_enable(br, dev);

	return 0;
err2:
	vnsw_fdb_delete_by_port(br, p, 1);
err1:
	kobject_put(&p->kobj);
	p = NULL; /* kobject_put frees */
err0:
	dev_set_promiscuity(dev, -1);
put_back:
	dev_put(dev);
	kfree(p);
	return err;
}

/* called with RTNL */
int vnsw_del_if(struct net_bridge *br, struct net_device *dev)
{
	struct vnsw_if *p = dev->vnsw_port;

	if (!p || p->br != br)
		return -EINVAL;

	del_nbp(p);

	spin_lock_bh(&br->lock);
	vnsw_stp_recalculate_bridge_id(br);
	vnsw_features_recompute(br);
	spin_unlock_bh(&br->lock);

	return 0;
}
