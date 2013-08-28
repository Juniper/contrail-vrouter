/*
 *	Forwarding decision
 *	Vnsw data path
 *
 *	Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */

#include <linux/err.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/netpoll.h>
#include <linux/skbuff.h>
#include <linux/if_vlan.h>
#include <linux/netfilter_bridge.h>
#include "vnsw_private.h"

static int deliver_clone(const struct vnsw_if *ifprev,
			 struct sk_buff *skb,
			 void (*__packet_hook)(const struct vnsw_if *ifp,
					       struct sk_buff *skb));

/* Don't forward packets to originating port or forwarding diasabled */
static inline int should_deliver(const struct vnsw_if *ifp,
				 const struct sk_buff *skb)
{
	return (((ifp->flags & BR_HAIRPIN_MODE) || skb->dev != ifp->dev) &&
		ifp->state == BR_STATE_FORWARDING);
}

static inline unsigned packet_length(const struct sk_buff *skb)
{
	return skb->len - (skb->protocol == htons(ETH_P_8021Q) ? VLAN_HLEN : 0);
}

int vnsw_dev_queue_push_xmit(struct sk_buff *skb)
{
	/* drop mtu oversized packets except gso */
	if (packet_length(skb) > skb->dev->mtu && !skb_is_gso(skb))
		kfree_skb(skb);
	else {
		/* ip_fragment doesn't copy the MAC header */
		if (nf_bridge_maybe_copy_header(skb))
			kfree_skb(skb);
		else {
			skb_push(skb, ETH_HLEN);
			dev_queue_xmit(skb);
		}
	}

	return 0;
}

int vnsw_forward_finish(struct sk_buff *skb)
{
	return NF_HOOK(NFPROTO_BRIDGE, NF_BR_POST_ROUTING, skb, NULL, skb->dev,
		       vnsw_dev_queue_push_xmit);

}

static void __vnsw_deliver(const struct vnsw_if *to, struct sk_buff *skb)
{
	skb->dev = to->dev;
	NF_HOOK(NFPROTO_BRIDGE, NF_BR_LOCAL_OUT, skb, NULL, skb->dev,
		vnsw_forward_finish);
}

static void __vnsw_forward(const struct vnsw_if *to, struct sk_buff *skb)
{
	struct net_device *indev;

	if (skb_warn_if_lro(skb)) {
		kfree_skb(skb);
		return;
	}

	indev = skb->dev;
	skb->dev = to->dev;
	skb_forward_csum(skb);

	NF_HOOK(NFPROTO_BRIDGE, NF_BR_FORWARD, skb, indev, skb->dev,
		vnsw_forward_finish);
}

/* called with rcu_read_lock */
void vnsw_deliver(const struct vnsw_if *to, struct sk_buff *skb)
{
	if (should_deliver(to, skb)) {
		__vnsw_deliver(to, skb);
		return;
	}

	kfree_skb(skb);
}

/* called with rcu_read_lock */
void vnsw_forward(const struct vnsw_if *to, struct sk_buff *skb, struct sk_buff *skb0)
{
	if (should_deliver(to, skb)) {
		if (skb0)
			deliver_clone(to, skb, __vnsw_forward);
		else
			__vnsw_forward(to, skb);
		return;
	}

	if (!skb0)
		kfree_skb(skb);
}

static int deliver_clone(const struct vnsw_if *prev,
			 struct sk_buff *skb,
			 void (*__packet_hook)(const struct vnsw_if *ifp,
					       struct sk_buff *skb))
{
	struct net_device *dev = VNSW_IN_SKB_CB(skb)->brdev;

	skb = skb_clone(skb, GFP_ATOMIC);
	if (!skb) {
		dev->stats.tx_dropped++;
		return -ENOMEM;
	}

	__packet_hook(prev, skb);
	return 0;
}

static struct vnsw_if *maybe_deliver(
	struct vnsw_if *ifprev, struct vnsw_if *ifp,
	struct sk_buff *skb,
	void (*__packet_hook)(const struct vnsw_if *ifp,
			      struct sk_buff *skb))
{
	int err;

	if (!should_deliver(p, skb))
		return prev;

	if (!prev)
		goto out;

        /**
         * Need to check if we deliver clone?
         */
	err = deliver_clone(prev, skb, __packet_hook);
	if (err)
		return ERR_PTR(err);

out:
	return ifp;
}

/* called with rcu_read_lock */
static void vnsw_multicast_send(struct net_vnsw_mdb_entry *mdst,
			       struct sk_buff *skb, struct sk_buff *skb0,
			       void (*__packet_hook)(
					const struct vnsw_if *ifp,
					struct sk_buff *skb))
{
    /**
     * add multicast forwarding here
     */
}

/* called with rcu_read_lock */
void vnsw_multicast_deliver(struct net_vnsw_mdb_entry *mdst,
			  struct sk_buff *skb)
{
	vnsw_multicast_send(mdst, skb, NULL, __vnsw_deliver);
}

/* called with rcu_read_lock */
void vnsw_multicast_forward(struct net_vnsw_mdb_entry *mdst,
			  struct sk_buff *skb, struct sk_buff *skb2)
{
	vnsw_multicast_send(mdst, skb, skb2, __vnsw_forward);
}
