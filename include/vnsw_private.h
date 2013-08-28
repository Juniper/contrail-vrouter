/*
 *	vnsw_private.h - vnsw structures
 *
 *	Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */

/* structure representing  vnsw instance */
struct vnsw_cb {   
    struct list_head *vcb_if_list; /*list of interfaces in the vnsw*/
    struct list_head *vcb_vrf_lst;
};

struct vnsw_vrf {
    struct list_head *vrf_list_node;
    u32               vrf_id;
    struct ip4_mtrie *vrf_mtrie;
};

struct vnsw_if {  /* switch interface structure */
    struct list_head  *if_list_node;
    struct vnsw_cb    *if_vnswcb;
    struct net_device *if_dev
};

struct vnsw_rx_skb_cb {
    struct vnsw_if *cb_rxif;
};

