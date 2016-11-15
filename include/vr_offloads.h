/*
 * vr_offloads.h -- register callbacks for hardware offload features
 *
 * Copyright (c) 2016 Netronome Systems, Inc. All rights reserved.
 */

#ifndef __VR_OFFLOADS_H__
#define __VR_OFFLOADS_H__

#include <vr_os.h>
#include <vr_types.h>
#include <vr_defs.h>
#if defined(__KERNEL__) &&  defined(__linux__)
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/netdevice.h>
#endif
#include <vr_interface.h>
#include <vr_nexthop.h>
#include <vr_flow.h>
#include <vr_mirror.h>
#include <vr_route.h>

#define VR_OFFLOAD_VER_MAJ 3
#define VR_OFFLOAD_VER_MIN 1
#define VR_OFFLOAD_VER_REV 0

#define VR_OFFLOAD_VER ((VR_OFFLOAD_VER_MAJ << 24) | \
                       (VR_OFFLOAD_VER_MIN << 16) | \
                       (VR_OFFLOAD_VER_REV << 8))

struct vr_offload_ops {
    char *handler_id;   /* Hardware vendor identifier */

    /* perform soft reset, including initializing tables */
    int (*soft_reset)(void);

    /* flow related functions */
    int (*flow_set)(struct vr_flow_entry *, unsigned int,
                    struct vr_flow_entry *);
    int (*flow_del)(struct vr_flow_entry *);
    int (*flow_meta_data_set)(unsigned int, unsigned int, void *,
                              unsigned short);

    /* Interface */
    int (*interface_add)(struct vr_interface *);
    int (*interface_del)(struct vr_interface *);
    int (*interface_get)(vr_interface_req *);

    /* vif_vrf table */
    int (*vif_vrf_set)(vr_vrf_assign_req *);
    int (*vif_vrf_get)(vr_vrf_assign_req *);

    /* MPLS (ILM) */
    int (*mpls_add)(struct vr_nexthop *, int);
    int (*mpls_del)(int);
    int (*mpls_get)(vr_mpls_req *);

    /* VXLAN (VNID) */
    int (*vxlan_add)(struct vr_nexthop *, int);
    int (*vxlan_del)(int);
    int (*vxlan_get)(vr_vxlan_req *);

    /* Mirror table */
    int (*mirror_add)(struct vr_mirror_entry *, unsigned int);
    int (*mirror_del)(unsigned int);
    int (*mirror_get)(vr_mirror_req *);

    /* NHOP */
    int (*nexthop_add)(struct vr_nexthop *);
    int (*nexthop_del)(struct vr_nexthop *);
    int (*nexthop_get)(struct vr_nexthop *, vr_nexthop_req *);

    /* route */
    int (*route_add)(vr_route_req *);
    int (*route_del)(vr_route_req *);
    int (*route_get)(vr_route_req *);

    /* QoS */
    int (*fc_map_add)(vr_fc_map_req *);
    int (*fc_map_del)(vr_fc_map_req *);
    int (*fc_map_get)(vr_fc_map_req *);

    int (*qos_map_add)(vr_qos_map_req *);
    int (*qos_map_del)(vr_qos_map_req *);
    int (*qos_map_get)(vr_qos_map_req *);
};

extern struct vr_offload_ops *offload_ops;

int vr_offload_version(void);
int vr_offload_init_handler(void);
int vr_offload_register(int version, const struct vr_offload_ops *new_handler);
int vr_offload_unregister(void);
void vr_offload_cleanup_handler(void);

/* Wrappers for calling offload function with locking in place */
static inline int vr_offload_soft_reset(void)
{
#if defined(__KERNEL__) && defined(__linux__)
    struct vr_offload_ops *offload = rcu_dereference(offload_ops);

    if (offload && offload->soft_reset)
        return offload->soft_reset();
#endif
    return 0;
}

/* Flow offload functions */
static inline void vr_offload_flow_set(struct vr_flow_entry * fe,
                                       unsigned int fe_index,
                                       struct vr_flow_entry * rfe)
{
#if defined(__KERNEL__) && defined(__linux__)
    struct vr_offload_ops *offload = rcu_dereference(offload_ops);

    if (offload && offload->flow_set)
        offload->flow_set(fe, fe_index, rfe);
#endif
}

static inline void vr_offload_flow_del(struct vr_flow_entry * fe)
{
#if defined(__KERNEL__) && defined(__linux__)
    struct vr_offload_ops *offload = rcu_dereference(offload_ops);

    if (offload && offload->flow_del)
        offload->flow_del(fe);
#endif
}

/*
 * Used both to set and reset meta data entry for a flow.
 */
static inline void vr_offload_flow_meta_data_set(unsigned int fe_index,
                                                 unsigned int meta_data_len,
                                                 void *meta_data,
                                                 unsigned short mir_vrf)
{
#if defined(__KERNEL__) && defined(__linux__)
    struct vr_offload_ops *offload = rcu_dereference(offload_ops);

    if (offload && offload->flow_meta_data_set)
        offload->flow_meta_data_set(fe_index, meta_data_len,
                                    meta_data, mir_vrf);
#endif
}

/* interface offload functions */
static inline int vr_offload_interface_add(struct vr_interface * intf)
{
#if defined(__KERNEL__) && defined(__linux__)
    struct vr_offload_ops *offload = rcu_dereference(offload_ops);

    if (offload && offload->interface_add)
        return offload->interface_add(intf);
#endif
    return 0;
}

static inline void vr_offload_interface_get(vr_interface_req *resp)
{
#if defined(__KERNEL__) && defined(__linux__)
    struct vr_offload_ops *offload = rcu_dereference(offload_ops);

    if (offload && offload->interface_get)
        offload->interface_get(resp);
#endif
}

static inline void vr_offload_interface_del(struct vr_interface * intf)
{
#if defined(__KERNEL__) && defined(__linux__)
    struct vr_offload_ops *offload = rcu_dereference(offload_ops);

    if (offload && offload->interface_del)
        offload->interface_del(intf);
#endif
}

static inline int vr_offload_vif_vrf_set(vr_vrf_assign_req *req)
{
#if defined(__KERNEL__) && defined(__linux__)
    struct vr_offload_ops *offload = rcu_dereference(offload_ops);

    if (offload && offload->vif_vrf_set)
       return offload->vif_vrf_set(req);
#endif
    return 0;
}

static inline void vr_offload_vif_vrf_get(vr_vrf_assign_req *resp)
{
#if defined(__KERNEL__) && defined(__linux__)
    struct vr_offload_ops *offload = rcu_dereference(offload_ops);

    if (offload && offload->vif_vrf_get)
        offload->vif_vrf_get(resp);
#endif
}

static inline int vr_offload_nexthop_add(struct vr_nexthop * nh)
{
#if defined(__KERNEL__) && defined(__linux__)
    struct vr_offload_ops *offload = rcu_dereference(offload_ops);

    if (offload && offload->nexthop_add)
        return offload->nexthop_add(nh);
#endif
    return 0;
}

static inline void vr_offload_nexthop_del(struct vr_nexthop * nh)
{
#if defined(__KERNEL__) && defined(__linux__)
    struct vr_offload_ops *offload = rcu_dereference(offload_ops);

    if (offload && offload->nexthop_del)
        offload->nexthop_del(nh);
#endif
}

static inline void vr_offload_nexthop_get(struct vr_nexthop * nh,
                                          vr_nexthop_req * resp)
{
#if defined(__KERNEL__) && defined(__linux__)
    struct vr_offload_ops *offload = rcu_dereference(offload_ops);

    if (offload && offload->nexthop_get)
        offload->nexthop_get(nh, resp);
#endif
}

static inline int vr_offload_mpls_add(struct vr_nexthop * nh, int label)
{
#if defined(__KERNEL__) && defined(__linux__)
    struct vr_offload_ops *offload = rcu_dereference(offload_ops);

    if (offload && offload->mpls_add)
        return offload->mpls_add(nh, label);
#endif
    return 0;
}

static inline void vr_offload_mpls_get(vr_mpls_req * resp)
{
#if defined(__KERNEL__) && defined(__linux__)
    struct vr_offload_ops *offload = rcu_dereference(offload_ops);

    if (offload && offload->mpls_get)
        offload->mpls_get(resp);
#endif
}

static inline void vr_offload_mpls_del(int label)
{
#if defined(__KERNEL__) && defined(__linux__)
    struct vr_offload_ops *offload = rcu_dereference(offload_ops);

    if (offload && offload->mpls_del)
        offload->mpls_del(label);
#endif
}

static inline int vr_offload_vxlan_add(struct vr_nexthop * nh, int vnid)
{
#if defined(__KERNEL__) && defined(__linux__)
    struct vr_offload_ops *offload = rcu_dereference(offload_ops);
    if (offload && offload->vxlan_add)
        return offload->vxlan_add(nh, vnid);
#endif
    return 0;
}

static inline void vr_offload_vxlan_get(vr_vxlan_req * resp)
{
#if defined(__KERNEL__) && defined(__linux__)
    struct vr_offload_ops *offload = rcu_dereference(offload_ops);

    if (offload && offload->vxlan_get)
        offload->vxlan_get(resp);
#endif
}

static inline void vr_offload_vxlan_del(int vnid)
{
#if defined(__KERNEL__) && defined(__linux__)
    struct vr_offload_ops *offload = rcu_dereference(offload_ops);

    if (offload && offload->vxlan_del)
        offload->vxlan_del(vnid);
#endif
}

static inline int vr_offload_mirror_add(struct vr_mirror_entry * mirror,
                                        unsigned int index)
{
#if defined(__KERNEL__) && defined(__linux__)
    struct vr_offload_ops *offload = rcu_dereference(offload_ops);

    if (offload && offload->mirror_add)
        return offload->mirror_add(mirror, index);
#endif
    return 0;
}

static inline void vr_offload_mirror_del(unsigned int index)
{
#if defined(__KERNEL__) && defined(__linux__)
    struct vr_offload_ops *offload = rcu_dereference(offload_ops);

    if (offload && offload->mirror_del)
        offload->mirror_del(index);
#endif
}

static inline void vr_offload_mirror_get(vr_mirror_req * resp)
{
#if defined(__KERNEL__) && defined(__linux__)
    struct vr_offload_ops *offload = rcu_dereference(offload_ops);

    if (offload && offload->mirror_get)
        offload->mirror_get(resp);
#endif
}

static inline void vr_offload_route_del(vr_route_req * req)
{
#if defined(__KERNEL__) && defined(__linux__)
    struct vr_offload_ops *offload = rcu_dereference(offload_ops);

    if (offload && offload->route_del)
        offload->route_del(req);
#endif
}

static inline int vr_offload_route_add(vr_route_req * req)
{
#if defined(__KERNEL__) && defined(__linux__)
    struct vr_offload_ops *offload = rcu_dereference(offload_ops);

    if (offload && offload->route_add)
        return offload->route_add(req);
#endif
    return 0;
}

static inline void vr_offload_route_get(vr_route_req * req)
{
#if defined(__KERNEL__) && defined(__linux__)
    struct vr_offload_ops *offload = rcu_dereference(offload_ops);

    if (offload && offload->route_get)
        offload->route_get(req);
#endif
}


static inline int vr_offload_fc_map_add(vr_fc_map_req * req)
{
#if defined(__KERNEL__) && defined(__linux__)
    struct vr_offload_ops *offload = rcu_dereference(offload_ops);

    if (offload && offload->fc_map_add)
        return offload->fc_map_add(req);
#endif
    return 0;
}

static inline int vr_offload_fc_map_del(vr_fc_map_req * req)
{
#if defined(__KERNEL__) && defined(__linux__)
    struct vr_offload_ops *offload = rcu_dereference(offload_ops);

    if (offload && offload->fc_map_del)
        return offload->fc_map_del(req);
#endif
    return 0;
}

static inline int vr_offload_fc_map_get(vr_fc_map_req * req)
{
#if defined(__KERNEL__) && defined(__linux__)
    struct vr_offload_ops *offload = rcu_dereference(offload_ops);

    if (offload && offload->fc_map_get)
        return offload->fc_map_get(req);
#endif
    return 0;
}

static inline int vr_offload_qos_map_add(vr_qos_map_req * req)
{
#if defined(__KERNEL__) && defined(__linux__)
    struct vr_offload_ops *offload = rcu_dereference(offload_ops);

    if (offload && offload->qos_map_add)
        return offload->qos_map_add(req);
#endif
    return 0;
}

static inline int vr_offload_qos_map_del(vr_qos_map_req * req)
{
#if defined(__KERNEL__) && defined(__linux__)
    struct vr_offload_ops *offload = rcu_dereference(offload_ops);

    if (offload && offload->qos_map_del)
        return offload->qos_map_del(req);
#endif
    return 0;
}

static inline int vr_offload_qos_map_get(vr_qos_map_req * req)
{
#if defined(__KERNEL__) && defined(__linux__)
    struct vr_offload_ops *offload = rcu_dereference(offload_ops);

    if (offload && offload->qos_map_get)
        return offload->qos_map_get(req);
#endif
    return 0;
}

#endif
