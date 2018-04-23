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

#define VR_OFFLOAD_VER_MAJ 4
#define VR_OFFLOAD_VER_MIN 1
#define VR_OFFLOAD_VER_REV 0

#define VR_OFFLOAD_VER ((VR_OFFLOAD_VER_MAJ << 24) | \
                       (VR_OFFLOAD_VER_MIN << 16) | \
                       (VR_OFFLOAD_VER_REV << 8))

#if defined(__KERNEL__) && defined(__linux__)
    #define vr_rcu_dereference(p) rcu_dereference(p);
#else
    #define vr_rcu_dereference(p) NULL;
#endif

struct vr_offload_ops {
    char *voo_handler_id;   /* Hardware vendor identifier */

    /* perform soft reset, including initializing tables */
    int (*voo_soft_reset)(void);

    /* flow related functions */
    int (*voo_flow_set)(struct vr_flow_entry *, unsigned int,
                    struct vr_flow_entry *);
    int (*voo_flow_del)(struct vr_flow_entry *);
    int (*voo_flow_meta_data_set)(unsigned int, unsigned int, void *,
                              unsigned short);

    /* Dropstats */
    int (*voo_drop_stats_get)(vr_drop_stats_req *response);

    /* Interface */
    int (*voo_interface_add)(struct vr_interface *);
    int (*voo_interface_del)(struct vr_interface *);
    int (*voo_interface_get)(vr_interface_req *);

    /* vif_vrf table */
    int (*voo_vif_vrf_set)(vr_vrf_assign_req *);
    int (*voo_vif_vrf_get)(vr_vrf_assign_req *);

    /* MPLS (ILM) */
    int (*voo_mpls_add)(struct vr_nexthop *, int);
    int (*voo_mpls_del)(int);
    int (*voo_mpls_get)(vr_mpls_req *);

    /* VXLAN (VNID) */
    int (*voo_vxlan_add)(struct vr_nexthop *, int);
    int (*voo_vxlan_del)(int);
    int (*voo_vxlan_get)(vr_vxlan_req *);

    /* Mirror table */
    int (*voo_mirror_add)(struct vr_mirror_entry *, unsigned int);
    int (*voo_mirror_del)(unsigned int);
    int (*voo_mirror_get)(vr_mirror_req *);

    /* NHOP */
    int (*voo_nexthop_add)(struct vr_nexthop *);
    int (*voo_nexthop_del)(struct vr_nexthop *);
    int (*voo_nexthop_get)(struct vr_nexthop *, vr_nexthop_req *);

    /* route */
    int (*voo_route_add)(vr_route_req *);
    int (*voo_route_del)(vr_route_req *);
    int (*voo_route_get)(vr_route_req *);
    int (*voo_route_dump)(struct vr_route_req *);

    /* QoS */
    int (*voo_fc_map_add)(vr_fc_map_req *);
    int (*voo_fc_map_del)(vr_fc_map_req *);
    int (*voo_fc_map_get)(vr_fc_map_req *);

    int (*voo_qos_map_add)(vr_qos_map_req *);
    int (*voo_qos_map_del)(vr_qos_map_req *);
    int (*voo_qos_map_get)(vr_qos_map_req *);
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
    struct vr_offload_ops *offload = vr_rcu_dereference(offload_ops);

    if (offload && offload->voo_soft_reset)
        return offload->voo_soft_reset();
    return 0;
}

/* Flow offload functions */
static inline int vr_offload_flow_set(struct vr_flow_entry * fe,
                                       unsigned int fe_index,
                                       struct vr_flow_entry * rfe)
{
    struct vr_offload_ops *offload = vr_rcu_dereference(offload_ops);

    if (offload && offload->voo_flow_set)
        return offload->voo_flow_set(fe, fe_index, rfe);
    return 0;
}

static inline int vr_offload_flow_del(struct vr_flow_entry * fe)
{
    struct vr_offload_ops *offload = vr_rcu_dereference(offload_ops);

    if (offload && offload->voo_flow_del)
        return offload->voo_flow_del(fe);
    return 0;
}

/*
 * Used both to set and reset meta data entry for a flow.
 */
static inline int vr_offload_flow_meta_data_set(unsigned int fe_index,
                                                 unsigned int meta_data_len,
                                                 void *meta_data,
                                                 unsigned short mir_vrf)
{
    struct vr_offload_ops *offload = vr_rcu_dereference(offload_ops);

    if (offload && offload->voo_flow_meta_data_set)
        return offload->voo_flow_meta_data_set(fe_index, meta_data_len,
                                    meta_data, mir_vrf);
    return 0;
}

/* Dropstats */
static inline int vr_offload_drop_stats_get(vr_drop_stats_req *resp)
{
    struct vr_offload_ops *offload = vr_rcu_dereference(offload_ops);

    if (offload && offload->voo_drop_stats_get)
        return offload->voo_drop_stats_get(resp);
    return 0;
}

/* interface offload functions */
static inline int vr_offload_interface_add(struct vr_interface * intf)
{
    struct vr_offload_ops *offload = vr_rcu_dereference(offload_ops);

    if (offload && offload->voo_interface_add)
        return offload->voo_interface_add(intf);
    return 0;
}

static inline int vr_offload_interface_get(vr_interface_req *resp)
{
    struct vr_offload_ops *offload = vr_rcu_dereference(offload_ops);

    if (offload && offload->voo_interface_get)
        return offload->voo_interface_get(resp);
    return 0;
}

static inline int vr_offload_interface_del(struct vr_interface * intf)
{
    struct vr_offload_ops *offload = vr_rcu_dereference(offload_ops);

    if (offload && offload->voo_interface_del)
        return offload->voo_interface_del(intf);
    return 0;
}

static inline int vr_offload_vif_vrf_set(vr_vrf_assign_req *req)
{
    struct vr_offload_ops *offload = vr_rcu_dereference(offload_ops);

    if (offload && offload->voo_vif_vrf_set)
       return offload->voo_vif_vrf_set(req);
    return 0;
}

static inline int vr_offload_vif_vrf_get(vr_vrf_assign_req *resp)
{
    struct vr_offload_ops *offload = vr_rcu_dereference(offload_ops);

    if (offload && offload->voo_vif_vrf_get)
        return offload->voo_vif_vrf_get(resp);
    return 0;
}

static inline int vr_offload_nexthop_add(struct vr_nexthop * nh)
{
    struct vr_offload_ops *offload = vr_rcu_dereference(offload_ops);

    if (offload && offload->voo_nexthop_add)
        return offload->voo_nexthop_add(nh);
    return 0;
}

static inline int vr_offload_nexthop_del(struct vr_nexthop * nh)
{
    struct vr_offload_ops *offload = vr_rcu_dereference(offload_ops);

    if (offload && offload->voo_nexthop_del)
        return offload->voo_nexthop_del(nh);
    return 0;
}

static inline int vr_offload_nexthop_get(struct vr_nexthop * nh,
                                          vr_nexthop_req * resp)
{
    struct vr_offload_ops *offload = vr_rcu_dereference(offload_ops);

    if (offload && offload->voo_nexthop_get)
        return offload->voo_nexthop_get(nh, resp);
    return 0;
}

static inline int vr_offload_mpls_add(struct vr_nexthop * nh, int label)
{
    struct vr_offload_ops *offload = vr_rcu_dereference(offload_ops);

    if (offload && offload->voo_mpls_add)
        return offload->voo_mpls_add(nh, label);
    return 0;
}

static inline int vr_offload_mpls_get(vr_mpls_req * resp)
{
    struct vr_offload_ops *offload = vr_rcu_dereference(offload_ops);

    if (offload && offload->voo_mpls_get)
        return offload->voo_mpls_get(resp);
    return 0;
}

static inline int vr_offload_mpls_del(int label)
{
    struct vr_offload_ops *offload = vr_rcu_dereference(offload_ops);

    if (offload && offload->voo_mpls_del)
        return offload->voo_mpls_del(label);
    return 0;
}

static inline int vr_offload_vxlan_add(struct vr_nexthop * nh, int vnid)
{
    struct vr_offload_ops *offload = vr_rcu_dereference(offload_ops);
    if (offload && offload->voo_vxlan_add)
        return offload->voo_vxlan_add(nh, vnid);
    return 0;
}

static inline int vr_offload_vxlan_get(vr_vxlan_req * resp)
{
    struct vr_offload_ops *offload = vr_rcu_dereference(offload_ops);

    if (offload && offload->voo_vxlan_get)
        return offload->voo_vxlan_get(resp);
    return 0;
}

static inline int vr_offload_vxlan_del(int vnid)
{
    struct vr_offload_ops *offload = vr_rcu_dereference(offload_ops);

    if (offload && offload->voo_vxlan_del)
        return offload->voo_vxlan_del(vnid);
    return 0;
}

static inline int vr_offload_mirror_add(struct vr_mirror_entry * mirror,
                                        unsigned int index)
{
    struct vr_offload_ops *offload = vr_rcu_dereference(offload_ops);

    if (offload && offload->voo_mirror_add)
        return offload->voo_mirror_add(mirror, index);
    return 0;
}

static inline int vr_offload_mirror_del(unsigned int index)
{
    struct vr_offload_ops *offload = vr_rcu_dereference(offload_ops);

    if (offload && offload->voo_mirror_del)
        return offload->voo_mirror_del(index);
    return 0;
}

static inline int vr_offload_mirror_get(vr_mirror_req * resp)
{
    struct vr_offload_ops *offload = vr_rcu_dereference(offload_ops);

    if (offload && offload->voo_mirror_get)
        return offload->voo_mirror_get(resp);
    return 0;
}

static inline int vr_offload_route_del(vr_route_req * req)
{
    struct vr_offload_ops *offload = vr_rcu_dereference(offload_ops);

    if (offload && offload->voo_route_del)
        return offload->voo_route_del(req);
    return 0;
}

static inline int vr_offload_route_add(vr_route_req * req)
{
    struct vr_offload_ops *offload = vr_rcu_dereference(offload_ops);

    if (offload && offload->voo_route_add)
        return offload->voo_route_add(req);
    return 0;
}

static inline int vr_offload_route_get(vr_route_req * req)
{
    struct vr_offload_ops *offload = vr_rcu_dereference(offload_ops);

    if (offload && offload->voo_route_get)
        return offload->voo_route_get(req);
    return 0;
}

static inline int vr_offload_route_dump(struct vr_route_req * req)
{
    struct vr_offload_ops *offload = vr_rcu_dereference(offload_ops);

    if (offload && offload->voo_route_dump)
        return offload->voo_route_dump(req);
    return 0;
}

static inline int vr_offload_fc_map_add(vr_fc_map_req * req)
{
    struct vr_offload_ops *offload = vr_rcu_dereference(offload_ops);

    if (offload && offload->voo_fc_map_add)
        return offload->voo_fc_map_add(req);
    return 0;
}

static inline int vr_offload_fc_map_del(vr_fc_map_req * req)
{
    struct vr_offload_ops *offload = vr_rcu_dereference(offload_ops);

    if (offload && offload->voo_fc_map_del)
        return offload->voo_fc_map_del(req);
    return 0;
}

static inline int vr_offload_fc_map_get(vr_fc_map_req * req)
{
    struct vr_offload_ops *offload = vr_rcu_dereference(offload_ops);

    if (offload && offload->voo_fc_map_get)
        return offload->voo_fc_map_get(req);
    return 0;
}

static inline int vr_offload_qos_map_add(vr_qos_map_req * req)
{
    struct vr_offload_ops *offload = vr_rcu_dereference(offload_ops);

    if (offload && offload->voo_qos_map_add)
        return offload->voo_qos_map_add(req);
    return 0;
}

static inline int vr_offload_qos_map_del(vr_qos_map_req * req)
{
    struct vr_offload_ops *offload = vr_rcu_dereference(offload_ops);

    if (offload && offload->voo_qos_map_del)
        return offload->voo_qos_map_del(req);
    return 0;
}

static inline int vr_offload_qos_map_get(vr_qos_map_req * req)
{
    struct vr_offload_ops *offload = vr_rcu_dereference(offload_ops);

    if (offload && offload->voo_qos_map_get)
        return offload->voo_qos_map_get(req);
    return 0;
}

#endif /* __VR_OFFLOADS_H__ */
