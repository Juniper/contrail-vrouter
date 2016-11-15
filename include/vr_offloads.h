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
#include <vr_interface.h>
#include <vr_nexthop.h>
#include <vr_flow.h>
#include <vr_mirror.h>
#include <vr_route.h>

/* RCU wrappers. */
#ifdef __linux__
#ifdef __KERNEL__
#include <linux/rcupdate.h>
#else
#include <urcu-bp.h>
#endif /* __KERNEL__ */

#define vr_rcu_dereference(p) rcu_dereference(p)
#define vr_rcu_read_lock() rcu_read_lock()
#define vr_rcu_read_unlock() rcu_read_unlock()
#define vr_synchronize_rcu() synchronize_rcu()
#define vr_rcu_assign_pointer(x, y) rcu_assign_pointer(x, y)
#else
#define vr_rcu_dereference(p) NULL
#define vr_rcu_read_lock()
#define vr_rcu_read_unlock()
#define vr_synchronize_rcu()
#define vr_rcu_assign_pointer(x, y) (x = y)
#endif /* __linux__ */

struct vr_offload_flow {
    struct vr_nexthop *nh;
    struct vr_flow_entry *fe;
    unsigned int fe_index;
    unsigned int tunnel_tag;
    unsigned int tunnel_type;
    bool is_mpls_l2;
    struct vr_interface *pvif;
    unsigned int ip;
    void *flow_handle;
}__attribute__((aligned(64)));

struct vr_offload_tag {
    unsigned int tag;
    bool is_mpls;
    bool valid;
};

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

int vr_offloads_init(struct vrouter *router);
void vr_offloads_exit(struct vrouter *router, bool soft_reset);
struct vr_offload_flow *vr_offloads_flow_get(unsigned int index);
int vr_offload_register(const struct vr_offload_ops *new_handler);
int vr_offload_unregister(void);

extern struct vr_offload_ops *offload_ops;

/* Wrappers for calling offload function with locking in place */
static inline int vr_offload_soft_reset(void)
{
    struct vr_offload_ops *offload;
    int ret = 0;

    vr_rcu_read_lock();
    offload = vr_rcu_dereference(offload_ops);
    if (offload && offload->voo_soft_reset)
        ret = offload->voo_soft_reset();
    vr_rcu_read_unlock();

    return ret;
}

/* Flow offload functions */
static inline int vr_offload_flow_set(struct vr_flow_entry * fe,
                                       unsigned int fe_index,
                                       struct vr_flow_entry * rfe)
{
    struct vr_offload_ops *offload;
    int ret = 0;

    vr_rcu_read_lock();
    offload = vr_rcu_dereference(offload_ops);
    if (offload && offload->voo_flow_set)
        ret = offload->voo_flow_set(fe, fe_index, rfe);
    vr_rcu_read_unlock();

    return ret;
}

static inline int vr_offload_flow_del(struct vr_flow_entry * fe)
{
    struct vr_offload_ops *offload;
    int ret = 0;

    vr_rcu_read_lock();
    offload = vr_rcu_dereference(offload_ops);
    if (offload && offload->voo_flow_del)
        ret = offload->voo_flow_del(fe);
    vr_rcu_read_unlock();

    return ret;
}

/*
 * Used both to set and reset meta data entry for a flow.
 */
static inline int vr_offload_flow_meta_data_set(unsigned int fe_index,
                                                 unsigned int meta_data_len,
                                                 void *meta_data,
                                                 unsigned short mir_vrf)
{
    struct vr_offload_ops *offload;
    int ret = 0;

    vr_rcu_read_lock();
    offload = vr_rcu_dereference(offload_ops);
    if (offload && offload->voo_flow_meta_data_set)
        ret = offload->voo_flow_meta_data_set(fe_index, meta_data_len,
                                                   meta_data, mir_vrf);
    vr_rcu_read_unlock();

    return ret;
}

/* Dropstats */
static inline int vr_offload_drop_stats_get(vr_drop_stats_req *resp)
{
    struct vr_offload_ops *offload;
    int ret = 0;

    vr_rcu_read_lock();
    offload = vr_rcu_dereference(offload_ops);
    if (offload && offload->voo_drop_stats_get)
        ret = offload->voo_drop_stats_get(resp);
    vr_rcu_read_unlock();

    return ret;
}

/* interface offload functions */
static inline int vr_offload_interface_add(struct vr_interface * intf)
{
    struct vr_offload_ops *offload;
    int ret = 0;

    vr_rcu_read_lock();
    offload = vr_rcu_dereference(offload_ops);
    if (offload && offload->voo_interface_add)
        ret = offload->voo_interface_add(intf);
    vr_rcu_read_unlock();

    return ret;
}

static inline int vr_offload_interface_get(vr_interface_req *resp)
{
    struct vr_offload_ops *offload;
    int ret = 0;

    vr_rcu_read_lock();
    offload = vr_rcu_dereference(offload_ops);
    if (offload && offload->voo_interface_get)
        ret = offload->voo_interface_get(resp);
    vr_rcu_read_unlock();

    return ret;
}

static inline int vr_offload_interface_del(struct vr_interface * intf)
{
    struct vr_offload_ops *offload;
    int ret = 0;

    vr_rcu_read_lock();
    offload = vr_rcu_dereference(offload_ops);
    if (offload && offload->voo_interface_del)
        ret = offload->voo_interface_del(intf);
    vr_rcu_read_unlock();

    return ret;
}

static inline int vr_offload_vif_vrf_set(vr_vrf_assign_req *req)
{
    struct vr_offload_ops *offload;
    int ret = 0;

    vr_rcu_read_lock();
    offload = vr_rcu_dereference(offload_ops);
    if (offload && offload->voo_vif_vrf_set)
       ret = offload->voo_vif_vrf_set(req);
    vr_rcu_read_unlock();

    return ret;
}

static inline int vr_offload_vif_vrf_get(vr_vrf_assign_req *resp)
{
    struct vr_offload_ops *offload;
    int ret = 0;

    vr_rcu_read_lock();
    offload = vr_rcu_dereference(offload_ops);
    if (offload && offload->voo_vif_vrf_get)
        ret = offload->voo_vif_vrf_get(resp);
    vr_rcu_read_unlock();

    return ret;
}

static inline int vr_offload_nexthop_add(struct vr_nexthop * nh)
{
    struct vr_offload_ops *offload;
    int ret = 0;

    vr_rcu_read_lock();
    offload = vr_rcu_dereference(offload_ops);
    if (offload && offload->voo_nexthop_add)
        ret = offload->voo_nexthop_add(nh);
    vr_rcu_read_unlock();

    return ret;
}

static inline int vr_offload_nexthop_del(struct vr_nexthop * nh)
{
    struct vr_offload_ops *offload;
    int ret = 0;

    vr_rcu_read_lock();
    offload = vr_rcu_dereference(offload_ops);
    if (offload && offload->voo_nexthop_del)
        ret = offload->voo_nexthop_del(nh);
    vr_rcu_read_unlock();

    return ret;
}

static inline int vr_offload_nexthop_get(struct vr_nexthop * nh,
                                          vr_nexthop_req * resp)
{
    struct vr_offload_ops *offload;
    int ret = 0;

    vr_rcu_read_lock();
    offload = vr_rcu_dereference(offload_ops);
    if (offload && offload->voo_nexthop_get)
        ret = offload->voo_nexthop_get(nh, resp);
    vr_rcu_read_unlock();

    return ret;
}

static inline int vr_offload_mpls_add(struct vr_nexthop * nh, int label)
{
    struct vr_offload_ops *offload;
    int ret = 0;

    vr_rcu_read_lock();
    offload = vr_rcu_dereference(offload_ops);
    if (offload && offload->voo_mpls_add)
        ret = offload->voo_mpls_add(nh, label);
    vr_rcu_read_unlock();

    return ret;
}

static inline int vr_offload_mpls_get(vr_mpls_req * resp)
{
    struct vr_offload_ops *offload;
    int ret = 0;

    vr_rcu_read_lock();
    offload = vr_rcu_dereference(offload_ops);
    if (offload && offload->voo_mpls_get)
        ret = offload->voo_mpls_get(resp);
    vr_rcu_read_unlock();

    return ret;
}

static inline int vr_offload_mpls_del(int label)
{
    struct vr_offload_ops *offload;
    int ret = 0;

    vr_rcu_read_lock();
    offload = vr_rcu_dereference(offload_ops);
    if (offload && offload->voo_mpls_del)
        ret = offload->voo_mpls_del(label);
    vr_rcu_read_unlock();

    return ret;
}

static inline int vr_offload_vxlan_add(struct vr_nexthop * nh, int vnid)
{
    struct vr_offload_ops *offload;
    int ret = 0;

    vr_rcu_read_lock();
    offload = vr_rcu_dereference(offload_ops);
    if (offload && offload->voo_vxlan_add)
        ret = offload->voo_vxlan_add(nh, vnid);
    vr_rcu_read_unlock();

    return ret;
}

static inline int vr_offload_vxlan_get(vr_vxlan_req * resp)
{
    struct vr_offload_ops *offload;
    int ret = 0;

    vr_rcu_read_lock();
    offload = vr_rcu_dereference(offload_ops);
    if (offload && offload->voo_vxlan_get)
        ret = offload->voo_vxlan_get(resp);
    vr_rcu_read_unlock();

    return ret;
}

static inline int vr_offload_vxlan_del(int vnid)
{
    struct vr_offload_ops *offload;
    int ret = 0;

    vr_rcu_read_lock();
    offload = vr_rcu_dereference(offload_ops);
    if (offload && offload->voo_vxlan_del)
        ret = offload->voo_vxlan_del(vnid);
    vr_rcu_read_unlock();

    return ret;
}

static inline int vr_offload_mirror_add(struct vr_mirror_entry * mirror,
                                        unsigned int index)
{
    struct vr_offload_ops *offload;
    int ret = 0;

    vr_rcu_read_lock();
    offload = vr_rcu_dereference(offload_ops);
    if (offload && offload->voo_mirror_add)
        ret = offload->voo_mirror_add(mirror, index);
    vr_rcu_read_unlock();

    return ret;
}

static inline int vr_offload_mirror_del(unsigned int index)
{
    struct vr_offload_ops *offload;
    int ret = 0;

    vr_rcu_read_lock();
    offload = vr_rcu_dereference(offload_ops);
    if (offload && offload->voo_mirror_del)
        ret = offload->voo_mirror_del(index);
    vr_rcu_read_unlock();

    return ret;
}

static inline int vr_offload_mirror_get(vr_mirror_req * resp)
{
    struct vr_offload_ops *offload;
    int ret = 0;

    vr_rcu_read_lock();
    offload = vr_rcu_dereference(offload_ops);
    if (offload && offload->voo_mirror_get)
        ret = offload->voo_mirror_get(resp);
    vr_rcu_read_unlock();

    return ret;
}

static inline int vr_offload_route_del(vr_route_req * req)
{
    struct vr_offload_ops *offload;
    int ret = 0;

    vr_rcu_read_lock();
    offload = vr_rcu_dereference(offload_ops);
    if (offload && offload->voo_route_del)
        ret = offload->voo_route_del(req);
    vr_rcu_read_unlock();

    return ret;
}

static inline int vr_offload_route_add(vr_route_req * req)
{
    struct vr_offload_ops *offload;
    int ret = 0;

    vr_rcu_read_lock();
    offload = vr_rcu_dereference(offload_ops);
    if (offload && offload->voo_route_add)
        ret = offload->voo_route_add(req);
    vr_rcu_read_unlock();

    return ret;
}

static inline int vr_offload_route_get(vr_route_req * req)
{
    struct vr_offload_ops *offload;
    int ret = 0;

    vr_rcu_read_lock();
    offload = vr_rcu_dereference(offload_ops);
    if (offload && offload->voo_route_get)
        ret = offload->voo_route_get(req);
    vr_rcu_read_unlock();

    return ret;
}

static inline int vr_offload_route_dump(struct vr_route_req * req)
{
    struct vr_offload_ops *offload;
    int ret = 0;

    vr_rcu_read_lock();
    offload = vr_rcu_dereference(offload_ops);
    if (offload && offload->voo_route_dump)
        ret = offload->voo_route_dump(req);
    vr_rcu_read_unlock();

    return ret;
}

static inline int vr_offload_fc_map_add(vr_fc_map_req * req)
{
    struct vr_offload_ops *offload;
    int ret = 0;

    vr_rcu_read_lock();
    offload = vr_rcu_dereference(offload_ops);
    if (offload && offload->voo_fc_map_add)
        ret = offload->voo_fc_map_add(req);
    vr_rcu_read_unlock();

    return ret;
}

static inline int vr_offload_fc_map_del(vr_fc_map_req * req)
{
    struct vr_offload_ops *offload;
    int ret = 0;

    vr_rcu_read_lock();
    offload = vr_rcu_dereference(offload_ops);
    if (offload && offload->voo_fc_map_del)
        ret = offload->voo_fc_map_del(req);
    vr_rcu_read_unlock();

    return ret;
}

static inline int vr_offload_fc_map_get(vr_fc_map_req * req)
{
    struct vr_offload_ops *offload;
    int ret = 0;

    vr_rcu_read_lock();
    offload = vr_rcu_dereference(offload_ops);
    if (offload && offload->voo_fc_map_get)
        ret = offload->voo_fc_map_get(req);
    vr_rcu_read_unlock();

    return ret;
}

static inline int vr_offload_qos_map_add(vr_qos_map_req * req)
{
    struct vr_offload_ops *offload;
    int ret = 0;

    vr_rcu_read_lock();
    offload = vr_rcu_dereference(offload_ops);
    if (offload && offload->voo_qos_map_add)
        ret = offload->voo_qos_map_add(req);
    vr_rcu_read_unlock();

    return ret;
}

static inline int vr_offload_qos_map_del(vr_qos_map_req * req)
{
    struct vr_offload_ops *offload;
    int ret = 0;

    vr_rcu_read_lock();
    offload = vr_rcu_dereference(offload_ops);
    if (offload && offload->voo_qos_map_del)
        ret = offload->voo_qos_map_del(req);
    vr_rcu_read_unlock();

    return ret;
}

static inline int vr_offload_qos_map_get(vr_qos_map_req * req)
{
    struct vr_offload_ops *offload;
    int ret = 0;

    vr_rcu_read_lock();
    offload = vr_rcu_dereference(offload_ops);
    if (offload && offload->voo_qos_map_get)
        ret = offload->voo_qos_map_get(req);
    vr_rcu_read_unlock();

    return ret;
}

#endif /* __VR_OFFLOADS_H__ */
