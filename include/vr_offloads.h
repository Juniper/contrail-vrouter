/*
 * vr_offloads.h -- common definitions for hardware offload features
 *
 * Copyright (c) 2016 Netronome Systems, Inc. All rights reserved.
 * Copyright 2018 Mellanox Technologies, Ltd
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

enum vr_offloads_tag_type {
    VR_OFFLOADS_TAG_TYPE_MPLS_L2,
    VR_OFFLOADS_TAG_TYPE_MPLS_L3,
    VR_OFFLOADS_TAG_TYPE_VXLAN,
    VR_OFFLOADS_TAG_TYPE_MAX
};

__attribute__packed__open__
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
} __attribute__packed__close__;

struct vr_offload_tag {
    unsigned int tag;
    struct vr_nexthop *nh;
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

#endif /* __VR_OFFLOADS_H__ */
