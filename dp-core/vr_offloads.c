/*
 * vr_offloads.c -- datapath flow offloads management
 *
 * Copyright 2018 Mellanox Technologies, Ltd
 */
#include <vrouter.h>
#include <vr_offloads_dp.h>
#include <vr_btable.h>
#include <vr_packet.h>

extern unsigned int vr_interfaces;
extern unsigned int vr_flow_entries;
extern unsigned int vr_oflow_entries;

struct vr_interface *pvif;
unsigned int host_ip;
struct vr_btable *offload_flows;
struct vr_btable *offload_tags;
unsigned int datapath_offloads;

int
vr_offloads_interface_add(struct vr_interface *vif)
{
    if (!vif)
        return -EINVAL;
    if (vif->vif_type == VIF_TYPE_PHYSICAL) {
        if (pvif && pvif != vif)
            vr_printf("offload: More than one physical interface\n");
        else
            pvif = vif;
    } else if (vif->vif_type == VIF_TYPE_HOST) {
        if (host_ip && vif->vif_ip != host_ip)
            vr_printf("offload: More than one host interface\n");
        else
            host_ip = vif->vif_ip;
    }
    return 0;
}

int
vr_offloads_interface_del(struct vr_interface *vif)
{
    if (!vif)
        return -EINVAL;
    if (vif->vif_type == VIF_TYPE_PHYSICAL) {
        if(vif != pvif)
            vr_printf("offload: More than one physical interface\n");
        else
            pvif = NULL;
    } else if (vif->vif_type == VIF_TYPE_HOST) {
        if (vif->vif_ip != host_ip)
            vr_printf("offload: More than one host interface\n");
        else
            host_ip = 0;
    }

    return 0;
}

static bool
vr_offloads_is_offloaded_nexthop(struct vr_nexthop *nh)
{
    return ((nh->nh_flags & NH_FLAG_VALID) && !(nh->nh_flags & NH_FLAG_MCAST) &&
        (nh->nh_flags & NH_FLAG_POLICY_ENABLED) && (nh->nh_type == NH_ENCAP) &&
        nh->nh_dev);
}

int
vr_offloads_mpls_add(struct vr_nexthop *nh, int label)
{
    struct vr_offload_tag *otag;

    if (!nh)
        return -EINVAL;
    if (!vr_offloads_is_offloaded_nexthop(nh))
        return 0;

    otag = (struct vr_offload_tag *)vr_btable_get(offload_tags, nh->nh_dev->vif_idx);
    if (!otag) {
        vr_printf("offload: Invalid tag for nexthop ID %u\n",nh->nh_id);
        return 0;
    }

    if (nh->nh_family == AF_BRIDGE && (nh->nh_flags & NH_FLAG_L2_CONTROL_DATA))
        otag += VR_OFFLOADS_TAG_TYPE_MPLS_L2;
    else if (nh->nh_family != AF_BRIDGE)
        otag += VR_OFFLOADS_TAG_TYPE_MPLS_L3;
    else
        return 0;

    if (!otag->nh) {
        otag->tag = label;
        otag->nh = nh;
    } else if (otag->tag != label) {
        vr_printf("offload: 2 different MPLS labels (%u,%u) point to the same"
                  " tag type of vif %u nexthop %u\n", otag->tag, label,
                  nh->nh_dev->vif_idx, nh->nh_id);
    }

    return 0;
}

int
vr_offloads_vxlan_add(struct vr_nexthop * nh, int vnid)
{
    struct vr_offload_tag *otag;

    if (!nh)
        return -EINVAL;
    if (!vr_offloads_is_offloaded_nexthop(nh))
        return 0;

    otag = (struct vr_offload_tag *)vr_btable_get(offload_tags, nh->nh_dev->vif_idx);
    if (!otag) {
        vr_printf("offload: Invalid tag for nexthop ID %u\n",nh->nh_id);
        return 0;
    }

    otag += VR_OFFLOADS_TAG_TYPE_VXLAN;

    if (!otag->nh) {
        otag->tag = vnid;
        otag->nh = nh;
    } else if (otag->tag != vnid) {
        vr_printf("offload: 2 different VXLAN VNIs (%u,%u) point to the same"
                  " tag type of vif %u nexthop %u\n", otag->tag, vnid,
                  nh->nh_dev->vif_idx, nh->nh_id);
    }

    return 0;
}

int
vr_offloads_mpls_del(int label)
{
    struct vr_offload_tag *otag;
    struct vrouter *router = vrouter_get(0);
    struct vr_nexthop *nh = __vrouter_get_label(router, label);

    if (!nh)
        return -EINVAL;

    if (!vr_offloads_is_offloaded_nexthop(nh))
        return 0;

    otag = (struct vr_offload_tag *)vr_btable_get(offload_tags, nh->nh_dev->vif_idx);
    if (!otag) {
        vr_printf("offload: Invalid tag for nexthop ID %u\n",nh->nh_id);
        return 0;
    }

    if (nh->nh_family == AF_BRIDGE && (nh->nh_flags & NH_FLAG_L2_CONTROL_DATA))
        otag += VR_OFFLOADS_TAG_TYPE_MPLS_L2;
    else if (nh->nh_family != AF_BRIDGE)
        otag += VR_OFFLOADS_TAG_TYPE_MPLS_L3;
    else
        return 0;

    if (otag->nh && otag->tag == label)
        memset(otag, 0, sizeof(*otag));
    else
        vr_printf("offload: Unexpected tag %u for MPLS label %u, nexthop %u\n",
                  otag->tag, label, nh->nh_id);

    return 0;
}

int
vr_offloads_vxlan_del(int vnid)
{
    struct vr_offload_tag *otag;
    struct vrouter *router = vrouter_get(0);
    struct vr_nexthop *nh = (struct vr_nexthop *)vr_itable_get(router->vr_vxlan_table, vnid);

    if (!nh)
        return -EINVAL;

    if (!vr_offloads_is_offloaded_nexthop(nh))
        return 0;

    otag = (struct vr_offload_tag *)vr_btable_get(offload_tags, nh->nh_dev->vif_idx);
    if (!otag) {
        vr_printf("offload: Invalid tag for nexthop ID %u\n",nh->nh_id);
        return 0;
    }

    otag += VR_OFFLOADS_TAG_TYPE_VXLAN;

    if (otag->nh && otag->tag == vnid)
        memset(otag, 0, sizeof(*otag));
    else
        vr_printf("offload: Unexpected tag %u for VXLAN vni %u, nexthop %u\n",
                  otag->tag, vnid, nh->nh_id);

    return 0;
}

int
vr_offloads_flow_del(struct vr_flow_entry * fe)
{
    struct vr_offload_flow *oflow;
    int ret = 0;

    if (!fe)
        return -EINVAL;

    if (!offload_flows)
        return 0;

    oflow = (struct vr_offload_flow *)vr_btable_get(offload_flows,
                                                    fe->fe_hentry.hentry_index);
    if (!oflow) {
        vr_printf("offload: Invalid tag for flow ID %u\n",
                  fe->fe_hentry.hentry_index);
        return 0;
    }

    if(oflow->flow_handle) {
        ret = vr_offload_flow_destroy(oflow);
        if (!ret)
            memset(oflow, 0, sizeof(*oflow));
        else
            vr_printf("offload: Failed to destroy flow ID %u\n", oflow->fe_index);
    }

    return 0;
}

int
vr_offloads_flow_set(struct vr_flow_entry * fe, unsigned int fe_index,
                        struct vr_flow_entry * rfe)
{
    struct vr_nexthop *nh, *snh;
    struct vr_offload_flow *oflow;
    struct vr_offload_tag *otag;
    struct vrouter *router = vrouter_get(0);
    int ret = 0;

    if (!fe)
        return -EINVAL;

    if (!pvif || !host_ip) {
        vr_printf("offload: Missing physical/host interface\n");
        return 0;
    }

    oflow = (struct vr_offload_flow *)vr_btable_get(offload_flows, fe_index);
    if (!oflow) {
        vr_printf("offload: Invalid tag for flow ID %u\n", fe_index);
        return 0;
    }

    /* For flow change do destroy and create */
    if (oflow->flow_handle) {
        ret = vr_offload_flow_destroy(oflow);
        if (!ret) {
            memset(oflow, 0, sizeof(*oflow));
        } else {
            vr_printf("offload: Failed to change flow ID %u\n", oflow->fe_index);
            return 0;
        }
    }

    nh = __vrouter_get_nexthop(router, fe->fe_key.flow_nh_id);
    if (!nh)
        return -EINVAL;

    if (!(fe->fe_flags & VR_FLOW_FLAG_ACTIVE) || fe->fe_action != VR_FLOW_ACTION_FORWARD ||
        !vr_offloads_is_offloaded_nexthop(nh))
        /* Not a valid flow to be offloaded */
        return 0;

    snh = __vrouter_get_nexthop(router, fe->fe_src_nh_index);
    if (!snh)
        return -EINVAL;

    if (snh->nh_type != NH_TUNNEL || !(snh->nh_flags & NH_FLAG_VALID))
        /* Not a valid flow to be offloaded */
        return 0;

    otag = (struct vr_offload_tag *)vr_btable_get(offload_tags, nh->nh_dev->vif_idx);
    if (!otag) {
        vr_printf("offload: Invalid tag for nexthop ID %u\n", nh->nh_id);
        return 0;
    }

    if (snh->nh_flags & NH_FLAG_TUNNEL_GRE) {
        if (otag[VR_OFFLOADS_TAG_TYPE_MPLS_L2].nh && (nh->nh_dev->vif_flags &
                                                      VIF_FLAG_L2_ENABLED)) {
            oflow->tunnel_type = NH_FLAG_TUNNEL_GRE;
            oflow->tunnel_tag =otag[VR_OFFLOADS_TAG_TYPE_MPLS_L2].tag;
            oflow->nh = otag[VR_OFFLOADS_TAG_TYPE_MPLS_L2].nh;
            oflow->is_mpls_l2 = true;
        } else if (otag[VR_OFFLOADS_TAG_TYPE_MPLS_L3].nh && (nh->nh_dev->vif_flags &
                                                             VIF_FLAG_L3_ENABLED)) {
            oflow->tunnel_type = NH_FLAG_TUNNEL_GRE;
            oflow->tunnel_tag = otag[VR_OFFLOADS_TAG_TYPE_MPLS_L3].tag;
            oflow->nh = otag[VR_OFFLOADS_TAG_TYPE_MPLS_L3].nh;
            oflow->is_mpls_l2 = false;
        }
    } else if (snh->nh_flags & NH_FLAG_TUNNEL_UDP_MPLS) {
        if (otag[VR_OFFLOADS_TAG_TYPE_MPLS_L2].nh && (nh->nh_dev->vif_flags &
                                                      VIF_FLAG_L2_ENABLED)) {
            oflow->tunnel_type = NH_FLAG_TUNNEL_UDP_MPLS;
            oflow->tunnel_tag =otag[VR_OFFLOADS_TAG_TYPE_MPLS_L2].tag;
            oflow->nh = otag[VR_OFFLOADS_TAG_TYPE_MPLS_L2].nh;
            oflow->is_mpls_l2 = true;
        } else if (otag[VR_OFFLOADS_TAG_TYPE_MPLS_L3].nh && (nh->nh_dev->vif_flags &
                                                             VIF_FLAG_L3_ENABLED)) {
            oflow->tunnel_type = NH_FLAG_TUNNEL_UDP_MPLS;
            oflow->tunnel_tag = otag[VR_OFFLOADS_TAG_TYPE_MPLS_L3].tag;
            oflow->nh = otag[VR_OFFLOADS_TAG_TYPE_MPLS_L3].nh;
            oflow->is_mpls_l2 = false;
        }
    } else if (snh->nh_flags & NH_FLAG_TUNNEL_VXLAN) {
        if (otag[VR_OFFLOADS_TAG_TYPE_VXLAN].nh) {
            oflow->tunnel_type = NH_FLAG_TUNNEL_VXLAN;
            oflow->tunnel_tag = otag[VR_OFFLOADS_TAG_TYPE_VXLAN].tag;
            oflow->nh = otag[VR_OFFLOADS_TAG_TYPE_VXLAN].nh;
        }
    } else {
        /* Not a valid flow to be offloaded */
        return 0;
    }

    if (!oflow->nh) {
        vr_printf("offload: Invalid tag type for flow create\n");
        return 0;
    }

    oflow->pvif = pvif;
    oflow->fe = fe;
    oflow->ip = host_ip;
    oflow->fe_index = fe_index;

    ret = vr_offload_flow_create(oflow);
    if (ret) {
        vr_printf("offload: Failed to create flow ID %u\n", fe_index);
        memset(oflow, 0, sizeof(*oflow));
    }

    return 0;
}

struct vr_offload_ops vr_offload_ops = {
    .voo_flow_set = vr_offloads_flow_set,
    .voo_flow_del = vr_offloads_flow_del,
    .voo_interface_add = vr_offloads_interface_add,
    .voo_interface_del = vr_offloads_interface_del,
    .voo_mpls_add = vr_offloads_mpls_add,
    .voo_mpls_del = vr_offloads_mpls_del,
    .voo_vxlan_add = vr_offloads_vxlan_add,
    .voo_vxlan_del = vr_offloads_vxlan_del,
};

int
vr_offloads_init(struct vrouter *router)
{
    unsigned int entry_size;
    struct vr_offload_ops *offload;

    if (!datapath_offloads)
        return 0;

    /* Do not initialize twice. E.g. a soft reset would not have unregistered
     * the offloads. */
    offload = vr_rcu_dereference(offload_ops);
    if (offload)
        return 0;

    if (!vr_offload_flow_destroy || !vr_offload_flow_create ||
        !vr_offload_prepare) {
        /* Not an error necessarily. Offloads are not implemented for this host
         * type, so don't register anything. External implementation can still
         * be registered after initialization. */
        vr_printf("offload: no built-in offload implementation for current context\n");
        return 0;
    }

    if (!offload_tags) {
        /* Round up to the next divisor */
        for (entry_size = sizeof(struct vr_offload_tag) * VR_OFFLOADS_TAG_TYPE_MAX;
             VR_SINGLE_ALLOC_LIMIT % entry_size; entry_size++);
        offload_tags = vr_btable_alloc(vr_interfaces, entry_size);
        if (!offload_tags) {
            return -ENOMEM;
        }
    }

    if (!offload_flows) {
        /* Round up to the next divisor */
        for (entry_size = sizeof(struct vr_offload_flow);
             VR_SINGLE_ALLOC_LIMIT % entry_size; entry_size++);
        offload_flows = vr_btable_alloc(vr_flow_entries + vr_oflow_entries, entry_size);
        if (!offload_flows) {
            vr_btable_free(offload_tags);
            offload_tags = NULL;
            return -ENOMEM;
        }
    }

    vr_offload_register(&vr_offload_ops);

    return 0;

}

static void
_vr_offloads_exit(struct vrouter *router, bool soft_reset)
{
    struct vr_offload_flow *oflow;
    struct vr_offload_tag *otag;
    unsigned int i;
    unsigned int entry_num, entry_size;

    if (!datapath_offloads)
        return;

    if (!vr_offload_flow_destroy || !vr_offload_flow_create ||
        !vr_offload_prepare)
        return;

    if (offload_flows) {
        entry_num = vr_btable_entries(offload_flows);
        entry_size = vr_btable_size(offload_flows) / entry_num;
        for (i = 0; i < entry_num; i++) {
            oflow = (struct vr_offload_flow *)vr_btable_get(offload_flows, i);
            if (!oflow)
                continue;
            if(oflow->flow_handle)
                vr_offload_flow_destroy(oflow);
            memset(oflow, 0, entry_size);
        }

        if (!soft_reset) {
            vr_btable_free(offload_flows);
            offload_flows = NULL;
        }
    }

    if (offload_tags) {
        entry_num = vr_btable_entries(offload_tags);
        entry_size = vr_btable_size(offload_tags) / entry_num;
        for (i = 0; i < entry_num; i++) {
            otag = (struct vr_offload_tag *)vr_btable_get(offload_tags, i);
            if (otag)
                    memset(otag, 0, entry_size);
        }

        if (!soft_reset) {
            vr_btable_free(offload_tags);
            offload_tags = NULL;
        }
    }

    pvif = NULL;
    host_ip = 0;
}

inline struct vr_offload_flow *
vr_offloads_flow_get(unsigned int index)
{
    struct vr_offload_flow *oflow = (struct vr_offload_flow *)
                                    vr_btable_get(offload_flows, index);

    if (!oflow || !oflow->flow_handle)
        /* An invalid packet flow */
        return NULL;

    return  oflow;
}

/*
 * Called by an external offload module to register itself with vrouter.
 */
int
vr_offload_register(const struct vr_offload_ops *new_handler)
{
    struct vr_offload_ops *offload;

    if (!datapath_offloads || !new_handler)
        return -EINVAL;

    offload = vr_rcu_dereference(offload_ops);
    if (offload)
        return -EBUSY;

    offload = vr_malloc(sizeof(*offload), VR_MALLOC_OBJECT);
    if (!offload)
        return -ENOMEM;
    *offload = *new_handler;
    vr_rcu_assign_pointer(offload_ops, offload);
    vr_synchronize_rcu();

    return 0;
}
#if defined(__linux__) && defined(__KERNEL__)
EXPORT_SYMBOL(vr_offload_register);
#endif

/*
 * Called by an external offload module to unregister itself with vrouter.
 */
static void
_vr_offload_unregister(void)
{
    struct vr_offload_ops *offload = vr_rcu_dereference(offload_ops);

    if (offload) {
        vr_rcu_assign_pointer(offload_ops, NULL);
        vr_synchronize_rcu();
        vr_free(offload, VR_MALLOC_OBJECT);
    }
}

int
vr_offload_unregister(void)
{
    struct vrouter *router = vrouter_get(0);

    _vr_offloads_exit(router, false);
    _vr_offload_unregister();

    return 0;
}
#if defined(__linux__) && defined(__KERNEL__)
EXPORT_SYMBOL(vr_offload_unregister);
#endif

void
vr_offloads_exit(struct vrouter *router, bool soft_reset)
{
    _vr_offloads_exit(router, soft_reset);
    if (!soft_reset)
        _vr_offload_unregister();
}

/* Statistics update functions used by offload module */
#if defined(__linux__) && defined(__KERNEL__)
EXPORT_SYMBOL(vr_flow_incr_stats);
EXPORT_SYMBOL(vr_nexthop_update_offload_vrfstats);
#endif
