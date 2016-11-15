/*
 * vr_offloads.c -- datapath flow offloads management
 *
 * Copyright 2018 Mellanox Technologies, Ltd
 */
#include <vrouter.h>
#include <vr_offloads.h>
#include <vr_btable.h>
#include <vr_packet.h>

extern unsigned int vr_nexthops;
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
            vr_printf("offload: more than one physical interface\n");
        else
            pvif = vif;
    } else if (vif->vif_type == VIF_TYPE_HOST) {
        if (host_ip && vif->vif_ip != host_ip)
            vr_printf("offload: more than one host interface\n");
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
            vr_printf("offload: more than one physical interface\n");
        else
            pvif = NULL;
    } else if (vif->vif_type == VIF_TYPE_HOST) {
        if (vif->vif_ip != host_ip)
            vr_printf("offload: more than one host interface\n");
        else
            host_ip = 0;
    }

    return 0;
}

int
vr_offloads_mpls_add(struct vr_nexthop *nh, int label)
{
    struct vr_offload_tag *otag;

    if (!nh)
        return -EINVAL;
    if (!(nh->nh_flags & NH_FLAG_VALID) || (nh->nh_flags & NH_FLAG_MCAST) ||
        nh->nh_type != NH_ENCAP)
        /* Not a valid nexthop to be offloaded */
        return 0;

    otag = (struct vr_offload_tag *)vr_btable_get(offload_tags, nh->nh_id);
    if (!otag) {
        vr_printf("offload: Invalid tag for nexthop ID %u\n",nh->nh_id);
        return 0;
    }

    if (!otag->valid) {
        otag->tag = label;
        otag->is_mpls = true;
        otag->valid = true;
    } else if (otag->is_mpls && otag->tag != label) {
        vr_printf("offload: 2 different MPLS label point to the same"
                  " UNICAST ENCAP nexthop\n");
    } else if (!otag->is_mpls) {
        vr_printf("offload: MPLS label and VXLAN vni point to the same"
                  " UNICAST ENCAP nexthop\n");
    }

    return 0;
}

int
vr_offloads_vxlan_add(struct vr_nexthop * nh, int vnid)
{
    struct vr_offload_tag *otag;

    if (!nh)
        return -EINVAL;
    if (!(nh->nh_flags & NH_FLAG_VALID) || (nh->nh_flags & NH_FLAG_MCAST) ||
        nh->nh_type != NH_ENCAP)
        /* Not a valid nexthop to be offloaded */
        return 0;

    otag = (struct vr_offload_tag *)vr_btable_get(offload_tags, nh->nh_id);
    if (!otag) {
        vr_printf("offload: Invalid tag for nexthop ID %u\n",nh->nh_id);
        return 0;
    }

    if (!otag->valid) {
        otag->tag = vnid;
        otag->is_mpls = false;
        otag->valid = true;
    } else if (!otag->is_mpls && otag->tag != vnid) {
        vr_printf("offload: 2 different VXLAN vni point to the same"
                  " UNICAST ENCAP nexthop\n");
    } else if (otag->is_mpls) {
        vr_printf("offload: VXLAN vni and MPLS label point to the same"
                  " UNICAST ENCAP nexthop\n");
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

    otag = (struct vr_offload_tag *)vr_btable_get(offload_tags, nh->nh_id);
    if (!otag) {
        vr_printf("offload: Invalid tag for nexthop ID %u\n",nh->nh_id);
        return 0;
    }

    if (otag->valid && otag->is_mpls && otag->tag == label)
        otag->valid = false;

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

    otag = (struct vr_offload_tag *)vr_btable_get(offload_tags, nh->nh_id);
    if (!otag) {
        vr_printf("offload: Invalid tag for nexthop ID %u\n",nh->nh_id);
        return 0;
    }

    if (otag->valid && !otag->is_mpls && otag->tag == vnid)
        otag->valid = false;

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
        vr_printf("offload: invalid tag for flow ID %u\n",
                  fe->fe_hentry.hentry_index);
        return 0;
    }

    if(oflow->flow_handle) {
        ret = vr_offload_flow_destroy(oflow);
        if (!ret) {
            vr_printf("offload: failed to destroy flow ID %u\n", oflow->fe_index);
            memset(oflow, 0, sizeof(*oflow));
        }
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
        vr_printf("offload: missing physical/host interface\n");
        return 0;
    }

    oflow = (struct vr_offload_flow *)vr_btable_get(offload_flows, fe_index);
    if (!oflow) {
        vr_printf("offload: invalid tag for flow ID %u\n", fe_index);
        return 0;
    }

    /* For flow change do destroy and create */
    if (oflow->flow_handle) {
        ret = vr_offload_flow_destroy(oflow);
        if (!ret) {
            memset(oflow, 0, sizeof(*oflow));
        } else {
            vr_printf("offload: failed to change flow ID %u\n", oflow->fe_index);
            return 0;
        }
    }

    nh = __vrouter_get_nexthop(router, fe->fe_key.flow_nh_id);
    if (!nh)
        return -EINVAL;

    if (!(fe->fe_flags & VR_FLOW_FLAG_ACTIVE) || fe->fe_action != VR_FLOW_ACTION_FORWARD ||
        !(nh->nh_flags & NH_FLAG_VALID) || !(nh->nh_flags & NH_FLAG_POLICY_ENABLED) ||
        (nh->nh_flags & NH_FLAG_MCAST) || nh->nh_type != NH_ENCAP )
        /* Not a valid flow to be offloaded */
        return 0;


    snh = __vrouter_get_nexthop(router, fe->fe_src_nh_index);
    if (!snh)
        return -EINVAL;

    otag = (struct vr_offload_tag *)vr_btable_get(offload_tags, nh->nh_id);
    if (!otag || !otag->valid) {
        vr_printf("offload: invalid tag for nexthop ID %u\n", nh->nh_id);
        return 0;
    }

    if (snh->nh_type != NH_TUNNEL || !(snh->nh_flags & NH_FLAG_VALID))
        /* Not a valid flow to be offloaded */
        return 0;

    if (otag->is_mpls && (snh->nh_flags & NH_FLAG_TUNNEL_GRE)) {
        oflow->tunnel_type = NH_FLAG_TUNNEL_GRE;
        oflow->tunnel_tag = otag->tag;
        oflow->is_mpls_l2 = nh->nh_family == AF_BRIDGE;
    } else if (otag->is_mpls && (snh->nh_flags & NH_FLAG_TUNNEL_UDP_MPLS)) {
        oflow->tunnel_type = NH_FLAG_TUNNEL_UDP_MPLS;
        oflow->tunnel_tag = otag->tag;
        oflow->is_mpls_l2 = nh->nh_family == AF_BRIDGE;
    } else if (!otag->is_mpls && (snh->nh_flags & NH_FLAG_TUNNEL_VXLAN)) {
        oflow->tunnel_type = NH_FLAG_TUNNEL_VXLAN;
        oflow->tunnel_tag = otag->tag;
        oflow->is_mpls_l2 = true;
    } else {
        /* Not a valid flow to be offloaded */
        return 0;
    }

    oflow->pvif = pvif;
    oflow->fe = fe;
    oflow->ip = host_ip;
    oflow->fe_index = fe_index;
    oflow->nh = nh;

    ret = vr_offload_flow_create(oflow);
    if (ret) {
        vr_printf("offload: failed to create flow ID %u\n", fe_index);
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
    if (!datapath_offloads)
        return 0;

    if (!vr_offload_flow_destroy || !vr_offload_flow_create ||
        !vr_offload_prepare)
        return -ENOSYS;

    if (!offload_tags) {
        offload_tags = vr_btable_alloc(vr_nexthops,
                                       sizeof(struct vr_offload_tag));
        if (!offload_tags)
            return -ENOMEM;
    }

    if (!offload_flows) {
        offload_flows = vr_btable_alloc(vr_flow_entries + vr_oflow_entries,
                                        sizeof(struct vr_offload_flow));
        if (!offload_flows) {
            vr_btable_free(offload_tags);
            offload_tags = NULL;
            return -ENOMEM;
        }
    }

    offload_ops = &vr_offload_ops;

    return 0;

}

void
vr_offloads_exit(struct vrouter *router, bool soft_reset)
{
    struct vr_offload_flow *oflow;
    struct vr_offload_tag *otag;
    unsigned int i;
    unsigned int size;

    if (!datapath_offloads)
        return;

    if (!vr_offload_flow_destroy || !vr_offload_flow_create ||
        !vr_offload_prepare)
        return;

    if (offload_flows) {
        size = vr_btable_size(offload_flows);
        for (i = 0; i < size; i++) {
            oflow = (struct vr_offload_flow *)vr_btable_get(offload_flows, i);
            if (!oflow || !oflow->flow_handle)
                continue;
            vr_offload_flow_destroy(oflow);
        }

        if (!soft_reset) {
            vr_btable_free(offload_flows);
            offload_flows = NULL;
        }
    }

    if (offload_tags) {
        size = vr_btable_size(offload_tags);
        for (i = 0; i < size; i++) {
            otag = (struct vr_offload_tag *)vr_btable_get(offload_tags, i);
            if (otag)
                memset(otag, 0 ,sizeof(*otag));
        }

        if (!soft_reset) {
            vr_btable_free(offload_tags);
            offload_tags = NULL;
        }
    }

    pvif = NULL;
    host_ip = 0;
    offload_ops = NULL;

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
