/*
 * vr_vxlan.c -- VXLAN encapsulation handling
 *
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#include <vr_os.h>
#include <vr_types.h>
#include <vr_packet.h>
#include "vr_interface.h"
#include "vr_message.h"
#include "vr_sandesh.h"
#include "vr_vxlan.h"
#include "vr_bridge.h"
#include "vr_datapath.h"

int
vr_vxlan_input(struct vrouter *router, struct vr_packet *pkt,
                                struct vr_forwarding_md *fmd)
{
    struct vr_vxlan *vxlan;
    unsigned int vnid, drop_reason;
    unsigned int flags;
    struct vr_nexthop *nh;
    struct vr_forwarding_md c_fmd;
    struct vr_ip *ip;

    if (!fmd) {
        vr_init_forwarding_md(&c_fmd);
        fmd = &c_fmd;
    }

    ip = (struct vr_ip *)pkt_network_header(pkt);
    fmd->fmd_outer_src_ip = ip->ip_saddr;

    vxlan = (struct vr_vxlan *)pkt_data(pkt);
    flags = ntohl(vxlan->vxlan_flags);
    if (!(flags & VR_VXLAN_IBIT)) {
        drop_reason = VP_DROP_INVALID_VNID;
        goto fail;
    }

    vnid = ntohl(vxlan->vxlan_vnid) >> VR_VXLAN_VNID_SHIFT;
    if (!pkt_pull(pkt, sizeof(struct vr_vxlan))) {
        drop_reason = VP_DROP_PULL;
        goto fail;
    }

    vr_fmd_set_label(fmd, vnid, VR_LABEL_TYPE_VXLAN_ID);

    nh = (struct vr_nexthop *)vr_itable_get(router->vr_vxlan_table, vnid);
    if (!nh) {
        drop_reason = VP_DROP_INVALID_VNID;
        goto fail;
    }

    fmd->fmd_vlan = VLAN_ID_INVALID;

    if (vr_pkt_type(pkt, 0, fmd) < 0) {
        drop_reason = VP_DROP_INVALID_PACKET;
        goto fail;
    }

    if (nh->nh_vrf >= 0) {
        fmd->fmd_dvrf = nh->nh_vrf;
    } else if (nh->nh_dev) {
        fmd->fmd_dvrf = nh->nh_dev->vif_vrf;
    } else {
        fmd->fmd_dvrf = pkt->vp_if->vif_vrf;
    }

    if (flags & VR_VXLAN_RABIT) {
        vr_trap(pkt, fmd->fmd_dvrf, AGENT_TRAP_ROUTER_ALERT, NULL);
        return 0;
    }

    if (vr_perfr)
        vr_pkt_set_gro(pkt);

    return nh_output(pkt, nh, fmd);

fail:
    vr_pfree(pkt, drop_reason);
    return 0;
}

static void
vr_vxlan_make_req(vr_vxlan_req *req, struct vr_nexthop *nh, unsigned int vnid)
{
    memset(req, 0, sizeof(*req));
    req->vxlanr_vnid = vnid;
    if (nh)
        req->vxlanr_nhid = nh->nh_id;
    return;
}

int
vr_vxlan_trav_cb(unsigned int index, void *data, void *udata)
{
    struct vr_nexthop *nh = (struct vr_nexthop *)data;
    struct vr_message_dumper *dumper = (struct vr_message_dumper *)udata;
    vr_vxlan_req resp;

    vr_vxlan_make_req(&resp, nh, index);
    return vr_message_dump_object(dumper, VR_VXLAN_OBJECT_ID, &resp);
}

int
vr_vxlan_dump(vr_vxlan_req *req)
{
    int ret;
    struct vr_message_dumper *dumper = NULL;
    struct vrouter *router = vrouter_get(req->vxlanr_rid);
    unsigned int index;

    if (!router && (ret = -ENODEV))
        goto generate_response;

    dumper = vr_message_dump_init(req);
    if (!dumper && (ret = -ENOMEM))
       goto generate_response;

   index = req->vxlanr_vnid;
   if (index)
       index++;

   ret = vr_itable_trav(router->vr_vxlan_table, vr_vxlan_trav_cb, index, dumper);

generate_response:
    vr_message_dump_exit(dumper, ret);
    return 0;
}

int
vr_vxlan_get(vr_vxlan_req *req)
{
    int ret = 0;
    struct vr_nexthop *nh = NULL;
    struct vrouter *router;

    router = vrouter_get(req->vxlanr_rid);
    if (!router) {
        ret = -ENODEV;
    } else {
        nh = (struct vr_nexthop *)vr_itable_get(router->vr_vxlan_table,
                req->vxlanr_vnid);
        if (!nh)
            ret = -ENOENT;
    }

    if (!ret)
        vr_vxlan_make_req(req, nh, req->vxlanr_vnid);
    else
        req = NULL;

    vr_message_response(VR_VXLAN_OBJECT_ID, req, ret, false);

    return 0;
}

int
vr_vxlan_del(vr_vxlan_req *req)
{
    struct vrouter *router;
    struct vr_nexthop *nh;
    int ret = 0;

    router = vrouter_get(req->vxlanr_rid);
    if (!router) {
        ret = -EINVAL;
        goto generate_resp;
    }

    nh = vr_itable_del(router->vr_vxlan_table, req->vxlanr_vnid);
    if (nh)
        vrouter_put_nexthop(nh);

generate_resp:
    vr_send_response(ret);
    return ret;
}

int
vr_vxlan_add(vr_vxlan_req *req)
{
    struct vrouter *router;
    struct vr_nexthop *nh, *nh_old;
    int ret = 0;

    router = vrouter_get(req->vxlanr_rid);
    if (!router) {
        ret = -EINVAL;
        goto generate_resp;
    }

    nh = vrouter_get_nexthop(req->vxlanr_rid, req->vxlanr_nhid);
    if (!nh) {
        ret = -EINVAL;
        goto generate_resp;
    }

    nh_old = vr_itable_set(router->vr_vxlan_table, req->vxlanr_vnid, nh);
    if (nh_old) {
        if (nh_old == VR_ITABLE_ERR_PTR) {
            ret = -EINVAL;
        } else {
            /* If there is any old nexthop, remove the reference */
            vrouter_put_nexthop(nh_old);
        }
    }

generate_resp:
    vr_send_response(ret);
    return ret;
}

void
vr_vxlan_req_process(void *s_req)
{
    vr_vxlan_req *req = (vr_vxlan_req *)s_req;

    switch(req->h_op) {
    case SANDESH_OP_ADD:
        vr_vxlan_add(req);
        break;

    case SANDESH_OP_GET:
        vr_vxlan_get(req);
        break;

    case SANDESH_OP_DUMP:
        vr_vxlan_dump(req);
        break;

    case SANDESH_OP_DEL:
        vr_vxlan_del(req);
        break;

    default:
        break;
    }

    return;
}

static void
vr_vxlan_destroy(unsigned int index, void *arg)
{
    struct vr_nexthop *nh = (struct vr_nexthop *)arg;

    if (nh && nh != VR_ITABLE_ERR_PTR) {
        vrouter_put_nexthop(nh);
    }

    return;
}

void
vr_vxlan_exit(struct vrouter *router, bool soft_reset)
{
    /* Delete the complete index table, irrespective of soft_reset */
    vr_itable_delete(router->vr_vxlan_table, vr_vxlan_destroy);
    router->vr_vxlan_table = NULL;
}

int
vr_vxlan_init(struct vrouter *router)
{
    /* Create an index table with two strides of 12 bits each */
    if (!router->vr_vxlan_table) {
        router->vr_vxlan_table = vr_itable_create(24, 2, 12, 12);
        if (!router->vr_vxlan_table) {
            vr_module_error(-ENOMEM, __FUNCTION__, __LINE__, 0);
            return -ENOMEM;
        }
    }
    return 0;
}
