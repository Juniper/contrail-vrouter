/*
 * vr_mpls.c -- mpls handling of packets
 *
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#include <vr_os.h>
#include <vr_types.h>
#include <vr_packet.h>
#include "vr_interface.h"
#include "vr_message.h"
#include "vr_sandesh.h"
#include "vr_mpls.h"
#include "vr_bridge.h"
#include "vr_datapath.h"
#include "vr_btable.h"
#include "vr_offloads.h"

unsigned int vr_mpls_labels = VR_DEF_LABELS;

struct vr_nexthop *
__vrouter_get_label(struct vrouter *router, unsigned int label)
{
    if (!router || label >= router->vr_max_labels)
        return NULL;

    return *(struct vr_nexthop **)vr_btable_get(router->vr_ilm, label);
}

static struct vr_nexthop *
vrouter_get_label(unsigned int rid, unsigned int label)
{
    struct vrouter *router = vrouter_get(rid);

    return __vrouter_get_label(router, label);
}

static int
__vrouter_set_label(struct vrouter *router, unsigned int label,
        struct vr_nexthop *nh)
{
    struct vr_nexthop **nh_p;

    nh_p = (struct vr_nexthop **)vr_btable_get(router->vr_ilm, label);
    if (!nh_p)
        return -EINVAL;

    *nh_p = nh;

    return 0;
}

int
__vr_mpls_del(struct vrouter *router, unsigned int label)
{
    struct vr_nexthop *nh;

    /* hardware packet filtering (Flow Director) support */
    nh = __vrouter_get_label(router, label);
    if (nh) {
        if (vrouter_host->hos_del_mpls
            && nh->nh_type == NH_ENCAP && !(nh->nh_flags & NH_FLAG_MCAST))
            vrouter_host->hos_del_mpls(router, label);

        vrouter_put_nexthop(nh);
    }

    return __vrouter_set_label(router, label, NULL);
}

int
vr_mpls_del(vr_mpls_req *req)
{
    int ret = 0;

    struct vrouter *router;

    router = vrouter_get(req->mr_rid);
    if (!router) {
        ret = -EINVAL;
        goto generate_resp;
    }

    if ((unsigned int)req->mr_label >= router->vr_max_labels) {
        ret = -EINVAL;
        goto generate_resp;
    }

    /* notify hw offload of change, if enabled */
    vr_offload_mpls_del(req->mr_label);

    ret =  __vr_mpls_del(router, req->mr_label);

generate_resp:
    vr_send_response(ret);

    return ret;
}

int
vr_mpls_add(vr_mpls_req *req)
{
    struct vrouter *router;
    struct vr_nexthop *nh;
    int ret = 0;

    router = vrouter_get(req->mr_rid);
    if (!router) {
        ret = -EINVAL;
        goto generate_resp;
    }

    if ((unsigned int)req->mr_label >= router->vr_max_labels) {
        ret = -EINVAL;
        goto generate_resp;
    }

    ret = __vr_mpls_del(router, req->mr_label);
    if (ret)
        goto generate_resp;

    nh = vrouter_get_nexthop(req->mr_rid, req->mr_nhid);
    if (!nh) {
        ret = -EINVAL;
        goto generate_resp;
    }

    ret = __vrouter_set_label(router, req->mr_label, nh);
    if (ret) {
        vrouter_put_nexthop(nh);
        goto generate_resp;
    }

    /* hardware packet filtering (Flow Director) support */
    if (vrouter_host->hos_add_mpls
        && nh->nh_type == NH_ENCAP && !(nh->nh_flags & NH_FLAG_MCAST))
        vrouter_host->hos_add_mpls(router, req->mr_label);

    /* notify hw offload of change, if enabled */
    if (!ret) {
        ret = vr_offload_mpls_add(nh, req->mr_label);
        if (ret)
            __vr_mpls_del(router, req->mr_label);
    }

generate_resp:
    vr_send_response(ret);

    return ret;
}

static void
vr_mpls_make_req(vr_mpls_req *req, struct vr_nexthop *nh,
                unsigned int label)
{
    req->mr_rid = 0;
    req->mr_nhid = nh->nh_id;
    req->mr_label = label;

    /* Debug comparison to check if matching entry is programmed on NIC */
    vr_offload_mpls_get(req);

    return;
}

int
vr_mpls_dump(vr_mpls_req *r)
{
    int ret = 0;
    unsigned int i;
    struct vr_nexthop *nh;
    struct vrouter *router = vrouter_get(r->mr_rid);
    struct vr_message_dumper *dumper = NULL;
    vr_mpls_req req;

    if (!router && (ret = -ENODEV))
        goto generate_response;

    if ((unsigned int)(r->mr_marker) + 1 >= router->vr_max_labels)
        goto generate_response;

    dumper = vr_message_dump_init(r);
    if (!dumper && (ret = -ENOMEM))
        goto generate_response;

    for (i = (unsigned int)(r->mr_marker + 1);
            i < router->vr_max_labels; i++) {
        nh = __vrouter_get_label(router, i);
        if (nh) {
           vr_mpls_make_req(&req, nh, i);
           ret = vr_message_dump_object(dumper, VR_MPLS_OBJECT_ID, &req);
           if (ret <= 0)
               break;
        }
    }

generate_response:
    vr_message_dump_exit(dumper, ret);

    return 0;
}

int
vr_mpls_get(vr_mpls_req *req)
{
    int ret = 0;
    struct vr_nexthop *nh = NULL;
    struct vrouter *router;

    router = vrouter_get(req->mr_rid);
    if (!router) {
        ret = -ENODEV;
        goto generate_response;
    }

    if (((unsigned int)req->mr_label >= router->vr_max_labels)) {
        ret = -EINVAL;
        goto generate_response;
    }

    nh = vrouter_get_label(req->mr_rid, req->mr_label);
    if (!nh) {
        ret = -ENOENT;
        goto generate_response;
    }

    vr_mpls_make_req(req, nh, req->mr_label);

generate_response:
    if (ret)
        req = NULL;

    vr_message_response(VR_MPLS_OBJECT_ID, req, ret, false);

    return 0;
}

void
vr_mpls_req_process(void *s_req)
{
    vr_mpls_req *req = (vr_mpls_req *)s_req;

    switch (req->h_op) {
    case SANDESH_OP_ADD:
        vr_mpls_add(req);
        break;

    case SANDESH_OP_GET:
        vr_mpls_get(req);
        break;

    case SANDESH_OP_DUMP:
        vr_mpls_dump(req);
        break;

    case SANDESH_OP_DEL:
        vr_mpls_del(req);
        break;

    default:
        break;
    }
}

int
vr_mpls_tunnel_type(unsigned int label, unsigned int control_data, unsigned
        short *reason)
{
    struct vr_nexthop *nh;
    struct vrouter *router = vrouter_get(0);
    unsigned short res;

    if (!router) {
        res = VP_DROP_MISC;
        goto fail;
    }

    label >>= VR_MPLS_LABEL_SHIFT;
    if (label >= router->vr_max_labels) {
        res = VP_DROP_INVALID_LABEL;
        goto fail;
    }

    nh = __vrouter_get_label(router, label);
    if(!nh) {
        res = VP_DROP_INVALID_LABEL;
        goto fail;
    }

    switch(nh->nh_family) {
    case AF_INET:
        return PKT_MPLS_TUNNEL_L3;
    case AF_BRIDGE:
        if ((nh->nh_type == NH_COMPOSITE) && (label >= VR_MAX_UCAST_LABELS))
            return PKT_MPLS_TUNNEL_L2_MCAST;

        if (nh->nh_flags & NH_FLAG_L2_CONTROL_DATA)
            return PKT_MPLS_TUNNEL_L2_CONTROL_DATA;

        return PKT_MPLS_TUNNEL_L2_UCAST;

    default:
        res = VP_DROP_INVALID_NH;
    }

fail:
    if (reason)
        *reason = res;
    return -1;
}

int
vr_mpls_input(struct vrouter *router, struct vr_packet *pkt,
        struct vr_forwarding_md *fmd)
{
    int ttl, l2_offset = 0, pull_len = 0;
    unsigned int label;
    unsigned short drop_reason;

    struct vr_nexthop *nh;
    struct vr_ip *ip;
    struct vr_forwarding_md c_fmd;

    if (!fmd) {
        vr_init_forwarding_md(&c_fmd);
        fmd = &c_fmd;
    }

    label = ntohl(*(unsigned int *)pkt_data(pkt));
    ttl = label & 0xFF;
    label >>= VR_MPLS_LABEL_SHIFT;
    if (label >= router->vr_max_labels) {
        drop_reason = VP_DROP_INVALID_LABEL;
        goto dropit;
    }

    if (--ttl <= 0) {
        drop_reason = VP_DROP_TTL_EXCEEDED;
        goto dropit;
    }

    ip = (struct vr_ip *)pkt_network_header(pkt);
    fmd->fmd_outer_src_ip = ip->ip_saddr;
    vr_fmd_set_label(fmd, label, VR_LABEL_TYPE_MPLS);

    /* Store the TTL in packet. Will be used for multicast replication */
    pkt->vp_ttl = ttl;

    /* drop the TOStack label */
    if (!pkt_pull(pkt, VR_MPLS_HDR_LEN)) {
        drop_reason = VP_DROP_PULL;
        goto dropit;
    }

    if (!fmd->fmd_fe) {
        nh = __vrouter_get_label(router, label);
        if (!nh) {
            drop_reason = VP_DROP_INVALID_LABEL;
            goto dropit;
        }
    } else
        nh = pkt->vp_nh;

    /*
     * Mark it for GRO. Diag, L2 and multicast nexthops unmark if
     * required
     */
    if (vr_perfr) {
        vr_pkt_set_gro(pkt);
    }

    /* Reset the flags which get defined below */
    pkt->vp_flags &= ~VP_FLAG_MULTICAST;
    fmd->fmd_vlan = VLAN_ID_INVALID;

    if (nh->nh_family == AF_INET) {
        ip = (struct vr_ip *)pkt_data(pkt);
        if (vr_ip_is_ip4(ip)) {
            pkt->vp_type = VP_TYPE_IP;
        } else if (vr_ip_is_ip6(ip)) {
            pkt->vp_type = VP_TYPE_IP6;
        } else {
            drop_reason = VP_DROP_INVALID_PROTOCOL;
            goto dropit;
        }

        pkt_set_network_header(pkt, pkt->vp_data);
        pkt_set_inner_network_header(pkt, pkt->vp_data);

    } else if (nh->nh_family == AF_BRIDGE) {

        if (nh->nh_flags & NH_FLAG_L2_CONTROL_DATA) {
            vr_fmd_update_l2_control_data(fmd, true);
            pull_len = VR_L2_CTRL_DATA_LEN;
        }

        if ((nh->nh_type == NH_COMPOSITE) && (label >= VR_MAX_UCAST_LABELS)) {
            l2_offset = VR_VXLAN_HDR_LEN;
            pull_len = VR_L2_CTRL_DATA_LEN;
        }

        if (pull_len) {
            if (*(unsigned int *)pkt_data(pkt) != VR_L2_CTRL_DATA) {
                drop_reason = VP_DROP_INVALID_PACKET;
                goto dropit;
            }

            if (!pkt_pull(pkt, pull_len)) {
                drop_reason = VP_DROP_PULL;
                goto dropit;
            }
        }

        if (vr_pkt_type(pkt, l2_offset, fmd) < 0) {
            drop_reason = VP_DROP_INVALID_PACKET;
            goto dropit;
        }
    } else {
        drop_reason = VP_DROP_INVALID_NH;
        goto dropit;
    }

    /*
     * We are typically looking at interface nexthops, and hence we will
     * hit the vrf of the destination device. But, labels can also point
     * to composite nexthops (ECMP being case in point), in which case we
     * will take the vrf from the nexthop. When everything else fails, we
     * will forward the packet in the vrf in which it came i.e fabric
     */
    if (nh->nh_vrf >= 0)
        fmd->fmd_dvrf = nh->nh_vrf;
    else if (nh->nh_dev)
        fmd->fmd_dvrf = nh->nh_dev->vif_vrf;
    else
        fmd->fmd_dvrf = pkt->vp_if->vif_vrf;

    nh_output(pkt, nh, fmd);

    return 0;

dropit:
    vr_pfree(pkt, drop_reason);
    return 0;
}

void
vr_mpls_exit(struct vrouter *router, bool soft_reset)
{
    unsigned int i;
    struct vr_nexthop *nh;

    if (!router->vr_max_labels || !router->vr_ilm)
        return;

    for (i = 0; i < router->vr_max_labels; i++) {
        nh = __vrouter_get_label(router, i);
        if (nh) {
            vrouter_put_nexthop(nh);
            __vrouter_set_label(router, i, NULL);
        }
    }

    if (soft_reset == false) {
        vr_btable_free(router->vr_ilm);
        router->vr_ilm = NULL;
        router->vr_max_labels = 0;
    }

    return;
}

int
vr_mpls_init(struct vrouter *router)
{
    int ilm_memory;

    if (!router->vr_ilm) {
        router->vr_max_labels = vr_mpls_labels;
        ilm_memory = sizeof(struct vr_nexthop *) * router->vr_max_labels;
        router->vr_ilm = vr_btable_alloc(router->vr_max_labels,
                sizeof(struct vr_nexthop *));
        if (!router->vr_ilm)
            return vr_module_error(-ENOMEM, __FUNCTION__,
                    __LINE__, ilm_memory);
    }

    return 0;
}
