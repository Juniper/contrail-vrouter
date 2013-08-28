/*
 * vr_mpls.c -- mpls handling of packets
 *
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#include <vr_os.h>
#include "vr_message.h"
#include "vr_sandesh.h"
#include "vr_mpls.h"

static struct vr_nexthop *
vrouter_get_label(unsigned int rid, unsigned int label)
{
    struct vrouter *router = vrouter_get(rid);

    if (!router || label > router->vr_max_labels)
        return NULL;

    return router->vr_ilm[label];
}

int
vr_mpls_del(vr_mpls_req *req)
{
    struct vrouter *router;
    int ret = 0;

    router = vrouter_get(req->mr_rid);
    if (!router) {
        ret = -EINVAL;
        goto generate_resp;
    }

    if (req->mr_label > (int)router->vr_max_labels) {
        ret = -EINVAL;
        goto generate_resp;
    }

    if (router->vr_ilm[req->mr_label])
        vrouter_put_nexthop(router->vr_ilm[req->mr_label]);

    router->vr_ilm[req->mr_label] = NULL;

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

    if ((unsigned int)req->mr_label > router->vr_max_labels) {
        ret = -EINVAL;
        goto generate_resp;
    }

    nh = vrouter_get_nexthop(req->mr_rid, req->mr_nhid);
    if (!nh)  {
        ret = -EINVAL;
        goto generate_resp;
    }

    router->vr_ilm[req->mr_label] = nh;

generate_resp:
    vr_send_response(ret);

    return ret;
}

static void
vr_mpls_make_req(vr_mpls_req *req, struct vr_nexthop *nh,
                unsigned short label)
{
    req->mr_rid = 0;
    req->mr_nhid = nh->nh_id;
    req->mr_label = label;

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
        nh = router->vr_ilm[i];
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
    if (!router || req->mr_label > (int)router->vr_max_labels) {
        ret = -ENODEV;
    } else {
        nh = vrouter_get_label(req->mr_rid, req->mr_label);
        if (!nh)
            ret = -ENOENT;
    }

    if (!ret)
        vr_mpls_make_req(req, nh, req->mr_label);
    else
        req = NULL;

    vr_message_response(VR_MPLS_OBJECT_ID, req, ret);

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

    case SANDESH_OP_DELETE:
        vr_mpls_del(req);
        break;

    default:
        break;
    }
}

static int
vr_mcast_mpls_input(struct vrouter *router, struct vr_packet *pkt,
        struct vr_forwarding_md *fmd) 
{
    unsigned int ttl;
    unsigned int label;
    unsigned short drop_reason = 0;
    int i;
    int found;
    struct vr_nexthop *nh;
    struct vr_nexthop *dir_nh;
    struct vr_ip *ip;

    label = ntohl(*(unsigned int *)pkt_data(pkt));
    ttl = label & 0xFF;
    label >>= VR_MPLS_LABEL_SHIFT;

    if (--ttl == 0) {
        drop_reason = VP_DROP_TTL_EXCEEDED;
        goto dropit;
    }

    nh = router->vr_ilm[label];
    if (!nh || nh->nh_type != NH_COMPOSITE) {
        drop_reason = VP_DROP_INVALID_NH;
        goto dropit;
    }

    if (!pkt_pull(pkt, VR_MPLS_HDR_LEN)) {
        drop_reason = VP_DROP_PUSH;
        goto dropit;
    }

    ip = (struct vr_ip *)pkt_network_header(pkt);

    /* Ensure that the packet is received from one of the tree descendants */
    for (i = 0, found = 0; i < nh->nh_component_cnt; i++) {
        dir_nh = nh->nh_component_nh[i].cnh;
        if (dir_nh->nh_type == NH_TUNNEL) {
            if (ip->ip_saddr == dir_nh->nh_gre_tun_dip) {
                found = 1;
                break;
            }
        }
    }

    if (found == 0) {
        drop_reason = VP_DROP_INVALID_MCAST_SOURCE;
        goto dropit;
    }

    /* Update the ttl to be used for the subsequent nh processing */
    pkt->vp_ttl = ttl;

    /* If from valid descndant, start replicating */
    nh_output(pkt->vp_if->vif_vrf, pkt, nh, fmd);
    return 0;

dropit:
    vr_pfree(pkt, drop_reason);
    return 0;
}

int
vr_mpls_input(struct vrouter *router, struct vr_packet *pkt,
        struct vr_forwarding_md *fmd)
{
    unsigned int label;
    unsigned short vrf;
    struct vr_nexthop *nh;
    unsigned char *data;
    struct vr_ip *ip;
    unsigned short drop_reason = 0;

    label = ntohl(*(unsigned int *)pkt_data(pkt));
    label >>= VR_MPLS_LABEL_SHIFT;
    if (label >= router->vr_max_labels) {
        drop_reason = VP_DROP_INVALID_LABEL;
        goto dropit;
    }

    /* Set network header to inner ip header only if unicast */
    if (vr_mpls_is_label_mcast(label) == true) {
        vr_mcast_mpls_input(router, pkt, fmd);
        return 0;
    }

    /* drop the TOStack label */
    data = pkt_pull(pkt, VR_MPLS_HDR_LEN);
    if (!data) {
        drop_reason = VP_DROP_PULL;
        goto dropit;
    }

    /* this is the new network header and inner network header too*/
    pkt_set_network_header(pkt, pkt->vp_data);
    pkt_set_inner_network_header(pkt, pkt->vp_data);
    pkt->vp_type = VP_TYPE_IP;

    nh = router->vr_ilm[label];
    if (!nh) {
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
        vrf = nh->nh_vrf;
    else if (nh->nh_dev)
        vrf = nh->nh_dev->vif_vrf;
    else
        vrf = pkt->vp_if->vif_vrf;

    ip = (struct vr_ip *)pkt_data(pkt);
    if (ip->ip_csum == VR_DIAG_IP_CSUM) {
        pkt->vp_flags |= VP_FLAG_DIAG;
    } else if (vr_perfr) {
        pkt->vp_flags |= VP_FLAG_GRO;
    }

    nh_output(vrf, pkt, nh, fmd);

    return 0;

dropit:
    vr_pfree(pkt, drop_reason);
    return 0;
}

void
vr_mpls_exit(struct vrouter *router, bool soft_reset)
{
    unsigned int i;

    if (!router->vr_max_labels || !router->vr_ilm)
        return;

    for (i = 0; i < router->vr_max_labels; i++) {
        if (router->vr_ilm[i]) {
            vrouter_put_nexthop(router->vr_ilm[i]);
            router->vr_ilm[i] = NULL;
        }
    }

    if (soft_reset == false) {
        vr_free(router->vr_ilm);
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
        router->vr_max_labels = VR_MAX_LABELS;
        ilm_memory = sizeof(struct vr_nexthop *) * router->vr_max_labels;
        router->vr_ilm = vr_zalloc(ilm_memory);
        if (!router->vr_ilm)
            return vr_module_error(-ENOMEM, __FUNCTION__,
                    __LINE__, ilm_memory);
    }

    return 0;
}
