/*
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */

#include "vr_os.h"
#include "vr_types.h"
#include "vr_packet.h"
#include "vr_interface.h"
#include "vr_sandesh.h"
#include "vr_message.h"
#include "vr_mirror.h"

struct vr_mirror_entry *
vrouter_get_mirror(unsigned int rid, unsigned int index)
{
    struct vrouter *router = vrouter_get(rid);

    if (!router || index >= router->vr_max_mirror_indices)
        return NULL;

    return router->vr_mirrors[index];
}

static void
vr_mirror_defer_delete(struct vrouter *router, void *arg)
{
    struct vr_defer_data *defer = (struct vr_defer_data *)arg;

    vr_free(defer->vdd_data, VR_MIRROR_OBJECT);

    return;
}

int
__vr_mirror_del(struct vrouter *router, unsigned int index)
{
    struct vr_nexthop *nh;
    struct vr_mirror_entry *mirror;
    struct vr_defer_data *defer;

    if (index >= router->vr_max_mirror_indices)
        return -EINVAL;

    mirror = router->vr_mirrors[index];
    if (!mirror)
        return -EINVAL;

    nh = mirror->mir_nh;
    router->vr_mirrors[index] = NULL;
    mirror->mir_nh = NULL;

    if (!vr_not_ready) {
        defer = vr_get_defer_data(sizeof(*defer));
        if (defer) {
            defer->vdd_data = (void *)mirror;
            vr_defer(router, vr_mirror_defer_delete, (void *)defer);
        } else {
            vr_delay_op();
            vr_free(mirror, VR_MIRROR_OBJECT);
        }
    } else {
        vr_free(mirror, VR_MIRROR_OBJECT);
    }
    vrouter_put_nexthop(nh);

    return 0;
}

int
vr_mirror_del(vr_mirror_req *req)
{
    int ret = -EINVAL;
    struct vrouter *router;

    router = vrouter_get(req->mirr_rid);
    if (router)
        ret = __vr_mirror_del(router, req->mirr_index);

    vr_send_response(ret);

    return ret;
}

int
vr_mirror_add(vr_mirror_req *req)
{
    int ret = 0;
    struct vrouter *router;
    struct vr_nexthop *nh, *old_nh = NULL;
    struct vr_mirror_entry *mirror;

    router = vrouter_get(req->mirr_rid);
    if (!router) {
        ret = -EINVAL;
        goto generate_resp;
    }

    if ((unsigned int)req->mirr_index >= router->vr_max_mirror_indices) {
        ret = -EINVAL;
        goto generate_resp;
    }

    nh = vrouter_get_nexthop(req->mirr_rid, req->mirr_nhid);
    if (!nh) {
        ret = -EINVAL;
        goto generate_resp;
    }

    mirror = router->vr_mirrors[req->mirr_index];
    if (!mirror) {
        mirror = vr_zalloc(sizeof(*mirror), VR_MIRROR_OBJECT);
        if (!mirror) {
            ret = -ENOMEM;
            vrouter_put_nexthop(nh);
            goto generate_resp;
        }
    } else {
        old_nh = mirror->mir_nh;
    }

    mirror->mir_nh = nh;
    mirror->mir_rid = req->mirr_rid;
    mirror->mir_flags = req->mirr_flags;
    mirror->mir_vni = req->mirr_vni;
    router->vr_mirrors[req->mirr_index] = mirror;

    if (old_nh)
        vrouter_put_nexthop(old_nh);

generate_resp:
    vr_send_response(ret);

    return ret;
}


static void
vr_mirror_make_req(vr_mirror_req *req, struct vr_mirror_entry *mirror,
                unsigned short index)
{
    req->mirr_index = index;
    if (mirror->mir_nh)
        req->mirr_nhid = mirror->mir_nh->nh_id;

    req->mirr_flags = mirror->mir_flags;
    req->mirr_rid = mirror->mir_rid;
    req->mirr_vni = mirror->mir_vni;
    return;
}


static int
vr_mirror_dump(vr_mirror_req *r)
{
    int ret = 0;
    unsigned int i;
    struct vrouter *router = vrouter_get(r->mirr_rid);
    vr_mirror_req req;
    struct vr_mirror_entry *mirror;
    struct vr_message_dumper *dumper = NULL;

    if (!router && (ret = -ENODEV))
        goto generate_response;

    if ((unsigned int)(r->mirr_marker + 1) >= router->vr_max_mirror_indices)
        goto generate_response;

    dumper = vr_message_dump_init(r);
    if (!dumper && (ret = -ENOMEM))
        goto generate_response;

    for (i = (unsigned int)(r->mirr_marker + 1);
            i < router->vr_max_mirror_indices; i++) {
        mirror = router->vr_mirrors[i];
        if (mirror) {
           vr_mirror_make_req(&req, mirror, i);
           ret = vr_message_dump_object(dumper, VR_MIRROR_OBJECT_ID, &req);
           if (ret <= 0)
               break;
        }
    }

generate_response:
    vr_message_dump_exit(dumper, ret);

    return 0;
}

static int
vr_mirror_get(vr_mirror_req *req)
{
    int ret = 0;
    struct vrouter *router;
    struct vr_mirror_entry *mirror = NULL;

    router = vrouter_get(req->mirr_rid);
    if (!router ||
            (unsigned int)req->mirr_index >= router->vr_max_mirror_indices) {
        ret = -ENODEV;
    } else {
        mirror = router->vr_mirrors[req->mirr_index];
        if (!mirror)
            ret = -ENOENT;
    }

    if (mirror) {
        vr_mirror_make_req(req, mirror, req->mirr_index);
    } else
        req = NULL;

    return vr_message_response(VR_MIRROR_OBJECT_ID, req, ret);
}

void
vr_mirror_req_process(void *s_req)
{
    vr_mirror_req *req = (vr_mirror_req *)s_req;

    switch (req->h_op) {
    case SANDESH_OP_ADD:
        vr_mirror_add(req);
        break;

    case SANDESH_OP_GET:
        vr_mirror_get(req);
        break;

    case SANDESH_OP_DUMP:
        vr_mirror_dump(req);
        break;

    case SANDESH_OP_DELETE:
        vr_mirror_del(req);
        break;

    default:
        break;
    }

    return;
}

static void
vr_mirror_meta_destroy(struct vr_mirror_meta_entry *me)
{
    if (!me)
        return;

    if (me->mirror_md)
        vr_free(me->mirror_md, VR_MIRROR_META_OBJECT);

    vr_free(me, VR_MIRROR_META_OBJECT);
    return;
}

static void
vr_mirror_meta_destructor(struct vrouter *router, void *arg)
{
    struct vr_defer_data *defer = (struct vr_defer_data *)arg;
    struct vr_mirror_meta_entry *me;

    if (!defer)
        return;

    me = (struct vr_mirror_meta_entry *)defer->vdd_data;
    vr_mirror_meta_destroy(me);

    return;
}

static void
vr_mirror_meta_entry_destroy(struct vrouter *router,
                            struct vr_mirror_meta_entry *me)
{
    struct vr_defer_data *defer;

    if (me) {
        if (!vr_not_ready) {
            defer = vr_get_defer_data(sizeof(*defer));
            if (!defer) {
                vr_delay_op();
                vr_mirror_meta_destroy(me);
                return;
            }
            defer->vdd_data = (void *)me;
            vr_defer(me->mirror_router, vr_mirror_meta_destructor, (void *)defer);
        } else {
            vr_mirror_meta_destroy(me);
        }
    }

    return;
}

struct vr_mirror_meta_entry *
vr_mirror_meta_entry_set(struct vrouter *router, unsigned int index,
                         unsigned int mir_sip, unsigned short mir_sport,
                         void *meta_data, unsigned int meta_data_len,
                         unsigned short mirror_vrf)
{
    char *buf;
    struct vr_mirror_meta_entry *me;

    me = vr_malloc(sizeof(*me), VR_MIRROR_META_OBJECT);
    if (!me)
        return NULL;

    buf = vr_malloc(meta_data_len, VR_MIRROR_META_OBJECT);
    if (!buf) {
        vr_free(me, VR_MIRROR_META_OBJECT);
        return NULL;
    }

    memcpy(buf, meta_data, meta_data_len);
    me->mirror_router = router;
    me->mirror_md = buf;
    me->mirror_md_len = meta_data_len;
    me->mirror_sip = mir_sip;
    me->mirror_sport = mir_sport;
    me->mirror_vrf = mirror_vrf;

    return me;
}

void
vr_mirror_meta_entry_del(struct vrouter *router,
                    struct vr_mirror_meta_entry *me)
{
    if (me)
        vr_mirror_meta_entry_destroy(router, (void *)me);

    return;
}

static struct vr_mirror_meta_entry *
vr_mirror_meta_entry_get(struct vrouter *router, unsigned int flow_index)
{
    struct vr_flow_entry *fe;

    fe = vr_flow_get_entry(router, flow_index);
    if (fe)
        return fe->fe_mme;

    return NULL;
}

int
vr_mirror(struct vrouter *router, uint8_t mirror_id, struct vr_packet *pkt,
            struct vr_forwarding_md *fmd, mirror_type_t mtype)
{
    bool reset = true;
    unsigned int captured_len, clone_len = 0, mirror_md_len = 0;
    unsigned long sec, usec;
    void *mirror_md;
    unsigned char *buf;
    struct vr_nexthop *nh, *pkt_nh;
    struct vr_pcap *pcap;
    struct vr_mirror_entry *mirror;
    struct vr_mirror_meta_entry *mme;
    unsigned char default_mme[2] = {0xff, 0x0};
    struct vr_forwarding_md new_fmd;

    /* If the packet is already mirrored, dont mirror again */
    if (pkt->vp_flags & VP_FLAG_FROM_DP)
        return 0;

    if (mtype <= MIRROR_TYPE_UNKNOWN || mtype >= MIRROR_TYPE_MAX)
        return 0;

    mirror = router->vr_mirrors[mirror_id];
    if (!mirror)
        return 0;

    /* in almost all the cases, fmd should be set */
    if (fmd) {
        memcpy(&new_fmd, fmd, sizeof(*fmd));
        new_fmd.fmd_ecmp_nh_index = -1;
    } else {
        vr_init_forwarding_md(&new_fmd);
    }
    fmd = &new_fmd;

    nh = mirror->mir_nh;
    if (!nh || !(nh->nh_flags & NH_FLAG_VALID))
        return 0;

    pkt = vr_pclone(pkt);
    if (!pkt)
        return 0;

    /* Mark as mirrored */
    pkt->vp_flags |= VP_FLAG_FROM_DP;

    /* Set the GSO and partial checksum flag */
    pkt->vp_flags |= (VP_FLAG_FLOW_SET | VP_FLAG_GSO);
    pkt->vp_flags &= ~VP_FLAG_GRO;

    if (mirror->mir_flags & VR_MIRROR_FLAG_DYNAMIC) {

        clone_len += sizeof(struct vr_pcap);

        if (mtype == MIRROR_TYPE_ACL) {
            if (fmd->fmd_flow_index >= 0) {
                mme = vr_mirror_meta_entry_get(router, fmd->fmd_flow_index);
                if (mme) {
                    mirror_md_len = mme->mirror_md_len;
                    mirror_md = mme->mirror_md;
                }
            }
        } else if (mtype == MIRROR_TYPE_PORT_RX) {
            if (!pkt->vp_if)
                goto fail;

            mirror_md_len = pkt->vp_if->vif_mirror_md_len;
            mirror_md = pkt->vp_if->vif_mirror_md;
        } else {
            if (!pkt->vp_nh || !pkt->vp_nh->nh_dev)
             goto fail;

            mirror_md_len = pkt->vp_nh->nh_dev->vif_mirror_md_len;
            mirror_md = pkt->vp_nh->nh_dev->vif_mirror_md;
        }

        if (!mirror_md_len) {
            mirror_md = default_mme;
            mirror_md_len = sizeof(default_mme);
        }

        clone_len += mirror_md_len;
        clone_len += VR_MIRROR_PKT_HEAD_SPACE;
    } else {
        clone_len += VR_VXLAN_HDR_LEN;
        fmd->fmd_label = mirror->mir_vni;
    }

    if (pkt->vp_if && (pkt->vp_if->vif_type == VIF_TYPE_PHYSICAL)) {
        /* No need to mirror the Tunnel headers. So packet cant be reset */
        reset = false;

        /* Identify whether the packet currently has L2 header. If not a
         * port mirroring, we need to add the extra L2 header
         */
        if (mtype == MIRROR_TYPE_ACL) {

            pkt_nh = pkt->vp_nh;
            if (pkt_nh && (pkt_nh->nh_flags & NH_FLAG_VALID) &&
                        (pkt_nh->nh_type == NH_ENCAP) &&
                        (pkt_nh->nh_family == AF_INET)) {

                clone_len += pkt_nh->nh_encap_len;


                if (vr_pcow(pkt, clone_len))
                    goto fail;
                clone_len = 0;

                if (!pkt_nh->nh_dev->vif_set_rewrite(pkt_nh->nh_dev, pkt, fmd,
                                    pkt_nh->nh_data, pkt_nh->nh_encap_len))
                        goto fail;
            }
        }
    }

    if (reset)
        vr_preset(pkt);

    if (clone_len) {
        if (vr_pcow(pkt, clone_len))
            goto fail;
    }

    captured_len = htonl(pkt_len(pkt));
    if (mirror_md_len) {

        buf = pkt_push(pkt, mirror_md_len);
        if (!buf)
            goto fail;
        memcpy(buf, mirror_md, mirror_md_len);

        /* Add the pcap header */
        pcap = (struct vr_pcap *)pkt_push(pkt, sizeof(struct vr_pcap));
        if (!pcap)
            goto fail;

        pcap->pcap_incl_len = captured_len;
        pcap->pcap_orig_len = captured_len;

        vr_get_time(&sec, &usec);

        pcap->pcap_ts_sec = sec;
        pcap->pcap_ts_usec = usec;

        pcap->pcap_ts_sec = htonl(pcap->pcap_ts_sec);
        pcap->pcap_ts_usec = htonl(pcap->pcap_ts_usec);
    }

    if (nh->nh_vrf >= 0)
        fmd->fmd_dvrf = nh->nh_vrf;

    /*
     * we are now in the mirroring context and there isn't a flow for this
     * mirror packet. hence, set the flow index to -1.
     */
    fmd->fmd_flow_index = -1;

    nh_output(pkt, nh, fmd);
    return 0;

fail:
    vr_pfree(pkt, VP_DROP_PUSH);
    return 0;
}

void
vr_mirror_exit(struct vrouter *router, bool soft_reset)
{
    unsigned int i;

    if (router->vr_mirrors)
        for (i = 0; i < router->vr_max_mirror_indices; i++)
            if (router->vr_mirrors[i])
                __vr_mirror_del(router, i);

    if (!soft_reset) {
        vr_free(router->vr_mirrors, VR_MIRROR_TABLE_OBJECT);
        router->vr_mirrors = NULL;
        router->vr_max_mirror_indices = 0;
    }

    return;
}

int
vr_mirror_init(struct vrouter *router)
{
    unsigned int size;

    if (!router->vr_mirrors) {
        router->vr_max_mirror_indices = VR_MAX_MIRROR_INDICES;
        size = sizeof(struct vr_mirror_entry *) * router->vr_max_mirror_indices;
        router->vr_mirrors = vr_zalloc(size, VR_MIRROR_TABLE_OBJECT);
        if (!router->vr_mirrors)
            return vr_module_error(-ENOMEM, __FUNCTION__, __LINE__, size);
    }

    return 0;

}

