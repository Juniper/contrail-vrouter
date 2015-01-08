/*
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */

#include "vr_os.h"
#include "vr_types.h"
#include "vr_packet.h"
#include "vr_sandesh.h"
#include "vr_message.h"
#include "vr_mirror.h"

int vr_mirror_add(vr_mirror_req *);
int vr_mirror_del(vr_mirror_req *);

static struct vr_mirror_entry *
__vrouter_get_mirror(unsigned int rid, unsigned int index)
{
    struct vrouter *router = vrouter_get(rid);

    if (!router || index >= router->vr_max_mirror_indices)
        return NULL;

    return router->vr_mirrors[index];
}

struct vr_mirror_entry *
vrouter_get_mirror(unsigned int rid, unsigned int index)
{
    struct vr_mirror_entry *mirror;

    mirror = __vrouter_get_mirror(rid, index);
    if (mirror)
        mirror->mir_users++;

    return mirror;
}

int
vrouter_put_mirror(struct vrouter *router, unsigned int index) 
{
    struct vr_mirror_entry *mirror;

    if (index >= router->vr_max_mirror_indices)
        return -EINVAL;

    mirror = router->vr_mirrors[index];
    if (!mirror)
        return -EINVAL;

    if (!--mirror->mir_users) {
        router->vr_mirrors[index] = NULL;

        if (!vr_not_ready)
            vr_delay_op();

        vrouter_put_nexthop(mirror->mir_nh);
        vr_free(mirror);
    }

    return 0;
}


int
vr_mirror_del(vr_mirror_req *req)
{
    int ret = 0;
    struct vrouter *router;
    struct vr_mirror_entry *mirror;
    struct vr_nexthop *nh;

    router = vrouter_get(req->mirr_rid);
    if (!router) {
        ret = -EINVAL;
        goto generate_resp;
    }

    mirror = __vrouter_get_mirror(req->mirr_rid, req->mirr_index);
    if (!mirror) {
        ret = -EINVAL;
        goto generate_resp;
    }

    mirror->mir_flags |= VR_MIRROR_FLAG_MARKED_DELETE;
    nh = mirror->mir_nh;
    mirror->mir_nh = vrouter_get_nexthop(req->mirr_rid, NH_DISCARD_ID);
    /* release the old nexthop */
    vrouter_put_nexthop(nh);

    /* ...and finally try to release the mirror entry */
    vrouter_put_mirror(router, req->mirr_index);

generate_resp:
    vr_send_response(ret);

    return ret;
}

static int
vr_mirror_change(struct vr_mirror_entry *mirror, vr_mirror_req *req,
        struct vr_nexthop *nh_new)
{
    struct vr_nexthop *nh_old = mirror->mir_nh;

    if (mirror->mir_flags & VR_MIRROR_FLAG_MARKED_DELETE) {
        mirror->mir_flags &= ~VR_MIRROR_FLAG_MARKED_DELETE;
        mirror->mir_users++;
    }

    mirror->mir_flags |= req->mirr_flags;
    mirror->mir_nh = nh_new;
    vrouter_put_nexthop(nh_old);

    return 0;
}

int
vr_mirror_add(vr_mirror_req *req)
{
    struct vrouter *router;
    struct vr_nexthop *nh;
    int ret = 0;
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

    req->mirr_flags &= ~VR_MIRROR_FLAG_MARKED_DELETE;

    nh = vrouter_get_nexthop(req->mirr_rid, req->mirr_nhid);
    if (!nh)  {
        ret = -EINVAL;
        goto generate_resp;
    }

    mirror = __vrouter_get_mirror(req->mirr_rid, req->mirr_index);
    if (mirror) {
        vr_mirror_change(mirror, req, nh);
    } else {
        mirror = vr_zalloc(sizeof(*mirror));
        mirror->mir_users++;
        mirror->mir_nh = nh;
        mirror->mir_rid = req->mirr_rid;
        mirror->mir_flags = req->mirr_flags;
        router->vr_mirrors[req->mirr_index] = mirror;
    }

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

    req->mirr_users = mirror->mir_users;
    req->mirr_flags = mirror->mir_flags;
    req->mirr_rid = mirror->mir_rid;
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
        mirror = __vrouter_get_mirror(req->mirr_rid, req->mirr_index);
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
        vr_free(me->mirror_md);

    vr_free(me);
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
vr_mirror_meta_entry_destroy(unsigned int index, void *arg)
{
    struct vr_mirror_meta_entry *me = (struct vr_mirror_meta_entry *)arg;
    struct vr_defer_data *defer;

    if (me && me != VR_ITABLE_ERR_PTR) {
        if (!vr_not_ready) {
            defer = vr_get_defer_data(sizeof(*defer));
            if (!defer) {
                vr_delay_op();
                vr_mirror_meta_destroy(me);
                return;
            }
            defer->vdd_data = (void *)me;
            vr_defer(me->mirror_router, vr_mirror_meta_destructor, (void *)defer);
        }
    }

    return;
}

int
vr_mirror_meta_entry_set(struct vrouter *router, unsigned int index,
                         unsigned int mir_sip, unsigned short mir_sport, 
                         void *meta_data, unsigned int meta_data_len,
                         unsigned short mirror_vrf)
{
    char *buf;
    struct vr_mirror_meta_entry *me, *me_old;

    me = vr_malloc(sizeof(*me));
    if (!me)
        return -ENOMEM;

    buf = vr_malloc(meta_data_len);
    if (!buf) {
        vr_free(me);
        return -ENOMEM;
    }

    memcpy(buf, meta_data, meta_data_len);
    me->mirror_router = router;
    me->mirror_md = buf;
    me->mirror_md_len = meta_data_len;
    me->mirror_sip = mir_sip;
    me->mirror_sport = mir_sport;
    me->mirror_vrf = mirror_vrf;

    me_old = vr_itable_set(router->vr_mirror_md, index, me);
    if (me_old && me_old != VR_ITABLE_ERR_PTR)
        vr_mirror_meta_entry_destroy(index, (void *)me_old);
    
    return 0;
}

void
vr_mirror_meta_entry_del(struct vrouter *router, unsigned int index)
{
    struct vr_mirror_meta_entry *me;

    me = vr_itable_del(router->vr_mirror_md, index);
    if (me)
        vr_mirror_meta_entry_destroy(index, (void *)me);

    return;
}

int
vr_mirror(struct vrouter *router, uint8_t mirror_id, 
          struct vr_packet *pkt, struct vr_forwarding_md *fmd)
{
    unsigned char *buf;
    struct vr_nexthop *nh;
    struct vr_pcap *pcap;
    struct vr_mirror_entry *mirror;
    struct vr_mirror_meta_entry *mme;
    unsigned int captured_len;
    unsigned int mirror_md_len = 0;
    unsigned char default_mme[2] = {0xff, 0x0};
    void *mirror_md;
    struct vr_nexthop *pkt_nh;
    bool reset;

    mirror = router->vr_mirrors[mirror_id];
    if (!mirror)
        return 0;

    if (fmd->fmd_flow_index >= 0) {
        mme = (struct vr_mirror_meta_entry *)vr_itable_get(router->vr_mirror_md,
                                                           fmd->fmd_flow_index);
        if (!mme)
            return 0;
        mirror_md_len = mme->mirror_md_len;
        mirror_md = mme->mirror_md;
        fmd->fmd_dvrf = mme->mirror_vrf;
    } else {
        mirror_md_len = sizeof(default_mme);
        mirror_md = default_mme;
    }

    nh = mirror->mir_nh;
    pkt = vr_pclone(pkt);
    if (!pkt)
        return 0;

    /* If packet is from fabric, mirror it by adding the required L2
     * header. If not get the processed headers by resetting the packet
     * and mirror it
     */
    reset = true;
    if (pkt->vp_if && pkt->vp_if->vif_type == VIF_TYPE_PHYSICAL) {
        pkt_nh = pkt->vp_nh;
        if (pkt_nh && pkt_nh->nh_type == NH_ENCAP && pkt_nh->nh_dev &&
            pkt_nh->nh_dev->vif_set_rewrite && pkt_nh->nh_encap_len) {

            reset = false;
            if (vr_pcow(pkt,  VR_MIRROR_PKT_HEAD_SPACE + mirror_md_len +
                    pkt_nh->nh_encap_len)) 
                goto fail;

            if (!pkt_nh->nh_dev->vif_set_rewrite(pkt_nh->nh_dev, pkt, 
                    pkt_nh->nh_data, pkt_nh->nh_encap_len))
                goto fail;
        }
    }

    if (reset) {
        vr_preset(pkt);
        if (vr_pcow(pkt,  VR_MIRROR_PKT_HEAD_SPACE + mirror_md_len))
            goto fail;
    }


    pkt->vp_flags |= VP_FLAG_FROM_DP;
    /* Set the GSO and partial checksum flag */
    pkt->vp_flags |= (VP_FLAG_FLOW_SET | VP_FLAG_GSO | VP_FLAG_CSUM_PARTIAL);
    pkt->vp_flags &= ~VP_FLAG_GRO;
    buf = pkt_push(pkt, mirror_md_len);
    if (!buf)
        goto fail;

    captured_len = htonl(pkt_len(pkt));
    if (mirror_md_len) 
        memcpy(buf, mirror_md, mirror_md_len);

    if (mirror->mir_flags & VR_MIRROR_PCAP) {
        /* Add the pcap header */
        pcap = (struct vr_pcap *)pkt_push(pkt, sizeof(struct vr_pcap));
        if (!pcap)
            goto fail;
        
        pcap->pcap_incl_len = captured_len;
        pcap->pcap_orig_len = captured_len;
        
        /* Get the time stamp in seconds and nanoseconds*/
        vr_get_time(&pcap->pcap_ts_sec, &pcap->pcap_ts_usec);
        pcap->pcap_ts_sec = htonl(pcap->pcap_ts_sec);
        /* Convert nanoseconds to usec */
        pcap->pcap_ts_usec = htonl(pcap->pcap_ts_usec/1000);
    }

    fmd->fmd_dvrf = nh->nh_vrf;
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
                vrouter_put_mirror(router, i);

    if (router->vr_mirror_md) {
        vr_itable_delete(router->vr_mirror_md,
                vr_mirror_meta_entry_destroy);
        router->vr_mirror_md = NULL;
    }

    if (!soft_reset) {
        vr_free(router->vr_mirrors);
        router->vr_mirrors = NULL; 
        router->vr_max_mirror_indices = 0;
    }

    return;
}

int
vr_mirror_init(struct vrouter *router)
{
    int ret = 0;
    unsigned int size;

    if (!router->vr_mirrors) {
        router->vr_max_mirror_indices = VR_MAX_MIRROR_INDICES;
        size = sizeof(struct vr_mirror_entry *) * router->vr_max_mirror_indices;
        router->vr_mirrors = vr_zalloc(size);
        if (!router->vr_mirrors)
            return vr_module_error(-ENOMEM, __FUNCTION__, __LINE__, size);
    }

    if (!router->vr_mirror_md) {
        router->vr_mirror_md = vr_itable_create(32, 4, 8, 8, 8, 8);
        if (!router->vr_mirror_md && (ret = -ENOMEM)) {
            vr_module_error(ret, __FUNCTION__, __LINE__, 0);
            goto cleanup;
        }
    }

    return 0;

cleanup:
    if (router->vr_mirrors) {
        vr_free(router->vr_mirrors);
        router->vr_mirrors = NULL;
    }

    if (router->vr_mirror_md) {
        vr_itable_delete(router->vr_mirror_md, vr_mirror_meta_entry_destroy);
        router->vr_mirror_md = NULL;
    }

    return ret;
}

