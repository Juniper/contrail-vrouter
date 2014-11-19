/*
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#include <vr_os.h>
#include <vr_types.h>
#include <vr_packet.h>
#include "vr_sandesh.h"
#include "vr_message.h"
#include <vr_mcast.h>
#include <vr_htable.h>
#include <vr_nexthop.h>

struct vr_mcast_entry_key {
    unsigned int src_ip; /* In network byte order */
    unsigned int dst_ip; /* This too */
    unsigned short vrf_id;
}__attribute__((packed));

struct vr_dummy_mcast_entry {
    struct vr_mcast_entry_key key;
    struct vr_nexthop *nh;
    unsigned short flags;
}__attribute__((packed));
#define VR_MCAST_ENTRY_PACK (32 - sizeof(struct vr_dummy_mcast_entry))

struct vr_mcast_entry {
    struct vr_mcast_entry_key key;
    struct vr_nexthop *nh;
    unsigned short flags;
    unsigned short pack[VR_MCAST_ENTRY_PACK];
}__attribute__((packed));

#define VR_DEF_MCAST_ENTRIES          (1 * 1024)
#define VR_DEF_MCAST_OENTRIES         (512)
#define VR_MCAST_FLAG_VALID           1

unsigned int vr_mcast_entries = VR_DEF_MCAST_ENTRIES;
unsigned int vr_mcast_oentries = VR_DEF_MCAST_OENTRIES;

static vr_htable_t vn_rtable;
extern struct vr_nexthop *ip4_default_nh;

struct vr_mcast_entry *vr_find_mcast_entry(struct vr_mcast_entry_key *);
struct vr_mcast_entry *vr_find_free_mcast_entry(struct vr_mcast_entry_key *);
void mcast_algo_deinit(struct vr_rtable *, struct rtable_fspec *, bool);
int mcast_algo_init(struct vr_rtable *, struct rtable_fspec *);

static bool
mcast_entry_valid(vr_htable_t htable, vr_hentry_t hentry,
                                              unsigned int index)
{
    struct vr_mcast_entry *ent = (struct vr_mcast_entry *)hentry;
    if (!htable || !ent)
        return false;

    if (ent->flags & VR_MCAST_FLAG_VALID)
        return true;

    return false;
}

struct vr_mcast_entry *
vr_find_mcast_entry(struct vr_mcast_entry_key *key)
{
    if (!vn_rtable || !key)
        return NULL;

    return vr_find_hentry(vn_rtable, key, NULL);
}

struct vr_mcast_entry *
vr_find_free_mcast_entry(struct vr_mcast_entry_key *key)
{

    if (!vn_rtable || !key)
        return NULL;

    return vr_find_free_hentry(vn_rtable, key, NULL);
}

static struct vr_nexthop *
mcast_lookup(unsigned int vrf_id, struct vr_route_req *rt,
        struct vr_packet *pkt) 
{
    struct vr_mcast_entry *ent;
    struct vr_mcast_entry_key key;

    key.vrf_id = rt->rtr_req.rtr_vrf_id;
    if (rt->rtr_req.rtr_src_size)
        key.src_ip = ntohl(*(uint32_t*)rt->rtr_req.rtr_src);
    else
        key.src_ip = 0;

    if (rt->rtr_req.rtr_prefix_size)
        key.dst_ip = ntohl(*(uint32_t*)rt->rtr_req.rtr_prefix);
    else
        key.dst_ip = 0;

    ent = vr_find_mcast_entry(&key);
    if (ent) {
        rt->rtr_req.rtr_label_flags = ent->flags;
        rt->rtr_nh = ent->nh;
        return rt->rtr_nh;
    }

    return NULL;
}

static int
mcast_get(unsigned int vrf_id, struct vr_route_req *rt)
{
    struct vr_nexthop *nh;

    rt->rtr_req.rtr_nh_id = NH_DISCARD_ID;
    nh = mcast_lookup(vrf_id, rt, NULL);
    if (nh)
        rt->rtr_req.rtr_nh_id = nh->nh_id;
    return 0;
}

static void
mcast_entry_free(vr_htable_t table, vr_hentry_t hentry, unsigned int
        index, void *data)
{
    struct vr_mcast_entry *ent = (struct vr_mcast_entry *)hentry;

    if (!ent)
        return;

    ent->flags &= ~VR_MCAST_FLAG_VALID;
    if (ent->nh)
        vrouter_put_nexthop(ent->nh);

    memset(ent, 0, sizeof(struct vr_mcast_entry));
    return;
}



static int
mcast_delete(struct vr_rtable * _unused, struct vr_route_req *rt)
{
    struct vr_mcast_entry *ent;
    struct vr_mcast_entry_key key;

    key.vrf_id = rt->rtr_req.rtr_vrf_id;
    if (rt->rtr_req.rtr_src_size)
        key.src_ip = ntohl(*(uint32_t*)rt->rtr_req.rtr_src);
    else
        key.src_ip = 0;

    if (rt->rtr_req.rtr_prefix_size)
        key.dst_ip = ntohl(*(uint32_t*)rt->rtr_req.rtr_prefix);
    else
        key.dst_ip = 0;

    ent = vr_find_mcast_entry(&key);
    if (!ent)
        return -ENOENT;

    mcast_entry_free(vn_rtable, (vr_hentry_t )ent, 0, NULL);
    return 0;
}

static int
__mcast_add(struct vr_route_req *rt) 
{
    struct vr_nexthop *old_nh;
    struct vr_mcast_entry *ent;
    struct vr_mcast_entry_key key;

    key.vrf_id = rt->rtr_req.rtr_vrf_id;
    if (rt->rtr_req.rtr_src_size)
        key.src_ip = ntohl(*(uint32_t*)rt->rtr_req.rtr_src);
    else
        key.src_ip = 0;

    if (rt->rtr_req.rtr_prefix_size)
        key.dst_ip = ntohl(*(uint32_t*)rt->rtr_req.rtr_prefix);
    else
        key.dst_ip = 0;

    ent = vr_find_mcast_entry(&key);
    if (!ent) {
        ent = vr_find_free_mcast_entry(&key);
        if (!ent)
            return -ENOMEM;
        ent->key.vrf_id = key.vrf_id;
        ent->key.src_ip = key.src_ip;
        ent->key.dst_ip = key.dst_ip;
        ent->flags |= VR_MCAST_FLAG_VALID;
    }

    /* The nexthop can be changed though entry exits */
    if (ent->nh != rt->rtr_nh) {

        old_nh = ent->nh;
        ent->nh = vrouter_get_nexthop(rt->rtr_req.rtr_rid,
                                        rt->rtr_req.rtr_nh_id);
        if (old_nh)
            vrouter_put_nexthop(old_nh);
    }

    return 0;
}

static int
mcast_add(struct vr_rtable * _unused, struct vr_route_req *rt)
{
    int ret;

    rt->rtr_nh = vrouter_get_nexthop(rt->rtr_req.rtr_rid, rt->rtr_req.rtr_nh_id);
    if (!rt->rtr_nh)
        return -ENOENT;

    ret = __mcast_add(rt);
    vrouter_put_nexthop(rt->rtr_nh);
    return ret;
}

static void
mcast_make_req(struct vr_route_req *resp, struct vr_mcast_entry *ent)
{
    *(uint32_t*)resp->rtr_req.rtr_prefix = ntohl(ent->key.dst_ip);
    *(uint32_t*)resp->rtr_req.rtr_src = ntohl(ent->key.src_ip);
    resp->rtr_req.rtr_prefix_size = resp->rtr_req.rtr_src_size = 4;
    resp->rtr_req.rtr_vrf_id = ent->key.vrf_id;
    if (ent->nh)
        resp->rtr_req.rtr_nh_id = ent->nh->nh_id;
    resp->rtr_req.rtr_rt_type =  RT_MCAST;
    resp->rtr_req.rtr_family = AF_INET;
    return;
}


static int
__mcast_dump(struct vr_message_dumper *dumper)
{
    struct vr_route_req *req = (struct vr_route_req *)(dumper->dump_req);
    struct vr_route_req resp;
    int ret;
    struct vr_mcast_entry *ent;
    unsigned int i;
    uint32_t rt_prefix, rt_src;

    for(i = 0; i < (vr_mcast_entries + vr_mcast_oentries); i++) {
        ent = (struct vr_mcast_entry *) vr_get_hentry_by_index(vn_rtable, i);
        if (!ent)
            continue;
        if (ent->flags & VR_MCAST_FLAG_VALID) {
            if (ent->key.vrf_id != req->rtr_req.rtr_vrf_id)
                continue;
            if (dumper->dump_been_to_marker == 0) {
                if ((ent->key.src_ip == ntohl(*(unsigned int*)req->rtr_req.rtr_src)) &&
                        (ent->key.dst_ip == ntohl(*(unsigned int*)req->rtr_req.rtr_prefix)) &&
                        (ent->key.vrf_id == req->rtr_req.rtr_vrf_id)) {
                    dumper->dump_been_to_marker = 1;
                }
            } else {
                memset(&resp, 0, sizeof(struct vr_route_req));
                resp.rtr_req.rtr_src = (uint8_t*)&rt_src;
                resp.rtr_req.rtr_prefix = (uint8_t*)&rt_prefix;

                mcast_make_req(&resp, ent);
                ret = vr_message_dump_object(dumper, VR_ROUTE_OBJECT_ID, &resp);
                if (ret <= 0) 
                    return ret;
            }
        }
    }

    return 0;
}

static int
mcast_dump(struct vr_rtable * __unsued, struct vr_route_req *rt)
{
    int ret = 0;
    struct vr_message_dumper *dumper;

    dumper = vr_message_dump_init(&rt->rtr_req);
    if (!dumper) {
        ret = -ENOMEM;
        goto generate_response;
    }

    if (!((vr_route_req *)(dumper->dump_req))->rtr_marker)
        dumper->dump_been_to_marker = 1;

    __mcast_dump(dumper);
generate_response:
    vr_message_dump_exit(dumper, ret);

    return 0;
}

void
mcast_algo_deinit(struct vr_rtable *rtable, struct rtable_fspec *fs, bool soft_reset)
{
    if (!vn_rtable)
        return;

    vr_htable_trav(vn_rtable, 0, mcast_entry_free, NULL);
 
    if (!soft_reset) {
        vr_htable_delete(vn_rtable);
        rtable->algo_data = NULL;
        vn_rtable = NULL;
    }

}

int
mcast_algo_init(struct vr_rtable *rtable, struct rtable_fspec *fs)
{

    if (rtable->algo_data)
        return 0;

    rtable->algo_data = vr_htable_create(vr_mcast_entries,
            vr_mcast_oentries, sizeof(struct vr_mcast_entry),
            sizeof(struct vr_mcast_entry_key), mcast_entry_valid);

    if (!rtable->algo_data)
        return -ENOMEM;

    rtable->algo_add = mcast_add;
    rtable->algo_del = mcast_delete;
    rtable->algo_lookup = mcast_lookup;
    rtable->algo_get = mcast_get;
    rtable->algo_dump = mcast_dump;

    /* local cache */
    vn_rtable = rtable->algo_data;

    return 0;
}

bool
vr_l2_mcast_control_data_add(struct vr_packet *pkt)
{

    unsigned int *data;

    if (pkt_head_space(pkt) < VR_L2_MCAST_CTRL_DATA_LEN) {
        pkt = vr_pexpand_head(pkt, VR_L2_MCAST_CTRL_DATA_LEN - 
                                                pkt_head_space(pkt));
        if (!pkt)
            return false;
    }

    data = (unsigned int *)pkt_push(pkt, VR_L2_MCAST_CTRL_DATA_LEN);
    if (!data)
        return false;

    *data = VR_L2_MCAST_CTRL_DATA;
    return true;
}

unsigned int
vr_mcast_forward(struct vrouter *router, unsigned short vrf, 
        struct vr_packet *pkt, struct vr_forwarding_md *fmd)
{
    struct vr_route_req rt;
    struct vr_nexthop *nh;
    struct vr_ip *ip;
    uint32_t rt_prefix, rt_src;

    pkt->vp_type = VP_TYPE_IP;
    ip = (struct vr_ip *)pkt_data(pkt);

    rt.rtr_req.rtr_vrf_id = vrf;
    rt.rtr_req.rtr_prefix_len = 32;

    rt.rtr_req.rtr_src = (uint8_t*)&rt_src;
    rt.rtr_req.rtr_prefix = (uint8_t*)&rt_prefix;
    rt.rtr_req.rtr_src_size = rt.rtr_req.rtr_prefix_size = 4;
    rt.rtr_req.rtr_marker_size = 0;
  
    if (IS_MCAST_LINK_LOCAL(ip->ip_daddr) || IS_BCAST_IP(ip->ip_daddr)) {
        memset(rt.rtr_req.rtr_src, 0, 4);
        *(uint32_t*)rt.rtr_req.rtr_prefix = 0xFFFFFFFF;
    } else {
        *(uint32_t*)rt.rtr_req.rtr_prefix = ntohl(ip->ip_daddr);
        *(uint32_t*)rt.rtr_req.rtr_src = ntohl(ip->ip_saddr);
    }

    nh = mcast_lookup(vrf, &rt, pkt);
    if (!nh) {
        nh = ip4_default_nh;
    }

    return nh_output(vrf, pkt, nh, fmd);
}
