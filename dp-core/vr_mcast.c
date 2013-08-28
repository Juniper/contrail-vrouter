/*
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#include <vr_os.h>
#include "vr_sandesh.h"
#include "vr_message.h"
#include <vr_mcast.h>

struct mcast_entry {
    unsigned int src_ip; /* In network byte order */
    unsigned int dst_ip; /* This too */
    struct vr_nexthop *nh;
    struct mcast_entry *next;
};

typedef vr_itable_t mcast_tbl_t;
static mcast_tbl_t *vn_rtable;
extern struct vr_nexthop *ip4_default_nh;

static mcast_tbl_t
vrfid_to_mcast_tbl(unsigned int id)
{
    if (id >= VR_MAX_VRFS)
        return NULL;

    return vn_rtable[id];
}

static mcast_tbl_t
mcast_table_alloc_vrf(unsigned int vrf_id)
{
    mcast_tbl_t table;

    /* Create an index table of 12 bits with 3 strides */
    table = vr_itable_create(MCAST_INDEX_LEN, 3, 4, 4, 4);
    if (table) {
        vn_rtable[vrf_id] = table;
    }

    return table;
}

static struct mcast_entry *
mcast_lookup_in_hash_bucket(struct mcast_entry *head, struct vr_route_req *rt)
{
    struct mcast_entry *ent;

    ent = head;
    while (ent) {
        if ((ent->src_ip == (unsigned int)rt->rtr_req.rtr_src) &&
                (ent->dst_ip == (unsigned int)rt->rtr_req.rtr_prefix)) {
            return ent;
        }
        ent = ent->next;
    }

    return NULL;
}

static struct vr_nexthop *
mcast_lookup(unsigned int vrf_id, struct vr_route_req *rt,
        struct vr_packet *pkt) 
{
    mcast_tbl_t table = vrfid_to_mcast_tbl(vrf_id);
    unsigned int hash;
    struct mcast_entry *ent;

    if (!table)
        return NULL;

    hash = vr_hash_3words(rt->rtr_req.rtr_src, rt->rtr_req.rtr_prefix, 0, 0);
    hash %= MCAST_HASH_SIZE;

    ent = vr_itable_get(table, hash);
    if (!ent) {
        return NULL;
    }

    ent = mcast_lookup_in_hash_bucket(ent, rt);
    if (!ent)
        return NULL;

    return ent->nh;
}

static int
mcast_get(unsigned int vrf_id, struct vr_route_req *rt)
{
    struct vr_nexthop *nh;

    nh = mcast_lookup(vrf_id, rt, NULL);
    if (nh)
        rt->rtr_req.rtr_nh_id = nh->nh_id;
    else
        rt->rtr_req.rtr_nh_id = -1;
    return 0;
}


static int
__mcast_delete(mcast_tbl_t table, struct vr_route_req *rt)
{
    unsigned int hash;
    struct mcast_entry *ent;
    struct mcast_entry *prev;

    hash = vr_hash_3words(rt->rtr_req.rtr_src, rt->rtr_req.rtr_prefix, 0, 0);
    hash %= MCAST_HASH_SIZE;

    ent = vr_itable_get(table, hash);
    if (!ent) {
        return -ENOENT;
    }

    prev = NULL;
    while(ent) {
        if ((ent->src_ip == (unsigned int)rt->rtr_req.rtr_src) &&
                (ent->dst_ip == (unsigned int)rt->rtr_req.rtr_prefix)) {
            break;
        }

        prev = ent;
        ent = ent->next;
    }

    if (!ent) {
        return -ENOENT;
    }

    /* 
     * Delete the entry now. Ensure that ent is delinked 
     */
    if (prev) {
        prev->next = ent->next;
    } else {
        if (vr_itable_set(table, hash, ent->next) == VR_ITABLE_ERR_PTR) {
            return -1;
        }
    }
    ent->next = NULL;

    /* Let everyone see this */
    vr_delay_op();

    /* Delete now */
    vrouter_put_nexthop(ent->nh);
    vr_free(ent);

    return 0;
}

static int
mcast_delete(struct vr_rtable * _unused, struct vr_route_req *rt)
{
    unsigned int vrf_id = rt->rtr_req.rtr_vrf_id;
    mcast_tbl_t table = vrfid_to_mcast_tbl(vrf_id);

    if (!table)
        return -ENOENT;

    return __mcast_delete(table, rt);
}

static int
__mcast_add(mcast_tbl_t table, struct vr_route_req *rt) 
{
    struct vr_nexthop *nh;
    unsigned int hash;
    struct mcast_entry *ent;
    struct mcast_entry *head;

    hash = vr_hash_3words(rt->rtr_req.rtr_src, rt->rtr_req.rtr_prefix, 0, 0);
    hash %= MCAST_HASH_SIZE;

    head = vr_itable_get(table, hash);
    if (head) {
        /* If the entry already exists, just replace with new nexthop */
        ent = mcast_lookup_in_hash_bucket(head, rt);
        if (ent) {
            if (ent->nh != rt->rtr_nh) {
                nh = ent->nh;
                ent->nh = vrouter_get_nexthop(rt->rtr_req.rtr_rid, rt->rtr_req.rtr_nh_id);

                /*Stop using old nexthop */
                vrouter_put_nexthop(nh);
            }
            return 0;
        }
    }

    /* Create a new entry */
    ent = vr_zalloc(sizeof(struct mcast_entry));
    if (!ent) {
        return -1;
    }

    ent->src_ip = rt->rtr_req.rtr_src;
    ent->dst_ip = rt->rtr_req.rtr_prefix;
    ent->nh = vrouter_get_nexthop(rt->rtr_req.rtr_rid, rt->rtr_req.rtr_nh_id);
    
    ent->next = head;
    head = ent;

    if (vr_itable_set(table, hash, head) != VR_ITABLE_ERR_PTR) {
        return 0;
    }

    vr_free(ent);
    return -1;
}

static int
mcast_add(struct vr_rtable * _unused, struct vr_route_req *rt)
{
    int ret;
    unsigned int vrf_id = rt->rtr_req.rtr_vrf_id;
    mcast_tbl_t table = vrfid_to_mcast_tbl(vrf_id);

    table = (table ? : mcast_table_alloc_vrf(vrf_id));
    if (!table)
        return -ENOMEM;

    rt->rtr_nh = vrouter_get_nexthop(rt->rtr_req.rtr_rid, rt->rtr_req.rtr_nh_id);
    if (!rt->rtr_nh)
        return -ENOENT;

    ret = __mcast_add(table, rt);
    vrouter_put_nexthop(rt->rtr_nh);
    return ret;
}

static void
mcast_make_req(struct vr_route_req *resp, struct mcast_entry *ent)
{
    memset(resp, 0, sizeof(struct vr_route_req));
    resp->rtr_req.rtr_prefix = ent->dst_ip;
    resp->rtr_req.rtr_src = ent->src_ip;
    resp->rtr_req.rtr_nh_id = ent->nh->nh_id;
    resp->rtr_req.rtr_rt_type =  RT_MCAST;
    return;
}


static int
mcast_dump_cb(unsigned int index, void *data, void *udata)
{
    struct mcast_entry *ent = (struct mcast_entry *)data;
    struct vr_message_dumper *dumper = (struct vr_message_dumper *)udata;
    struct vr_route_req *req = (struct vr_route_req *)(dumper->dump_req);
    struct vr_route_req resp;
    int ret;

    while(ent) {
        /* Wait till the marker is reached */
        if (dumper->dump_been_to_marker == 0) {
            if (ent->src_ip == (unsigned int)req->rtr_req.rtr_src && 
                    ent->dst_ip == (unsigned int)req->rtr_req.rtr_prefix) {
                dumper->dump_been_to_marker = 1;
            }
        } else {

            /* As marker reached, create response message */
            mcast_make_req(&resp, ent); 
            vr_printf("Index %d: (%x, %x) Nh:%d\n", index, 
                    resp.rtr_req.rtr_src, resp.rtr_req.rtr_prefix, 
                    resp.rtr_req.rtr_nh_id);

            /* If no memory for next route return -ve, other wise continue */
            ret = vr_message_dump_object(dumper, VR_ROUTE_OBJECT_ID, &resp);
            if (ret <= 0) {
                return ret;
            }
        }
        ent = ent->next;
    }

    return 1;
}

static int
mcast_dump(struct vr_rtable * __unsued, struct vr_route_req *rt)
{
    int ret = 0;
    struct vr_message_dumper *dumper;
    mcast_tbl_t table;


    dumper = vr_message_dump_init(&rt->rtr_req);
    if (!dumper) {
        ret = -ENOMEM;
        goto generate_response;
    }

    if (!((vr_route_req *)(dumper->dump_req))->rtr_marker)
        dumper->dump_been_to_marker = 1;

    table = vrfid_to_mcast_tbl(rt->rtr_req.rtr_vrf_id);
    if (!table) {
        return -EINVAL;
    }

    ret = vr_itable_trav(table, mcast_dump_cb, 0, dumper);

generate_response:
    vr_message_dump_exit(dumper, ret);

    return 0;

}


static void
mcast_free_table_cb(unsigned int index, void *data)
{
    struct mcast_entry *ent = (struct mcast_entry *)data;
    struct mcast_entry *next;

    while(ent) {
        next = ent->next;
        vrouter_put_nexthop(ent->nh);
        vr_free(ent);
        ent = next;
    }

    return;
}

static void
mcast_free_table(mcast_tbl_t table)
{
    vr_itable_delete(table, mcast_free_table_cb);
    return;
}

static void
mcast_free_vrf(struct vr_rtable *rtable, unsigned int vrf_id)
{
    mcast_tbl_t *vrf_tables;
    mcast_tbl_t table;

    vrf_tables = (mcast_tbl_t *)(rtable->algo_data);
    table = vrf_tables[vrf_id];
    if (!table) 
        return;

    /* Delete the whole table entries */
    mcast_free_table(table);

    /* Make the vrf null and free its memory */
    vrf_tables[vrf_id] = NULL;
    return;
}

void
mcast_algo_deinit(struct vr_rtable *rtable, struct rtable_fspec *fs)
{
   unsigned int i;

   /* 
    * Invoked by disabling the packet path. We are free to delete
    * in our own order 
    */
    if (!vn_rtable)
        return;

    vn_rtable = NULL;

    for (i = 0; i < fs->rtb_max_vrfs; i++)
        mcast_free_vrf(rtable, i);

    vr_free(rtable->algo_data);
    rtable->algo_data = NULL;
    return;
}

int
mcast_algo_init(struct vr_rtable *rtable, struct rtable_fspec *fs)
{
   rtable->algo_data = vr_zalloc(sizeof(mcast_tbl_t) * fs->rtb_max_vrfs);
    if (!rtable->algo_data)
        return -ENOMEM;

    rtable->algo_add = mcast_add;
    rtable->algo_del = mcast_delete;
    rtable->algo_lookup = mcast_lookup;
    rtable->algo_get = mcast_get;
    rtable->algo_dump = mcast_dump;

    /* local cache */
    vn_rtable = (mcast_tbl_t *)(rtable->algo_data);

    return 0;
}

unsigned int
vr_mcast_forward(struct vrouter *router, unsigned short vrf, 
        struct vr_packet *pkt, struct vr_forwarding_md *fmd)
{
    struct vr_route_req rt;
    struct vr_nexthop *nh;
    struct vr_ip *ip;

    pkt->vp_type = VP_TYPE_IP;
    ip = (struct vr_ip *)pkt_data(pkt);

    rt.rtr_req.rtr_vrf_id = vrf;
    rt.rtr_req.rtr_prefix_len = 32;
    if (IS_MCAST_LINK_LOCAL(ip->ip_daddr) || IS_BCAST_IP(ip->ip_daddr)) {
        rt.rtr_req.rtr_src = 0;
        rt.rtr_req.rtr_prefix = 0xFFFFFFFF;
    } else {
        rt.rtr_req.rtr_src = ip->ip_saddr;
        rt.rtr_req.rtr_prefix = ip->ip_daddr;
    }

    nh = mcast_lookup(vrf, &rt, pkt);
    if (!nh) {
        nh = ip4_default_nh;
    }

    return nh_output(vrf, pkt, nh, fmd);
}
