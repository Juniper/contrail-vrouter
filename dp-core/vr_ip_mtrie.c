/*
 * vr_ip_mtrie.c -- 	VRF mtrie management
 *
 * Copyright (c) 2014 Juniper Networks, Inc. All rights reserved.	
 */
#include <vr_os.h>
#include "vr_sandesh.h"
#include "vr_message.h"
#include "vr_packet.h"
#include "vr_interface.h"
#include "vr_route.h"
#include "vr_bridge.h"
#include "vr_datapath.h"
#include "vr_ip_mtrie.h"

extern unsigned int vr_vrfs;

extern struct vr_nexthop *ip4_default_nh;

static struct vr_vrf_stats **mtrie_vrf_stats;
static struct vr_vrf_stats *invalid_vrf_stats;

struct vr_vrf_stats *(*vr_inet_vrf_stats)(int, unsigned int);

static struct ip_mtrie *mtrie_alloc_vrf(unsigned int, unsigned int);

/* mtrie specific, bucket_info for v4 and v6 */
#define IP4_BKT_LEVELS  (IP4_PREFIX_LEN / IPBUCKET_LEVEL_BITS) 
#define IP6_BKT_LEVELS  (IP6_PREFIX_LEN / IPBUCKET_LEVEL_BITS) 

struct mtrie_bkt_info ip4_bkt_info[IP4_BKT_LEVELS];
struct mtrie_bkt_info ip6_bkt_info[IP6_BKT_LEVELS];

struct ip_mtrie **vn_rtable[2];
static int algo_init_done = 0;
static vr_route_req dump_resp;

static int mtrie_debug = 0;

static void
mtrie_ip_bkt_info_init(struct mtrie_bkt_info *ip_bkt_info, int pfx_len)
{
    int level;

    ip_bkt_info[0].bi_bits = IPBUCKET_LEVEL_BITS;
    ip_bkt_info[0].bi_pfx_len = IPBUCKET_LEVEL_BITS;
    ip_bkt_info[0].bi_shift = pfx_len - IPBUCKET_LEVEL_BITS;
    ip_bkt_info[0].bi_size = IPBUCKET_LEVEL_SIZE;
    ip_bkt_info[0].bi_mask = IPBUCKET_LEVEL_MASK;

    for (level = 1; level < (pfx_len/IPBUCKET_LEVEL_BITS); level++) {
        ip_bkt_info[level].bi_bits = IPBUCKET_LEVEL_BITS;
        ip_bkt_info[level].bi_pfx_len = ip_bkt_info[level-1].bi_pfx_len 
                                              + IPBUCKET_LEVEL_BITS;
        ip_bkt_info[level].bi_shift =  ip_bkt_info[level-1].bi_shift - IPBUCKET_LEVEL_BITS;
        ip_bkt_info[level].bi_size = IPBUCKET_LEVEL_SIZE;
        ip_bkt_info[level].bi_mask = IPBUCKET_LEVEL_MASK;
    }
}

/*
 * given a vrf id, get the routing table corresponding to the id
 */
static inline struct ip_mtrie * 
vrfid_to_mtrie(unsigned int vrf_id, unsigned int family)
{
    int index = 0;
    struct ip_mtrie **mtrie_table;
    if (vrf_id >= vr_vrfs)
        return NULL;

    if (family == AF_INET6)
        index = 1;

    mtrie_table = vn_rtable[index];
    return mtrie_table[vrf_id];
}

#define PREFIX_TO_INDEX(prefix, level) (prefix[level]) 

static inline unsigned int
ip_bkt_get_max_level(int family)
{
    if (family == AF_INET6)
        return(IP6_BKT_LEVELS);
    else
        return(IP4_BKT_LEVELS);
}

static struct mtrie_bkt_info * 
ip_bkt_info_get(unsigned int family)
{
    if (family == AF_INET6)
        return ip6_bkt_info;
    else
        return ip4_bkt_info;
}
    
/*
 * we have to be careful about 'level' here. assumption is that level
 * will be passed sane from whomever is calling
 */
static inline unsigned char
rt_to_index(struct vr_route_req *rt, unsigned int level)
{
    return PREFIX_TO_INDEX(rt->rtr_req.rtr_prefix, level);
}

static inline struct ip_bucket_entry *
index_to_entry(struct ip_bucket *bkt, int index)
{
    return &bkt->bkt_data[index];
}

static void
set_entry_to_bucket(struct ip_bucket_entry *ent, struct ip_bucket *bkt)
{
    struct vr_nexthop *tmp_nh = NULL;

    if (ENTRY_IS_NEXTHOP(ent)) {
        /* save old... */
        tmp_nh = ent->entry_nh_p;
    }
    /* update... */
    ent->entry_long_i = (uintptr_t) bkt;
    /* set entry_type */
    ent->entry_type = ENTRY_TYPE_BUCKET;
    /* release old */
    if (tmp_nh)
        vrouter_put_nexthop(tmp_nh);

    return;
}

/*
 * the nh pointer is something which will be retained. So, call this function
 * with an nh * that you are willing to forget about in your function
 */
static void
set_entry_to_nh(struct ip_bucket_entry *entry, struct vr_nexthop *nh)
{
    struct vr_nexthop *tmp_nh;
    int orig_entry_nh = ENTRY_IS_NEXTHOP(entry);

    tmp_nh = vrouter_get_nexthop(nh->nh_rid, nh->nh_id);
    if (tmp_nh != nh) {
        /*
         * if the original nexthop was deleted, then there are
         * two cases
         *
         * 1. no new nexthop was created (& hence the null check)
         * 2. new nexthop has taken it's place (in which case, we need to
         *    put the reference we took above
         */
        if (tmp_nh)
            vrouter_put_nexthop(tmp_nh);

        nh = vrouter_get_nexthop(nh->nh_rid, NH_DISCARD_ID);
    }

    /* save the original */
    tmp_nh = entry->entry_nh_p;
    /* update the entry */
    entry->entry_nh_p = nh;
    /* set entry type */
    entry->entry_type = ENTRY_TYPE_NEXTHOP;

    /* ...and then take steps to release original */
    if (tmp_nh && orig_entry_nh) {
        vrouter_put_nexthop(tmp_nh);
    }

    return;
}

static void
set_entry_to_vdata(struct ip_bucket_entry *entry, void *data)
{
    /* update the entry */
    entry->entry_vdata_p = data;
    /* set entry type */
    entry->entry_type = ENTRY_TYPE_VDATA;
}

static inline struct ip_bucket *
entry_to_bucket(struct ip_bucket_entry *ent)
{
    if (ENTRY_IS_BUCKET(ent))
        return PTR_TO_BUCKET(ent->entry_long_i);

    return NULL;
}

static void
mtrie_free_entry(struct ip_bucket_entry *entry, unsigned int level)
{
    unsigned int i;
    struct ip_bucket *bkt;

    if (!ENTRY_IS_BUCKET(entry)) {
        if (ENTRY_IS_NEXTHOP(entry)) {
            vrouter_put_nexthop(entry->entry_nh_p);
            entry->entry_nh_p = NULL;
        } else {
            entry->entry_vdata_p = NULL;
        }
        return;
    }

    bkt = entry_to_bucket(entry);
    if (!bkt)
        return;

    for (i = 0; i < IPBUCKET_LEVEL_SIZE; i++) {
        if (ENTRY_IS_BUCKET(&bkt->bkt_data[i])) {
            mtrie_free_entry(&bkt->bkt_data[i], level + 1);
        } else {
            if (ENTRY_IS_NEXTHOP(&bkt->bkt_data[i])) {
                vrouter_put_nexthop(bkt->bkt_data[i].entry_nh_p);
            }
        }
    }

    entry->entry_bkt_p = NULL;
    vr_free(bkt, VR_MTRIE_BUCKET_OBJECT);

    return;
}

static void
mtrie_free_bkt(struct ip_bucket *bkt)
{
    unsigned int i;

    for (i = 0; i < IPBUCKET_LEVEL_SIZE; i++) {
        mtrie_free_entry(&bkt->bkt_data[i], 0);
    }

    vr_free(bkt, VR_MTRIE_BUCKET_OBJECT);

    return;
}

static void
mtrie_free_bkt_cb(struct vrouter *router, void *data)
{
    struct vr_defer_data *vdd = (struct vr_defer_data *)data;

    if (!vdd)
        return;

    mtrie_free_bkt((struct ip_bucket *)(vdd->vdd_data));

    return;
}

static int
mtrie_free_bkt_defer(struct vrouter *router, struct ip_bucket *bkt)
{

    struct vr_defer_data *defer;

    defer = vr_get_defer_data(sizeof(*defer));
    if (!defer)
        return -ENOMEM;

    defer->vdd_data = bkt;
    vr_defer(router, mtrie_free_bkt_cb, (void *)defer);

    return 0;
}

static void
mtrie_delete_bkt(struct ip_bucket_entry *ent, struct vr_route_req *rt, int defer_delete, int data_is_nh)
{
    struct ip_bucket *bkt;

    if (!ENTRY_IS_BUCKET(ent)) {
        if (ENTRY_IS_NEXTHOP(ent)) {
            vrouter_put_nexthop(ent->entry_nh_p);
            ent->entry_nh_p = NULL;
        } else {
            ent->entry_vdata_p = NULL;
        }
        return;
    }

    bkt = entry_to_bucket(ent);
    if (data_is_nh) {
        set_entry_to_nh(ent, rt->rtr_nh);
    } else {
        set_entry_to_vdata(ent, (void *)rt->rtr_nh);
    }
    ent->entry_label_flags = rt->rtr_req.rtr_label_flags;
    ent->entry_label = rt->rtr_req.rtr_label;
    ent->entry_bridge_index = rt->rtr_req.rtr_index;

    if (defer_delete) {
        mtrie_free_bkt_defer(vrouter_get(0), bkt);
    } else {
        if (!vr_not_ready) {
            if (!mtrie_free_bkt_defer(rt->rtr_nh->nh_router, bkt))
                return;

            vr_delay_op();
        }
        mtrie_free_bkt(bkt);
    }

    return;
}


/*
 * alloc a mtrie bucket
 */
static struct ip_bucket *
mtrie_alloc_bucket(struct mtrie_bkt_info *ip_bkt_info, unsigned char level,
                   struct ip_bucket_entry *parent, int data_is_nh)
{
    unsigned int                bkt_size;
    unsigned int                i;
    struct ip_bucket           *bkt;
    struct ip_bucket_entry     *ent;

    bkt_size = ip_bkt_info[level].bi_size;
    bkt = vr_zalloc(sizeof(struct ip_bucket) 
                    + sizeof(struct ip_bucket_entry) * bkt_size,
                    VR_MTRIE_BUCKET_OBJECT);
    if (!bkt)
        return NULL;

    for (i = 0; i < bkt_size; i++) {
        ent = &bkt->bkt_data[i];
        if (data_is_nh) {
            set_entry_to_nh(ent, parent->entry_nh_p);
        } else {
            set_entry_to_vdata(ent, parent->entry_vdata_p);
        }
        ent->entry_prefix_len = parent->entry_prefix_len;
        ent->entry_label_flags = parent->entry_label_flags;
        ent->entry_label = parent->entry_label;
        ent->entry_bridge_index = parent->entry_bridge_index;
    }

    return bkt;
}

static void
add_to_tree(struct ip_bucket_entry *ent, int level, struct vr_route_req *rt)
{
    unsigned int i;
    struct ip_bucket      *bkt;
    struct mtrie_bkt_info *ip_bkt_info;

    if (ent->entry_prefix_len > rt->rtr_req.rtr_prefix_len)
        return;

    ent->entry_prefix_len = rt->rtr_req.rtr_prefix_len;

    if (!ENTRY_IS_BUCKET(ent)) {
        /* a less specific entry, which needs to be replaced */
        if (ENTRY_IS_NEXTHOP(ent)) {
            set_entry_to_nh(ent, rt->rtr_nh);
        } else {
            set_entry_to_vdata(ent, (void *)rt->rtr_nh);
        }
        ent->entry_label_flags = rt->rtr_req.rtr_label_flags;
        ent->entry_label = rt->rtr_req.rtr_label;
        ent->entry_bridge_index = rt->rtr_req.rtr_index;

        return;
    }

    if (level >= (ip_bkt_get_max_level(rt->rtr_req.rtr_family) - 1))
        return;

    ip_bkt_info = ip_bkt_info_get(rt->rtr_req.rtr_family);

    /* Assured that this is valid bucket now */
    bkt = entry_to_bucket(ent);
    level++;

    for (i = 0; i < ip_bkt_info[level].bi_size; i++) {
        ent = index_to_entry(bkt, i);
        add_to_tree(ent, level, rt);
    }

    return;
}

static void
mtrie_reset_entry(struct ip_bucket_entry *ent, int level,
                  void *data, int data_is_nh)
{
    struct ip_bucket_entry cp_ent;
    struct ip_bucket *bkt;
    struct vr_nexthop *nh;
    struct vrouter *vrouter;

    memcpy(&cp_ent, ent, sizeof(cp_ent));

    /* remove from the tree */
    if (data) {
        if (data_is_nh) {
            nh = (struct vr_nexthop *) data;
            set_entry_to_nh(ent, nh);
        } else {
            set_entry_to_vdata(ent, data);
        }
    }

    /* ...and then work with the copy */
    bkt = entry_to_bucket(&cp_ent);
    if (!bkt)
        return;

    if (data_is_nh) {
        nh = (struct vr_nexthop *) data;
        vrouter = nh->nh_router;
    } else {
        vrouter = vrouter_get(0);
    }
    if (!vr_not_ready) {
        if (!mtrie_free_bkt_defer(vrouter, bkt))
            return;
        vr_delay_op();
    }
    mtrie_free_entry(&cp_ent, level);

    return;
}

/*
 * When adding a route:
 * - descend the tree to the bucket at which the route is significant.
 * (i.e. the bucket corresponding to a prefix >= to the route prefix).
 * - if the bucket needs to be created, it is first initialized and only
 * linked to the tree when the function exits.
 * - if the bucket exists, populate any descendent bucket entries that
 * themselfs do not have more specific routes.
 * - when a bucket is created, initialize any entries with the parent that
 * covers them.
 *
 * Flag data_is_nh indicates if the data in the mtrie nodes is nexthop or
 * void *vdata
 */
static int
__mtrie_add(struct ip_mtrie *mtrie, struct vr_route_req *rt, int data_is_nh)
{
    int ret, index = 0, level, err_level = 0, fin;
    unsigned char i;
    struct ip_bucket *bkt;
    struct ip_bucket_entry *ent, *err_ent = NULL;
    void *data, *err_data = NULL;
    struct mtrie_bkt_info *ip_bkt_info = ip_bkt_info_get(rt->rtr_req.rtr_family);

    ent = &mtrie->root;

    data = (void *)ent->entry_long_i;
    for (level = 0; level < ip_bkt_get_max_level(rt->rtr_req.rtr_family); level++) {
        if (!ENTRY_IS_BUCKET(ent)) {
            bkt = mtrie_alloc_bucket(ip_bkt_info, level, ent, data_is_nh);
            set_entry_to_bucket(ent, bkt);

            if (!err_ent) {
                err_ent = ent;
                err_data = data;
                err_level = level;
            }
        }

        bkt = entry_to_bucket(ent);
        if (!bkt) {

            ret = -ENOMEM;
            goto exit_ret;
        }

        index = rt_to_index(rt, level);
        ent = index_to_entry(bkt, index);

        if (rt->rtr_req.rtr_prefix_len > ip_bkt_info[level].bi_pfx_len) {
            if (!ENTRY_IS_BUCKET(ent)) {
                data = (void *)ent->entry_long_i;
            }

            continue;

        } else {
            /*
             * cover all the indices for which this route is the best
             * prefix match
             */

            fin = ip_bkt_info[level].bi_size;

            if ((rt->rtr_req.rtr_prefix_len >
                        (ip_bkt_info[level].bi_pfx_len - ip_bkt_info[level].bi_bits)) &&
                    (rt->rtr_req.rtr_prefix_len <= ip_bkt_info[level].bi_pfx_len)) {
                fin = 1 << (ip_bkt_info[level].bi_pfx_len - rt->rtr_req.rtr_prefix_len); 
            }

            i = index;
            for (; ((i <= (ip_bkt_info[level].bi_size-1)) && fin);
                                                        i++, fin--) {
                ent = index_to_entry(bkt, i);
                add_to_tree(ent, level, rt);
             }

             break;
        }
    }

    return 0;

exit_ret:
    if (err_ent)
        mtrie_reset_entry(err_ent, err_level, err_data, data_is_nh);

    return ret;
}

/*
 * Common API to delete both mtrie with nexthop nodes or void *data;
 * The flag defer_delete is used to indicate if the nodes should be defer deleted or
 * immediately deleted; defer delete is useful in multithreaded scenarios where the
 * delete happens in a rcu callback context thus avoiding taking locks.
 * The flag data_is_nh is used to indicate if the mtrie is created with nexthop nodes
 * or void * data nodes;
 */
static int
__mtrie_delete(struct vr_route_req *rt, struct ip_bucket_entry *ent,
                unsigned char level, int defer_delete, int data_is_nh)
{
    unsigned int        index, i, fin;
    struct ip_bucket    *bkt;
    struct ip_bucket_entry *tmp_ent;
    struct mtrie_bkt_info *ip_bkt_info = ip_bkt_info_get(rt->rtr_req.rtr_family);

    if (!ENTRY_IS_BUCKET(ent)) {
        /* Cleanup the entry as it is valid */
        if (ent->entry_prefix_len == rt->rtr_req.rtr_prefix_len) {
            ent->entry_label_flags = rt->rtr_req.rtr_label_flags;
            ent->entry_label = rt->rtr_req.rtr_label;
            ent->entry_prefix_len = rt->rtr_req.rtr_replace_plen;

            if (ENTRY_IS_NEXTHOP(ent)) {
                set_entry_to_nh(ent, rt->rtr_nh);
            } else {
                set_entry_to_vdata(ent, (void *)rt->rtr_nh);
            }
            ent->entry_bridge_index = rt->rtr_req.rtr_index;
            return 0;
        } else {
            return -ENOENT;
        }
    }

    bkt = entry_to_bucket(ent);
    index = rt_to_index(rt, level);

    if (rt->rtr_req.rtr_prefix_len > ip_bkt_info[level].bi_pfx_len) {
        tmp_ent = index_to_entry(bkt, index);
        __mtrie_delete(rt, tmp_ent, level + 1, defer_delete, data_is_nh);
    } else {
        if ((rt->rtr_req.rtr_prefix_len >
                (ip_bkt_info[level].bi_pfx_len - ip_bkt_info[level].bi_bits)) &&
                (rt->rtr_req.rtr_prefix_len <= ip_bkt_info[level].bi_pfx_len)) {
            fin = 1 << (ip_bkt_info[level].bi_pfx_len - rt->rtr_req.rtr_prefix_len); 
            index &= ~(fin - 1);
        } else {
            fin = ip_bkt_info[level].bi_size;
            index = 0;
        }

         fin += index;
         if (fin > ip_bkt_info[level].bi_size)
             fin = ip_bkt_info[level].bi_size;

         for (i = index; i < fin; i++) {
            tmp_ent = index_to_entry(bkt, i);

            if (tmp_ent->entry_prefix_len == rt->rtr_req.rtr_prefix_len) {
                tmp_ent->entry_label_flags = rt->rtr_req.rtr_label_flags;
                tmp_ent->entry_label = rt->rtr_req.rtr_label;
                tmp_ent->entry_prefix_len = rt->rtr_req.rtr_replace_plen;

                if (!ENTRY_IS_BUCKET(tmp_ent)) {
                    if (ENTRY_IS_NEXTHOP(tmp_ent)) {
                        set_entry_to_nh(tmp_ent, rt->rtr_nh);
                    } else {
                        set_entry_to_vdata(tmp_ent, (void *)rt->rtr_nh);
                    }
                    tmp_ent->entry_bridge_index = rt->rtr_req.rtr_index;
                } else {
                    __mtrie_delete(rt, tmp_ent, level + 1, defer_delete, data_is_nh);
                }
            }
        }
    }

    /* check if current bucket neds to be deleted */
    for (i = 1; i < ip_bkt_info[level].bi_size; i++) {
        if (memcmp(bkt->bkt_data + i, bkt->bkt_data,
                        sizeof(struct ip_bucket_entry)))
            return 0;
    }

    mtrie_delete_bkt(ent, rt, defer_delete, data_is_nh);
    return 0;
}

static int
mtrie_dumper_route_encode(struct vr_message_dumper *dumper, vr_route_req *resp)
{
    int len;

    len = vr_message_dump_object(dumper, VR_ROUTE_OBJECT_ID, resp);
    if (len <= 0)
        return len;

    return 1;
}

static void
mtrie_dumper_make_response(struct vr_message_dumper *dumper, vr_route_req *resp,
        struct ip_bucket_entry *ent, int8_t *prefix, unsigned int prefix_len)
{
    vr_route_req *req = (vr_route_req *)dumper->dump_req;
     struct vr_route_req lreq;

    resp->rtr_vrf_id = req->rtr_vrf_id;
    resp->rtr_family = req->rtr_family;
    memcpy(resp->rtr_prefix, prefix, prefix_len / IPBUCKET_LEVEL_BITS);
    resp->rtr_prefix_size = req->rtr_prefix_size;
    resp->rtr_marker_size = 0;
    resp->rtr_marker = NULL;
    resp->rtr_prefix_len = prefix_len;
    resp->rtr_rid = req->rtr_rid;
    resp->rtr_label_flags = ent->entry_label_flags;
    resp->rtr_label = ent->entry_label;
    resp->rtr_nh_id = ent->entry_nh_p->nh_id;
    resp->rtr_index = ent->entry_bridge_index;
    if (resp->rtr_index != VR_BE_INVALID_INDEX) {
        resp->rtr_mac = vr_zalloc(VR_ETHER_ALEN, VR_ROUTE_REQ_MAC_OBJECT);
        resp->rtr_mac_size = VR_ETHER_ALEN;
        lreq.rtr_req.rtr_mac = resp->rtr_mac;
        lreq.rtr_req.rtr_index = resp->rtr_index;
        lreq.rtr_req.rtr_mac_size = VR_ETHER_ALEN;
        vr_bridge_lookup(resp->rtr_vrf_id, &lreq);
    } else {
        resp->rtr_mac_size = 0;
        resp->rtr_mac = NULL;
    }
    resp->rtr_replace_plen = ent->entry_prefix_len;

    return;
}

static int
mtrie_dump_entry(struct vr_message_dumper *dumper, struct ip_bucket_entry *orig_ent,
        int8_t *prefix, int level)
{
    int i = 0, j, ret;
    uint32_t rt_prefix[4];
    struct ip_bucket *bkt;
    struct ip_bucket_entry *ent;
    struct mtrie_bkt_info *ip_bkt_info;
    vr_route_req *req = dumper->dump_req;

    if (!orig_ent|| level > ip_bkt_get_max_level(req->rtr_family))
        return 0;

    ip_bkt_info = ip_bkt_info_get(req->rtr_family);

    if (ENTRY_IS_BUCKET(orig_ent)) {
        bkt = entry_to_bucket(orig_ent);
        if (!dumper->dump_been_to_marker) {
            i = ip_bkt_info[level].bi_mask &
                    (PREFIX_TO_INDEX(req->rtr_marker, level));
            ent = index_to_entry(bkt, i);
            prefix[level] = i;
            if (mtrie_dump_entry(dumper, ent, prefix, level + 1))
                return -1;
            i++;
        }

        j = ip_bkt_info[level].bi_size - i;
        for (; j > 0; j--, i++) {
            ent = index_to_entry(bkt, i);
            prefix[level] = i;
            if (mtrie_dump_entry(dumper, ent, prefix, level + 1) < 0)
                return -1;
        }
    } else if (orig_ent->entry_nh_p) {
        if (!dumper->dump_been_to_marker) {
            dumper->dump_been_to_marker = 1;
            return 0;
        }
        memset(rt_prefix, 0, sizeof(rt_prefix));
        dump_resp.rtr_prefix = (uint8_t*)&rt_prefix;
        mtrie_dumper_make_response(dumper, &dump_resp, orig_ent, prefix,
                ip_bkt_info[level - 1].bi_pfx_len);

        ret = mtrie_dumper_route_encode(dumper, &dump_resp);
        if (dump_resp.rtr_mac_size) {
            vr_free(dump_resp.rtr_mac, VR_ROUTE_REQ_MAC_OBJECT);
            dump_resp.rtr_mac_size = 0;
            dump_resp.rtr_mac = NULL;
        }

        dump_resp.rtr_prefix = NULL;
        if (ret <= 0)
           return -1;
    }

    return 0;
}

static int
mtrie_walk(struct vr_message_dumper *dumper, unsigned int family)
{
    vr_route_req *req;
    struct ip_mtrie *mtrie;
    struct ip_bucket_entry *ent;
    uint32_t rt_prefix[4] = {0};

    req = (vr_route_req *)dumper->dump_req;
    mtrie = vrfid_to_mtrie(req->rtr_vrf_id, family);
    if (!mtrie)
        return -EINVAL;

    ent = &mtrie->root;

    return mtrie_dump_entry(dumper, ent, (uint8_t*)&rt_prefix, 0);
}

static int
mtrie_dump(struct vr_rtable * __unsued, struct vr_route_req *rt)
{
    int ret = 0;
    struct vr_message_dumper *dumper;

    dumper = vr_message_dump_init(&rt->rtr_req);
    if (!dumper) {
        ret = -ENOMEM;
        goto generate_response;
    }

    if (((vr_route_req *)(dumper->dump_req))->rtr_marker_size == 0)
        dumper->dump_been_to_marker = 1;

    ret = mtrie_walk(dumper, rt->rtr_req.rtr_family);

generate_response:
    vr_message_dump_exit(dumper, ret);

    return 0;
}

/*
 * Delete a route from the table.
 * prefix is in network byte order.
 * returns 0 on failure; or non-zero if an entry was found.
 *
 * When deleting a route:
 * - Move all descendent bucket (not covered by more-specifics) with the
 * parent of this node.
 * - If any buckets contain the same next-hop result, the bucket can be
 * deleted. Memory should be freed after a delay in order to deal with
 * concurrency.
 */
static int
mtrie_delete(struct vr_rtable * _unused, struct vr_route_req *rt)
{
    int vrf_id = rt->rtr_req.rtr_vrf_id;
    struct ip_mtrie *rtable;
    struct vr_route_req lreq;

    rtable = vrfid_to_mtrie(vrf_id, rt->rtr_req.rtr_family);
    if (!rtable)
        return -ENOENT;

    rt->rtr_nh = vrouter_get_nexthop(rt->rtr_req.rtr_rid, rt->rtr_req.rtr_nh_id);
    if (!rt->rtr_nh)
        return -ENOENT;


    rt->rtr_req.rtr_index = VR_BE_INVALID_INDEX;
    if ((rt->rtr_req.rtr_mac_size == VR_ETHER_ALEN) &&
                (!IS_MAC_ZERO(rt->rtr_req.rtr_mac))) {
        lreq.rtr_req.rtr_index = rt->rtr_req.rtr_index;
        lreq.rtr_req.rtr_mac_size = VR_ETHER_ALEN;
        lreq.rtr_req.rtr_mac = rt->rtr_req.rtr_mac;
        lreq.rtr_req.rtr_vrf_id = vrf_id;
        if (!vr_bridge_lookup(vrf_id, &lreq))
            return -ENOENT;
        rt->rtr_req.rtr_index = lreq.rtr_req.rtr_index;
    }

    if (!(rt->rtr_req.rtr_label_flags & VR_RT_LABEL_VALID_FLAG)) {
        rt->rtr_req.rtr_label = 0xFFFFFF;
    } else {
        rt->rtr_req.rtr_label &= 0xFFFFFF;
    }

    __mtrie_delete(rt, &rtable->root, 0, 0, 1);
    vrouter_put_nexthop(rt->rtr_nh);

   return 0;
}

static inline struct vr_vrf_stats *
mtrie_stats(int vrf, unsigned int cpu)
{
    if ((unsigned int)vrf >= vr_vrfs)
        return &invalid_vrf_stats[cpu];

    if (mtrie_vrf_stats) 
       return &((mtrie_vrf_stats[vrf])[cpu]);

    return NULL;
}

static int
mtrie_stats_get(vr_vrf_stats_req *req, vr_vrf_stats_req *response)
{
    unsigned int i;
    struct vr_vrf_stats *stats;

    memset(response, 0, sizeof(*response));

    response->vsr_rid = req->vsr_rid;
    response->vsr_family = req->vsr_family;
    response->vsr_type = req->vsr_type;
    response->vsr_vrf = req->vsr_vrf;

    for (i = 0; i < vr_num_cpus; i++) {
        stats = mtrie_stats(req->vsr_vrf, i);
        if (stats) {
            response->vsr_discards += stats->vrf_discards;
            response->vsr_resolves += stats->vrf_resolves;
            response->vsr_receives += stats->vrf_receives;
            response->vsr_l2_receives += stats->vrf_l2_receives;
            response->vsr_ecmp_composites += stats->vrf_ecmp_composites;
            response->vsr_encap_composites += stats->vrf_encap_composites;
            response->vsr_evpn_composites += stats->vrf_evpn_composites;
            response->vsr_l2_mcast_composites += stats->vrf_l2_mcast_composites;
            response->vsr_fabric_composites += stats->vrf_fabric_composites;
            response->vsr_udp_tunnels += stats->vrf_udp_tunnels;
            response->vsr_udp_mpls_tunnels += stats->vrf_udp_mpls_tunnels;
            response->vsr_gre_mpls_tunnels += stats->vrf_gre_mpls_tunnels;
            response->vsr_l2_encaps += stats->vrf_l2_encaps;
            response->vsr_encaps += stats->vrf_encaps;
            response->vsr_gros += stats->vrf_gros;
            response->vsr_diags += stats->vrf_diags;
            response->vsr_vxlan_tunnels += stats->vrf_vxlan_tunnels;
            response->vsr_arp_virtual_proxy += stats->vrf_arp_virtual_proxy;
            response->vsr_arp_virtual_stitch += stats->vrf_arp_virtual_stitch;
            response->vsr_arp_virtual_flood += stats->vrf_arp_virtual_flood;
            response->vsr_arp_physical_stitch += stats->vrf_arp_physical_stitch;
            response->vsr_arp_tor_proxy += stats->vrf_arp_tor_proxy;
            response->vsr_arp_physical_flood += stats->vrf_arp_physical_flood;
            response->vsr_vrf_translates += stats->vrf_vrf_translates;
            response->vsr_uuc_floods += stats->vrf_uuc_floods;
            response->vsr_pbb_tunnels += stats->vrf_pbb_tunnels;
            response->vsr_udp_mpls_over_mpls_tunnels +=
                                    stats->vrf_udp_mpls_over_mpls_tunnels;
        }
    }

    return 0;
}

static bool
mtrie_stats_empty(vr_vrf_stats_req *r)
{
    if (r->vsr_discards || r->vsr_resolves || r->vsr_receives ||
            r->vsr_ecmp_composites || r->vsr_l2_mcast_composites ||
            r->vsr_fabric_composites || r->vsr_udp_tunnels ||
            r->vsr_udp_mpls_tunnels || r->vsr_gre_mpls_tunnels ||
            r->vsr_l2_encaps || r->vsr_encaps || r->vsr_gros ||
            r->vsr_diags || r->vsr_encap_composites ||
            r->vsr_evpn_composites || r->vsr_vrf_translates ||
            r->vsr_vxlan_tunnels || r->vsr_arp_virtual_proxy ||
            r->vsr_arp_virtual_stitch || r->vsr_arp_virtual_flood ||
            r->vsr_arp_physical_stitch || r->vsr_arp_tor_proxy ||
            r->vsr_arp_physical_flood || r->vsr_l2_receives ||
            r->vsr_uuc_floods || r->vsr_pbb_tunnels ||
            r->vsr_udp_mpls_over_mpls_tunnels)
        return false;

    return true;
}

static int
mtrie_stats_dump(struct vr_rtable *rtable, vr_vrf_stats_req *req)
{
    int ret = 0, len;
    unsigned int i;
    struct vr_message_dumper *dumper;
    vr_vrf_stats_req response;

    dumper = vr_message_dump_init(req);
    if (!dumper) {
        ret = -ENOMEM;
        goto generate_response;
    }


    for (i = req->vsr_marker + 1; i < rtable->algo_max_vrfs; i++) {
        req->vsr_vrf = i;
        mtrie_stats_get(req, &response);
        if (mtrie_stats_empty(&response))
            continue;
        len = vr_message_dump_object(dumper, VR_VRF_STATS_OBJECT_ID,
                &response);
        if (len <= 0)
            goto generate_response;
    }

    req->vsr_vrf = -1;
    mtrie_stats_get(req, &response);
    if (mtrie_stats_empty(&response))
        goto generate_response;

    len = vr_message_dump_object(dumper, VR_VRF_STATS_OBJECT_ID,
            &response);

generate_response:
    vr_message_dump_exit(dumper, ret);

    return 0;
}

/*
 * Common API to do lookup for both nexthop information or void * data
 */
void *
__mtrie_lookup(struct vr_route_req *rt, struct ip_bucket *bkt, unsigned int level)
{
    unsigned int i, limit, index;

    struct ip_bucket_entry *ent;
    struct mtrie_bkt_info *ip_bkt_info;
    void *ret_data = NULL;

    if (!bkt || level >= ip_bkt_get_max_level(rt->rtr_req.rtr_family))
        return NULL;

    ip_bkt_info = ip_bkt_info_get(rt->rtr_req.rtr_family);
    index = rt_to_index(rt, level);

    if (rt->rtr_req.rtr_prefix_len > ip_bkt_info[level].bi_pfx_len) {
        limit = ip_bkt_info[level].bi_size;
    } else {
        limit = (1 <<
                (ip_bkt_info[level].bi_pfx_len - rt->rtr_req.rtr_prefix_len));
    }


    /*
     * ideally, we would have just followed the calculated index to the
     * bottom of the tree and returned. however, what happens when the
     * bottom of the tree is populated with a more specific route? for
     * e.g.: we are searching for 1.1.0.0/16, but we also have a more
     * specific route for 1.1.0.0/24. So, to get around that case, we
     * need to loop the whole bucket, searching for a prefix length match.
     *
     * So what happens if all of the prefixes below have a more specific
     * route. For e.g.: 1.1.0, 1.1.1, 1.1.2, ... 1.1.255. While there are
     * no practical applications of such a route, for correctness, in such
     * a case, we loop around the current bucket: i.e. in this case, we will
     * loop around the bucket that holds 1.1/16. Maybe 1.2/16 was inherited
     * from a lesser specific prefix and hence a match.
     */
    for (i = 0; i < ip_bkt_info[level].bi_size; i++) {
        ent = index_to_entry(bkt, (index + i) % ip_bkt_info[level].bi_size);

        if (!ENTRY_IS_BUCKET(ent)) {
            if (i >= limit) {
                if (ent->entry_prefix_len >= rt->rtr_req.rtr_prefix_len)
                    continue;
            }

            if (ent->entry_prefix_len > rt->rtr_req.rtr_prefix_len)
                continue;

            rt->rtr_req.rtr_label_flags = ent->entry_label_flags;
            rt->rtr_req.rtr_label = ent->entry_label;
            rt->rtr_req.rtr_prefix_len = ent->entry_prefix_len;
            rt->rtr_req.rtr_index = ent->entry_bridge_index;
            ret_data = (void *)ent->entry_long_i;
            rt->rtr_nh = (struct vr_nexthop *) ret_data;
            break;
        } else {
            bkt = ent->entry_bkt_p;
            ret_data = __mtrie_lookup(rt, bkt, level + 1);
            if (ret_data)
                break;
        }
    }

    return (void *) rt->rtr_nh;
}

/*
 * longest prefix match. go down the tree till you encounter a next-hop.
 * if no nexthop, there is something wrong with the tree which was built.
 *
 * returns the nexthop of the LPM route
 */
static struct vr_nexthop *
mtrie_lookup(unsigned int vrf_id, struct vr_route_req *rt)
{
    unsigned int level = 0;
    uintptr_t ptr;

    struct ip_mtrie *table;
    struct ip_bucket *bkt;
    struct ip_bucket_entry *ent;
    struct vr_nexthop *default_nh, *ret_nh;

    default_nh = ip4_default_nh;
    table = vrfid_to_mtrie(vrf_id, rt->rtr_req.rtr_family);
    if (!table) {
        rt->rtr_nh = default_nh;
        return default_nh;
    }

    ent = &table->root;
    ptr = ent->entry_long_i;
    if (!ptr) {
        rt->rtr_nh = default_nh;
        return default_nh;
    }

    if (ENTRY_IS_NEXTHOP(ent)) {
        rt->rtr_req.rtr_label_flags = ent->entry_label_flags;
        rt->rtr_req.rtr_label = ent->entry_label;
        rt->rtr_req.rtr_prefix_len = ent->entry_prefix_len;
        rt->rtr_req.rtr_index = ent->entry_bridge_index;
        ret_nh = ent->entry_nh_p;
        rt->rtr_nh = ret_nh;
        return ret_nh;
    }

    bkt = ent->entry_bkt_p;
    if (!bkt) {
        rt->rtr_nh = default_nh;
        return default_nh;
    }

    ret_nh = (struct vr_nexthop *) __mtrie_lookup(rt, bkt, level);
    if (!ret_nh)
        ret_nh = default_nh;

    rt->rtr_nh = ret_nh;

    return ret_nh;
}


/*
 * adds a route to the corresponding vrf table. returns 0 on
 * success and non-zero otherwise
 */
static int
mtrie_add(struct vr_rtable * _unused, struct vr_route_req *rt)
{
    unsigned int            vrf_id = rt->rtr_req.rtr_vrf_id;
    struct ip_mtrie       *mtrie = vrfid_to_mtrie(vrf_id, rt->rtr_req.rtr_family);
    int ret;
    struct vr_route_req tmp_req;

    mtrie = (mtrie ? mtrie : mtrie_alloc_vrf(vrf_id, rt->rtr_req.rtr_family));
    if (!mtrie)
        return -ENOMEM;

    rt->rtr_nh = vrouter_get_nexthop(rt->rtr_req.rtr_rid, rt->rtr_req.rtr_nh_id);
    if (!rt->rtr_nh)
        return -ENOENT;

    if ((!(rt->rtr_req.rtr_label_flags & VR_RT_LABEL_VALID_FLAG)) &&
                 (rt->rtr_nh->nh_type == NH_TUNNEL)) {
        vrouter_put_nexthop(rt->rtr_nh);
        return -EINVAL;
    }


    rt->rtr_req.rtr_index = VR_BE_INVALID_INDEX;
    if ((rt->rtr_req.rtr_mac_size == VR_ETHER_ALEN) &&
            (!IS_MAC_ZERO(rt->rtr_req.rtr_mac))) {

        tmp_req.rtr_req.rtr_index = rt->rtr_req.rtr_index;
        tmp_req.rtr_req.rtr_mac_size = VR_ETHER_ALEN;
        tmp_req.rtr_req.rtr_mac = rt->rtr_req.rtr_mac;
        tmp_req.rtr_req.rtr_vrf_id = rt->rtr_req.rtr_vrf_id;
        if (!vr_bridge_lookup(tmp_req.rtr_req.rtr_vrf_id, &tmp_req))
            return -ENOENT;
        rt->rtr_req.rtr_index = tmp_req.rtr_req.rtr_index;
    }

    if (!(rt->rtr_req.rtr_label_flags & VR_RT_LABEL_VALID_FLAG)) {
        rt->rtr_req.rtr_label = 0xFFFFFF;
    } else {
        rt->rtr_req.rtr_label &= 0xFFFFFF;
    }

    ret = __mtrie_add(mtrie, rt, 1);
    vrouter_put_nexthop(rt->rtr_nh);
    return ret;
}

/*
 * Exact-match
 * returns the next-hop on exact match. NULL otherwise
 */
static int
mtrie_get(unsigned int vrf_id, struct vr_route_req *rt)
{
    struct vr_nexthop *nh;
    struct vr_route_req breq;
    vr_route_req *req = &rt->rtr_req;

    nh = mtrie_lookup(vrf_id, rt);
    if (nh)
        req->rtr_nh_id = nh->nh_id;
    else
        req->rtr_nh_id = -1;

    if (req->rtr_index != VR_BE_INVALID_INDEX) {
        req->rtr_mac = vr_zalloc(VR_ETHER_ALEN, VR_ROUTE_REQ_MAC_OBJECT);
        req->rtr_mac_size = VR_ETHER_ALEN;

        breq.rtr_req.rtr_mac = req->rtr_mac;
        breq.rtr_req.rtr_index = req->rtr_index;
        breq.rtr_req.rtr_mac_size = VR_ETHER_ALEN;
        vr_bridge_lookup(req->rtr_vrf_id, &breq);

    } else {
        req->rtr_mac_size = 0;
        req->rtr_mac = NULL;
    }

    return 0;
}

static struct ip_mtrie *
mtrie_alloc_vrf(unsigned int vrf_id, unsigned int family)
{
    struct ip_mtrie *mtrie;
    struct ip_mtrie **mtrie_table;
    int index = 0;

    if (family == AF_INET6)
        index = 1;

    mtrie = vr_zalloc(sizeof(struct ip_mtrie), VR_MTRIE_OBJECT);
    if (mtrie) {
        mtrie->root.entry_nh_p = vrouter_get_nexthop(0, NH_DISCARD_ID);
        mtrie->root.entry_bridge_index =  VR_BE_INVALID_INDEX;
        mtrie->root.entry_type = ENTRY_TYPE_NEXTHOP;
        mtrie_table = vn_rtable[index];
        mtrie_table[vrf_id] = mtrie;
        mtrie->root.entry_label = 0xFFFFFF;
        mtrie->root.entry_label_flags = 0;
    }

    return mtrie;
}

static void
mtrie_free_vrf(struct vr_rtable *rtable, unsigned int vrf_id)
{
    struct ip_mtrie *mtrie;
    struct ip_mtrie **vrf_tables;
    int i;

    /* Free V4 and V6 tables */
    for (i = 0; i < 2; i++) {
        vrf_tables = vn_rtable[i];
        mtrie = vrf_tables[vrf_id];
        if (!mtrie)
            continue;
    
        mtrie_free_entry(&mtrie->root, 0);
        vrf_tables[vrf_id] = NULL;
        vr_free(mtrie, VR_MTRIE_OBJECT);
    }

    return;
}

static void
mtrie_stats_cleanup(struct vr_rtable *rtable, bool soft_reset)
{
    unsigned int i, stats_memory_size;

    if (!mtrie_vrf_stats)
        return;

    stats_memory_size = sizeof(struct vr_vrf_stats) * vr_num_cpus;
    for (i = 0; i < rtable->algo_max_vrfs; i++) {
        if (mtrie_vrf_stats[i]) {
            if (soft_reset) {
                memset(mtrie_vrf_stats[i], 0, stats_memory_size);
            } else {
                vr_free(mtrie_vrf_stats[i], VR_MTRIE_STATS_OBJECT);
                mtrie_vrf_stats[i] = NULL;
            }
        }
    }

    if (!soft_reset) {
        vr_free(mtrie_vrf_stats, VR_MTRIE_STATS_OBJECT);
        rtable->vrf_stats = mtrie_vrf_stats = NULL;

        if (invalid_vrf_stats) {
            vr_free(invalid_vrf_stats, VR_MTRIE_STATS_OBJECT);
            invalid_vrf_stats = NULL;
        }
    } else {
        if (invalid_vrf_stats)
            memset(invalid_vrf_stats, 0, stats_memory_size);
    }

    return;
}

void
mtrie_algo_deinit(struct vr_rtable *rtable, struct rtable_fspec *fs,
        bool soft_reset)
{
    unsigned int i;

    mtrie_stats_cleanup(rtable, soft_reset);
    if (rtable->algo_data) {
        for (i = 0; i < fs->rtb_max_vrfs; i++)
            mtrie_free_vrf(rtable, i);
    }

    if (!soft_reset) {
        vn_rtable[0] = vn_rtable[1] = NULL;
        vr_free(rtable->algo_data, VR_MTRIE_TABLE_OBJECT);
        rtable->algo_data = NULL;
    }

    algo_init_done = 0;

    return;
}


static int
mtrie_stats_init(struct vr_rtable *rtable)
{
    int ret = 0, i = 0;
    unsigned int stats_memory;

    if (!mtrie_vrf_stats) {
        stats_memory = sizeof(void *) * rtable->algo_max_vrfs;
        mtrie_vrf_stats = vr_zalloc(stats_memory, VR_MTRIE_STATS_OBJECT);
        if (!mtrie_vrf_stats)
            return vr_module_error(-ENOMEM, __FUNCTION__,
                    __LINE__, stats_memory);
        for (i = 0; i < rtable->algo_max_vrfs; i++) {
            stats_memory = sizeof(struct vr_vrf_stats) * vr_num_cpus;
            mtrie_vrf_stats[i] = vr_zalloc(stats_memory,
                    VR_MTRIE_STATS_OBJECT);
            if (!mtrie_vrf_stats[i] && (ret = -ENOMEM)) {
                vr_module_error(ret, __FUNCTION__, __LINE__, i);
                goto cleanup;
            }
        }

        rtable->vrf_stats = mtrie_vrf_stats;
    }

    if (!invalid_vrf_stats) {
        invalid_vrf_stats = vr_zalloc(sizeof(struct vr_vrf_stats) *
                vr_num_cpus, VR_MTRIE_STATS_OBJECT);
        if (!invalid_vrf_stats && (ret = -ENOMEM)) {
            vr_module_error(ret, __FUNCTION__, __LINE__, -1);
            goto cleanup;
        }

    }

    return 0;

cleanup:
    if (!i)
        return ret;

    for (--i; i >= 0; i--) {
        if (mtrie_vrf_stats[i]) {
            vr_free(mtrie_vrf_stats[i], VR_MTRIE_STATS_OBJECT);
            mtrie_vrf_stats[i] = NULL;
        }
    }

    if (mtrie_vrf_stats) {
        vr_free(mtrie_vrf_stats, VR_MTRIE_STATS_OBJECT);
        mtrie_vrf_stats = NULL;
    }

    if (invalid_vrf_stats) {
        vr_free(invalid_vrf_stats, VR_MTRIE_STATS_OBJECT);
        invalid_vrf_stats = NULL;
    }

    return ret;
}

struct vr_nexthop *
vr_inet_route_lookup(unsigned int vrf_id, struct vr_route_req *rt)
{
    if (!vn_rtable[0] || !vn_rtable[1])
        return NULL;
    return mtrie_lookup(vrf_id, rt);
}

int
mtrie_algo_init(struct vr_rtable *rtable, struct rtable_fspec *fs)
{
    int ret = 0;
    unsigned int table_memory;

    if (algo_init_done)
        return 0;

    if (!rtable->algo_data) {
        table_memory = 2 * sizeof(void *) * fs->rtb_max_vrfs;
        rtable->algo_data = vr_zalloc(table_memory, VR_MTRIE_TABLE_OBJECT);
        if (!rtable->algo_data)
            return vr_module_error(-ENOMEM, __FUNCTION__, __LINE__, table_memory);
    }

    rtable->algo_max_vrfs = fs->rtb_max_vrfs;
    if ((ret = mtrie_stats_init(rtable))) {
        vr_module_error(ret, __FUNCTION__, __LINE__, 0);
        goto init_fail;
    }

    rtable->algo_add = mtrie_add;
    rtable->algo_del = mtrie_delete;
    rtable->algo_lookup = mtrie_lookup;
    rtable->algo_get = mtrie_get;
    rtable->algo_dump = mtrie_dump;
    rtable->algo_stats_get = mtrie_stats_get;
    rtable->algo_stats_dump = mtrie_stats_dump;

    vr_inet_vrf_stats = mtrie_stats;
    /* local cache */
    /* ipv4 table */
    vn_rtable[0] = (struct ip_mtrie **)rtable->algo_data;
    /* ipv6 table */
    vn_rtable[1] = (struct ip_mtrie **)((unsigned char **)rtable->algo_data
                                                 + fs->rtb_max_vrfs);

    mtrie_ip_bkt_info_init(ip4_bkt_info, IP4_PREFIX_LEN);
    mtrie_ip_bkt_info_init(ip6_bkt_info, IP6_PREFIX_LEN);

    algo_init_done = 1;
    return 0;

init_fail:
    if (rtable->algo_data) {
        vr_free(rtable->algo_data, VR_MTRIE_TABLE_OBJECT);
        rtable->algo_data = NULL;
    }

    return ret;
}

/*
 * API to initialize vdata mtrie
 */
struct ip_mtrie *
vdata_mtrie_init (unsigned int prefix_len, void *data)
{
    struct ip_mtrie *mtrie;

    mtrie = vr_zalloc(sizeof(struct ip_mtrie), VR_MTRIE_OBJECT);
    if (mtrie) {
        mtrie->root.entry_type = ENTRY_TYPE_VDATA;
        mtrie->root.entry_prefix_len = prefix_len;
        mtrie->root.entry_vdata_p = data;
        mtrie->root.entry_bridge_index =  VR_BE_INVALID_INDEX;
        mtrie->root.entry_label = 0xFFFFFF;
    }

    return mtrie;
}

/*
 * API to add a prefix in vdata mtrie
 */
int
vdata_mtrie_add(struct ip_mtrie *mtrie, struct vr_route_req *rt)
{
    int ret = 0;
    mtrie_debug = 1;
    ret = __mtrie_add(mtrie, rt, 0);
    mtrie_debug = 0;
    return ret;
}

/*
 * API to lookup a prefix in vdata mtrie
 */
void *
vdata_mtrie_lookup(struct ip_mtrie *mtrie, struct vr_route_req *rt)
{
    struct ip_bucket_entry *ent;
    struct ip_bucket *bkt;
    void *ret = NULL;

    if (!mtrie)
        return NULL;

    ent = &mtrie->root;

    if (ENTRY_IS_VDATA(ent)) {
        rt->rtr_req.rtr_prefix_len = ent->entry_prefix_len;
        return ent->entry_vdata_p;
    }

    bkt = ent->entry_bkt_p;
    mtrie_debug = 1;
    ret = __mtrie_lookup(rt, bkt, 0);
    mtrie_debug = 0;
    return ret;
}

/*
 * API to delete a prefix in vdata mtrie; NOTE: The delete is always deferred delete
 */
int
vdata_mtrie_delete(struct ip_mtrie *mtrie, struct vr_route_req *rt)
{
    return __mtrie_delete(rt, &mtrie->root, 0, 1, 0);
}

/*
 * API to delete the complete mtrie at once
 */
void
vdata_mtrie_delete_all(struct ip_mtrie *mtrie)
{
    mtrie_free_entry(&mtrie->root, 0);
    vr_free(mtrie, VR_MTRIE_OBJECT);
}

