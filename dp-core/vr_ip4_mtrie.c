/*
 * vr_ip4_mtrie.c -- 	VRF mtrie management
 *
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.	
 */
#include <vr_os.h>
#include "vr_sandesh.h"
#include "vr_message.h"
#include "vr_ip4_mtrie.h"

extern struct vr_nexthop *ip4_default_nh; 

static struct vr_vrf_stats **mtrie_vrf_stats;
static struct vr_vrf_stats *invalid_vrf_stats;

struct vr_nexthop *(*vr_inet_route_lookup)(unsigned int, struct vr_route_req *,
        struct vr_packet *);
struct vr_vrf_stats *(*vr_inet_vrf_stats)(unsigned short, unsigned int);

static struct ip4_mtrie *mtrie_alloc_vrf(unsigned int);

/* mtrie specific */
#define IP4_BKT_LEVELS  4 /* 8/8/8/8 */
struct mtrie_bkt_info ip4_bkt_info[IP4_BKT_LEVELS] = {
    {
        .bi_size    =   IP4BUCKET_LEVEL0_SIZE,
        .bi_shift   =   IP4BUCKET_LEVEL0_SHIFT,
        .bi_pfx_len =   IP4BUCKET_LEVEL0_PFX_LEN,
        .bi_mask    =   IP4BUCKET_LEVEL0_MASK,
        .bi_bits    =   IP4BUCKET_LEVEL0_BITS,
    },
    {
        .bi_size    =   IP4BUCKET_LEVEL1_SIZE,
        .bi_shift   =   IP4BUCKET_LEVEL1_SHIFT,
        .bi_pfx_len =   IP4BUCKET_LEVEL1_PFX_LEN,
        .bi_mask    =   IP4BUCKET_LEVEL1_MASK,
        .bi_bits    =   IP4BUCKET_LEVEL1_BITS,
    },
    {
        .bi_size    =   IP4BUCKET_LEVEL2_SIZE,
        .bi_shift   =   IP4BUCKET_LEVEL2_SHIFT,
        .bi_pfx_len =   IP4BUCKET_LEVEL2_PFX_LEN,
        .bi_mask    =   IP4BUCKET_LEVEL2_MASK,
        .bi_bits    =   IP4BUCKET_LEVEL2_BITS,
    },
    {
        .bi_size    =   IP4BUCKET_LEVEL3_SIZE,
        .bi_shift   =   IP4BUCKET_LEVEL3_SHIFT,
        .bi_pfx_len =   IP4BUCKET_LEVEL3_PFX_LEN,
        .bi_mask    =   IP4BUCKET_LEVEL3_MASK,
        .bi_bits    =   IP4BUCKET_LEVEL3_BITS,
    },
};

struct ip4_mtrie **vn_rtable;

/*
 * given a vrf id, get the routing table corresponding to the id
 */
static inline struct ip4_mtrie * 
vrfid_to_mtrie(unsigned int vrf_id)
{
    if (vrf_id >= VR_MAX_VRFS)
        return NULL;

    return vn_rtable[vrf_id];
}

#define PREFIX_TO_INDEX(prefix, level) \
    ((prefix >> ip4_bkt_info[level].bi_shift) & \
     ip4_bkt_info[level].bi_mask)
/*
 * we have to be careful about 'level' here. assumption is that level
 * will be passed sane from whomever is calling
 */
static inline int
rt_to_index(struct vr_route_req *rt, unsigned int level)
{
    return PREFIX_TO_INDEX(rt->rtr_req.rtr_prefix, level);
}

static inline struct ip4_bucket_entry *
index_to_entry(struct ip4_bucket *bkt, int index)
{
    return &bkt->bkt_data[index];
}

static void
set_entry_to_bucket(struct ip4_bucket_entry *ent, struct ip4_bucket *bkt)
{
    struct vr_nexthop *tmp_nh;

    /* save old... */
    tmp_nh = ent->entry_nh_p;
    /* update... */
    ent->entry_long_i = (unsigned long)bkt | 0x1ul;
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
set_entry_to_nh(struct ip4_bucket_entry *entry, struct vr_nexthop *nh)
{
    struct vr_nexthop *tmp_nh;

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

    /* ...and then take steps to release original */
    if (tmp_nh && PTR_IS_NEXTHOP((unsigned long)(tmp_nh))) {
        vrouter_put_nexthop(tmp_nh);
    }

    return;
}

static inline struct ip4_bucket *
entry_to_bucket(struct ip4_bucket_entry *ent)
{
    unsigned long long_i = ent->entry_long_i;

    if (PTR_IS_BUCKET(long_i))
        return (struct ip4_bucket *)(long_i & ~0x1UL);

    return NULL;
}

/*
 * alloc a mtrie bucket
 */
static struct ip4_bucket *
mtrie_alloc_bucket(unsigned char level, struct ip4_bucket_entry *parent)
{
    unsigned int                bkt_size;
    unsigned int                i;
    struct ip4_bucket          *bkt;
    struct ip4_bucket_entry    *ent;

    bkt_size = ip4_bkt_info[level].bi_size;
    bkt = vr_zalloc(sizeof(struct ip4_bucket) 
                    + sizeof(struct ip4_bucket_entry) * bkt_size);
    if (!bkt)
        return NULL;

    for (i = 0; i < bkt_size; i++) {
        ent = &bkt->bkt_data[i];
        set_entry_to_nh(ent, parent->entry_nh_p);
        ent->entry_prefix_len = parent->entry_prefix_len;
        ent->entry_label_flags = parent->entry_label_flags;
        ent->entry_label = parent->entry_label;
    }

    return bkt;
}

static void
add_to_tree(struct ip4_bucket_entry *ent, int level, struct vr_route_req *rt)
{
    unsigned int i;
    struct ip4_bucket              *bkt;

    if (level >= IP4_BKT_LEVELS - 1)
        /* assert here ? */
        return;

    /* assured that the first one is a bucket */
    bkt = entry_to_bucket(ent);
    level++;

    for (i = 0; i < ip4_bkt_info[level].bi_size; i++) {
        ent = index_to_entry(bkt, i);
        if (!ENTRY_IS_NEXTHOP(ent))
            add_to_tree(ent, level, rt);
        else if (ent->entry_prefix_len <= rt->rtr_req.rtr_prefix_len) {
            /* a less specific entry, which needs to be replaced */
            set_entry_to_nh(ent, rt->rtr_nh);
            ent->entry_prefix_len = rt->rtr_req.rtr_prefix_len;
            ent->entry_label_flags = rt->rtr_req.rtr_label_flags;
            ent->entry_label = rt->rtr_req.rtr_label;
        }
    }

    return;
}

static void
mtrie_free_entry(struct ip4_bucket_entry *entry, unsigned int level)
{
    unsigned int i;
    struct ip4_bucket *bkt;

    if (ENTRY_IS_NEXTHOP(entry)) {
        vrouter_put_nexthop(entry->entry_nh_p);
        return;
    }

    bkt = entry_to_bucket(entry);
    if (!bkt)
        return;

    for (i = 0; i < ip4_bkt_info[level].bi_size; i++)
        if (ENTRY_IS_BUCKET(&bkt->bkt_data[i])) {
            mtrie_free_entry(&bkt->bkt_data[i], level + 1);
        } else {
            if (bkt->bkt_data[i].entry_nh_p) {
                vrouter_put_nexthop(bkt->bkt_data[i].entry_nh_p);
            }
        }

    entry->entry_bkt_p = NULL;
    vr_free(bkt);

    return;
}
        
static void
mtrie_reset_entry(struct ip4_bucket_entry *ent, int level,
                struct vr_nexthop *nh)
{
    struct ip4_bucket_entry cp_ent;

    memcpy(&cp_ent, ent, sizeof(cp_ent));

    /* remove from the tree */
    if (nh)
        set_entry_to_nh(ent, nh);

    /* wait for all cores to see it */
    if (!vr_not_ready)
        vr_delay_op();

    /* ...and then work with the copy */
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
 */
static int
__mtrie_add(struct ip4_mtrie *mtrie, struct vr_route_req *rt)
{
    int                         ret, index, level, err_level = 0;
    unsigned int                i, fin;
    struct ip4_bucket          *bkt;
    struct ip4_bucket_entry    *ent, *err_ent = NULL;
    struct vr_nexthop          *nh, *err_nh = NULL;

    ent = &mtrie->root;
    nh = ent->entry_nh_p;
    for (level = 0; level < IP4_BKT_LEVELS; level++) {
        if (!ENTRY_IS_BUCKET(ent)) {
            bkt = mtrie_alloc_bucket(level, ent);
            set_entry_to_bucket(ent, bkt);
            if (!err_ent) {
                err_ent = ent;
                err_nh = nh;
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

        if (rt->rtr_req.rtr_prefix_len > ip4_bkt_info[level].bi_pfx_len) {
            if (ENTRY_IS_NEXTHOP(ent)) {
                nh = ent->entry_nh_p;
            }

            continue;

        } else {
            /* 
             * cover all the indices for which this route is the best
             * prefix match
             */
            if ((rt->rtr_req.rtr_prefix_len >
                        (ip4_bkt_info[level].bi_pfx_len - ip4_bkt_info[level].bi_bits)) &&
                    (rt->rtr_req.rtr_prefix_len <= ip4_bkt_info[level].bi_pfx_len)) {
                fin = 1 << (ip4_bkt_info[level].bi_pfx_len - rt->rtr_req.rtr_prefix_len); 
            } else {
                fin = ip4_bkt_info[level].bi_size;
            }

             fin += index;
             if (fin > ip4_bkt_info[level].bi_size)
                 fin = ip4_bkt_info[level].bi_size;

             for (i = index; i < fin; i++) {
                ent = index_to_entry(bkt, i);
                if (ENTRY_IS_BUCKET(ent))
                    add_to_tree(ent, level, rt);
                else if (ent->entry_prefix_len <= rt->rtr_req.rtr_prefix_len) {
                    /* a less specific entry, which needs to be replaced */
                    set_entry_to_nh(ent, rt->rtr_nh);
                    ent->entry_prefix_len = rt->rtr_req.rtr_prefix_len;
                    ent->entry_label_flags = rt->rtr_req.rtr_label_flags;
                    ent->entry_label = rt->rtr_req.rtr_label;
                }
             }

             break;
        }
    }

    return 0;

exit_ret:
    if (err_ent)
        mtrie_reset_entry(err_ent, err_level, err_nh);

    return ret;
}


static void
ip4_bucket_sched_for_free(struct ip4_bucket *bkt, int level)
{
    unsigned int i;
    struct ip4_bucket_entry *tmp_ent;

    if (!vr_not_ready)
        vr_delay_op();

    for (i = 0; i < ip4_bkt_info[level].bi_size; i++) {
        tmp_ent = &bkt->bkt_data[i];
        if (tmp_ent->entry_nh_p) {
            vrouter_put_nexthop(tmp_ent->entry_nh_p);
        }
    }
    vr_free(bkt);
}

static void
free_bucket(struct ip4_bucket_entry *ent, int level, struct vr_route_req *rt)
{
    struct ip4_bucket *bkt;

    if (ENTRY_IS_NEXTHOP(ent)) {
        return;
    }

    bkt = entry_to_bucket(ent);
    set_entry_to_nh(ent, rt->rtr_nh);
    ent->entry_label_flags = rt->rtr_req.rtr_label_flags;
    ent->entry_label = rt->rtr_req.rtr_label;
    
    ip4_bucket_sched_for_free(bkt, level);
}

static int
__mtrie_delete(struct vr_route_req *rt, struct ip4_bucket_entry *ent,
                unsigned char level)
{
    unsigned int        index, i, fin;
    struct ip4_bucket    *bkt;
    struct ip4_bucket_entry *tmp_ent;

    if (ENTRY_IS_NEXTHOP(ent))
        return -ENOENT;

    bkt = entry_to_bucket(ent);
    index = rt_to_index(rt, level);

    if (rt->rtr_req.rtr_prefix_len > ip4_bkt_info[level].bi_pfx_len) {
        tmp_ent = index_to_entry(bkt, index);
        __mtrie_delete(rt, tmp_ent, level + 1);
    } else {
        if ((rt->rtr_req.rtr_prefix_len >
                (ip4_bkt_info[level].bi_pfx_len - ip4_bkt_info[level].bi_bits)) &&
                (rt->rtr_req.rtr_prefix_len <= ip4_bkt_info[level].bi_pfx_len)) {
            fin = 1 << (ip4_bkt_info[level].bi_pfx_len - rt->rtr_req.rtr_prefix_len); 
        } else {
            fin = ip4_bkt_info[level].bi_size;
        }

         fin += index;
         if (fin > ip4_bkt_info[level].bi_size)
             fin = ip4_bkt_info[level].bi_size;

         for (i = index; i < fin; i++) {
            tmp_ent = index_to_entry(bkt, i);
            if (ENTRY_IS_NEXTHOP(tmp_ent) &&
                            (tmp_ent->entry_prefix_len == rt->rtr_req.rtr_prefix_len)) {
                set_entry_to_nh(tmp_ent, rt->rtr_nh);
                tmp_ent->entry_label_flags = rt->rtr_req.rtr_label_flags;
                tmp_ent->entry_label = rt->rtr_req.rtr_label;
                tmp_ent->entry_prefix_len = rt->rtr_req.rtr_replace_plen;
            } else 
                __mtrie_delete(rt, tmp_ent, level + 1);
        }
    }

    /* check if current bucket neds to be deleted */
    for (i = 1; i < ip4_bkt_info[level].bi_size; i++) {
        if ((bkt->bkt_data[i].entry_long_i == bkt->bkt_data[0].entry_long_i) &&
                (bkt->bkt_data[i].entry_label_flags ==
                	bkt->bkt_data[0].entry_label_flags) &&
                (bkt->bkt_data[i].entry_label ==
                	bkt->bkt_data[0].entry_label) && 
                (bkt->bkt_data[i].entry_prefix_len == 
			bkt->bkt_data[0].entry_prefix_len)) {
            continue;
        } else
            return 0;
    }

    free_bucket(ent, level, rt);
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
        struct ip4_bucket_entry *ent, unsigned int prefix, unsigned int prefix_len)
{
    vr_route_req *req = (vr_route_req *)dumper->dump_req;

    resp->rtr_vrf_id = req->rtr_vrf_id;
    resp->rtr_family = req->rtr_family;
    resp->rtr_prefix = prefix;
    resp->rtr_prefix_len = prefix_len;
    resp->rtr_rid = req->rtr_rid;
    resp->rtr_label_flags = ent->entry_label_flags;
    resp->rtr_label = ent->entry_label;
    resp->rtr_nh_id = ent->entry_nh_p->nh_id;
    resp->rtr_rt_type = RT_UCAST;
    resp->rtr_mac_size = 0;
    resp->rtr_mac = NULL;
    resp->rtr_replace_plen = ent->entry_prefix_len;

    return;
}

static int
mtrie_dump_entry(struct vr_message_dumper *dumper, struct ip4_bucket_entry *ent,
        unsigned int byte, int level)
{
#ifdef VR_ROUTE_DEBUG
    unsigned char *addr;
#endif
    unsigned int i = 0, prefix;
    int ret;
    struct ip4_bucket *bkt;
    struct ip4_bucket_entry *ent_p = ent;
    vr_route_req *req, resp;

    req = dumper->dump_req;
    if (!dumper->dump_been_to_marker) {
        i = PREFIX_TO_INDEX(req->rtr_marker, level);
        bkt = entry_to_bucket(ent);
        ent = index_to_entry(bkt, i);

        prefix = byte | (i << ip4_bkt_info[level].bi_shift);
        if ((prefix == (unsigned int)req->rtr_marker &&
                    ip4_bkt_info[level].bi_pfx_len == req->rtr_marker_plen))
            dumper->dump_been_to_marker = 1;

        if (ENTRY_IS_BUCKET(ent) && !dumper->dump_been_to_marker) {
            if (mtrie_dump_entry(dumper, ent, prefix, level + 1))
                return -1;
            i++;
        } else {
            if (dumper->dump_been_to_marker)
                i++;
            dumper->dump_been_to_marker = 1;
        }
    }

    if (ENTRY_IS_BUCKET(ent_p)) {
        bkt = entry_to_bucket(ent_p);
        for (; i < ip4_bkt_info[level].bi_size; i++) {
            ent = &bkt->bkt_data[i];
            prefix = byte | (i << ip4_bkt_info[level].bi_shift);
            if (mtrie_dump_entry(dumper, ent, prefix, level + 1) < 0)
                return -1;
        }
    } else if (ent_p->entry_nh_p) {
        mtrie_dumper_make_response(dumper, &resp, ent_p, byte,
                ip4_bkt_info[level - 1].bi_pfx_len);

#ifdef VR_ROUTE_DEBUG
        addr = (unsigned char *)&byte;
        vr_printf("%u.%u.%u.%u/%u\t\t", addr[3], addr[2], addr[1], addr[0],
                        ip4_bkt_info[level - 1].bi_pfx_len);
        if (ent_p->entry_label_flags) {
            vr_printf("%d\t", ent_p->entry_label);
        } else {
            vr_printf("N/A\t");
        }
        vr_printf("%d\n", ent_p->entry_nh_p->nh_id);
#endif

        ret = mtrie_dumper_route_encode(dumper, &resp);
        if (ret <= 0)
            return -1;
    }

    return 0;
}

static int
mtrie_walk(struct vr_message_dumper *dumper)
{
    vr_route_req *req;
    struct ip4_mtrie *mtrie;
    struct ip4_bucket_entry *ent;

    req = (vr_route_req *)dumper->dump_req;
    mtrie = vrfid_to_mtrie(req->rtr_vrf_id);
    if (!mtrie)
        return -EINVAL; 

    ent = &mtrie->root;
    if (ENTRY_IS_BUCKET(ent)) {
        return mtrie_dump_entry(dumper, ent, 0, 0);
    }

    return 0;
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

    if (!((vr_route_req *)(dumper->dump_req))->rtr_marker)
        dumper->dump_been_to_marker = 1;

    ret = mtrie_walk(dumper);

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
    struct ip4_mtrie *rtable;

    rtable = vrfid_to_mtrie(vrf_id);
    if (!rtable)
        return -ENOENT;

    rt->rtr_nh = vrouter_get_nexthop(rt->rtr_req.rtr_rid, rt->rtr_req.rtr_nh_id);
    if (!rt->rtr_nh)
        return -ENOENT;

    __mtrie_delete(rt, &rtable->root, 0);
    vrouter_put_nexthop(rt->rtr_nh);

   return 0;
}

static inline struct vr_vrf_stats *
mtrie_stats(unsigned short vrf, unsigned int cpu)
{
    if (vrf >= VR_MAX_VRFS)
        return &invalid_vrf_stats[cpu];

    return &((mtrie_vrf_stats[vrf])[cpu]);
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
            response->vsr_ecmp_composites += stats->vrf_ecmp_composites;
            response->vsr_encap_composites += stats->vrf_encap_composites;
            response->vsr_evpn_composites += stats->vrf_evpn_composites;
            response->vsr_l3_mcast_composites += stats->vrf_l3_mcast_composites;
            response->vsr_l2_mcast_composites += stats->vrf_l2_mcast_composites;
            response->vsr_fabric_composites += stats->vrf_fabric_composites;
            response->vsr_multi_proto_composites +=
                stats->vrf_multi_proto_composites;
            response->vsr_udp_tunnels  += stats->vrf_udp_tunnels;
            response->vsr_udp_mpls_tunnels  += stats->vrf_udp_mpls_tunnels;
            response->vsr_gre_mpls_tunnels  += stats->vrf_gre_mpls_tunnels;
            response->vsr_l2_encaps += stats->vrf_l2_encaps;
            response->vsr_encaps += stats->vrf_encaps;
            response->vsr_gros += stats->vrf_gros;
            response->vsr_diags += stats->vrf_diags;
        }
    }

    return 0;
}

static bool
mtrie_stats_empty(vr_vrf_stats_req *r)
{
    if (r->vsr_discards || r->vsr_resolves || r->vsr_receives || 
            r->vsr_ecmp_composites || r->vsr_l3_mcast_composites ||
            r->vsr_l2_mcast_composites || r->vsr_fabric_composites ||
            r->vsr_multi_proto_composites || r->vsr_udp_tunnels || 
            r->vsr_udp_mpls_tunnels || r->vsr_gre_mpls_tunnels || 
            r->vsr_l2_encaps || r->vsr_encaps || r->vsr_gros ||
            r->vsr_diags)
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
 * longest prefix match. go down the tree till you encounter a next-hop.
 * if no nexthop, there is something wrong with the tree which was built.
 *
 * returns the nexthop of the LPM route
 */
static struct vr_nexthop *
mtrie_lookup(unsigned int vrf_id, struct vr_route_req *rt,
        struct vr_packet *pkt)
{
    unsigned int        level, index;
    unsigned long       ptr;
    struct ip4_mtrie   *table;
    struct ip4_bucket  *bkt;
    struct ip4_bucket_entry *ent;

    /* we do not support any thing other than /32 route lookup */
    if (rt->rtr_req.rtr_prefix_len != IP4_PREFIX_LEN)
        return ip4_default_nh;

    table = vrfid_to_mtrie(vrf_id);
    if (!table)
        return ip4_default_nh;

    ent = &table->root;
    ptr = ent->entry_long_i;
    if (!ptr)
        return ip4_default_nh;

    if (PTR_IS_NEXTHOP(ptr)) {
        rt->rtr_req.rtr_label_flags = ent->entry_label_flags;
        rt->rtr_req.rtr_label = ent->entry_label;
        rt->rtr_req.rtr_prefix_len = ent->entry_prefix_len;
        return PTR_TO_NEXTHOP(ptr);
    }

    bkt = PTR_TO_BUCKET(ptr);
    if (!bkt)
        return ip4_default_nh;

    for (level = 0; level < IP4_BKT_LEVELS; level++) {
        index = rt_to_index(rt, level);
        ent = index_to_entry(bkt, index);
        ptr = ent->entry_long_i;
        if (PTR_IS_NEXTHOP(ptr)) {
            rt->rtr_req.rtr_label_flags = ent->entry_label_flags;
            rt->rtr_req.rtr_label = ent->entry_label;
            rt->rtr_req.rtr_prefix_len = ent->entry_prefix_len;
            return PTR_TO_NEXTHOP(ptr);
        }

        bkt = PTR_TO_BUCKET(ptr);
    }

    /* no nexthop; assert */
    ASSERT(0);

    return NULL;
}

/*
 * adds a route to the corresponding vrf table. returns 0 on
 * success and non-zero otherwise
 */
static int
mtrie_add(struct vr_rtable * _unused, struct vr_route_req *rt)
{
    unsigned int            vrf_id = rt->rtr_req.rtr_vrf_id;
    struct ip4_mtrie       *mtrie = vrfid_to_mtrie(vrf_id);
    int ret;

    mtrie = (mtrie ? : mtrie_alloc_vrf(vrf_id));
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
    ret = __mtrie_add(mtrie, rt);
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

    nh = mtrie_lookup(vrf_id, rt, NULL);
    if (nh)
        rt->rtr_req.rtr_nh_id = nh->nh_id;
    else
        rt->rtr_req.rtr_nh_id = -1;
    return 0;
}

static struct ip4_mtrie *
mtrie_alloc_vrf(unsigned int vrf_id)
{
    struct ip4_mtrie *mtrie;

    mtrie = vr_zalloc(sizeof(struct ip4_mtrie));
    if (mtrie) {
        mtrie->root.entry_nh_p = vrouter_get_nexthop(0, NH_DISCARD_ID);
        vn_rtable[vrf_id] = mtrie;
    }

    return mtrie;
}

static void
mtrie_free_vrf(struct vr_rtable *rtable, unsigned int vrf_id)
{
    struct ip4_mtrie *mtrie;
    struct ip4_mtrie **vrf_tables;

    vrf_tables = (struct ip4_mtrie **)rtable->algo_data;
    mtrie = vrf_tables[vrf_id];
    if (!mtrie)
        return;

    mtrie_free_entry(&mtrie->root, 0);
    vrf_tables[vrf_id] = NULL;
    vr_free(mtrie);

    return;
}

static void
mtrie_stats_cleanup(struct vr_rtable *rtable)
{
    unsigned int i;

    for (i = 0; i < rtable->algo_max_vrfs; i++) {
        if (mtrie_vrf_stats[i]) {
            vr_free(mtrie_vrf_stats[i]);
            mtrie_vrf_stats[i] = NULL;
        }
    }

    vr_free(mtrie_vrf_stats);
    rtable->vrf_stats = mtrie_vrf_stats = NULL;

    if (invalid_vrf_stats) {
        vr_free(invalid_vrf_stats);
        invalid_vrf_stats = NULL;
    }

    return;
}

void
mtrie4_algo_deinit(struct vr_rtable *rtable, struct rtable_fspec *fs, bool soft_reset)
{
    unsigned int i;

    if (!vn_rtable) 
        return;

    mtrie_stats_cleanup(rtable);

    vn_rtable = NULL;
    for (i = 0; i < fs->rtb_max_vrfs; i++)
        mtrie_free_vrf(rtable, i);

    vr_free(rtable->algo_data);
    rtable->algo_data = NULL;

    return;
}


static int
mtrie_stats_init(struct vr_rtable *rtable)
{
    int ret = 0;
    unsigned int i;
    unsigned int stats_memory;

    stats_memory = sizeof(void *) * rtable->algo_max_vrfs;
    mtrie_vrf_stats = vr_zalloc(stats_memory);
    if (!mtrie_vrf_stats)
        return vr_module_error(-ENOMEM, __FUNCTION__,
                __LINE__, stats_memory);

    for (i = 0; i < rtable->algo_max_vrfs; i++) {
        stats_memory = sizeof(struct vr_vrf_stats) * vr_num_cpus;
        mtrie_vrf_stats[i] = vr_zalloc(stats_memory);
        if (!mtrie_vrf_stats[i] && (ret = -ENOMEM)) {
            vr_module_error(ret, __FUNCTION__, __LINE__, i);
            goto cleanup;
        }
    }

    invalid_vrf_stats = vr_zalloc(sizeof(struct vr_vrf_stats) *
                            vr_num_cpus);
    if (!invalid_vrf_stats && (ret = -ENOMEM)) {
        vr_module_error(ret, __FUNCTION__, __LINE__, -1);
        goto cleanup;
    }

    rtable->vrf_stats = mtrie_vrf_stats;

    return 0;

cleanup:
    if (!i)
        return ret;

    for (--i; i >= 0; i--) {
        if (mtrie_vrf_stats[i]) {
            vr_free(mtrie_vrf_stats[i]);
            mtrie_vrf_stats[i] = NULL;
        }
    }

    vr_free(mtrie_vrf_stats);
    mtrie_vrf_stats = NULL;

    return ret;
}

int
mtrie4_algo_init(struct vr_rtable *rtable, struct rtable_fspec *fs)
{
    int ret = 0;
    unsigned int table_memory;

    table_memory = sizeof(void *) * fs->rtb_max_vrfs;
    rtable->algo_data = vr_zalloc(table_memory);
    if (!rtable->algo_data)
        return vr_module_error(-ENOMEM, __FUNCTION__, __LINE__, table_memory);

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

    vr_inet_route_lookup = mtrie_lookup;
    vr_inet_vrf_stats = mtrie_stats;
    /* local cache */
    vn_rtable = (struct ip4_mtrie **)rtable->algo_data;

    return 0;

init_fail:
    if (rtable->algo_data) {
        vr_free(rtable->algo_data);
        rtable->algo_data = NULL;
    }

    return ret;
}
