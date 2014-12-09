/*
 * vr_ip_mtrie.c -- 	VRF mtrie management
 *
 * Copyright (c) 2014 Juniper Networks, Inc. All rights reserved.	
 */
#include <vr_os.h>
#include "vr_sandesh.h"
#include "vr_message.h"
#include "vr_packet.h"
#include "vr_route.h"
#include "vr_ip_mtrie.h"

extern struct vr_nexthop *ip4_default_nh; 

static struct vr_vrf_stats **mtrie_vrf_stats;
static struct vr_vrf_stats *invalid_vrf_stats;

struct vr_nexthop *(*vr_inet_route_lookup)(unsigned int, struct vr_route_req *,
        struct vr_packet *);
struct vr_vrf_stats *(*vr_inet_vrf_stats)(unsigned short, unsigned int);

static struct ip_mtrie *mtrie_alloc_vrf(unsigned int, unsigned int);

/* mtrie specific, bucket_info for v4 and v6 */
#define IP4_BKT_LEVELS  (IP4_PREFIX_LEN / IPBUCKET_LEVEL_BITS) 
#define IP6_BKT_LEVELS  (IP6_PREFIX_LEN / IPBUCKET_LEVEL_BITS) 

struct mtrie_bkt_info ip4_bkt_info[IP4_BKT_LEVELS];
struct mtrie_bkt_info ip6_bkt_info[IP6_BKT_LEVELS];

struct ip_mtrie **vn_rtable[2];
static int algo_init_done = 0;
static vr_route_req dump_resp;

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
    if (vrf_id >= VR_MAX_VRFS)
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
set_entry_to_nh(struct ip_bucket_entry *entry, struct vr_nexthop *nh)
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

static inline struct ip_bucket *
entry_to_bucket(struct ip_bucket_entry *ent)
{
    unsigned long long_i = ent->entry_long_i;

    if (PTR_IS_BUCKET(long_i))
        return (struct ip_bucket *)(long_i & ~0x1UL);

    return NULL;
}

/*
 * alloc a mtrie bucket
 */
static struct ip_bucket *
mtrie_alloc_bucket(struct mtrie_bkt_info *ip_bkt_info, unsigned char level, struct ip_bucket_entry *parent)
{
    unsigned int                bkt_size;
    unsigned int                i;
    struct ip_bucket           *bkt;
    struct ip_bucket_entry     *ent;

    bkt_size = ip_bkt_info[level].bi_size;
    bkt = vr_zalloc(sizeof(struct ip_bucket) 
                    + sizeof(struct ip_bucket_entry) * bkt_size);
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
add_to_tree(struct ip_bucket_entry *ent, int level, struct vr_route_req *rt)
{
    unsigned int i;
    struct ip_bucket      *bkt;
    struct mtrie_bkt_info *ip_bkt_info;

    if (level >= (ip_bkt_get_max_level(rt->rtr_req.rtr_family) - 1))
        /* assert here ? */
        return;

    ip_bkt_info = ip_bkt_info_get(rt->rtr_req.rtr_family);

    /* assured that the first one is a bucket */
    bkt = entry_to_bucket(ent);
    level++;

    for (i = 0; i < ip_bkt_info[level].bi_size; i++) {
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
mtrie_free_entry(struct ip_bucket_entry *entry, unsigned int level)
{
    unsigned int i;
    struct ip_bucket *bkt;

    if (ENTRY_IS_NEXTHOP(entry)) {
        vrouter_put_nexthop(entry->entry_nh_p);
        return;
    }

    bkt = entry_to_bucket(entry);
    if (!bkt)
        return;

    for (i = 0; i < IPBUCKET_LEVEL_SIZE; i++)
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
mtrie_reset_entry(struct ip_bucket_entry *ent, int level,
                struct vr_nexthop *nh)
{
    struct ip_bucket_entry cp_ent;

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
__mtrie_add(struct ip_mtrie *mtrie, struct vr_route_req *rt)
{
    int                         ret, index = 0, level, err_level = 0;
    unsigned char                i, fin = 0;
    struct ip_bucket          *bkt;
    struct ip_bucket_entry    *ent, *err_ent = NULL;
    struct vr_nexthop          *nh, *err_nh = NULL;
    struct mtrie_bkt_info *ip_bkt_info = ip_bkt_info_get(rt->rtr_req.rtr_family);

    ent = &mtrie->root;

    nh = ent->entry_nh_p;
    for (level = 0; level < ip_bkt_get_max_level(rt->rtr_req.rtr_family); level++) {
        if (!ENTRY_IS_BUCKET(ent)) {
            bkt = mtrie_alloc_bucket(ip_bkt_info, level, ent);
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

        if (rt->rtr_req.rtr_prefix_len > ip_bkt_info[level].bi_pfx_len) {
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
                        (ip_bkt_info[level].bi_pfx_len - ip_bkt_info[level].bi_bits)) &&
                    (rt->rtr_req.rtr_prefix_len <= ip_bkt_info[level].bi_pfx_len)) {
                fin = 1 << (ip_bkt_info[level].bi_pfx_len - rt->rtr_req.rtr_prefix_len); 
            }


             /* 
              * Run through the loop 'fin' times only
              * If fin is 0, it actually means 256 ('char' overflow), so run the
              * loop 256 times
              */
             for (i = index; i <= (ip_bkt_info[level].bi_size-1); i++) {
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
                if (fin) {
                    /* Repeat the loop 'fin' times only */
                    fin--;
                    if (fin == 0)
                        break;
                } 
                /* 
                 * Bailout at the last index, 
                 * the below check takes care of overflow 
                 */
                if (i == (ip_bkt_info[level].bi_size-1))
                    break;
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
ip_bucket_sched_for_free(struct ip_bucket *bkt, int level)
{
    unsigned int i;
    struct ip_bucket_entry *tmp_ent;

    if (!vr_not_ready)
        vr_delay_op();

    for (i = 0; i < IPBUCKET_LEVEL_SIZE; i++) {
        tmp_ent = &bkt->bkt_data[i];
        if (tmp_ent->entry_nh_p) {
            vrouter_put_nexthop(tmp_ent->entry_nh_p);
        }
    }
    vr_free(bkt);
}

static void
free_bucket(struct ip_bucket_entry *ent, int level, struct vr_route_req *rt)
{
    struct ip_bucket *bkt;

    if (ENTRY_IS_NEXTHOP(ent)) {
        return;
    }

    bkt = entry_to_bucket(ent);
    set_entry_to_nh(ent, rt->rtr_nh);
    ent->entry_label_flags = rt->rtr_req.rtr_label_flags;
    ent->entry_label = rt->rtr_req.rtr_label;
    
    ip_bucket_sched_for_free(bkt, level);
}

static int
__mtrie_delete(struct vr_route_req *rt, struct ip_bucket_entry *ent,
                unsigned char level)
{
    unsigned int        index, i, fin;
    struct ip_bucket    *bkt;
    struct ip_bucket_entry *tmp_ent;
    struct mtrie_bkt_info *ip_bkt_info = ip_bkt_info_get(rt->rtr_req.rtr_family);

    if (ENTRY_IS_NEXTHOP(ent))
        return -ENOENT;

    bkt = entry_to_bucket(ent);
    index = rt_to_index(rt, level);

    if (rt->rtr_req.rtr_prefix_len > ip_bkt_info[level].bi_pfx_len) {
        tmp_ent = index_to_entry(bkt, index);
        __mtrie_delete(rt, tmp_ent, level + 1);
    } else {
        if ((rt->rtr_req.rtr_prefix_len >
                (ip_bkt_info[level].bi_pfx_len - ip_bkt_info[level].bi_bits)) &&
                (rt->rtr_req.rtr_prefix_len <= ip_bkt_info[level].bi_pfx_len)) {
            fin = 1 << (ip_bkt_info[level].bi_pfx_len - rt->rtr_req.rtr_prefix_len); 
        } else {
            fin = ip_bkt_info[level].bi_size;
        }

         fin += index;
         if (fin > ip_bkt_info[level].bi_size)
             fin = ip_bkt_info[level].bi_size;

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
    for (i = 1; i < ip_bkt_info[level].bi_size; i++) {
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
        struct ip_bucket_entry *ent, int8_t *prefix, unsigned int prefix_len)
{
    vr_route_req *req = (vr_route_req *)dumper->dump_req;

    resp->rtr_vrf_id = req->rtr_vrf_id;
    resp->rtr_family = req->rtr_family;
    memcpy(resp->rtr_prefix, prefix, RT_IP_ADDR_SIZE(req->rtr_family));
    resp->rtr_prefix_size = req->rtr_prefix_size;
    resp->rtr_marker_size = 0;
    resp->rtr_marker = NULL;
    resp->rtr_prefix_len = prefix_len;
    resp->rtr_rid = req->rtr_rid;
    resp->rtr_label_flags = ent->entry_label_flags;
    resp->rtr_label = ent->entry_label;
    resp->rtr_nh_id = ent->entry_nh_p->nh_id;
    resp->rtr_mac_size = 0;
    resp->rtr_mac = NULL;
    resp->rtr_replace_plen = ent->entry_prefix_len;

    return;
}

static int
mtrie_dump_entry(struct vr_message_dumper *dumper, struct ip_bucket_entry *ent,
        int8_t *prefix, int level)
{
    unsigned char i = 0;
    unsigned int j;
    int ret;
    struct ip_bucket *bkt;
    struct ip_bucket_entry *ent_p = ent;
    struct mtrie_bkt_info *ip_bkt_info;
    vr_route_req *req;
    int done = 0;
    uint32_t rt_prefix[4];

    req = dumper->dump_req;

    ip_bkt_info = ip_bkt_info_get(req->rtr_family);
    if (!dumper->dump_been_to_marker) {
        i = PREFIX_TO_INDEX(req->rtr_marker, level);
        bkt = entry_to_bucket(ent);
        ent = index_to_entry(bkt, i);

        prefix[level] = i;
        
        if ((!memcmp(prefix, req->rtr_marker, ip_bkt_info[level].bi_pfx_len/8)) &&
              (ip_bkt_info[level].bi_pfx_len == req->rtr_marker_plen)) {
            dumper->dump_been_to_marker = 1;
        }

        /* take care of overflow */
        if (i == (ip_bkt_info[level].bi_size - 1))
            done = 1;

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
        if (done)
            return 0;
        j = ip_bkt_info[level].bi_size - i;
        bkt = entry_to_bucket(ent_p);
        for (; j > 0; j--, i++) {
            ent = &bkt->bkt_data[i];
            prefix[level] = i;
            if (mtrie_dump_entry(dumper, ent, prefix, level + 1) < 0)
                return -1;
        }
    } else if (ent_p->entry_nh_p) {
        dump_resp.rtr_prefix = (uint8_t*)&rt_prefix;
        mtrie_dumper_make_response(dumper, &dump_resp, ent_p, prefix,
                ip_bkt_info[level - 1].bi_pfx_len);

        ret = mtrie_dumper_route_encode(dumper, &dump_resp);

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
    int ret = 0;
    uint32_t rt_prefix[4];

    req = (vr_route_req *)dumper->dump_req;
    mtrie = vrfid_to_mtrie(req->rtr_vrf_id, family);
    if (!mtrie)
        return -EINVAL; 

    ent = &mtrie->root;

    if (ENTRY_IS_BUCKET(ent)) {
        ret =  mtrie_dump_entry(dumper, ent, (uint8_t*)&rt_prefix, 0);
    }

    return ret;
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

    rtable = vrfid_to_mtrie(vrf_id, rt->rtr_req.rtr_family);
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
            response->vsr_ecmp_composites += stats->vrf_ecmp_composites;
            response->vsr_encap_composites += stats->vrf_encap_composites;
            response->vsr_evpn_composites += stats->vrf_evpn_composites;
            response->vsr_l2_mcast_composites += stats->vrf_l2_mcast_composites;
            response->vsr_fabric_composites += stats->vrf_fabric_composites;
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
            r->vsr_ecmp_composites || r->vsr_l2_mcast_composites ||
            r->vsr_fabric_composites || r->vsr_udp_tunnels ||
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
    struct ip_mtrie   *table;
    struct ip_bucket  *bkt;
    struct ip_bucket_entry *ent;
    struct vr_nexthop *default_nh, *ret_nh;

      default_nh = ip4_default_nh;

    /* we do not support any thing other than /32 route lookup */
    if ((rt->rtr_req.rtr_family == AF_INET) && 
        (rt->rtr_req.rtr_prefix_len != IP4_PREFIX_LEN))
        return default_nh;

    if ((rt->rtr_req.rtr_family == AF_INET6) && 
        (rt->rtr_req.rtr_prefix_len != IP6_PREFIX_LEN))
        return default_nh;

    table = vrfid_to_mtrie(vrf_id, rt->rtr_req.rtr_family);
    if (!table)
        return default_nh;

    ent = &table->root;

    ptr = ent->entry_long_i;
    if (!ptr)
        return default_nh;

    if (PTR_IS_NEXTHOP(ptr)) {
        rt->rtr_req.rtr_label_flags = ent->entry_label_flags;
        rt->rtr_req.rtr_label = ent->entry_label;
        rt->rtr_req.rtr_prefix_len = ent->entry_prefix_len;
        ret_nh = PTR_TO_NEXTHOP(ptr);

        return ret_nh;
    }

    bkt = PTR_TO_BUCKET(ptr);
    if (!bkt)
        return default_nh;

    for (level = 0; level < ip_bkt_get_max_level(rt->rtr_req.rtr_family); level++) {
        index = rt_to_index(rt, level);
        ent = index_to_entry(bkt, index);
        ptr = ent->entry_long_i;
        if (PTR_IS_NEXTHOP(ptr)) {
            rt->rtr_req.rtr_label_flags = ent->entry_label_flags;
            rt->rtr_req.rtr_label = ent->entry_label;
            rt->rtr_req.rtr_prefix_len = ent->entry_prefix_len;
            ret_nh = PTR_TO_NEXTHOP(ptr);
            return ret_nh;
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
    struct ip_mtrie       *mtrie = vrfid_to_mtrie(vrf_id, rt->rtr_req.rtr_family);
    int ret;

    mtrie = (mtrie ? : mtrie_alloc_vrf(vrf_id, rt->rtr_req.rtr_family));
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

static struct ip_mtrie *
mtrie_alloc_vrf(unsigned int vrf_id, unsigned int family)
{
    struct ip_mtrie *mtrie;
    struct ip_mtrie **mtrie_table;
    int index = 0;

    if (family == AF_INET6)
        index = 1;

    mtrie = vr_zalloc(sizeof(struct ip_mtrie));
    if (mtrie) {
        mtrie->root.entry_nh_p = vrouter_get_nexthop(0, NH_DISCARD_ID);
        mtrie_table = vn_rtable[index];
        mtrie_table[vrf_id] = mtrie;
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
    for (i=0; i<2; i++) {
        vrf_tables = vn_rtable[i];
        mtrie = vrf_tables[vrf_id];
        if (!mtrie)
            continue;
    
        mtrie_free_entry(&mtrie->root, 0);
        vrf_tables[vrf_id] = NULL;
        vr_free(mtrie);
    }

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
mtrie_algo_deinit(struct vr_rtable *rtable, struct rtable_fspec *fs, bool soft_reset)
{
    unsigned int i;

    if (!vn_rtable[0]) 
        return;

    mtrie_stats_cleanup(rtable);

    for (i = 0; i < fs->rtb_max_vrfs; i++)
        mtrie_free_vrf(rtable, i);

    *vn_rtable[0] = *vn_rtable[1] = NULL;

    vr_free(rtable->algo_data);
    rtable->algo_data = NULL;

    algo_init_done = 0;

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
mtrie_algo_init(struct vr_rtable *rtable, struct rtable_fspec *fs)
{
    int ret = 0;
    unsigned int table_memory;

    if (algo_init_done)
        return 0;

    table_memory = 2 * sizeof(void *) * fs->rtb_max_vrfs;
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
    vn_rtable[0] = (struct ip_mtrie **)rtable->algo_data; // V4 table
    vn_rtable[1] = (struct ip_mtrie **)((char*)rtable->algo_data 
                                                 + fs->rtb_max_vrfs); // V6 table

    mtrie_ip_bkt_info_init(ip4_bkt_info, IP4_PREFIX_LEN);
    mtrie_ip_bkt_info_init(ip6_bkt_info, IP6_PREFIX_LEN);

    algo_init_done = 1;
    return 0;

init_fail:
    if (rtable->algo_data) {
        vr_free(rtable->algo_data);
        rtable->algo_data = NULL;
    }

    return ret;
}
