/*
 * vr_ip_mtrie.h -- 
 *
 * Copyright (c) 2014 Juniper Networks, Inc. All rights reserved.
 */
#ifndef __VR_IP_MTRIE_H__
#define __VR_IP_MTRIE_H__

#ifdef __cplusplus
extern "C" {
#endif
struct ip_bucket;

#define ENTRY_TYPE_BUCKET      1
#define ENTRY_TYPE_NEXTHOP     2
#define ENTRY_TYPE_VDATA       3

#define ENTRY_IS_BUCKET(EPtr)        ((EPtr)->entry_type == ENTRY_TYPE_BUCKET)
#define ENTRY_IS_NEXTHOP(EPtr)       ((EPtr)->entry_type == ENTRY_TYPE_NEXTHOP)
#define ENTRY_IS_VDATA(EPtr)         ((EPtr)->entry_type == ENTRY_TYPE_VDATA)

#define PTR_TO_BUCKET(ptr)           ((struct ip_bucket *)(ptr))
#define PTR_TO_NEXTHOP(ptr)          ((struct vr_nexthop *)(ptr))
#define PTR_TO_VDATA(ptr)            ((void *)(ptr))

struct ip_bucket_entry {
    union {
        struct vr_nexthop *nexthop_p;
        struct ip_bucket  *bucket_p;
        void              *vdata_p;
        uintptr_t         long_i;
    } entry_data;                  

    unsigned char entry_type;
    unsigned int entry_prefix_len:8;
    unsigned int entry_label_flags:4;
    unsigned int entry_label:24;
    unsigned int entry_bridge_index;
};

#define entry_nh_p      entry_data.nexthop_p
#define entry_bkt_p     entry_data.bucket_p
#define entry_long_i    entry_data.long_i
#define entry_vdata_p   entry_data.vdata_p

struct ip_bucket {
    struct ip_bucket_entry bkt_data[0];
};

/*
 * IpMtrie
 *
 * IpMtrie ensures that an IPv4 lookup can be performed in 3 data fetches. 
 * IPv6 lookup will require 15 data fetches.
 * 
 */
struct ip_mtrie {
    struct ip_bucket_entry root;
};

#define IP4_PREFIX_LEN              32
#define IP6_PREFIX_LEN              128

#define IPBUCKET_LEVEL_BITS         8
#define IPBUCKET_LEVEL_PFX_LEN      IPBUCKET_LEVEL_BITS
#define IPBUCKET_LEVEL_SIZE         (1 << IPBUCKET_LEVEL_BITS)
#define IPBUCKET_LEVEL_MASK         (IPBUCKET_LEVEL_SIZE - 1)


struct mtrie_bkt_info {
    unsigned int            bi_bits;
    unsigned char           bi_shift;
    unsigned char           bi_pfx_len;
    unsigned int            bi_mask;
    unsigned int            bi_size;
};

/* vdata mtrie APIs */
struct ip_mtrie * vdata_mtrie_init (unsigned int prefix_len, void *data);
int vdata_mtrie_add(struct ip_mtrie *mtrie, struct vr_route_req *rt);
void * vdata_mtrie_lookup(struct ip_mtrie *mtrie, struct vr_route_req *rt);
int vdata_mtrie_delete(struct ip_mtrie *mtrie, struct vr_route_req *rt);
void vdata_mtrie_delete_all(struct ip_mtrie *mtrie);

#ifdef __cplusplus
}
#endif
#endif /* __VR_IP_MTRIE_H__ */
