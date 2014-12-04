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

/*
 * The last two bits of the pointer indicate the entry type
 * 00 - Nexthop
 * 01 - Index
 * 10 - Bucket
 */
#define ENTRY_IS_BUCKET(EPtr)        ((((EPtr)->entry_long_i) & 0x3ul) == 0x2ul)
#define ENTRY_IS_NEXTHOP(EPtr)       ((((EPtr)->entry_long_i) & 0x3ul) == 0)
#define ENTRY_IS_INDEX(EPtr)         ((((EPtr)->entry_long_i) & 0x3ul) == 0x1ul)

#define DATA_IS_BUCKET(ptr)           (((ptr) & 0x3ul) == 0x2ul)
#define DATA_IS_INDEX(ptr)            (((ptr) & 0x3ul) == 0x1ul)
#define DATA_IS_NEXTHOP(ptr)          (((ptr) & 0x3ul) == 0)

#define DATA_TO_BUCKET(ptr)           ((struct ip_bucket *)((ptr) ^ 0x2ul))
#define DATA_TO_INDEX(ptr)            (((unsigned long)(ptr)) >> 2)
#define DATA_TO_NEXTHOP(ptr)          ((struct vr_nexthop *)(ptr))

#define BUCKET_TO_DATA(index)         (((unsigned long)(index)) | 0x2ul)
#define INDEX_TO_DATA(index)          ((((unsigned long)(index)) << 2) | 0x1ul)

struct ip_bucket_entry {
    union {
        struct vr_nexthop *nexthop_p;
        struct ip_bucket  *bucket_p;
        unsigned long      long_i;
    } entry_data;                  

    unsigned int entry_prefix_len:8;
    unsigned int entry_label_flags:4;
    unsigned int entry_label:20;
};

#define entry_nh_p      entry_data.nexthop_p
#define entry_bkt_p     entry_data.bucket_p
#define entry_long_i    entry_data.long_i

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


#ifdef __cplusplus
}
#endif
#endif /* __VR_IP_MTRIE_H__ */
