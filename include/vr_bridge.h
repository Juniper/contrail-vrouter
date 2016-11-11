/*
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#ifndef __VR_BRIDGE_H__
#define __VR_BRIDGE_H__

#include "vr_defs.h"
#include "vr_htable.h"

#define VR_DEF_BRIDGE_ENTRIES          (256 * 1024)

#define VR_MAC_COPY(dst, src) { \
    ((uint16_t *)(dst))[0] = ((uint16_t *)(src))[0]; \
    ((uint16_t *)(dst))[1] = ((uint16_t *)(src))[1]; \
    ((uint16_t *)(dst))[2] = ((uint16_t *)(src))[2]; \
}

#define VR_ETH_COPY(dst, src) { \
    VR_MAC_COPY((unsigned char *)(dst), (unsigned char *)(src)); \
    VR_MAC_COPY(((unsigned char *)(dst) + 6), ((unsigned char *)(src) + 6)); \
    ((uint16_t *)(dst))[6] = ((uint16_t *)(src))[6]; \
}

#define VR_MAC_CMP(dst, src)  \
     ((((uint16_t *)dst)[0] == ((uint16_t *)src)[0]) && \
     (((uint16_t *)dst)[1] == ((uint16_t *)src)[1]) &&  \
     (((uint16_t *)dst)[2] == ((uint16_t *)src)[2]))  \

#define IS_MAC_ZERO(dst) \
     ((((uint16_t *)dst)[0] == 0) && \
     (((uint16_t *)dst)[1] == 0) &&  \
     (((uint16_t *)dst)[2] == 0))  \

#define IS_MAC_BCAST(dst) \
     ((((uint16_t *)dst)[0] == 0xffff) && \
     (((uint16_t *)dst)[1] == 0xffff) &&  \
     (((uint16_t *)dst)[2] == 0xffff))  \

#define IS_MAC_BMCAST(dst) \
     (((uint8_t *)dst)[0]& 0x1)

#define VR_BE_INVALID_INDEX              ((unsigned int)-1)

struct vr_bridge_entry_key {
    unsigned char be_mac[VR_ETHER_ALEN];
    unsigned short be_vrf_id;
}__attribute__((packed));

struct vr_bridge_entry;

struct vr_dummy_bridge_entry {
    vr_hentry_t be_hentry;
    struct vr_bridge_entry_key be_key;
    struct vr_nexthop *be_nh;
    uint64_t be_packets;
    uint32_t be_label;
    uint32_t be_nh_id;
    unsigned short be_flags;
} __attribute__((packed));

#define VR_BRIDGE_ENTRY_PACK (64 - sizeof(struct vr_dummy_bridge_entry))

struct vr_bridge_entry {
    vr_hentry_t be_hentry;
    struct vr_bridge_entry_key be_key;
    struct vr_nexthop *be_nh;
    uint64_t be_packets;
    uint32_t be_label;
    int32_t be_nh_id;
    unsigned short be_flags;
    unsigned char be_pack[VR_BRIDGE_ENTRY_PACK];
} __attribute__((packed));


extern unsigned int vr_bridge_entries, vr_bridge_oentries;
#define VR_BRIDGE_TABLE_SIZE        (vr_bridge_entries *\
        sizeof(struct vr_bridge_entry))
#define VR_BRIDGE_OFLOW_TABLE_SIZE  (vr_bridge_oentries *\
        sizeof(struct vr_bridge_entry))

extern char vr_bcast_mac[];

unsigned int vr_bridge_table_used_oflow_entries(struct vrouter *);
unsigned int vr_bridge_table_used_total_entries(struct vrouter *);
void *vr_bridge_get_va(struct vrouter *, uint64_t);
unsigned int vr_bridge_table_size(struct vrouter *);

#endif
