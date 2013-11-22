/*
 * vr_flow.h --
 *
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#ifndef __VR_FLOW_H__
#define __VR_FLOW_H__

#include "vr_defs.h"

#define VR_FLOW_ACTION_DROP         0x0
#define VR_FLOW_ACTION_HOLD         0x1
#define VR_FLOW_ACTION_FORWARD      0x2
#define VR_FLOW_ACTION_NAT          0x4

#define VR_FLOW_LOOKUP              0x0
#define VR_FLOW_BYPASS              0x1
#define VR_FLOW_TRAP                0x2

#define VR_FLOW_FLAG_ACTIVE         0x1
#define VR_RFLOW_VALID              0x1000
#define VR_FLOW_FLAG_MIRROR         0x2000
#define VR_FLOW_FLAG_VRFT           0x4000

/* rest of the flags are action specific */

/* for NAT */
#define VR_FLOW_FLAG_SNAT           0x2
#define VR_FLOW_FLAG_SPAT           0x4
#define VR_FLOW_FLAG_DNAT           0x8
#define VR_FLOW_FLAG_DPAT           0x10
#define VR_FLOW_FLAG_NAT_MASK       (VR_FLOW_FLAG_SNAT | VR_FLOW_FLAG_SPAT | \
        VR_FLOW_FLAG_DNAT | VR_FLOW_FLAG_DPAT)

/* for TRAP */
#define VR_FLOW_FLAG_TRAP_ECMP      0x20
#define VR_FLOW_FLAG_TRAP_MASK      (VR_FLOW_FLAG_TRAP_ECMP)
struct vr_forwarding_md;

struct vr_flow_key {
    unsigned short key_src_port;
    /* we should be doing memcpy for the two ips */
    unsigned int key_src_ip;
    unsigned int key_dest_ip;
    unsigned short key_dst_port;
    unsigned short key_vrf_id;
    unsigned char key_proto;
    unsigned char key_zero;
} __attribute__((packed));

/* 
 * flow bytes and packets are of same width. this should be
 * ok since agent really has to take care of overflows. this
 * is also better probably because processor does not have to
 * do bit operations
 */
struct vr_flow_stats {
    uint32_t flow_bytes;
    uint32_t flow_packets;
    uint16_t flow_bytes_oflow;
    uint8_t  flow_packets_oflow;
} __attribute__((packed));

struct vr_dummy_flow_entry {
    struct vr_flow_stats fe_stats;
     /* not used. if you are in need of a byte, please use this field */
    uint8_t fe_dummy;
    struct vr_list_head fe_hold_list;
    struct vr_flow_key fe_key;
    unsigned short fe_action;
    unsigned short fe_flags;
    int fe_rflow;
    unsigned short fe_dvrf;
    uint16_t fe_src_nh_index;
    uint8_t fe_mirror_id;
    uint8_t fe_sec_mirror_id;
    int8_t fe_ecmp_nh_index;
} __attribute__((packed));

#define VR_FLOW_ENTRY_PACK (64 - sizeof(struct vr_dummy_flow_entry))

/* do not change. any field positions as it might lead to incompatibility */
struct vr_flow_entry {
    struct vr_flow_stats fe_stats;
    /* not used. if you are in need of a byte, please use this field */
    uint8_t fe_dummy;
    struct vr_list_head fe_hold_list;
    struct vr_flow_key fe_key;
    unsigned short fe_action;
    unsigned short fe_flags;
    int fe_rflow;
    unsigned short fe_dvrf;
    uint16_t fe_src_nh_index;
    uint8_t fe_mirror_id;
    uint8_t fe_sec_mirror_id;
    int8_t fe_ecmp_nh_index;
    unsigned char fe_pack[VR_FLOW_ENTRY_PACK];
} __attribute__((packed));

#define VR_FLOW_PROTO_SHIFT             16

#define VR_UDP_DHCP_SPORT   (17 << 16 | htons(67))
#define VR_UDP_DHCP_CPORT   (17 << 16 | htons(68))
#define VR_UDP_DNS_SPORT    (17 << 16 | htons(53))
#define VR_TCP_DNS_SPORT    (6 << 16 | htons(53))

#define VR_DNS_SERVER_PORT  htons(53)

struct vr_flow_md {
    struct vrouter *flmd_router;
    unsigned int flmd_index;
    unsigned short flmd_action;
    unsigned short flmd_flags;
};

struct vr_packet;
struct vrouter;

extern int vr_flow_init(struct vrouter *);
extern void vr_flow_exit(struct vrouter *, bool);
extern unsigned int vr_flow_inet_input(struct vrouter *, unsigned short, 
        struct vr_packet *, unsigned short, struct vr_forwarding_md *);
extern inline unsigned int
vr_flow_bypass(struct vrouter *, struct vr_flow_key *, struct vr_packet *, unsigned int *);
void *vr_flow_get_va(struct vrouter *, uint64_t);
unsigned int vr_flow_table_size(struct vrouter *);
unsigned int vr_oflow_table_size(struct vrouter *);

#endif /* __VR_FLOW_H__ */
