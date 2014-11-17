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
#define VR_FLOW_FLAG_LINK_LOCAL     0x8000

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

/* Flow Action Reason code */
#define VR_FLOW_DR_UNKNOWN              0x00
#define VR_FLOW_DR_UNAVIALABLE_INTF     0x01
#define VR_FLOW_DR_IPv4_FWD_DIS         0x02
#define VR_FLOW_DR_UNAVAILABLE_VRF      0x03
#define VR_FLOW_DR_NO_SRC_ROUTE         0x04
#define VR_FLOW_DR_NO_DST_ROUTE         0x05
#define VR_FLOW_DR_AUDIT_ENTRY          0x06
#define VR_FLOW_DR_VRF_CHANGE           0x07
#define VR_FLOW_DR_NO_REVERSE_FLOW      0x08
#define VR_FLOW_DR_REVERSE_FLOW_CHANGE  0x09
#define VR_FLOW_DR_NAT_CHANGE           0x0a
#define VR_FLOW_DR_FLOW_LIMIT           0x0b
#define VR_FLOW_DR_LINKLOCAL_SRC_NAT    0x0c
#define VR_FLOW_DR_POLICY               0x0d
#define VR_FLOW_DR_OUT_POLICY           0x0e
#define VR_FLOW_DR_SG                   0x0f
#define VR_FLOW_DR_OUT_SG               0x10
#define VR_FLOW_DR_REVERSE_SG           0x11
#define VR_FLOW_DR_REVERSE_OUT_SG       0x12

struct vr_forwarding_md;

struct vr_flow_key {
    unsigned short key_src_port;
    unsigned short key_dst_port;
    /* we should be doing memcpy for the two ips */
    unsigned int key_src_ip;
    unsigned int key_dest_ip;
    unsigned short key_nh_id;
    unsigned char key_proto;
    unsigned char key_zero;
} __attribute__((packed));

/* 
 * Limit the number of outstanding flows in hold state. The flow rate can
 * be much more than what agent can handle. In such cases, to make sure that
 *
 * . pkt0 is not overrun
 * . too many packets are not cached in flow table
 * . too many entries in hold state which will get serviced slowly (of the
 * order of seconds)
 * . and thus starving the table of new entries
 *
 * we limit the number of entries that are in hold state. In a simplistic
 * scenario, all we would need is one variable that is incremented every
 * time a hold entry is added, and decremented when agent changes the
 * state of the entry from hold to any other state (including deletion).
 * However, there will be contention for that variable from all cpus. To
 * avoid the contention, we will make it a per-cpu variable. Once we make
 * a per-cpu variable, there no longer can be a single variable whose
 * value can be decremented. So, to work around that problem, we
 * will have two monotonically incrementing objects, monitoring the hold
 * count and the count of entries that went from hold to active/delete.
 * The single variable that tracks the latter can't be 32 bit, but the
 * former has to be 32 bit since the sum of all of them has to be compared
 * against the latter, and hence can't be each 64bit.
 *
 * How do we solve overflows?
 *
 * We don't care for overflow of the first variable (since it is 64bit).
 * Whenever any of the per-cpu variable (32bit) overflows, our strategy
 * is to decrement the 64 bit variable from the 32 bit, if the former is
 * lesser or to decrement the 64 bit variable by 32bit_max, if the former
 * is greater. Only in those cases, lock is taken. It is guaranteed that
 * no two values will differ by more than hold count.
 */
struct vr_flow_table_info {
    uint64_t vfti_action_count;
    uint32_t vfti_hold_count[0];
};

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

#define VR_MAX_FLOW_QUEUE_ENTRIES   3U

struct vr_packet_node {
    unsigned short pl_proto;
    struct vr_packet *pl_packet;
    uint32_t pl_outer_src_ip;
    uint32_t pl_label;
    uint32_t pl_vif_idx;
};

struct vr_flow_queue {
    unsigned int vfq_index;
    unsigned int vfq_entries;
    struct vr_packet_node vfq_pnodes[VR_MAX_FLOW_QUEUE_ENTRIES];
};

struct vr_dummy_flow_entry {
    struct vr_flow_key fe_key;
    struct vr_flow_queue *fe_hold_list;
    unsigned short fe_action;
    unsigned short fe_flags;
    int fe_rflow;
    unsigned short fe_vrf;
    unsigned short fe_dvrf;
    uint16_t fe_src_nh_index;
    uint8_t fe_mirror_id;
    uint8_t fe_sec_mirror_id;
    struct vr_flow_stats fe_stats;
    int8_t fe_ecmp_nh_index;
    uint8_t fe_drop_reason;
    unsigned short fe_udp_src_port;
} __attribute__((packed));

#define VR_FLOW_ENTRY_PACK (64 - sizeof(struct vr_dummy_flow_entry))

/* do not change. any field positions as it might lead to incompatibility */
struct vr_flow_entry {
    struct vr_flow_key fe_key;
    struct vr_flow_queue *fe_hold_list;
    unsigned short fe_action;
    unsigned short fe_flags;
    int fe_rflow;
    unsigned short fe_vrf;
    unsigned short fe_dvrf;
    uint16_t fe_src_nh_index;
    uint8_t fe_mirror_id;
    uint8_t fe_sec_mirror_id;
    struct vr_flow_stats fe_stats;
    int8_t fe_ecmp_nh_index;
    uint8_t fe_drop_reason;
    unsigned short fe_udp_src_port;
    unsigned char fe_pack[VR_FLOW_ENTRY_PACK];
} __attribute__((packed));

#define VR_FLOW_PROTO_SHIFT             16

#define VR_UDP_DHCP_SPORT   (17 << 16 | htons(67))
#define VR_UDP_DHCP_CPORT   (17 << 16 | htons(68))
#define VR_UDP_DNS_SPORT    (17 << 16 | htons(53))
#define VR_TCP_DNS_SPORT    (6 << 16 | htons(53))

#define VR_DHCP6_SPORT htons(546)
#define VR_DHCP6_DPORT htons(547)

#define VR_DNS_SERVER_PORT  htons(53)

struct vr_flow_md {
    struct vrouter *flmd_router;
    struct vr_defer_data *flmd_defer_data;
    unsigned int flmd_index;
    unsigned short flmd_flags;
};

struct vr_flow_trap_arg {
    unsigned int vfta_index;
    unsigned int vfta_nh_index;
};

struct vr_packet;
struct vrouter;

extern int vr_flow_init(struct vrouter *);
extern void vr_flow_exit(struct vrouter *, bool);
extern unsigned int vr_flow_inet_input(struct vrouter *, unsigned short, 
        struct vr_packet *, unsigned short, struct vr_forwarding_md *);
extern unsigned int vr_flow_inet6_input(struct vrouter *, unsigned short, 
        struct vr_packet *, unsigned short, struct vr_forwarding_md *);

extern int vr_flow_forward(unsigned short vrf, struct vr_packet *pkt,
        unsigned short proto, struct vr_forwarding_md *fmd);
extern inline unsigned int
vr_flow_bypass(struct vrouter *, struct vr_flow_key *, struct vr_packet *, unsigned int *);
void *vr_flow_get_va(struct vrouter *, uint64_t);
unsigned int vr_flow_table_size(struct vrouter *);
unsigned int vr_oflow_table_size(struct vrouter *);
struct vr_flow_entry * vr_get_flow_entry(struct vrouter *, int );
bool vr_valid_link_local_port(struct vrouter *, int , int , int );

#endif /* __VR_FLOW_H__ */
