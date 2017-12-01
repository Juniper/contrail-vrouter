/*
 * nexthop.h --
 *
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#ifndef __NEXTHOP_H__
#define __NEXTHOP_H__

#include "vr_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

#include "vr_os.h"
#include "vr_types.h"

/*
 * nexthop id is also part of the flow key and is only 16 bits. Hence, you
 * know where you are getting into if you want to increase this limit
 */
#define VR_DEF_NEXTHOPS                 65536
#define NH_TABLE_ENTRIES                VR_DEF_NEXTHOPS

#define VR_NEXTHOP_COMPONENT_DUMP_LIMIT 16

#define NH_DISCARD_ID                   0

enum nexthop_type {
    NH_DEAD,
    NH_RCV,
    NH_ENCAP,
    NH_TUNNEL,
    NH_RESOLVE,
    NH_DISCARD,
    NH_COMPOSITE,
    NH_VRF_TRANSLATE,
    NH_L2_RCV,
    NH_MAX,
};

#define NH_VXLAN_VRF                        NH_VRF_TRANSLATE

#define NH_FLAG_VALID                       0x000001
#define NH_FLAG_POLICY_ENABLED              0x000002
#define NH_FLAG_ENCAP_L2                    0x000004
#define NH_FLAG_TUNNEL_GRE                  0x000008
#define NH_FLAG_TUNNEL_UDP                  0x000010
/*
 * Mcast flag can be appended to any type of nexthop, either an Encap,
 * composite etc
 */
#define NH_FLAG_MCAST                       0x000020
#define NH_FLAG_TUNNEL_UDP_MPLS             0x000040
#define NH_FLAG_TUNNEL_VXLAN                0x000080
#define NH_FLAG_RELAXED_POLICY              0x000100
#define NH_FLAG_COMPOSITE_FABRIC            0x000200
#define NH_FLAG_COMPOSITE_ECMP              0x000400
#define NH_FLAG_COMPOSITE_L2                0x000800
#define NH_FLAG_COMPOSITE_EVPN              0x001000
#define NH_FLAG_COMPOSITE_ENCAP             0x002000
#define NH_FLAG_COMPOSITE_TOR               0x004000
#define NH_FLAG_ROUTE_LOOKUP                0x008000
#define NH_FLAG_UNKNOWN_UC_FLOOD            0x010000
#define NH_FLAG_TUNNEL_SIP_COPY             0x020000
#define NH_FLAG_FLOW_LOOKUP                 0x040000
#define NH_FLAG_TUNNEL_PBB                  0x080000
#define NH_FLAG_MAC_LEARN                   0x100000
#define NH_FLAG_ETREE_ROOT                  0x200000
#define NH_FLAG_INDIRECT                    0x400000
#define NH_FLAG_L2_CONTROL_DATA             0x800000

#define NH_SOURCE_INVALID                   0
#define NH_SOURCE_VALID                     1
#define NH_SOURCE_MISMATCH                  2


#define NH_ECMP_CONFIG_HASH_BITS            5
#define NH_ECMP_CONFIG_HASH_MASK            ((1 << NH_ECMP_CONFIG_HASH_BITS) - 1)
#define NH_ECMP_CONFIG_HASH_PROTO           0x01
#define NH_ECMP_CONFIG_HASH_SRC_IP          0x02
#define NH_ECMP_CONFIG_HASH_SRC_PORT        0x04
#define NH_ECMP_CONFIG_HASH_DST_IP          0x08
#define NH_ECMP_CONFIG_HASH_DST_PORT        0x10

struct vr_packet;

struct vr_forwarding_md;

struct vr_component_nh {
    int cnh_label;
    int cnh_ecmp_index;
    struct vr_nexthop *cnh;
};

typedef enum {
    NH_PROCESSING_COMPLETE,
    NH_PROCESSING_INCOMPLETE,
} nh_processing_t;

struct vr_nexthop {
    uint8_t         nh_type;
    /*
     * nh_family is going to be AF_INET for L3 nexthops, AF_BRIDGE for L2
     * nexthops
     */
    uint8_t         nh_family;
    uint16_t        nh_data_size;
    uint32_t        nh_flags;
    int             nh_vrf;
    unsigned int    nh_id;
    unsigned int    nh_rid;
    unsigned int    nh_users;
    union {
        struct {
            uint16_t        encap_len;
            uint16_t        encap_family;
        } nh_encap;

        struct {
            unsigned int    tun_sip;
            unsigned int    tun_dip;
            uint16_t        tun_encap_len;
        } nh_gre_tun;

        struct {
            unsigned int    tun_sip;
            unsigned int    tun_dip;
            unsigned short  tun_sport;
            unsigned short  tun_dport;
            uint16_t        tun_encap_len;
        } nh_udp_tun;

        struct {
            int             tun_pbb_label;
            uint8_t         tun_pbb_mac[VR_ETHER_ALEN];
        } nh_pbb_tun;

        struct {
             uint8_t        *tun_sip6;
             uint8_t        *tun_dip6;
             unsigned short tun_sport6;
             unsigned short tun_dport6;
             uint16_t       tun_encap_len;
        } nh_udp_tun6;

        struct {
            unsigned short cnt;
            unsigned short ecmp_cnt;
            unsigned short ecmp_config_hash;
            struct vr_component_nh *component;
            struct vr_component_nh *ecmp_active;
        } nh_composite;

    } nh_u;

    struct vrouter      *nh_router;
    struct vr_nexthop   *nh_direct_nh;
    int                 (*nh_validate_src)(struct vr_packet *,
                                           struct vr_nexthop *,
                                           struct vr_forwarding_md *,
                                           void *);
    nh_processing_t     (*nh_reach_nh)(struct vr_packet *,
                                       struct vr_nexthop *,
                                       struct vr_forwarding_md *);
    struct vr_interface *nh_dev;
    void                (*nh_destructor)(struct vr_nexthop *);
    uint8_t             nh_data[0];
};

#define nh_encap_family         nh_u.nh_encap.encap_family
#define nh_encap_len            nh_u.nh_encap.encap_len

#define nh_gre_tun_sip          nh_u.nh_gre_tun.tun_sip
#define nh_gre_tun_dip          nh_u.nh_gre_tun.tun_dip

#define nh_udp_tun_sip          nh_u.nh_udp_tun.tun_sip
#define nh_udp_tun_dip          nh_u.nh_udp_tun.tun_dip
#define nh_udp_tun_sport        nh_u.nh_udp_tun.tun_sport
#define nh_udp_tun_dport        nh_u.nh_udp_tun.tun_dport
#define nh_udp_tun_encap_len    nh_u.nh_udp_tun.tun_encap_len

#define nh_udp_tun6_sip         nh_u.nh_udp_tun6.tun_sip6
#define nh_udp_tun6_dip         nh_u.nh_udp_tun6.tun_dip6
#define nh_udp_tun6_sport       nh_u.nh_udp_tun6.tun_sport6
#define nh_udp_tun6_dport       nh_u.nh_udp_tun6.tun_dport6
#define nh_udp_tun6_encap_len   nh_u.nh_udp_tun6.tun_encap_len

#define nh_gre_tun_encap_len    nh_u.nh_gre_tun.tun_encap_len

#define nh_component_cnt        nh_u.nh_composite.cnt
#define nh_component_nh         nh_u.nh_composite.component
#define nh_component_ecmp_cnt   nh_u.nh_composite.ecmp_cnt
#define nh_component_ecmp       nh_u.nh_composite.ecmp_active
#define nh_ecmp_config_hash     nh_u.nh_composite.ecmp_config_hash

#define nh_pbb_mac         nh_u.nh_pbb_tun.tun_pbb_mac
#define nh_pbb_label       nh_u.nh_pbb_tun.tun_pbb_label

static inline bool
vr_nexthop_is_vcp(struct vr_nexthop *nh)
{
    if (nh && (nh->nh_type == NH_RESOLVE))
        return true;

    return false;
}

extern int vr_nexthop_init(struct vrouter *);
extern void vr_nexthop_exit(struct vrouter *, bool);
extern struct vr_nexthop *__vrouter_get_nexthop(struct vrouter *, unsigned int);
extern struct vr_nexthop *vrouter_get_nexthop(unsigned int, unsigned int);
extern void vrouter_put_nexthop(struct vr_nexthop *);
extern int vr_ip_rcv(struct vrouter *, struct vr_packet *,
        struct vr_forwarding_md *);
extern int nh_output(struct vr_packet *,
        struct vr_nexthop *, struct vr_forwarding_md *);
extern int vr_nexthop_add(vr_nexthop_req *);
extern int vr_nexthop_get(vr_nexthop_req *);
extern int vr_nexthop_dump(vr_nexthop_req *);
extern bool vr_gateway_nexthop(struct vr_nexthop *);
extern bool vr_hosted_nexthop(struct vr_nexthop *);
extern unsigned int vr_nexthop_req_get_size(void *);

extern struct vr_nexthop *vr_discard_nh;
#ifdef __cplusplus
}
#endif

#endif /* __VNSW_NEXTHOP_H__ */
