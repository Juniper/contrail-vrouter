/*
 * nexthop.h --
 *
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#ifndef __NEXTHOP_H__
#define __NEXTHOP_H__

#ifdef __cplusplus
extern "C" {
#endif

/*
 * nexthop id is also part of the flow key and is only 16 bits. Hence, you
 * know where you are getting into if you want to increase this limit
 */
#define NH_TABLE_ENTRIES                65536
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
    NH_MAX,
};

#define NH_VXLAN_VRF                        NH_VRF_TRANSLATE

#define NH_FLAG_VALID                       0x00001
#define NH_FLAG_POLICY_ENABLED              0x00002
#define NH_FLAG_ENCAP_L2                    0x00004
#define NH_FLAG_TUNNEL_GRE                  0x00008
#define NH_FLAG_TUNNEL_UDP                  0x00010
/*
 * Mcast flag can be appended to any type of nexthop, either an Encap,
 * composite etc
 */
#define NH_FLAG_MCAST                       0x00020
#define NH_FLAG_TUNNEL_UDP_MPLS             0x00040
#define NH_FLAG_TUNNEL_VXLAN                0x00080
#define NH_FLAG_RELAXED_POLICY              0x00100
#define NH_FLAG_COMPOSITE_FABRIC            0x00200
#define NH_FLAG_COMPOSITE_ECMP              0x00400
#define NH_FLAG_COMPOSITE_L2                0x00800
#define NH_FLAG_COMPOSITE_EVPN              0x01000
#define NH_FLAG_COMPOSITE_ENCAP             0x02000
#define NH_FLAG_COMPOSITE_TOR               0x04000

#define NH_SOURCE_INVALID                   0
#define NH_SOURCE_VALID                     1
#define NH_SOURCE_MISMATCH                  2

struct vr_packet;

struct vr_forwarding_md;

struct vr_component_nh {
    int cnh_label;
    struct vr_nexthop *cnh;
};

struct vr_nexthop {
    uint8_t         nh_type;
    /*
     * nh_family is going to be AF_INET for L3 nexthops, AF_BRIDGE for L2
     * nexthops
     */
    uint8_t         nh_family;
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
            unsigned short cnt;
            struct vr_component_nh *component;
         } nh_composite;

    } nh_u;

    uint16_t            nh_data_size;
    struct vrouter      *nh_router;
    int                 (*nh_validate_src)(unsigned short,
                                           struct vr_packet *,
                                           struct vr_nexthop *,
                                           struct vr_forwarding_md *,
                                           void *);
    int                 (*nh_reach_nh)(unsigned short, 
                                       struct vr_packet *,
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
#define nh_gre_tun_encap_len    nh_u.nh_gre_tun.tun_encap_len
#define nh_udp_tun_encap_len    nh_u.nh_udp_tun.tun_encap_len
#define nh_component_cnt        nh_u.nh_composite.cnt
#define nh_component_nh         nh_u.nh_composite.component

extern int vr_nexthop_init(struct vrouter *);
extern void vr_nexthop_exit(struct vrouter *, bool);
extern struct vr_nexthop *__vrouter_get_nexthop(struct vrouter *, unsigned int);
extern struct vr_nexthop *vrouter_get_nexthop(unsigned int, unsigned int);
extern void vrouter_put_nexthop(struct vr_nexthop *);
extern int vr_ip_rcv(struct vrouter *, struct vr_packet *,
        struct vr_forwarding_md *);
extern int nh_output(unsigned short, struct vr_packet *,
        struct vr_nexthop *, struct vr_forwarding_md *);
extern int vr_nexthop_add(vr_nexthop_req *);
extern int vr_nexthop_get(vr_nexthop_req *);
extern int vr_nexthop_dump(vr_nexthop_req *);

extern struct vr_nexthop *vr_discard_nh;

extern struct vr_nexthop *vr_discard_nh;

#ifdef __cplusplus
}
#endif

#endif /* __VNSW_NEXTHOP_H__ */
