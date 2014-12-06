/*
 * vr_route.h --
 *
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#ifndef __VR_ROUTE_H__
#define __VR_ROUTE_H__

#ifdef __cplusplus
extern "C" {
#endif

#define VR_NUM_ROUTES_PER_DUMP  20
#define VR_MAX_VRFS             4096

#define METADATA_IP_SUBNET      0xA9FE0000 /* link local subnet (169.254.0.0/16) */
#define METADATA_IP_MASK        (0xFFFF << 16)

#define IS_LINK_LOCAL_IP(ip) \
    ((ntohl(ip) & METADATA_IP_MASK) == METADATA_IP_SUBNET)

#define RT_IP_ADDR_SIZE(family) \
    ((family == AF_INET6)?16:4)

struct vrouter;
struct rtable_fspec;

struct vr_route_req {
    vr_route_req        rtr_req;
    struct vr_nexthop   *rtr_nh;
};

struct vr_vrf_stats {
    uint64_t vrf_discards;
    uint64_t vrf_resolves;
    uint64_t vrf_receives;
    uint64_t vrf_ecmp_composites;
    uint64_t vrf_encap_composites;
    uint64_t vrf_evpn_composites;
    uint64_t vrf_l3_mcast_composites;
    uint64_t vrf_l2_mcast_composites;
    uint64_t vrf_fabric_composites;
    uint64_t vrf_multi_proto_composites;
    uint64_t vrf_udp_tunnels;
    uint64_t vrf_udp_mpls_tunnels;
    uint64_t vrf_gre_mpls_tunnels;
    uint64_t vrf_l2_encaps;
    uint64_t vrf_encaps;
    uint64_t vrf_gros;
    uint64_t vrf_diags;
};

struct vr_route {
    unsigned int        rt_vrf_id;
    unsigned int        rt_family;
    /* radix tree node */
    unsigned int        rt_prefix;         /* network byte order */
    int                 rt_prefix_len;
    unsigned int        rt_label;
    unsigned int        rt_nh_id;
    /* the result of lookup is better served by a nexthop pointer */
    struct vn_nexthop   *rt_nh;
};

struct vr_rtable {
    int (*algo_add)(struct vr_rtable *, struct vr_route_req *);
    int (*algo_del)(struct vr_rtable *, struct vr_route_req *);
    struct vr_nexthop *(*algo_lookup)(unsigned int, struct vr_route_req *,
            struct vr_packet *);
    int (*algo_get)(unsigned int, struct vr_route_req *);
    int (*algo_dump)(struct vr_rtable *, struct vr_route_req *);
    struct vr_vrf_stats *(*algo_stats)(unsigned short, unsigned int);
    int (*algo_stats_get)(vr_vrf_stats_req *, vr_vrf_stats_req *);
    int (*algo_stats_dump)(struct vr_rtable *, vr_vrf_stats_req *);
    unsigned int algo_max_vrfs;
    void *algo_data;
    struct vr_vrf_stats **vrf_stats;
};

typedef int (*algo_init_decl)(struct vr_rtable *, struct rtable_fspec *);
typedef void (*algo_deinit_decl)(struct vr_rtable *, struct rtable_fspec *, bool);

struct rtable_fspec {
    unsigned int rtb_family;
    unsigned int rtb_max_vrfs;
    int (*rtb_family_init)(struct rtable_fspec *, struct vrouter *);
    void (*rtb_family_deinit)(struct rtable_fspec *, struct vrouter *, bool);

    int (*route_add)(struct rtable_fspec *, struct vr_route_req *);
    int (*route_del)(struct rtable_fspec *, struct vr_route_req *);
    int (*route_dump)(struct rtable_fspec *, struct vr_route_req *);

    algo_init_decl algo_init;
    algo_deinit_decl algo_deinit;
};

extern int vr_fib_init(struct vrouter *);
extern void vr_fib_exit(struct vrouter *, bool);
extern int vr_route_add(vr_route_req *);
extern struct vr_nexthop *(*vr_inet_route_lookup)(unsigned int,
               struct vr_route_req *, struct vr_packet *);


#ifdef __cplusplus
}
#endif

#endif /* __VR_ROUTE_H__ */
