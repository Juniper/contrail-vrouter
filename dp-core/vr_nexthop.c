/*
 * vr_nexthop.c -- data path nexthop management
 *
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#include <vr_os.h>
#include "vr_message.h"
#include "vr_sandesh.h"
#include "vr_mcast.h"
#include "vr_bridge.h"

static int nh_discard(unsigned short, struct vr_packet *,
        struct vr_nexthop *, struct vr_forwarding_md *);
extern unsigned int vr_forward(struct vrouter *, unsigned short,
        struct vr_packet *, struct vr_forwarding_md *);
extern void vr_init_forwarding_md(struct vr_forwarding_md *);
struct vr_nexthop *vr_inet_src_lookup(unsigned short, struct vr_ip *, struct vr_packet *);
extern struct vr_vrf_stats *(*vr_inet_vrf_stats)(unsigned short, unsigned int);
struct vr_nexthop *ip4_default_nh;

struct vr_nexthop *
__vrouter_get_nexthop(struct vrouter *router, unsigned int index)
{
    if (!router || index >= router->vr_max_nexthops)
        return NULL;

    return router->vr_nexthops[index];
}

struct vr_nexthop *
vrouter_get_nexthop(unsigned int rid, unsigned int index) 
{
    struct vr_nexthop *nh;
    struct vrouter *router;

    router = vrouter_get(rid);
    nh = __vrouter_get_nexthop(router, index);
    if (nh)
        nh->nh_users++;

    return nh;
}

void
vrouter_put_nexthop(struct vr_nexthop *nh)
{
    int i;

    /* This function might get invoked with zero ref_cnt */
    if (nh->nh_users) {
        nh->nh_users--;
    }

    if (!nh->nh_users ) {
        vr_delay_op();
        /* If composite de-ref the internal nexthops */
        if (nh->nh_type == NH_COMPOSITE) {
            for (i = 0; i < nh->nh_component_cnt; i++) {
                if (nh->nh_component_nh[i].cnh)
                    vrouter_put_nexthop(nh->nh_component_nh[i].cnh);
            }

            vr_free(nh->nh_component_nh);
        }
        if (nh->nh_dev) {
            vrouter_put_interface(nh->nh_dev);
        }
        vr_free(nh);
    }

    return;
}

static int
vrouter_add_nexthop(struct vr_nexthop *nh)
{
    struct vrouter *router = vrouter_get(nh->nh_rid);

    if (!router || nh->nh_id > router->vr_max_nexthops)
        return -EINVAL;

    /*
     * NH change just copies the field
     * over to nexthop, incase of change
     * just return
     */  
    if (router->vr_nexthops[nh->nh_id])
        return 0;
 
    nh->nh_users++;
    router->vr_nexthops[nh->nh_id] = nh;
    return 0;
}

static void
nh_del(struct vr_nexthop *nh)
{
    struct vrouter *router = vrouter_get(nh->nh_rid);
    
    if (!router || nh->nh_id > router->vr_max_nexthops)
        return; 

    if (router->vr_nexthops[nh->nh_id]) {
        router->vr_nexthops[nh->nh_id] = NULL;
    }
    vrouter_put_nexthop(nh);

    return;
}

static int
nh_resolve(unsigned short vrf, struct vr_packet *pkt,
        struct vr_nexthop *nh, struct vr_forwarding_md *fmd)
{
    struct vr_vrf_stats *stats;

    stats = vr_inet_vrf_stats(vrf, pkt->vp_cpu);
    if (stats)
        stats->vrf_resolves++;

    vr_trap(pkt, vrf, AGENT_TRAP_RESOLVE, NULL);
    return 0;
}

static int
nh_vxlan_vrf(unsigned short vrf, struct vr_packet *pkt,
        struct vr_nexthop *nh, struct vr_forwarding_md *fmd)
{
    return vr_bridge_input(nh->nh_router, nh->nh_vrf, pkt, fmd);
}

static int
nh_rcv(unsigned short vrf, struct vr_packet *pkt,
        struct vr_nexthop *nh, struct vr_forwarding_md *fmd)
{
    struct vr_vrf_stats *stats;

    stats = vr_inet_vrf_stats(vrf, pkt->vp_cpu);
    if (stats)
        stats->vrf_receives++;

    if (nh->nh_family == AF_INET)
        return vr_ip_rcv(nh->nh_router, pkt, fmd);
    else
        vr_pfree(pkt, VP_DROP_INVALID_PROTOCOL);

    return 0;
}


static int
nh_push_mpls_header(struct vr_packet *pkt, unsigned int label)
{
    unsigned int *lbl;
    unsigned int ttl;

    lbl = (unsigned int *)pkt_push(pkt, sizeof(unsigned int));
    if (!lbl)
        return -ENOSPC;

    /* Use the ttl from packet. If not ttl, 
     * initialise to some arbitrary value */
    ttl = pkt->vp_ttl;
    if (!ttl) {
        ttl = 64;
    }

    *lbl = htonl((label << VR_MPLS_LABEL_SHIFT) | VR_MPLS_STACK_BIT | ttl);

    return 0;
}

static struct vr_packet *
nh_mcast_clone(struct vr_packet *pkt, unsigned short head_room)
{
    struct vr_packet *clone_pkt;

    /* Clone the packet */
    clone_pkt = vr_pclone(pkt);
    if (!clone_pkt) {
        return NULL;
    }

    /* Increase the head space by the hear_room */
    if (vr_pcow(clone_pkt, head_room)) {
        vr_pfree(clone_pkt, VP_DROP_PCOW_FAIL);
        return NULL;
    }

    /* Copy the ttl from old packet */
    clone_pkt->vp_ttl = pkt->vp_ttl;

    return clone_pkt;
}

static int
nh_composite_ecmp_validate_src(unsigned short vrf, struct vr_packet *pkt,
        struct vr_nexthop *nh, struct vr_forwarding_md *fmd)
{
    int i;
    struct vr_nexthop *cnh;

    /* the first few checks are straight forward */
    if (!fmd || (uint8_t)fmd->fmd_ecmp_src_nh_index >= nh->nh_component_cnt)
        return NH_SOURCE_INVALID;

    cnh = nh->nh_component_nh[fmd->fmd_ecmp_src_nh_index].cnh;
    if (cnh && !cnh->nh_validate_src)
        return NH_SOURCE_INVALID;

    /*
     * when the 'supposed' source goes down, cnh is null, in which
     * case validate the source against other present nexthops. follow
     * the same logic if the component validate source returns invalid
     * source, which could mean that source has moved
     */
    if (!cnh ||
            (NH_SOURCE_INVALID == cnh->nh_validate_src(vrf, pkt, cnh, fmd))) {
        for (i = 0; i < nh->nh_component_cnt; i++) {
            if (i == fmd->fmd_ecmp_src_nh_index)
                continue;

            cnh = nh->nh_component_nh[fmd->fmd_ecmp_src_nh_index].cnh;
            if (!cnh || !cnh->nh_validate_src)
                continue;

            /*
             * if the source has moved to a present and valid source,
             * return mismatch
             */
            if ((NH_SOURCE_VALID == cnh->nh_validate_src(vrf, pkt, cnh, fmd)))
                return NH_SOURCE_MISMATCH;
        }

        /* if everything else fails, source is indeed invalid */
        return NH_SOURCE_INVALID;
    }

    /* source is validated by validate_src */
    return NH_SOURCE_VALID;
}

static int
nh_composite_ecmp(unsigned short vrf, struct vr_packet *pkt,
        struct vr_nexthop *nh, struct vr_forwarding_md *fmd)
{
    int ret = 0;
    struct vr_nexthop *member_nh = NULL;
    struct vr_vrf_stats *stats;

    pkt->vp_type = VP_TYPE_IP;
    stats = vr_inet_vrf_stats(vrf, pkt->vp_cpu);
    if (stats)
        stats->vrf_ecmp_composites++;

    if (!fmd || (uint8_t)fmd->fmd_ecmp_nh_index >= nh->nh_component_cnt)
        goto drop;

    if (fmd->fmd_ecmp_nh_index >= 0)
        member_nh = nh->nh_component_nh[fmd->fmd_ecmp_nh_index].cnh;

    if (!member_nh) {
        vr_trap(pkt, vrf, AGENT_TRAP_ECMP_RESOLVE, &fmd->fmd_flow_index);
        return 0;
    }

    fmd->fmd_label = nh->nh_component_nh[fmd->fmd_ecmp_nh_index].cnh_label;
    return nh_output(vrf, pkt, member_nh, fmd);

drop:
    vr_pfree(pkt, VP_DROP_NO_FMD);
    return ret;
}

/*
 * This function validate the source  of the tunnel incase of L2 or L3
 * multicast
 */

static int
nh_composite_mcast_l3_validate_src(unsigned short vrf, struct vr_packet *pkt,
        struct vr_nexthop *nh, struct vr_forwarding_md *fmd) 
{
    int i;
    struct vr_nexthop *dir_nh;

    for (i = 0; i < nh->nh_component_cnt; i++) {
        dir_nh = nh->nh_component_nh[i].cnh;

        /* Dont forward to same source */
        if (fmd->fmd_outer_src_ip && 
                fmd->fmd_outer_src_ip == dir_nh->nh_gre_tun_dip)
            return NH_SOURCE_VALID;
    }

    return NH_SOURCE_INVALID;
}

static int
nh_composite_mcast_l2(unsigned short vrf, struct vr_packet *pkt,
        struct vr_nexthop *nh, struct vr_forwarding_md *fmd) 
{
    int i;
    struct vr_nexthop *dir_nh;
    unsigned short drop_reason, pkt_vrf;
    struct vr_packet *new_pkt;
    uint32_t *ptr;
    struct vr_vrf_stats *stats;

    stats = vr_inet_vrf_stats(vrf, pkt->vp_cpu);
    if (stats)
        stats->vrf_l2_mcast_composites++;

    drop_reason = VP_DROP_CLONED_ORIGINAL;

    if (!fmd) {
        drop_reason = VP_DROP_NO_FMD;
        goto drop;
    }

    /*
     * If multicast packet is received on fabric interface, we need to
     * validate whether the source of this packet is in the distribution
     * tree. If source is not in the list, packet needs to be dropped.
     * It is assumed that L2 Multicast component's first member is
     * always Fabric nexthop. Nexthop should reorder properly even if
     * Agent adds in different order
     */
    if ((pkt->vp_if->vif_type == VIF_TYPE_PHYSICAL) &&
            nh->nh_validate_src) {
        if (nh->nh_component_cnt && 
             (nh->nh_component_nh[0].cnh->nh_type == NH_COMPOSITE) && 
             (nh->nh_component_nh[0].cnh->nh_flags &
              NH_FLAG_COMPOSITE_FABRIC)) {
            if (nh->nh_validate_src(vrf, pkt,
                        nh->nh_component_nh[0].cnh, fmd) == NH_SOURCE_INVALID) {
                drop_reason = VP_DROP_INVALID_MCAST_SOURCE;
                goto drop;
            }
        }
    }

    /*
     * Packet is always received here with no control information. L2
     * control information needs to be added if we are forwarding only
     * to Fabric. So push control flags in fabric case
     */
    for (i = 0; i < nh->nh_component_cnt; i++) {
        dir_nh = nh->nh_component_nh[i].cnh;

        if (dir_nh->nh_type == NH_ENCAP) {

            /* Dont give back the packet to same VM */
            if (dir_nh->nh_dev == pkt->vp_if)
                continue;

            /* Create the head space for complete L2 header and process the nh */
            if (!(new_pkt = nh_mcast_clone(pkt, VR_MCAST_PKT_HEAD_SPACE))) {
                drop_reason = VP_DROP_MCAST_CLONE_FAIL;
                break;
            }

            pkt_vrf = dir_nh->nh_dev->vif_vrf;
        } else {

            /* Create head space for L2 control information */
            if (!(new_pkt = nh_mcast_clone(pkt, sizeof(uint32_t)))) {
                drop_reason = VP_DROP_MCAST_CLONE_FAIL;
                break;
            }

            /* Add L2 control information */
            ptr = (uint32_t *)pkt_push(new_pkt, sizeof(uint32_t));
            if (!ptr) {
                drop_reason = VP_DROP_PUSH;
                break;
            }
            *ptr = 0;
            pkt_vrf = vrf;
        }

        fmd->fmd_label = nh->nh_component_nh[i].cnh_label;
        nh_output(pkt_vrf, new_pkt, dir_nh, fmd);
    }

    /* Original packet needs to be unconditionally dropped */
drop:
    vr_pfree(pkt, drop_reason);
    return 0;
}


static int
nh_composite_mcast_l3(unsigned short vrf, struct vr_packet *pkt,
        struct vr_nexthop *nh, struct vr_forwarding_md *fmd) 
{
    struct vr_vrf_stats *stats;
    unsigned short drop_reason, pkt_vrf;
    struct vr_nexthop *dir_nh;
    struct vr_packet *new_pkt;
    int i;

    drop_reason = VP_DROP_CLONED_ORIGINAL;
    stats = vr_inet_vrf_stats(vrf, pkt->vp_cpu);
    if (stats)
        stats->vrf_l3_mcast_composites++;

    if (!fmd) {
        drop_reason = VP_DROP_NO_FMD;
        goto drop;
    }

    /*
     * If multicast packet is received on fabric interface, we need to
     * validate whether the source of this packet is in the distribution
     * tree. If source is not in the list, packet needs to be dropped.
     * It is assumed that L3 Multicast component's first member is
     * always Fabric nexthop. Nexthop should reorder properly even if
     * Agent adds in different order
     */
    if ((pkt->vp_if->vif_type == VIF_TYPE_PHYSICAL) && nh->nh_validate_src) {
        if (nh->nh_component_cnt && 
             (nh->nh_component_nh[0].cnh->nh_type == NH_COMPOSITE) && 
             (nh->nh_component_nh[0].cnh->nh_flags &
              NH_FLAG_COMPOSITE_FABRIC)) {
            if (nh->nh_validate_src(vrf, pkt,
                        nh->nh_component_nh[0].cnh, fmd) == NH_SOURCE_INVALID) {
                drop_reason = VP_DROP_INVALID_MCAST_SOURCE;
                goto drop;
            }
        }
    }


    for (i = 0; i < nh->nh_component_cnt; i++) {
        dir_nh = nh->nh_component_nh[i].cnh;
        if (dir_nh->nh_type == NH_ENCAP) {

            /* Dont give back the packet to same VM */
            if (dir_nh->nh_dev == pkt->vp_if) 
                continue;
            /* 
             * Cow the packet as interface nexthop is not going to
             * clone any more
             */
            if (!(new_pkt = nh_mcast_clone(pkt, VR_MCAST_PKT_HEAD_SPACE))) {
                drop_reason = VP_DROP_MCAST_CLONE_FAIL;
                break;
            }

            pkt_vrf = dir_nh->nh_dev->vif_vrf;
        } else {
            /* Just clone the packet as subsequent nexthops would create
             * the required head space */
            new_pkt = vr_pclone(pkt);
            if (!new_pkt) {
                drop_reason = VP_DROP_CLONE_FAIL;
                break;
            }

            pkt_vrf = vrf;
        }

        fmd->fmd_label = nh->nh_component_nh[i].cnh_label;
        nh_output(pkt_vrf, new_pkt, dir_nh, fmd);
    }

    /* Original packet needs to be unconditionally dropped */
drop:
    vr_pfree(pkt, drop_reason);
    return 0;
}

static int
nh_composite_fabric(unsigned short vrf, struct vr_packet *pkt,
        struct vr_nexthop *nh, struct vr_forwarding_md *fmd) 
{
    int i;
    struct vr_vrf_stats *stats;
    struct vr_nexthop *dir_nh;
    unsigned short drop_reason;
    struct vr_packet *new_pkt;

    drop_reason = VP_DROP_CLONED_ORIGINAL;
    stats = vr_inet_vrf_stats(vrf, pkt->vp_cpu);
    if (stats)
        stats->vrf_fabric_composites++;

    if (!fmd) {
        drop_reason = VP_DROP_NO_FMD;
        goto drop;
    }

    /*
     * Packet can be L2 or L3 with or without control information. It is
     * always ensured before coming to this nexthop that packet headers
     * along with control inforation is in first buffer. So it can be
     * safely cow'd for the required length
     */
    for (i = 0; i < nh->nh_component_cnt; i++) {
        dir_nh = nh->nh_component_nh[i].cnh;

        if (dir_nh->nh_type != NH_TUNNEL)
            continue;

        /* Dont forward to same source */
        if (fmd->fmd_outer_src_ip && 
                fmd->fmd_outer_src_ip == dir_nh->nh_gre_tun_dip) 
            continue;

        new_pkt = nh_mcast_clone(pkt, VR_MCAST_PKT_HEAD_SPACE);
        if (!new_pkt) {
            drop_reason = VP_DROP_MCAST_CLONE_FAIL;
            break;
        }

        fmd->fmd_label = nh->nh_component_nh[i].cnh_label;
        nh_output(dir_nh->nh_dev->vif_vrf, new_pkt, dir_nh, fmd);
    }

    /* Original packet needs to be unconditionally dropped */
drop:
    vr_pfree(pkt, drop_reason);
    return 0;
}

static int
nh_composite_multi_proto(unsigned short vrf, struct vr_packet *pkt,
        struct vr_nexthop *nh, struct vr_forwarding_md *fmd) 
{
    uint32_t *ctrl_data;
    unsigned short drop_reason, cp;
    struct vr_vrf_stats *stats;
    unsigned short pkt_type_flag;
    struct vr_ip *ip;
    struct vr_packet *new_pkt;
    int i;

    stats = vr_inet_vrf_stats(vrf, pkt->vp_cpu);
    if (stats)
        stats->vrf_multi_proto_composites++;

    if (!fmd) {
        drop_reason = VP_DROP_NO_FMD;
        goto drop;
    }

    /* Identify whether L2 or L3 packet */
    pkt_type_flag = NH_FLAG_COMPOSITE_L2;
    ctrl_data = (uint32_t *)pkt_data(pkt);
    if (*ctrl_data != 0) {
        pkt_type_flag = NH_FLAG_COMPOSITE_L3;
        pkt->vp_type = VP_TYPE_IP;

       /*
        * We need to pull the inner network and transport
        * headers to new head skb that we are going to add as
        * checksum offload expects the headers to be in head skb
        * The checksum offload would be enabled for multicast
        * only incase of udp, so pull only incase of udp
        */

        ip = (struct vr_ip *)pkt_network_header(pkt);
        if (ip->ip_proto == VR_IP_PROTO_UDP) {

            cp = (ip->ip_hl * 4)  + sizeof(struct vr_udp);
            if (!pkt_pull(pkt, cp)) {
                drop_reason = VP_DROP_PULL;
                goto drop;
            }

            new_pkt = vr_palloc_head(pkt, (cp + sizeof(uint32_t)));
            if (!new_pkt) {
                drop_reason = VP_DROP_HEAD_ALLOC_FAIL;
                goto drop;
            }
            pkt = new_pkt;

            /* Create enough head space */
            if (!pkt_reserve_head_space(pkt, cp)) {
                drop_reason = VP_DROP_HEAD_SPACE_RESERVE_FAIL; 
                goto drop;
            }

            memcpy(pkt_push(pkt, cp), ip, cp);

            /* Mark it as L3 multicast packet */
            pkt->vp_flags |= VP_FLAG_MULTICAST;
        }
    } else {
        /* Pull the control flags */
        pkt->vp_type = VP_TYPE_L2;
        pkt_pull(pkt, sizeof(uint32_t));
    }

    /* 
     * Look for the same nexthop flags and forward to the first nexthop
     */
    for(i = 0; i < nh->nh_component_cnt; i++) {
        if (nh->nh_component_nh[i].cnh->nh_flags & pkt_type_flag) {
            nh_output(vrf, pkt, nh->nh_component_nh[i].cnh, fmd);
            return 0;
        }
    }

    drop_reason = VP_DROP_INVALID_NH;
drop:
    vr_pfree(pkt, drop_reason);
    return 0;
}

static int
nh_discard(unsigned short vrf, struct vr_packet *pkt,
        struct vr_nexthop *nh, struct vr_forwarding_md *fmd)
{
    struct vr_vrf_stats *stats;

    stats = vr_inet_vrf_stats(vrf, pkt->vp_cpu);
    if (stats)
        stats->vrf_discards++;

    vr_pfree(pkt, VP_DROP_DISCARD);
    return 0;
}

/*
 * nh_udp_tunnel_helper - helper function to use for UDP tunneling. Used
 * by mirroring and MPLS over UDP. Returns 0 on success, 1 otherwise.
 */
static int
nh_udp_tunnel_helper(struct vr_packet *pkt, unsigned short sport,
                     unsigned short dport, unsigned int sip, 
                     unsigned int dip) 
{
    struct vr_ip *ip;
    struct vr_udp *udp;

    /* Udp Header */
    udp = (struct vr_udp *)pkt_push(pkt, sizeof(struct vr_udp));
    if (!udp) {
        return 1;
    }

    udp->udp_sport = sport;
    udp->udp_dport = dport;
    udp->udp_length = htons(pkt_len(pkt));
    udp->udp_csum = 0;

    /* And now the IP header */
    ip = (struct vr_ip *)pkt_push(pkt, sizeof(struct vr_ip));
    if (!ip) {
        return 1;
    }

    ip->ip_version = 4;
    ip->ip_hl = 5;
    ip->ip_tos = 0;
    ip->ip_id = htons(vr_generate_unique_ip_id());
    ip->ip_frag_off = 0;
    ip->ip_ttl = 64;
    ip->ip_proto = VR_IP_PROTO_UDP;
    ip->ip_saddr = sip;
    ip->ip_daddr = dip;
    ip->ip_len = htons(pkt_len(pkt));

    /* 
     * header checksum 
     */
    ip->ip_csum = 0;
    ip->ip_csum = vr_ip_csum(ip);    

    pkt_set_network_header(pkt, pkt->vp_data);
    return 0;
}

static int
nh_udp_tunnel(unsigned short vrf, struct vr_packet *pkt,
        struct vr_nexthop *nh, struct vr_forwarding_md *fmd)
{
    struct vr_packet *tmp;
    struct vr_ip *ip;
    struct vr_udp *udp;
    struct vr_vrf_stats *stats;

    if (!fmd)
        goto send_fail;

    if (pkt_head_space(pkt) < VR_UDP_HEAD_SPACE) {
        tmp = vr_palloc_head(pkt, VR_UDP_HEAD_SPACE);
        if (!tmp) 
            goto send_fail;

        pkt = tmp;
        if (!pkt_reserve_head_space(pkt, VR_UDP_HEAD_SPACE)) 
            goto send_fail;
    }

    if (nh_udp_tunnel_helper(pkt, nh->nh_udp_tun_sport,
                             nh->nh_udp_tun_dport, nh->nh_udp_tun_sip,
                             nh->nh_udp_tun_dip)) {
        goto send_fail;
    }

    /* 
     * Incase of mirroring set the inner network header to the newly added 
     * header so that this is fragmented and checksummed
     */
    pkt_set_inner_network_header(pkt, pkt->vp_data);

    /*
     * Calculate the partial checksum for udp header
     */
    ip = (struct vr_ip *)(pkt_data(pkt));
    udp = (struct vr_udp *)((char *)ip + ip->ip_hl * 4);
    udp->udp_csum = vr_ip_partial_csum(ip);

    stats = vr_inet_vrf_stats(vrf, pkt->vp_cpu);
    if (stats)
        stats->vrf_udp_tunnels++;

    vr_forward(vrouter_get(nh->nh_rid), 
               (vrf == (unsigned short)-1) ? fmd->fmd_dvrf : vrf,
               pkt, fmd);

    return 0;

send_fail:
    vr_pfree(pkt, VP_DROP_PUSH);
    return 0;
}

/*
 * nh_vxlan_tunnel - tunnel packet with VXLAN header
 */
static int
nh_vxlan_tunnel(unsigned short vrf, struct vr_packet *pkt, 
                   struct vr_nexthop *nh, struct vr_forwarding_md *fmd)
{
    unsigned char *tun_encap;
    struct vr_interface *vif;
    struct vr_vrf_stats *stats;
    unsigned int head_space;
    struct vr_vxlan *vxlanh;
    __u16 udp_src_port = VR_VXLAN_UDP_SRC_PORT;
    unsigned short reason = VP_DROP_PUSH;
    struct vr_packet *tmp_pkt;

    stats = vr_inet_vrf_stats(vrf, pkt->vp_cpu);
    if (stats)
        stats->vrf_udp_mpls_tunnels++;

    if (!fmd || fmd->fmd_label < 0)
        return vr_forward(nh->nh_router, vrf, pkt, fmd);

    head_space = sizeof(struct vr_ip) + sizeof(struct vr_udp) +
                                sizeof(struct vr_vxlan) +
                                nh->nh_udp_tun_encap_len;

    if (pkt_head_space(pkt) < head_space) {
        tmp_pkt = vr_pexpand_head(pkt, head_space - pkt_head_space(pkt));
        if (!tmp_pkt) {
            goto send_fail;
        }
        pkt = tmp_pkt;
    }

    /* Change the packet type to VXLAN as we added the vxlan header */
    pkt->vp_type = VP_TYPE_VXLAN;
   
    /*
     * The UDP source port is a hash of the inner headers
     */
    if (vr_get_udp_src_port) {
        udp_src_port = vr_get_udp_src_port(pkt, fmd, vrf);
        if (udp_src_port == 0) {
            reason = VP_DROP_PULL;
            goto send_fail;
        }
    }

    /* Add the vxlan header */
    vxlanh = (struct vr_vxlan *)pkt_push(pkt, sizeof(struct vr_vxlan));
    vxlanh->vnid = htonl(fmd->fmd_label << VR_VXLAN_VNID_SHIFT);
    vxlanh->res = 0;

    if (nh_udp_tunnel_helper(pkt, htons(udp_src_port), 
                             htons(VR_VXLAN_UDP_DST_PORT),
                             nh->nh_udp_tun_sip, nh->nh_udp_tun_dip)) {
        goto send_fail;
    }

    /* slap l2 header */
    vif = nh->nh_dev;
    tun_encap = vif->vif_set_rewrite(vif, pkt, nh->nh_data, 
                                     nh->nh_udp_tun_encap_len);
    if (!tun_encap) {
        goto send_fail;
    }

    vif->vif_tx(vif, pkt);

    return 0;

send_fail:

    vr_pfree(pkt, reason);
    return 0;

}

static int
nh_mpls_udp_tunnel_validate_src(unsigned short vrf, struct vr_packet *pkt,
        struct vr_nexthop *nh, struct vr_forwarding_md *fmd)
{
    if (fmd->fmd_outer_src_ip == nh->nh_udp_tun_dip)
        return NH_SOURCE_VALID;

    return NH_SOURCE_INVALID;
}


/*
 * nh_mpls_udp_tunnel - tunnel packet with MPLS label in UDP.
 */
static int
nh_mpls_udp_tunnel(unsigned short vrf, struct vr_packet *pkt, 
                   struct vr_nexthop *nh, struct vr_forwarding_md *fmd)
{
    unsigned char *tun_encap;
    struct vr_interface *vif;
    struct vr_vrf_stats *stats;
    unsigned int tun_sip, tun_dip, udp_head_space;
    __u16 tun_encap_len, udp_src_port = VR_MPLS_OVER_UDP_SRC_PORT; 
    unsigned short reason = VP_DROP_PUSH;
    struct vr_packet *tmp_pkt;

    /*
     * If we are testing MPLS over UDP using the vr_mudp sysctl, use the
     * values from the GRE tunnel nexthop below. Otherwise, use the values
     * from the UDP tunnel nexthop.
     */
    if (vr_mudp) {
        tun_sip = nh->nh_gre_tun_sip;
        tun_dip = nh->nh_gre_tun_dip;
        tun_encap_len = nh->nh_gre_tun_encap_len;
    } else {
        tun_sip = nh->nh_udp_tun_sip;
        tun_dip = nh->nh_udp_tun_dip;
        tun_encap_len = nh->nh_udp_tun_encap_len;
    }    

    stats = vr_inet_vrf_stats(vrf, pkt->vp_cpu);
    if (stats)
        stats->vrf_udp_mpls_tunnels++;

    if (!fmd || fmd->fmd_label < 0)
        return vr_forward(nh->nh_router, vrf, pkt, fmd);

    /*
     * The UDP source port is a hash of the inner IP src/dst address and vrf 
     */
    if (vr_get_udp_src_port) {
        udp_src_port = vr_get_udp_src_port(pkt, fmd, vrf);
        if (udp_src_port == 0) {
            reason = VP_DROP_PULL;
            goto send_fail;
        }
    }

    if (nh_push_mpls_header(pkt, fmd->fmd_label) < 0)
        goto send_fail;

    if (vr_perfs)
        pkt->vp_flags |= VP_FLAG_GSO;
   
    udp_head_space = sizeof(struct vr_ip) + sizeof(struct vr_udp);
    udp_head_space += tun_encap_len;

    if (pkt_head_space(pkt) < udp_head_space) {
        tmp_pkt = vr_pexpand_head(pkt, udp_head_space - pkt_head_space(pkt));
        if (!tmp_pkt) 
            goto send_fail;

        pkt = tmp_pkt;
    }
   
    /*
     * Change the packet type
     */
    if (pkt->vp_type == VP_TYPE_L2)
        pkt->vp_type = VP_TYPE_L2OIP;
    else 
        pkt->vp_type = VP_TYPE_IPOIP;

    if (nh_udp_tunnel_helper(pkt, htons(udp_src_port), 
                             htons(VR_MPLS_OVER_UDP_DST_PORT),
                             tun_sip, tun_dip)) {
        goto send_fail;
    }

    /* slap l2 header */
    vif = nh->nh_dev;
    tun_encap = vif->vif_set_rewrite(vif, pkt, nh->nh_data, 
                                     tun_encap_len);
    if (!tun_encap) {
        goto send_fail;
    }

    vif->vif_tx(vif, pkt);

    return 0;

send_fail:

    vr_pfree(pkt, reason);
    return 0;

}

static int
nh_gre_tunnel_validate_src(unsigned short vrf, struct vr_packet *pkt,
        struct vr_nexthop *nh, struct vr_forwarding_md *fmd)
{
    if (fmd->fmd_outer_src_ip == nh->nh_gre_tun_dip)
        return NH_SOURCE_VALID;

    return NH_SOURCE_INVALID;
}

static int
nh_gre_tunnel(unsigned short vrf, struct vr_packet *pkt,
        struct vr_nexthop *nh, struct vr_forwarding_md *fmd)
{
    unsigned int id;
    int gre_head_space;
    unsigned short drop_reason = VP_DROP_INVALID_NH;
    struct vr_gre *gre_hdr;
    struct vr_ip *ip;
    unsigned char *tun_encap;
    struct vr_interface *vif;
    struct vr_vrf_stats *stats;
    struct vr_packet *tmp_pkt;

    if (vr_mudp && vr_perfs) {
        return nh_mpls_udp_tunnel(vrf, pkt, nh, fmd);
    }

    stats = vr_inet_vrf_stats(vrf, pkt->vp_cpu);
    if (stats)
        stats->vrf_gre_mpls_tunnels++;

    /*
     * When the packet encounters a tunnel nexthop with policy enabled,
     * the forwarding metadata (and hence the label filled up by vr_forward)
     * is lost as packets are queued in the flow entry. Note also the fact
     * that nh_output sets pkt->vp_nh to the looked up NH. So, once the
     * flow queue is flushed, we will not do vr_forward again and hence we
     * will not have label information. For those packets, we need to do
     * vr_forward again. One practical example of where this can happen is
     * when ECMP source initiates traffic to a target in a remote (not in
     * the same) server. vr_forward->tunnel_nh->nh_output sets pkt->vp_nh
     * (source is ECMP)->pass through flow lookup->
     */ 
    if (!fmd || fmd->fmd_label < 0)
        return vr_forward(nh->nh_router, vrf, pkt, fmd);


    if (vr_perfs)
        pkt->vp_flags |= VP_FLAG_GSO;

    ip = (struct vr_ip *)pkt_network_header(pkt);
    id = ip->ip_id;

    gre_head_space = VR_MPLS_HDR_LEN + sizeof(struct vr_ip) + sizeof(struct vr_gre);
    gre_head_space += nh->nh_gre_tun_encap_len;

    if (pkt_head_space(pkt) < gre_head_space) {
        tmp_pkt = vr_pexpand_head(pkt, gre_head_space - pkt_head_space(pkt));
        if (!tmp_pkt) {
            drop_reason = VP_DROP_HEAD_ALLOC_FAIL;
            goto send_fail;
        }
        pkt = tmp_pkt;
    }

    if (nh_push_mpls_header(pkt, fmd->fmd_label) < 0)
        goto send_fail;

    gre_hdr = (struct vr_gre *)pkt_push(pkt, sizeof(struct vr_gre));
    if (!gre_hdr) {
        drop_reason = VP_DROP_PUSH;
        goto send_fail;
    }

    gre_hdr->gre_flags = 0;
    gre_hdr->gre_proto = VR_GRE_PROTO_MPLS_NO;

    ip = (struct vr_ip *)pkt_push(pkt, sizeof(struct vr_ip));
    if (!ip) {
        drop_reason = VP_DROP_PUSH;
        goto send_fail;
    }
    pkt_set_network_header(pkt, pkt->vp_data);
    if (pkt->vp_type == VP_TYPE_L2)
        pkt->vp_type = VP_TYPE_L2OIP;
    else 
        pkt->vp_type = VP_TYPE_IPOIP;

    ip->ip_version = 4;
    ip->ip_hl = 5;
    ip->ip_tos = 0;
    ip->ip_id = id;
    ip->ip_frag_off = 0;
    ip->ip_ttl = 64;
    ip->ip_proto = VR_IP_PROTO_GRE;
    ip->ip_saddr = nh->nh_gre_tun_sip;
    ip->ip_daddr = nh->nh_gre_tun_dip;
    ip->ip_len = htons(pkt_len(pkt));
    /* checksum will be calculated in linux_xmit_segment */

    /* slap l2 header */
    vif = nh->nh_dev;
    tun_encap = vif->vif_set_rewrite(vif, pkt, nh->nh_data,
            nh->nh_gre_tun_encap_len);
    if (!tun_encap) {
        drop_reason = VP_DROP_PUSH;
        goto send_fail;
    }
    vif->vif_tx(vif, pkt);
    return 0;

send_fail:
    vr_pfree(pkt, drop_reason);
    return 0;
}


int
nh_output(unsigned short vrf, struct vr_packet *pkt,
        struct vr_nexthop *nh, struct vr_forwarding_md *fmd)
{
    struct vr_nexthop *src_nh = NULL;
    struct vr_ip *ip;
    bool need_flow_lookup = false;

    pkt->vp_nh = nh;

    if (pkt->vp_type == VP_TYPE_IP) {
        /*
         * If the packet has not gone through flow lookup once
         * (!VP_FLAG_FLOW_SET), we need to determine whether it has to undergo
         * flow lookup now or not. There are two cases:
         *
         * 1. when policy flag is set in the nexthop, and
         * 2. when the source is an ECMP.
         * 
         * When the source is an ECMP, we would like the packet to reach the
         * same place from where it came from, and hence a flow has to be setup
         * so that DP knows where to send the packet to (from an ECMP NH).
         * Typical example for this situation is when the packet reaches the
         * target VM's server from an ECMP-ed service chain.
         */
        if (!(pkt->vp_flags & VP_FLAG_FLOW_SET)) {
            if (nh->nh_flags & NH_FLAG_POLICY_ENABLED) {
                need_flow_lookup = true;
            } else {
                ip = (struct vr_ip *)pkt_network_header(pkt);
                src_nh = vr_inet_src_lookup(vrf, ip, pkt);
                if (src_nh && src_nh->nh_type == NH_COMPOSITE &&
                        src_nh->nh_flags & NH_FLAG_COMPOSITE_ECMP) {
                    need_flow_lookup = true;
                }
            }

            if (need_flow_lookup) {
                pkt->vp_flags |= VP_FLAG_FLOW_GET;
                return vr_flow_inet_input(nh->nh_router, vrf,
                        pkt, VR_ETH_PROTO_IP, fmd);
            }
        }
    }

    return nh->nh_reach_nh(vrf, pkt, nh, fmd);
}

static int
nh_encap_mcast(unsigned short vrf, struct vr_packet *pkt,
        struct vr_nexthop *nh, struct vr_forwarding_md *md)
{
    struct vr_interface *vif;
    struct vr_ip *ip;
    unsigned int dip;
    unsigned char *mptr;    
    struct vr_vrf_stats *stats;

    stats = vr_inet_vrf_stats(vrf, pkt->vp_cpu);
    if (stats)
        stats->vrf_encaps++;

    vif = nh->nh_dev;
    if (!vif->vif_set_rewrite(vif, pkt, nh->nh_data,
            nh->nh_encap_len)) {
        vr_pfree(pkt, VP_DROP_REWRITE_FAIL);
        return 0;
    }

    /* 
     * The dmac of L2 rewrite information contains 0xFFFFFFFF. If L3 multicast
     *  we need to compute L2 multicast and slap it. If not, keep the same
     */
    ip = (struct vr_ip *)pkt_network_header(pkt);
    dip = ntohl(ip->ip_daddr);
    if ((dip & MCAST_IP_MASK) == MCAST_IP) {
        /* Multicast address */
        mptr = pkt_data(pkt);
        mptr[0] = 0x01;
        mptr[1] = 0;
        mptr[2] = 0x5e;
        mptr[3] = (unsigned char )(((dip & 0x00FF0000) >> 16) & 0X7F);
        mptr[4] = (unsigned char )(((dip & 0x0000FF00) >> 8) & 0X7F);
        mptr[5] = (unsigned char )(dip & 0x000000FF); 
    }
   
    pkt->vp_flags &= ~VP_FLAG_GRO;
    vif->vif_tx(vif, pkt);

    return 0;
}

static int
nh_encap_l2_unicast(unsigned short vrf, struct vr_packet *pkt, 
        struct vr_nexthop *nh, struct vr_forwarding_md *md)
{
    struct vr_interface *vif;
    struct vr_vrf_stats *stats;

    stats = vr_inet_vrf_stats(vrf, pkt->vp_cpu);
    if (stats)
        stats->vrf_l2_encaps++;

    /*
     * Mark the packet as L2 and make it inelgible for GRO
     */
    pkt->vp_flags &= ~VP_FLAG_GRO;
    pkt->vp_type = VP_TYPE_L2;

    vif = nh->nh_dev;
    vif->vif_tx(vif, pkt);

    return 0;
}

static int
nh_encap_l3_validate_src(unsigned short vrf, struct vr_packet *pkt,
        struct vr_nexthop *nh, struct vr_forwarding_md *fmd)
{
    if (pkt->vp_if == nh->nh_dev)
        return NH_SOURCE_VALID;

    return NH_SOURCE_INVALID;
}

static int
nh_encap_l3_unicast(unsigned short vrf, struct vr_packet *pkt,
        struct vr_nexthop *nh, struct vr_forwarding_md *md)
{
    struct vr_interface *vif;
    struct vr_vrf_stats *stats;
    struct vr_ip *ip;

    stats = vr_inet_vrf_stats(vrf, pkt->vp_cpu);
    if (stats)
        stats->vrf_encaps++;

    vif = nh->nh_dev;
    pkt->vp_type = VP_TYPE_IP;
    ip = (struct vr_ip *)pkt_network_header(pkt);
    if (ip->ip_csum == VR_DIAG_IP_CSUM) {
        pkt->vp_flags &= ~VP_FLAG_GRO;
    }

    /*
     * For packets being sent up a tap interface, retain the MPLS label
     * if we are attempting GRO. We will need the label later to figure
     * out which interface to send the packet to.
     */
    if ((pkt->vp_flags & VP_FLAG_GRO) &&
                 (vif->vif_type == VIF_TYPE_VIRTUAL)) {
        /*
         * ECMP case. When we send the packet up for GRO, the label typically
         * points to the composite nexthop. When the packet lands back in DP,
         * there is no flow information, and hence there is no way to get back
         * ECMP NH index without doing a flow lookup again. To workaround that
         * issue, overwrite the label with the component (unicast) nexthop's
         * label, which is passed in forwarding metadata. The below if comes
         * into play (as of now) only in that case.
         */
        if (md && md->fmd_label >= 0) {
            if (nh_push_mpls_header(pkt, md->fmd_label) < 0) {
                vr_pfree(pkt, VP_DROP_PUSH);
                return 0;
            }
            pkt_pull(pkt, VR_MPLS_HDR_LEN);
        }
    } else {
        if (!vif->vif_set_rewrite(vif, pkt, nh->nh_data,
                nh->nh_encap_len)) {
            vr_pfree(pkt, VP_DROP_REWRITE_FAIL);
            return 0;
        }
    }

    /*
     * Look if this is the Diag packet to trap to agent
     */
    if (ip->ip_csum == VR_DIAG_IP_CSUM) {
        pkt->vp_if = vif;
        vr_pset_data(pkt, pkt->vp_data);
        return vr_trap(pkt, vrf, AGENT_TRAP_DIAG, &vif->vif_idx);
    }

    vif->vif_tx(vif, pkt);

    return 0;
}

static int
vr_nexthop_delete(vr_nexthop_req *req)
{
    struct vr_nexthop *nh;
    int ret = 0;

    nh = vrouter_get_nexthop(req->nhr_rid, req->nhr_id);
    if (!nh) {
        ret = -EINVAL;
    } else {
        vrouter_put_nexthop(nh);
        nh->nh_destructor(nh);
    }

    ret = vr_send_response(ret);

    return ret;
}


static int
nh_resolve_add(struct vr_nexthop *nh, vr_nexthop_req *req)
{
    nh->nh_reach_nh = nh_resolve;
    return 0;
}

static int
nh_rcv_add(struct vr_nexthop *nh, vr_nexthop_req *req)
{
    nh->nh_dev = vrouter_get_interface(nh->nh_rid, req->nhr_encap_oif_id);
    if (!nh->nh_dev)
        return -ENODEV;

    nh->nh_reach_nh = nh_rcv;
    return 0;
}

static int
nh_vxlan_vrf_add(struct vr_nexthop *nh, vr_nexthop_req *req)
{
    nh->nh_reach_nh = nh_vxlan_vrf;
    return 0;
}

static int 
nh_composite_add(struct vr_nexthop *nh, vr_nexthop_req *req)
{
    unsigned int i;
    struct vr_nexthop *tmp_nh;

    nh->nh_validate_src = NULL;
    /* Delete the old nexthops first */
    if (nh->nh_component_cnt && nh->nh_component_nh) {
        for (i = 0; i < nh->nh_component_cnt; i++) {
            if (nh->nh_component_nh[i].cnh)
                vrouter_put_nexthop(nh->nh_component_nh[i].cnh);
        }
        vr_free(nh->nh_component_nh);
        nh->nh_component_nh = NULL;
        nh->nh_component_cnt = 0;
    }

    if ((req->nhr_nh_list_size < 0) || (req->nhr_nh_list_size != req->nhr_label_list_size))
        return -EINVAL;

    /* Nh list of size 0 is valid */
    if (req->nhr_nh_list_size == 0)
        return 0;

    nh->nh_component_nh = vr_zalloc(req->nhr_nh_list_size *
            sizeof(struct vr_component_nh)); 
    if (!nh->nh_component_nh) {
        return -ENOMEM;
    }

    for (i = 0; i < req->nhr_nh_list_size; i++) {
        nh->nh_component_nh[i].cnh = vrouter_get_nexthop(req->nhr_rid, req->nhr_nh_list[i]);
        nh->nh_component_nh[i].cnh_label = req->nhr_label_list[i];
    }
    nh->nh_component_cnt = req->nhr_nh_list_size;

    /*
     * Some requirements if nexthop is multicast. If Multiproto, first
     * subnexthop should be L2 and next should be L3. If L2 or L3 first
     * nexthop should be Fabric and subsequent should interface nexthops
     */

    if ((req->nhr_flags & NH_FLAG_MCAST) && 
           (req->nhr_flags & (NH_FLAG_COMPOSITE_L3 | NH_FLAG_COMPOSITE_L2))) {
        tmp_nh = nh->nh_component_nh[0].cnh;

        /* If first nh is not fabric nh */
        if ((tmp_nh->nh_type != NH_COMPOSITE) ||
                (!(tmp_nh->nh_flags & NH_FLAG_COMPOSITE_FABRIC))) {

            for (i = 1; i < nh->nh_component_cnt; i++) {
                if ((nh->nh_component_nh[i].cnh->nh_type == NH_COMPOSITE) && 
                    (nh->nh_component_nh[i].cnh->nh_flags & 
                                    NH_FLAG_COMPOSITE_FABRIC)) {
                    /* Swap the fabric nh with first nh */
                    nh->nh_component_nh[0].cnh = nh->nh_component_nh[i].cnh;
                    nh->nh_component_nh[0].cnh_label =
                            nh->nh_component_nh[i].cnh_label;
                    nh->nh_component_nh[i].cnh = tmp_nh;
                    nh->nh_component_nh[i].cnh_label = req->nhr_label_list[0];
                    break;
                }
            }
        }
    }

    /* This needs to be the last */
    if ((req->nhr_flags & NH_FLAG_COMPOSITE_L3) && 
            (req->nhr_flags & NH_FLAG_MCAST)) {
        nh->nh_reach_nh = nh_composite_mcast_l3;
        nh->nh_validate_src = nh_composite_mcast_l3_validate_src;
    } else if ((req->nhr_flags & NH_FLAG_COMPOSITE_L2) && 
            (req->nhr_flags & NH_FLAG_MCAST)) {
        nh->nh_reach_nh = nh_composite_mcast_l2;
        nh->nh_validate_src = nh_composite_mcast_l3_validate_src;
    } else if (req->nhr_flags & NH_FLAG_COMPOSITE_ECMP) {
        nh->nh_reach_nh = nh_composite_ecmp;
        nh->nh_validate_src = nh_composite_ecmp_validate_src;
    } else if (req->nhr_flags & NH_FLAG_COMPOSITE_FABRIC) {
        nh->nh_reach_nh = nh_composite_fabric;
    } else if (req->nhr_flags & NH_FLAG_COMPOSITE_MULTI_PROTO) {
        nh->nh_reach_nh = nh_composite_multi_proto;
    }
    return 0;
}

static int
nh_tunnel_add(struct vr_nexthop *nh, vr_nexthop_req *req)
{
    if (!req->nhr_tun_sip || !req->nhr_tun_dip)
        return -EINVAL;

    nh->nh_dev = vrouter_get_interface(nh->nh_rid, req->nhr_encap_oif_id);

    if (nh->nh_flags & NH_FLAG_TUNNEL_GRE) {
        if (!nh->nh_dev)
            return -ENODEV;
        nh->nh_gre_tun_sip = req->nhr_tun_sip;
        nh->nh_gre_tun_dip = req->nhr_tun_dip;
        nh->nh_gre_tun_encap_len = req->nhr_encap_size;
        nh->nh_reach_nh = nh_gre_tunnel;
        nh->nh_validate_src = nh_gre_tunnel_validate_src;
    } else if (nh->nh_flags & NH_FLAG_TUNNEL_UDP) {
        nh->nh_udp_tun_sip = req->nhr_tun_sip;
        nh->nh_udp_tun_dip = req->nhr_tun_dip;
        nh->nh_udp_tun_sport = req->nhr_tun_sport;
        nh->nh_udp_tun_dport = req->nhr_tun_dport;
        nh->nh_udp_tun_encap_len = req->nhr_encap_size;
        nh->nh_reach_nh = nh_udp_tunnel;
    } else if (nh->nh_flags & NH_FLAG_TUNNEL_UDP_MPLS) {
        nh->nh_udp_tun_sip = req->nhr_tun_sip;
        nh->nh_udp_tun_dip = req->nhr_tun_dip;
        nh->nh_udp_tun_encap_len = req->nhr_encap_size;
        nh->nh_reach_nh = nh_mpls_udp_tunnel;
        nh->nh_validate_src = nh_mpls_udp_tunnel_validate_src;
    } else if (nh->nh_flags & NH_FLAG_TUNNEL_VXLAN) {
        nh->nh_udp_tun_sip = req->nhr_tun_sip;
        nh->nh_udp_tun_dip = req->nhr_tun_dip;
        nh->nh_udp_tun_encap_len = req->nhr_encap_size;
        nh->nh_reach_nh = nh_vxlan_tunnel;
    } else {
        return -EINVAL;
    }

    memcpy(nh->nh_data, req->nhr_encap, req->nhr_encap_size);

    return 0;
}


static int
nh_encap_add(struct vr_nexthop *nh, vr_nexthop_req *req)
{
    nh->nh_dev = vrouter_get_interface(nh->nh_rid, req->nhr_encap_oif_id);
    if (!nh->nh_dev) {
        return -ENODEV;
    }

    if (req->nhr_flags & NH_FLAG_ENCAP_L2) {
         nh->nh_reach_nh = nh_encap_l2_unicast;
    } else {
        nh->nh_encap_family = req->nhr_encap_family;
        nh->nh_encap_len = req->nhr_encap_size;
        memcpy(nh->nh_data, req->nhr_encap, nh->nh_encap_len);

        if (req->nhr_flags & NH_FLAG_MCAST) {
            nh->nh_reach_nh = nh_encap_mcast;
        } else {
            nh->nh_reach_nh = nh_encap_l3_unicast;
            nh->nh_validate_src = nh_encap_l3_validate_src;
        }
    }

    return 0;
}

static int
nh_discard_add(struct vr_nexthop *nh, vr_nexthop_req *req)
{
    if (nh->nh_id != NH_DISCARD_ID) {
        return -EINVAL;
    }
    nh->nh_family = req->nhr_family;
    nh->nh_type = NH_DISCARD;
    nh->nh_router = vrouter_get(0);
    nh->nh_reach_nh = nh_discard;
    ip4_default_nh = nh;
    return 0;
}

static bool
vr_nexthop_valid_request(vr_nexthop_req *req)
{
    struct vrouter *router = vrouter_get(req->nhr_rid);

    if (!router)
        return false;

    if ((unsigned int)req->nhr_id >= router->vr_max_nexthops)
        return false;

    if ((unsigned int)req->nhr_type >= NH_MAX)
        return false;

    return true;
}

static int
vr_nexthop_size(vr_nexthop_req *req)
{
    unsigned int size = sizeof(struct vr_nexthop);

    if ((((req->nhr_type == NH_ENCAP) && (!(req->nhr_flags &
               NH_FLAG_ENCAP_L2))) || (req->nhr_type == NH_TUNNEL))) {
        if (!req->nhr_encap_size || req->nhr_encap == NULL) 
            return -EINVAL;
        size += req->nhr_encap_size;
    }

    return size;
}

static bool
vr_nexthop_valid_change(vr_nexthop_req *req, struct vr_nexthop *nh)
{
    if (!(req->nhr_flags & NH_FLAG_VALID))
        return true;

    if (req->nhr_type != nh->nh_type)
        return false;

    if (req->nhr_encap_size &&
            req->nhr_encap_size != nh->nh_data_size)
        return false;

    return true;
}

int
vr_nexthop_add(vr_nexthop_req *req)
{
    int ret = 0, len = 0;
    struct vr_nexthop *nh;
    struct vrouter *router = vrouter_get(req->nhr_rid);

    if (!vr_nexthop_valid_request(req) && (ret = -EINVAL))
        goto generate_resp;

    nh = __vrouter_get_nexthop(router, req->nhr_id);
    if (!nh) {
        ret = vr_nexthop_size(req);
        if (ret < 0)
            goto generate_resp;

        len = ret;
        nh = vr_zalloc(len);
        if (!nh) {
            ret = -ENOMEM;
            goto generate_resp;
        }

        nh->nh_data_size = len - sizeof(struct vr_nexthop);
    } else {
        /* 
         * If modification of old_nh change the action to discard and ensure
         * everybody sees that
         */
        if (!vr_nexthop_valid_change(req, nh)) {
            ret = -EINVAL;
            goto generate_resp;
        }

        nh->nh_reach_nh = nh_discard;
        vr_delay_op();
    }

    nh->nh_destructor = nh_del;
    nh->nh_type = req->nhr_type;
    nh->nh_family = req->nhr_family;
    nh->nh_id = req->nhr_id;
    nh->nh_rid = req->nhr_rid;
    nh->nh_router = vrouter_get(nh->nh_rid);
    nh->nh_flags = req->nhr_flags;
    nh->nh_vrf = req->nhr_vrf;
    /* 
     * By default point it to discard. Individual NH 
     * Handling will point to right nh processing
     */
    nh->nh_reach_nh = nh_discard;

    if (nh->nh_flags & NH_FLAG_VALID) {
        switch (nh->nh_type) {
        case NH_ENCAP:
            ret = nh_encap_add(nh, req);
            break;

        case NH_TUNNEL:
            ret = nh_tunnel_add(nh, req);
            break;

        case NH_RCV:
            ret = nh_rcv_add(nh, req);
            break;

        case NH_RESOLVE:
            ret = nh_resolve_add(nh, req);
            break;

        case NH_DISCARD:
            ret = nh_discard_add(nh, req);
            break;

        case NH_COMPOSITE:
            ret = nh_composite_add(nh, req);
            break;

        case NH_VXLAN_VRF:
            ret = nh_vxlan_vrf_add(nh, req);
            break;

        default:
            ret = -EINVAL;
        }

        if (ret) {
            if (nh->nh_destructor)
                nh->nh_destructor(nh);

            goto generate_resp;
        }
    }


    ret = vrouter_add_nexthop(nh);
    if (ret)
        nh->nh_destructor(nh);

generate_resp:
    ret = vr_send_response(ret);

    return ret;
}

/* we expect the caller to bzero req, before sending it here */
static int
vr_nexthop_make_req(vr_nexthop_req *req, struct vr_nexthop *nh)
{
    unsigned char *encap = NULL;
    unsigned int i;

    req->nhr_type = nh->nh_type;
    req->nhr_family = nh->nh_family;
    req->nhr_flags = nh->nh_flags;
    req->nhr_id = nh->nh_id;
    req->nhr_rid = nh->nh_rid;
    req->nhr_ref_cnt = nh->nh_users;
    req->nhr_nh_list_size = 0;
    req->nhr_vrf = nh->nh_vrf;

    switch (nh->nh_type) {
    case NH_RCV:
        if (nh->nh_dev)
            req->nhr_encap_oif_id = nh->nh_dev->vif_idx;
        break;

    case NH_ENCAP:
        if (nh->nh_dev)
            req->nhr_encap_oif_id = nh->nh_dev->vif_idx;

        req->nhr_encap_size = nh->nh_encap_len;
        req->nhr_encap_family = nh->nh_encap_family;
        if (req->nhr_encap_size)
            encap = nh->nh_data;
        break;

    case NH_COMPOSITE:
        req->nhr_nh_list_size = nh->nh_component_cnt;
        if (nh->nh_component_cnt) {
            req->nhr_nh_list = vr_zalloc(req->nhr_nh_list_size * sizeof(unsigned int));
            if (!req->nhr_nh_list)
                return -ENOMEM;

            req->nhr_label_list_size = nh->nh_component_cnt;
            req->nhr_label_list = vr_zalloc(req->nhr_nh_list_size * sizeof(unsigned int));
            /* don't bother about freeing. we will free it in req_destroy */
            if (!req->nhr_label_list)
                return -ENOMEM;

            for (i = 0; i < req->nhr_nh_list_size; i++) {
                if (nh->nh_component_nh[i].cnh)
                    req->nhr_nh_list[i] = nh->nh_component_nh[i].cnh->nh_id;
                else
                    req->nhr_nh_list[i] = -1;

                req->nhr_label_list[i] = nh->nh_component_nh[i].cnh_label;
            }
        }

        break;

    case NH_TUNNEL:
        req->nhr_encap_family = nh->nh_encap_family;
        if (nh->nh_flags & NH_FLAG_TUNNEL_GRE) {
            req->nhr_tun_sip = nh->nh_gre_tun_sip;
            req->nhr_tun_dip = nh->nh_gre_tun_dip;
            req->nhr_encap_size = nh->nh_gre_tun_encap_len;
            if (req->nhr_encap_size)
                encap = nh->nh_data;
            if (nh->nh_dev)
                req->nhr_encap_oif_id = nh->nh_dev->vif_idx;
        } else if (nh->nh_flags & NH_FLAG_TUNNEL_UDP) {
            req->nhr_tun_sip = nh->nh_udp_tun_sip;
            req->nhr_tun_dip = nh->nh_udp_tun_dip;
            req->nhr_encap_size = nh->nh_udp_tun_encap_len;
            req->nhr_tun_sport = nh->nh_udp_tun_sport;
            req->nhr_tun_dport = nh->nh_udp_tun_dport;
            if (req->nhr_encap_size)
                encap = nh->nh_data;
            if (nh->nh_dev)
                req->nhr_encap_oif_id = nh->nh_dev->vif_idx;
        } else if (nh->nh_flags & NH_FLAG_TUNNEL_UDP_MPLS) {
            req->nhr_tun_sip = nh->nh_udp_tun_sip;
            req->nhr_tun_dip = nh->nh_udp_tun_dip;
            req->nhr_encap_size = nh->nh_udp_tun_encap_len;
            if (req->nhr_encap_size)
                encap = nh->nh_data;
            if (nh->nh_dev)
                req->nhr_encap_oif_id = nh->nh_dev->vif_idx;
        } else if (nh->nh_flags & NH_FLAG_TUNNEL_VXLAN) {
            req->nhr_tun_sip = nh->nh_udp_tun_sip;
            req->nhr_tun_dip = nh->nh_udp_tun_dip;
            req->nhr_encap_size = nh->nh_udp_tun_encap_len;
            if (req->nhr_encap_size)
                encap = nh->nh_data;
            if (nh->nh_dev)
                req->nhr_encap_oif_id = nh->nh_dev->vif_idx;
        }

        break;
    }

    if (req->nhr_encap_size) {
        req->nhr_encap = vr_zalloc(req->nhr_encap_size);
        if (req->nhr_encap) {
            memcpy(req->nhr_encap, encap,
                    req->nhr_encap_size);
        } else {
            req->nhr_encap_size = 0;
            return -ENOMEM;
        }
    }

    return 0;
}

static vr_nexthop_req *
vr_nexthop_req_get(void)
{
    return vr_zalloc(sizeof(vr_nexthop_req));
}

static void
vr_nexthop_req_destroy(vr_nexthop_req *req)
{
    if (!req)
        return;

    if (req->nhr_encap_size && req->nhr_encap) {
        vr_free(req->nhr_encap);
        req->nhr_encap_size = 0;
        req->nhr_encap = NULL;
    }

    if (req->nhr_nh_list_size && req->nhr_nh_list) {
        vr_free(req->nhr_nh_list);
        req->nhr_nh_list_size = 0;
        req->nhr_nh_list = NULL;
    }

    if (req->nhr_label_list_size && req->nhr_label_list) {
        vr_free(req->nhr_label_list);
        req->nhr_label_list = NULL;
        req->nhr_label_list_size = 0;
    }

    vr_free(req);
    return;
}

int
vr_nexthop_get(vr_nexthop_req *req)
{
    int ret = 0;
    struct vr_nexthop *nh = NULL;
    struct vrouter *router;
    vr_nexthop_req *resp = NULL;

    router = vrouter_get(req->nhr_rid);
    if (!router || (unsigned int)req->nhr_id >= router->vr_max_nexthops) {
        ret = -ENODEV;
        goto generate_response;
    } 

    nh = __vrouter_get_nexthop(router, req->nhr_id);
    if (nh) {
        resp = vr_nexthop_req_get();
        if (resp)
            ret = vr_nexthop_make_req(resp, nh);
        else
            ret = -ENOMEM;
    } else
        ret = -ENOENT;

generate_response:
    vr_message_response(VR_NEXTHOP_OBJECT_ID, ret < 0 ? NULL : resp, ret);
    if (resp)
        vr_nexthop_req_destroy(resp);

    return 0;
}

int
vr_nexthop_dump(vr_nexthop_req *r)
{
    int ret = 0;
    unsigned int i;
    vr_nexthop_req *resp = NULL;
    struct vr_message_dumper *dumper = NULL;
    struct vr_nexthop *nh;
    struct vrouter *router = vrouter_get(0);

    if (!router && (ret = -ENODEV))
        goto generate_response;

    if ((unsigned int)(r->nhr_marker) + 1 >= router->vr_max_nexthops)
        goto generate_response;

    dumper = vr_message_dump_init(r);
    if (!dumper && (ret = -ENOMEM))
        goto generate_response;

    for (i = (unsigned int)(r->nhr_marker + 1);
            i < router->vr_max_nexthops; i++) {
        nh = router->vr_nexthops[i];
        if (nh) {
            resp = vr_nexthop_req_get();
            if (!resp && (ret = -ENOMEM))
                goto generate_response;

           ret = vr_nexthop_make_req(resp, nh);
           if (ret || ((ret = vr_message_dump_object(dumper,
                           VR_NEXTHOP_OBJECT_ID, resp)) <= 0)) {
               vr_nexthop_req_destroy(resp);
               if (ret <= 0) 
                   break;
           }

           vr_nexthop_req_destroy(resp);
        }
    }

generate_response:
    vr_message_dump_exit(dumper, ret);
    return 0;
}

/*
 * called by sandesh_process based on type of the request
 */
void
vr_nexthop_req_process(void *s_req)
{
    int ret;
    vr_nexthop_req *req = (vr_nexthop_req *)s_req;

    switch (req->h_op) {
    case SANDESH_OP_ADD:
        ret = vr_nexthop_add(req);
        break;

    case SANDESH_OP_GET:
        ret = vr_nexthop_get(req);
        break;

    case SANDESH_OP_DELETE:
        ret = vr_nexthop_delete(req);
        break;

    case SANDESH_OP_DUMP:
        ret = vr_nexthop_dump(req);
        break;

    default:
        ret = -EOPNOTSUPP;
        vr_send_response(ret);
        break;
    }
}


static void
nh_table_exit(struct vrouter *router, bool soft_reset)
{
    unsigned int i;
    struct vr_nexthop **vnt;

    vnt = router->vr_nexthops;
    if (!vnt)
        return;

    for (i = 0; i < router->vr_max_nexthops; i++) {
        if (vnt[i]) {
            if (soft_reset && i == NH_DISCARD_ID)
                continue;

            vnt[i]->nh_destructor(vnt[i]);
        }
    }


    if (soft_reset == false) {
        router->vr_nexthops = NULL;
        /* Make the default nh point to NULL */
        ip4_default_nh = NULL;
        vr_free(vnt);
        router->vr_max_nexthops = 0;
    }

    return;
}

static int
nh_allocate_discard(void)
{
    ip4_default_nh = vr_zalloc(sizeof(struct vr_nexthop));
    if (!ip4_default_nh)
        return -ENOMEM;

    ip4_default_nh->nh_id = NH_DISCARD_ID;
    ip4_default_nh->nh_type = NH_DISCARD;
    ip4_default_nh->nh_router = vrouter_get(0);
    ip4_default_nh->nh_reach_nh = nh_discard;
    ip4_default_nh->nh_destructor = nh_del;
    ip4_default_nh->nh_flags = NH_FLAG_VALID;
    ip4_default_nh->nh_family = AF_INET;

    return vrouter_add_nexthop(ip4_default_nh);
}

static int
nh_table_init(struct vrouter *router)
{
    int ret;
    unsigned int table_memory;

    if (!router->vr_max_nexthops) {
        router->vr_max_nexthops = NH_TABLE_ENTRIES;
        table_memory = router->vr_max_nexthops * sizeof(struct vr_nexthop *);
        router->vr_nexthops = vr_zalloc(table_memory);
        if (!router->vr_nexthops)
            return vr_module_error(-ENOMEM, __FUNCTION__,
                    __LINE__, table_memory);
    }

    if (!ip4_default_nh) {
        ret = nh_allocate_discard();
        if (ret) {
            vr_module_error(ret, __FUNCTION__, __LINE__, 0);
            goto init_fail;
        }
    }

    return 0;

init_fail:
    if (router->vr_nexthops)
        vr_free(router->vr_nexthops);

    router->vr_max_nexthops = 0;
    router->vr_nexthops = NULL;

    return ret;
}

void
vr_nexthop_exit(struct vrouter *router, bool soft_reset)
{
    nh_table_exit(router, soft_reset);
    return;
}

int
vr_nexthop_init(struct vrouter *router)
{
    return nh_table_init(router);
}
