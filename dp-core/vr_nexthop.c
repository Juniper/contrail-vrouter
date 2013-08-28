/*
 * vr_nexthop.c -- data path nexthop management
 *
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#include <vr_os.h>
#include "vr_message.h"
#include "vr_sandesh.h"
#include "vr_mcast.h"

static int nh_discard(unsigned short, struct vr_packet *,
        struct vr_nexthop *, struct vr_forwarding_md *);
extern unsigned int vr_forward(struct vrouter *, unsigned short,
        struct vr_packet *, struct vr_forwarding_md *);
extern void vr_init_forwarding_md(struct vr_forwarding_md *);
struct vr_nexthop *vr_inet_src_lookup(unsigned short, struct vr_ip *, struct vr_packet *);
extern struct vr_vrf_stats *(*vr_inet_vrf_stats)(unsigned short, unsigned int);
struct vr_nexthop *ip4_default_nh;

static struct vr_nexthop *
__vrouter_get_nexthop(unsigned int rid, unsigned int index)
{
    struct vrouter *router = vrouter_get(rid);

    if (!router || index >= router->vr_max_nexthops)
        return NULL;

    return router->vr_nexthops[index];
}

struct vr_nexthop *
vrouter_get_nexthop(unsigned int rid, unsigned int index) 
{
    struct vr_nexthop *nh;

    nh = __vrouter_get_nexthop(rid, index);
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
        vrouter_put_nexthop(nh);
    }

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
nh_mcast_clone(struct vr_packet *pkt, int cp, void *ip)
{
    struct vr_packet *clone_pkt, *new_pkt;

    /* Clone the packet */
    clone_pkt = vr_pclone(pkt);
    if (!clone_pkt) {
        return NULL;
    }

    if (cp) {

        /* If we have some thing to pull 
         * make a new head packet and pull into that 
         */
        new_pkt = vr_palloc_head(clone_pkt, (VR_MCAST_PKT_HEAD_SPACE + cp));
        if (!new_pkt) {
            vr_pfree(clone_pkt, VP_DROP_HEAD_ALLOC_FAIL);
            return NULL;
        }

        /* Create enough head space */
        if (!pkt_reserve_head_space(new_pkt, (VR_MCAST_PKT_HEAD_SPACE + cp))) {
            vr_pfree(new_pkt, VP_DROP_HEAD_SPACE_RESERVE_FAIL);
            return NULL;
        }

        /* We have new network headers now */
        memcpy(pkt_push(new_pkt, cp), ip, cp);
        pkt_set_network_header(new_pkt, new_pkt->vp_data);
        pkt_set_inner_network_header(new_pkt, new_pkt->vp_data);
    } else {

        /* There is nothing to copy, expand the existing buffer */
        if (vr_pcow(clone_pkt, VR_MCAST_PKT_HEAD_SPACE)) {
            vr_pfree(clone_pkt, VP_DROP_PCOW_FAIL);
            return NULL;
        }
        new_pkt = clone_pkt;
    }


    /* Copy the ttl from old packet */
    new_pkt->vp_ttl = pkt->vp_ttl;

    return new_pkt;
}

static int
nh_composite_ecmp(unsigned short vrf, struct vr_packet *pkt,
        struct vr_nexthop *nh, struct vr_forwarding_md *fmd)
{
    int ret = 0;
    struct vr_nexthop *member_nh = NULL;
    struct vr_vrf_stats *stats;

    stats = vr_inet_vrf_stats(vrf, pkt->vp_cpu);
    if (stats)
        stats->vrf_composites++;

    if (!fmd || fmd->fmd_ecmp_nh_index >= nh->nh_component_cnt)
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
    vr_pfree(pkt, VP_DROP_INVALID_NH);
    return ret;
}



static int
nh_composite_flood(unsigned short vrf, struct vr_packet *pkt,
        struct vr_nexthop *nh, struct vr_forwarding_md *fmd)
{
    struct vr_vrf_stats *stats;

    stats = vr_inet_vrf_stats(vrf, pkt->vp_cpu);
    if (stats)
        stats->vrf_composites++;

    vr_pfree(pkt, VP_DROP_FLOOD);
    return 0;
}

/*
 * Packet handling differs depnding on ingress interface of the packet:
 * 1) Virtual interface: Packets enter the VR with all headers in SKB
 * and data in frags[]. This can have GSO enabled. For the segmentation 
 * to happen, we need to have the content in single SKB and frags. So mcast
 * headers are added by expanding the existing SKB using skb_cow(). 
 * 2) Physical interface: Packet likely stays in a single skb without making
 * use of frags[]. As we will not take advantage of GSO for these packets, 
 * we use palloc_head() to add multicast headers to avoid skb_cow() which 
 * results in the complete packet getting copied. This would be fine as long 
 * as the packet is not getting fragmented. When the support for multiple
 * physical interface is added, fragmentation might get kicked in, in that
 * case we need to use skb_cow().
 */

static int
nh_composite_multicast(unsigned short vrf, struct vr_packet *pkt,
        struct vr_nexthop *nh, struct vr_forwarding_md *fmd) 
{
    int i, cp;
    unsigned short drop_reason = VP_DROP_INVALID_NH;
    struct vr_nexthop *dir_nh;
    struct vr_packet *new_pkt;
    struct vr_ip *ip, *inner_ip;
    struct vr_vrf_stats *stats;
    struct vr_forwarding_md c_fmd;

    stats = vr_inet_vrf_stats(vrf, pkt->vp_cpu);
    if (stats)
        stats->vrf_composites++;
   
    new_pkt = NULL;
    inner_ip = NULL;
    cp = 0;

    if (!fmd) {
        vr_init_forwarding_md(&c_fmd);
        fmd = &c_fmd;
    }

    switch (pkt->vp_if->vif_type) {
    case VIF_TYPE_VIRTUAL:

        for (i = 0; i < nh->nh_component_cnt; i++) {
            dir_nh = nh->nh_component_nh[i].cnh;
            /* Dont give back the packet to same VM */
            if ((dir_nh->nh_type == NH_ENCAP) && 
                        (dir_nh->nh_dev == pkt->vp_if)) {
                continue;
            }

            if (!(new_pkt = nh_mcast_clone(pkt, 0, NULL))) {
                drop_reason = VP_DROP_MCAST_CLONE_FAIL;
                break;
            }

            fmd->fmd_label = nh->nh_component_nh[i].cnh_label;
            nh_output(dir_nh->nh_dev->vif_vrf, new_pkt, dir_nh, fmd);
        }
        break;

    case VIF_TYPE_PHYSICAL:
        /* Get the outer IP header from network header offset*/
        ip = (struct vr_ip *)pkt_network_header(pkt);

        inner_ip = (struct vr_ip *)pkt_data(pkt);
        pkt_set_network_header(pkt, pkt->vp_data);

        /*
         * We need to pull the inner network and transport
         * headers to new head skb that we are going to add as
         * checksum offload expects the headers to be in head skb
         * The checksum offload would be enabled for multicast
         * only incase of udp, so pull only incase of udp
         */
        if (inner_ip->ip_proto == VR_IP_PROTO_UDP) {
            cp = (inner_ip->ip_hl * 4)  + sizeof(struct vr_udp);
            if (!pkt_pull(pkt, cp)) {
                drop_reason = VP_DROP_PULL;
                break;
            }
        }

        for (i = 0; i < nh->nh_component_cnt; i++) {
            dir_nh = nh->nh_component_nh[i].cnh;

            /* Dont forward to same source */
            if ((dir_nh->nh_type == NH_TUNNEL) && 
                   ((dir_nh->nh_flags & NH_FLAG_TUNNEL_GRE))) {
                if (ip->ip_saddr == dir_nh->nh_gre_tun_dip) 
                    continue;
            }

            if (!(new_pkt = nh_mcast_clone(pkt, cp, inner_ip))) {
                drop_reason = VP_DROP_MCAST_CLONE_FAIL;
                break;
            }
                    
            fmd->fmd_label = nh->nh_component_nh[i].cnh_label;
            nh_output(dir_nh->nh_dev->vif_vrf, new_pkt, dir_nh, fmd);
        }
        break;

    case VIF_TYPE_AGENT:

        for (i = 0; i < nh->nh_component_cnt; i++) {
            dir_nh = nh->nh_component_nh[i].cnh;

            /* Send the packet only to encap nexthops */
            if (dir_nh->nh_type == NH_ENCAP) {
                if (!(new_pkt = nh_mcast_clone(pkt, 0, NULL))) {
                    drop_reason = VP_DROP_MCAST_CLONE_FAIL;
                    break;
                }
                nh_output(dir_nh->nh_dev->vif_vrf, new_pkt, dir_nh, fmd);
            }

        }
        break;

    default:
        break;
    }

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

    vr_pfree(pkt,VP_DROP_DISCARD);
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
     *
     * FIXME - this may not be needed if this is a GSO packet as 
     * linux_xmit_segment will calculate the checksum.
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
     * Incase of mirroring set the innert network header to the newly added 
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
        stats->vrf_tunnels++;

    vr_forward(vrouter_get(nh->nh_rid), 
               (vrf == (unsigned short)-1) ? fmd->fmd_dvrf : vrf,
               pkt, fmd);

    return 0;

send_fail:
    vr_pfree(pkt, VP_DROP_PUSH);
    return 0;
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
        stats->vrf_tunnels++;

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
        pkt = vr_pexpand_head(pkt, udp_head_space - pkt_head_space(pkt));
        if (!pkt) {
            goto send_fail;
        }
    }
   
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

    if (vr_mudp && vr_perfs) {
        return nh_mpls_udp_tunnel(vrf, pkt, nh, fmd);
    }

    stats = vr_inet_vrf_stats(vrf, pkt->vp_cpu);
    if (stats)
        stats->vrf_tunnels++;

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

    if (nh_push_mpls_header(pkt, fmd->fmd_label) < 0)
        goto send_fail;

    if (vr_perfs)
        pkt->vp_flags |= VP_FLAG_GSO;

    ip = (struct vr_ip *)pkt_network_header(pkt);
    id = ip->ip_id;

    gre_head_space = sizeof(struct vr_ip) + sizeof(struct vr_gre);
    gre_head_space += nh->nh_gre_tun_encap_len;

    if (pkt_head_space(pkt) < gre_head_space) {
        pkt = vr_pexpand_head(pkt, gre_head_space - pkt_head_space(pkt));
        if (!pkt) {
            drop_reason = VP_DROP_HEAD_ALLOC_FAIL;
            goto send_fail;
        }
    }

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
    
    vif->vif_tx(vif, pkt);

    return 0;
}

static int
nh_encap_unicast(unsigned short vrf, struct vr_packet *pkt,
        struct vr_nexthop *nh, struct vr_forwarding_md *md)
{
    struct vr_interface *vif;
    struct vr_vrf_stats *stats;

    stats = vr_inet_vrf_stats(vrf, pkt->vp_cpu);
    if (stats)
        stats->vrf_encaps++;

    vif = nh->nh_dev;

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

    if (pkt->vp_flags & VP_FLAG_DIAG) {
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
nh_composite_add(struct vr_nexthop *nh, vr_nexthop_req *req)
{
    unsigned int i;

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

    if (req->nhr_nh_list_size <= 0) {
        return 0;
    }

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
    /* This needs to be the last */
    if (req->nhr_flags & NH_FLAG_COMPOSITE_MCAST) {
        nh->nh_reach_nh = nh_composite_multicast;
    } else if (req->nhr_flags & NH_FLAG_COMPOSITE_ECMP) {
        nh->nh_reach_nh = nh_composite_ecmp;
    } else {
        nh->nh_reach_nh = nh_composite_flood;
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

    nh->nh_encap_family = req->nhr_encap_family;
    nh->nh_encap_len = req->nhr_encap_size;

    memcpy(nh->nh_data, req->nhr_encap, nh->nh_encap_len);
    if (req->nhr_flags & NH_FLAG_ENCAP_MCAST) {
        nh->nh_reach_nh = nh_encap_mcast;
    } else {
        nh->nh_reach_nh = nh_encap_unicast;
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

    if (req->nhr_type == NH_ENCAP || req->nhr_type == NH_TUNNEL) {
        if (!req->nhr_encap_size || req->nhr_encap == NULL) 
            return -EINVAL;
        size += req->nhr_encap_size;
    }

    return size;
}

int
vr_nexthop_add(vr_nexthop_req *req)
{
    int ret = 0, len = 0;
    struct vr_nexthop *nh;

    if (!vr_nexthop_valid_request(req) && (ret = -EINVAL))
        goto generate_resp;

    nh = __vrouter_get_nexthop(req->nhr_rid, req->nhr_id);
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
    } else {
        /* 
         * If modification of old_nh change the action to discard and ensure
         * everybody sees that
         */
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

    nh = __vrouter_get_nexthop(req->nhr_rid, req->nhr_id);
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
