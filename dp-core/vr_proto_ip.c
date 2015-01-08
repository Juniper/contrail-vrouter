/*
 * vr_proto_ip.c -- IP protocol handling
 *
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#include <vr_os.h>
#include <vr_types.h>
#include <vr_packet.h>

#include "vr_datapath.h"
#include "vr_mpls.h"
#include "vr_vxlan.h"
#include "vr_ip_mtrie.h"
#include "vr_fragment.h"

static unsigned short vr_ip_id;

unsigned short
vr_generate_unique_ip_id()
{
    vr_ip_id++;
    if (!vr_ip_id)
        vr_ip_id++;

    return vr_ip_id;
}

struct vr_nexthop *
vr_inet_src_lookup(unsigned short vrf, struct vr_ip *ip, struct vr_packet *pkt)
{
    struct vr_route_req rt;
    struct vr_nexthop *nh;
    struct vr_ip6 *ip6;
    uint32_t rt_prefix[4];

    if (!ip || !pkt) 
        return NULL;

    rt.rtr_req.rtr_vrf_id = vrf;
    if (pkt->vp_type == VP_TYPE_IP) {
        rt.rtr_req.rtr_prefix = (uint8_t*)&rt_prefix;
        *(uint32_t*)rt.rtr_req.rtr_prefix = (ip->ip_saddr);
        rt.rtr_req.rtr_prefix_size = 4;
        rt.rtr_req.rtr_prefix_len = IP4_PREFIX_LEN;
        rt.rtr_req.rtr_family = AF_INET;
    } else if (pkt->vp_type == VP_TYPE_IP6) {
        ip6 = (struct vr_ip6 *)pkt_data(pkt);
        rt.rtr_req.rtr_prefix = (uint8_t*)&rt_prefix;
        memcpy(rt.rtr_req.rtr_prefix, ip6->ip6_src, 16);
        rt.rtr_req.rtr_prefix_size = 16;
        rt.rtr_req.rtr_prefix_len = IP6_PREFIX_LEN;
        rt.rtr_req.rtr_family = AF_INET6;
    }
    rt.rtr_req.rtr_marker_size = 0;
    rt.rtr_req.rtr_nh_id = 0;

    nh = vr_inet_route_lookup(vrf, &rt);

    return nh;
}

static inline unsigned char
vr_ip_decrement_ttl(struct vr_ip *ip)
{
    unsigned int diff = 0xfffe;
    unsigned int csum;

    csum = (~ip->ip_csum) & 0xffff;
    csum += diff;
    csum = (csum >> 16) + (csum & 0xffff);
    if (csum >> 16)
        csum = (csum & 0xffff) + 1;

    --ip->ip_ttl;
    ip->ip_csum = ~(csum & 0xffff);

    return ip->ip_ttl;
}

void
vr_ip_update_csum(struct vr_packet *pkt, unsigned int ip_inc, unsigned int inc)
{
    struct vr_ip *ip;
    struct vr_tcp *tcp;
    struct vr_udp *udp;
    unsigned int csum;
    unsigned short *csump;

    ip = (struct vr_ip *)pkt_network_header(pkt);
    ip->ip_csum = vr_ip_csum(ip);

    if (ip->ip_proto == VR_IP_PROTO_TCP) {
        tcp = (struct vr_tcp *)((unsigned char *)ip + ip->ip_hl * 4);
        csump = &tcp->tcp_csum;
    } else if (ip->ip_proto == VR_IP_PROTO_UDP) {
        udp = (struct vr_udp *)((unsigned char *)ip + ip->ip_hl * 4);
        csump = &udp->udp_csum;
    } else {
        return;
    }

    if (vr_ip_transport_header_valid(ip)) {
        /*
         * for partial checksums, the actual value is stored rather
         * than the complement
         */
        if (pkt->vp_flags & VP_FLAG_CSUM_PARTIAL) {
            csum = (*csump) & 0xffff;
            inc = ip_inc; 
        } else {
            csum = ~(*csump) & 0xffff;
        }

        csum += inc;
        if (csum < inc)
            csum += 1;

        csum = (csum & 0xffff) + (csum >> 16);
        if (csum >> 16)
            csum = (csum & 0xffff) + 1;

        if (pkt->vp_flags & VP_FLAG_CSUM_PARTIAL) {
            *csump = csum & 0xffff;
        } else {
            *csump = ~(csum) & 0xffff;
        }
    }

    return;
}

unsigned short
vr_ip_csum(struct vr_ip *ip)
{
    int sum = 0;
    unsigned short *ptr = (unsigned short *)ip;
    unsigned short answer = 0;
    unsigned short *w = ptr;
    int len = ip->ip_hl * 4;
    int nleft = len;

    ip->ip_csum = 0;

    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    /* mop up an odd byte, if necessary */
    if (nleft == 1) {
        *(unsigned char *)(&answer) = *(unsigned char *)w;
        sum += answer;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    answer = ~sum;

    return answer;
}

unsigned short
vr_ip_partial_csum(struct vr_ip *ip)
{
    unsigned long long s;
    unsigned int sum;
    unsigned short csum, proto;

    proto = ip->ip_proto;
    s = ip->ip_saddr;
    s += ip->ip_daddr;
    s += htons(ntohs(ip->ip_len) - (ip->ip_hl * 4));
    s += htons(proto);

    s = (s & 0xFFFFFFFF) + (s >> 32);
    sum = (s & 0xFFFF) + (s >> 16);
    csum = (sum & 0xFFFF) + (sum >> 16);
    return csum;
}

int
vr_forward(struct vrouter *router, struct vr_packet *pkt,
           struct vr_forwarding_md *fmd)
{
    struct vr_route_req rt;
    struct vr_nexthop *nh;
    struct vr_ip *ip;
    struct vr_ip6 *ip6, *outer_ip6;
    struct vr_icmp *icmph;
    struct vr_forwarding_md rt_fmd;
    struct vr_interface *vif;
    int family, status, encap_len = 0;
    unsigned char ttl;
    short plen;
    uint32_t rt_prefix[4];

    ip6 = NULL;
    ip = (struct vr_ip *)pkt_data(pkt);
    if (vr_ip_is_ip6(ip)) {
        family = AF_INET6;
        ip6 = (struct vr_ip6 *)pkt_data(pkt);
        /* ttl = --ip6->ip6_hlim */
        ttl = ip6->ip6_hlim;
        pkt->vp_type = VP_TYPE_IP6;
    } else {
        family = AF_INET;
        if (!ip->ip_ttl) {
            vr_pfree(pkt, VP_DROP_TTL_EXCEEDED);
            return 0;
        }

        ttl = vr_ip_decrement_ttl(ip);
        pkt->vp_type = VP_TYPE_IP;
    }
 
    pkt->vp_ttl = ttl;

    rt.rtr_req.rtr_vrf_id = fmd->fmd_dvrf;
    rt.rtr_req.rtr_family = family;
    if (family == AF_INET) {
        rt.rtr_req.rtr_prefix = (uint8_t*)&rt_prefix;
        *(uint32_t*)rt.rtr_req.rtr_prefix = (ip->ip_daddr);
        rt.rtr_req.rtr_prefix_size = 4;
        rt.rtr_req.rtr_prefix_len = IP4_PREFIX_LEN;
    } else {
        rt.rtr_req.rtr_prefix = (uint8_t*)&rt_prefix;
        rt.rtr_req.rtr_prefix_size = 16;
        memcpy(rt.rtr_req.rtr_prefix, ip6->ip6_dst, 16);
        rt.rtr_req.rtr_prefix_len = IP6_PREFIX_LEN;
    }
    rt.rtr_req.rtr_nh_id = 0;
    rt.rtr_req.rtr_marker_size = 0;

    nh = vr_inet_route_lookup(fmd->fmd_dvrf, &rt);
    if (rt.rtr_req.rtr_label_flags & VR_RT_LABEL_VALID_FLAG) {
        if (!fmd) {
            vr_init_forwarding_md(&rt_fmd);
            fmd = &rt_fmd;
        }
        fmd->fmd_label = rt.rtr_req.rtr_label;
    } 
    
    vif = nh->nh_dev;

    if (vif) {
        if (vif->vif_type == VIF_TYPE_PHYSICAL) {
            encap_len = sizeof(struct vr_eth) + sizeof(struct vr_ip)+ sizeof(struct vr_udp) +sizeof(unsigned int);
        }
            
       if (family == AF_INET) {
           if ((ip->ip_frag_off & VR_IP_DF) &&
               (vif->vif_mtu < (sizeof(struct vr_ip)+ip->ip_len+encap_len))) {
           }
       } else if (family == AF_INET6) {
           plen = ntohs(ip6->ip6_plen);
           /* Handle PMTU for inet6 */
           if (vif->vif_mtu < (sizeof(struct vr_ip6)+plen+encap_len)) {
               /*Send ICMP too big message */
               if (pkt->vp_data < (sizeof(struct vr_ip6) + sizeof(struct vr_icmp))) {
                   /* Not enough head room to add ip6/icmpv6 headers*/
                   vr_pfree(pkt, VP_DROP_PUSH);
                   return 0;
               }
               icmph = (struct vr_icmp*) pkt_push(pkt, sizeof(struct vr_icmp));
               icmph->icmp_type = VR_ICMP6_TYPE_PKT_TOO_BIG; 
               icmph->icmp_code = 0;
               icmph->icmp_csum = 0;
               icmph->icmp_eid = 0;
               icmph->icmp_eseq = htons(vif->vif_mtu - encap_len); /*set MTU in lower bytes of second word*/

               /* Build the outer header */
               outer_ip6 = (struct vr_ip6*) pkt_push(pkt, sizeof(struct vr_ip6));
               memset(outer_ip6, 0, sizeof(struct vr_ip6));
               memcpy(outer_ip6, ip6, sizeof(struct vr_ip6));
               memcpy(outer_ip6->ip6_dst, ip6->ip6_src, 16);
               memcpy(outer_ip6->ip6_src, ip6->ip6_dst, 16);
               outer_ip6->ip6_src[15] = 0xff; //Mimic the GW IP as the src IP
               
               if (pkt->vp_if->vif_mtu >= (plen + 2*sizeof(struct vr_ip6) 
                                                    + sizeof(struct vr_icmp))) {
                   outer_ip6->ip6_plen = htons(plen + sizeof(struct vr_ip6) + sizeof(struct vr_icmp));
               } else {
                   /* TODO: Chop the packet at the tail for the added header*/
               }

               /* Calculate ICMP6 checksum */
               icmph->icmp_csum = ~(vr_icmp6_checksum(outer_ip6, 
                                    sizeof(struct vr_ip6) + sizeof(struct vr_icmp)));

               /* Update packet pointers, perform route lookup and forward */
               pkt_set_network_header(pkt, pkt->vp_data);

               memcpy(rt.rtr_req.rtr_prefix, outer_ip6->ip6_dst, 16);
               nh = vr_inet_route_lookup(fmd->fmd_dvrf, &rt);
           }
       }
    }
    
    status =  nh_output(pkt, nh, fmd);

    return status;
}

unsigned int
vr_icmp_input(struct vrouter *router, struct vr_packet *pkt,
        struct vr_forwarding_md *fmd)
{
    int ret;
    unsigned int offset = 0, pull_len = 0;
    unsigned int unhandled = 1, handled = 0;
    struct vr_icmp *icmph;
    struct vr_ip *iph;
    struct vr_udp *udph;

    icmph = (struct vr_icmp *)(pkt_data(pkt) + offset);
    pull_len += sizeof(*icmph);

    if (vr_icmp_error(icmph)) {
        pull_len += sizeof(*iph);
        ret = vr_pkt_may_pull(pkt, pull_len);
        if (ret)
            return unhandled;

        offset += sizeof(*icmph);
        iph = (struct vr_ip *)(pkt_data(pkt) + offset);
        if ((iph->ip_proto != VR_IP_PROTO_GRE) &&
                (iph->ip_proto != VR_IP_PROTO_UDP))
            return unhandled;

        pull_len += ((iph->ip_hl * 4) - sizeof(*iph));
        ret = vr_pkt_may_pull(pkt, pull_len);
        if (ret)
            return unhandled;

        iph = (struct vr_ip *)(pkt_data(pkt) + offset);
        if (iph->ip_proto == VR_IP_PROTO_UDP) {
            /* for sport and dport */
            pull_len += 4;
            offset += (iph->ip_hl * 4);
            ret = vr_pkt_may_pull(pkt, pull_len);
            if (ret)
                return unhandled;
            /*
             * Note - we can't look at any other data other than ports
             * since we pull only the first 4 bytes
             */
            udph = (struct vr_udp *)(pkt_data(pkt) + offset);
            if (ntohs(udph->udp_dport) != VR_MPLS_OVER_UDP_DST_PORT)
                return unhandled;
        }

        vr_trap(pkt, pkt->vp_if->vif_vrf, AGENT_TRAP_ICMP_ERROR, 0);
        return handled;
    }

    return unhandled;
}

/*
 * vr_udp_input - handle incoming UDP packets. If the UDP destination
 * port is for MPLS over UDP or VXLAN, decap the packet and forward the inner
 * packet. Returns 1 if the packet was not handled, 0 otherwise.
 */
unsigned int
vr_udp_input(struct vrouter *router, struct vr_packet *pkt,
             struct vr_forwarding_md *fmd)
{
    struct vr_udp *udph, udp;
    int handled = 0, ret = PKT_RET_FAST_PATH;
    unsigned short reason;
    int encap_type = PKT_ENCAP_MPLS;

    if (vr_perfp && vr_pull_inner_headers_fast) {
        handled = vr_pull_inner_headers_fast(pkt, VR_IP_PROTO_UDP,
                vr_mpls_tunnel_type, &ret, &encap_type);
        if (!handled) {
            return 1;
        }

        if (ret == PKT_RET_FAST_PATH) {
            goto next_encap;
        }

        if (ret == PKT_RET_ERROR) {
            vr_pfree(pkt, VP_DROP_CKSUM_ERR);
            return 0;
        }

        /* Fall through to the slower path */
        ASSERT(ret == PKT_RET_SLOW_PATH);
    }
   
    udph = (struct vr_udp *)vr_pheader_pointer(pkt, sizeof(struct vr_udp),
                                                &udp);
    if (udph == NULL) {
        vr_pfree(pkt, VP_DROP_MISC);
        return 0;
    }

    if (ntohs(udph->udp_dport) == VR_MPLS_OVER_UDP_DST_PORT) {
        encap_type = PKT_ENCAP_MPLS;
    } else if (ntohs(udph->udp_dport) == VR_VXLAN_UDP_DST_PORT) {
        encap_type = PKT_ENCAP_VXLAN;
    } else {
        return 1;
    }

    /*
     * We are going to handle this packet. Pull as much of the inner packet
     * as required into the contiguous part of the pkt.
     */
    if (vr_pull_inner_headers) {
        if (!vr_pull_inner_headers(pkt, VR_IP_PROTO_UDP,
                    &reason, vr_mpls_tunnel_type)) {
            vr_pfree(pkt, reason);
            return 0;
        }
    }

    pkt_pull(pkt, sizeof(struct vr_udp));
next_encap:
    if (encap_type == PKT_ENCAP_MPLS) {
        vr_mpls_input(router, pkt, fmd);
    } else {
        vr_vxlan_input(router, pkt, fmd);
    }

    return 0;
}

unsigned int
vr_gre_input(struct vrouter *router, struct vr_packet *pkt,
        struct vr_forwarding_md *fmd)
{
    unsigned short *gre_hdr, gre_proto, hdr_len, reason;
    char buf[4];
    int handled = 0, ret = PKT_RET_FAST_PATH;
    int encap_type;

    if (vr_perfp && vr_pull_inner_headers_fast) {
        handled = vr_pull_inner_headers_fast(pkt, VR_IP_PROTO_GRE,
                vr_mpls_tunnel_type, &ret, &encap_type);
        if (!handled) {
            goto unhandled;
        }

        if (ret == PKT_RET_FAST_PATH) {
            goto mpls_input;
        }

        if (ret == PKT_RET_ERROR) {
            vr_pfree(pkt, VP_DROP_CKSUM_ERR);
            return 0;
        }

        /* Fall through to the slower path */
        ASSERT(ret == PKT_RET_SLOW_PATH);
    }

    /* start with basic GRE header */
    hdr_len = 4;
    gre_hdr = (unsigned short *) vr_pheader_pointer(pkt, hdr_len, buf);
    if (gre_hdr == NULL) {
        vr_pfree(pkt, VP_DROP_MISC);
        return 0;
    }

    if (*gre_hdr & VR_GRE_FLAG_CSUM)
            hdr_len += 4;

    if (*gre_hdr & VR_GRE_FLAG_KEY)
            hdr_len += 4;

    /* we are not RFC 1701 compliant receiver */
    if (*gre_hdr & (~(VR_GRE_FLAG_CSUM | VR_GRE_FLAG_KEY)))
            goto unhandled;

    /*
     * ... and we do not deal with any other protocol other than MPLS
     * for now
     */
    gre_proto = ntohs(*(gre_hdr + 1));
    if (gre_proto != VR_GRE_PROTO_MPLS)
            goto unhandled;

    /*
     * We are going to handle this packet. Pull as much of the inner packet
     * as required into the contiguous part of the pkt.
     */
    if (vr_pull_inner_headers) {
        if (!vr_pull_inner_headers(pkt, VR_IP_PROTO_GRE, &reason,
                    vr_mpls_tunnel_type)) {
            vr_pfree(pkt, reason);
            return 0;
        }
    }

    /* pull and junk the GRE header */
    pkt_pull(pkt, hdr_len);
mpls_input:
    vr_mpls_input(router, pkt, fmd);

    return 0;

unhandled:
    return 1;
}


int
vr_ip_rcv(struct vrouter *router, struct vr_packet *pkt,
        struct vr_forwarding_md *fmd)
{
    struct vr_ip *ip;
    struct vr_interface *vif = NULL;
    unsigned char *l2_hdr;
    unsigned int hlen;
    unsigned short drop_reason;
    int ret = 0, unhandled = 1;

    ip = (struct vr_ip *)pkt_data(pkt);
    hlen = ip->ip_hl * 4;
    pkt_pull(pkt, hlen);

    /*
     * this is a check to make sure that packets were indeed destined to
     * me or not. there are two ways a packet can reach here. either through
     *
     * route lookup->receive nexthop->vr_ip_rcv or through
     * VP_FLAG_TO_ME(NO route lookup(!vp->vp_nh))->vr_ip_rcv 
     */
    if ((pkt->vp_nh) || (!pkt->vp_nh &&
                    vr_myip(pkt->vp_if, ip->ip_saddr))) {
        if (ip->ip_proto == VR_IP_PROTO_GRE) {
            unhandled = vr_gre_input(router, pkt, fmd);
        } else if (ip->ip_proto == VR_IP_PROTO_UDP) {
            unhandled = vr_udp_input(router, pkt, fmd);
        } else if (ip->ip_proto == VR_IP_PROTO_ICMP) {
            unhandled = vr_icmp_input(router, pkt, fmd);
        }
    }

    if (unhandled) {
        /*
         * the gre, udp, icmp handlers could have pulled the packet. so
         * reset the notion of ip header
         */
        if (!(ip = (struct vr_ip *)pkt_push(pkt, hlen))) {
            drop_reason = VP_DROP_PUSH;
            goto drop_pkt;
        }

        /* ...and position the data back to l4 header */
        pkt_pull(pkt, hlen);

        if (pkt->vp_nh) {

            /*
             * If flow processing is already not done, relaxed policy
             * enabled, not in cross connect mode, not mirror packet,
             * lets subject it to flow processing.
             */
            if (pkt->vp_nh->nh_flags & NH_FLAG_RELAXED_POLICY) {
                unsigned short l4_size = 0;
                unsigned char ip_proto = ip->ip_proto;
                if (ip_proto == VR_IP_PROTO_UDP) {
                    l4_size = sizeof(struct vr_udp);
                } else if (ip_proto == VR_IP_PROTO_TCP) {
                    l4_size = sizeof(struct vr_tcp);
                }

                if (l4_size) {
                    unsigned short l4_port = 0;
                    if (vr_pkt_may_pull(pkt, l4_size)) {
                        drop_reason = VP_DROP_PUSH;
                        goto drop_pkt;
                    }

                    l4_port = *(unsigned short *) (pkt_data(pkt) + 2);
                    if (vr_valid_link_local_port(router, AF_INET,
                            ip_proto, ntohs(l4_port))) {
                        if (!(pkt->vp_flags & VP_FLAG_FLOW_SET) &&
                            !(pkt->vp_flags & (VP_FLAG_TO_ME |
                                               VP_FLAG_FROM_DP))) {
                             /* Force the flow lookup */
                             pkt->vp_flags |= VP_FLAG_FLOW_GET;

                             /* Get back the IP header */
                             if (!pkt_push(pkt, hlen)) {
                                drop_reason = VP_DROP_PUSH;
                                goto drop_pkt;
                             }
                            /* Subject it to flow for Linklocal */
                            if (!vr_flow_forward(router, pkt, fmd))
                                return 0;
                        }
                    }
                }
            }
            vif = pkt->vp_nh->nh_dev;
        }

        if (!vif && !(vif = pkt->vp_if->vif_bridge) &&
                                !(vif = router->vr_host_if)) {
            drop_reason = VP_DROP_TRAP_NO_IF;
            goto drop_pkt;
        }

        if ((pkt->vp_flags & VP_FLAG_FROM_DP) ||
                !vr_phead_len(pkt)) {
            /* get the ip header back */
            if (!pkt_push(pkt, hlen)) {
                drop_reason = VP_DROP_PUSH;
                goto drop_pkt;
            }

            /* push the l2 header */
            l2_hdr = pkt_push(pkt, sizeof(vif->vif_rewrite));
            if (!l2_hdr) {
                drop_reason = VP_DROP_PUSH;
                goto drop_pkt;
            }

            memcpy(l2_hdr, vif->vif_rewrite, sizeof(vif->vif_rewrite));
        } else {
            vr_preset(pkt);
        }
        ret = vif->vif_tx(vif, pkt);
    }

    return ret;

drop_pkt:
    vr_pfree(pkt, drop_reason);
    return 0;
}

flow_result_t
vr_inet_flow_nat(struct vr_flow_entry *fe, struct vr_packet *pkt,
                 struct vr_forwarding_md *fmd)
{
    bool hdr_update = false;
    unsigned int ip_inc, inc = 0;
    unsigned short *t_sport, *t_dport;

    struct vrouter *router = pkt->vp_if->vif_router;
    struct vr_flow_entry *rfe;
    struct vr_ip *ip, *icmp_pl_ip;
    struct vr_icmp *icmph;

    if (fe->fe_rflow < 0)
        goto drop;

    rfe = vr_get_flow_entry(router, fe->fe_rflow);
    if (!rfe)
        goto drop;

    ip = (struct vr_ip *)pkt_network_header(pkt);
    if (ip->ip_proto == VR_IP_PROTO_ICMP) {
        icmph = (struct vr_icmp *)((unsigned char *)ip + (ip->ip_hl * 4));
        if (vr_icmp_error(icmph)) {
            icmp_pl_ip = (struct vr_ip *)(icmph + 1);
            if (fe->fe_flags & VR_FLOW_FLAG_SNAT) {
                icmp_pl_ip->ip_daddr = rfe->fe_key.flow4_dip;
                hdr_update = true;
            }

            if (fe->fe_flags & VR_FLOW_FLAG_DNAT) {
                icmp_pl_ip->ip_saddr = rfe->fe_key.flow4_sip;
                hdr_update = true;
            }

            if (hdr_update)
                icmp_pl_ip->ip_csum = vr_ip_csum(icmp_pl_ip);

            t_sport = (unsigned short *)((unsigned char *)icmp_pl_ip +
                    (icmp_pl_ip->ip_hl * 4));
            t_dport = t_sport + 1;
            if (fe->fe_flags & VR_FLOW_FLAG_SPAT)
                *t_dport = rfe->fe_key.flow4_dport;

            if (fe->fe_flags & VR_FLOW_FLAG_DPAT)
                *t_sport = rfe->fe_key.flow4_sport;
        }
    }


    if ((fe->fe_flags & VR_FLOW_FLAG_SNAT) &&
            (ip->ip_saddr == fe->fe_key.flow4_sip)) {
        vr_incremental_diff(ip->ip_saddr, rfe->fe_key.flow4_dip, &inc);
        ip->ip_saddr = rfe->fe_key.flow4_dip;
    }

    if (fe->fe_flags & VR_FLOW_FLAG_DNAT) {
        vr_incremental_diff(ip->ip_daddr, rfe->fe_key.flow4_sip, &inc);
        ip->ip_daddr = rfe->fe_key.flow4_sip;
    }

    ip_inc = inc;

    if (vr_ip_transport_header_valid(ip)) {
        t_sport = (unsigned short *)((unsigned char *)ip +
                (ip->ip_hl * 4));
        t_dport = t_sport + 1;

        if (fe->fe_flags & VR_FLOW_FLAG_SPAT) {
            vr_incremental_diff(*t_sport, rfe->fe_key.flow4_dport, &inc);
            *t_sport = rfe->fe_key.flow4_dport;
        }

        if (fe->fe_flags & VR_FLOW_FLAG_DPAT) {
            vr_incremental_diff(*t_dport, rfe->fe_key.flow4_sport, &inc);
            *t_dport = rfe->fe_key.flow4_sport;
        }
    }

    if (!vr_pkt_is_diag(pkt))
        vr_ip_update_csum(pkt, ip_inc, inc);

    if ((fe->fe_flags & VR_FLOW_FLAG_VRFT) &&
            pkt->vp_nh && pkt->vp_nh->nh_vrf != fmd->fmd_dvrf) {
        pkt->vp_nh = NULL;
    }

    return FLOW_FORWARD;

drop:
    vr_pfree(pkt, VP_DROP_FLOW_NAT_NO_RFLOW);
    return FLOW_CONSUMED;
}

static void
vr_inet_flow_swap(struct vr_flow *key_p)
{
    unsigned short port;
    unsigned int ipaddr;

    port = key_p->flow4_sport;
    key_p->flow4_sport = key_p->flow4_dport;
    key_p->flow4_dport = port;

    ipaddr = key_p->flow4_sip;
    key_p->flow4_sip = key_p->flow4_dip;
    key_p->flow4_dip = ipaddr;

    return;
}

static unsigned short
vr_inet_flow_nexthop(struct vr_packet *pkt, unsigned short vlan)
{
    unsigned short nh_id;

    if (vif_is_fabric(pkt->vp_if) && pkt->vp_nh) {
        /* this is more a requirement from agent */
        if ((pkt->vp_nh->nh_type == NH_ENCAP)) {
            nh_id = pkt->vp_nh->nh_dev->vif_nh_id;
        } else {
            nh_id = pkt->vp_nh->nh_id;
        }
    } else if (vif_is_service(pkt->vp_if)) {
        nh_id = vif_vrf_table_get_nh(pkt->vp_if, vlan);
    } else {
        nh_id = pkt->vp_if->vif_nh_id;
    }

    return nh_id;
}

void
vr_inet_fill_flow(struct vr_flow *flow_p, unsigned short nh_id,
        uint32_t sip, uint32_t dip, uint8_t proto,
        uint16_t sport, uint16_t dport)
{
    /* copy both source and destinations */
    flow_p->flow4_sip = sip;
    flow_p->flow4_dip = dip;
    flow_p->flow4_proto = proto;
    flow_p->flow4_nh_id = nh_id;
    flow_p->flow4_sport = sport;
    flow_p->flow4_dport = dport;

    flow_p->key_len = sizeof(struct vr_inet_flow);

    return;
}

static int
vr_inet_fragment_flow(struct vrouter *router, unsigned short vrf,
        struct vr_packet *pkt, uint16_t vlan, struct vr_flow *flow_p)
{
    uint16_t sport, dport;
    unsigned short nh_id;

    struct vr_fragment *frag;
    struct vr_ip *ip = (struct vr_ip *)pkt_network_header(pkt);

    frag = vr_fragment_get(router, vrf, ip);
    if (!frag) {
        return -1;
    }

    sport = frag->f_sport;
    dport = frag->f_dport;
    if (vr_ip_fragment_tail(ip))
        vr_fragment_del(frag);

    nh_id = vr_inet_flow_nexthop(pkt, vlan);
    vr_inet_fill_flow(flow_p, nh_id, ip->ip_saddr, ip->ip_daddr,
            ip->ip_proto, sport, dport);
    return 0;
}

static int
vr_inet_proto_flow(struct vrouter *router, unsigned short vrf,
        struct vr_packet *pkt, uint16_t vlan, struct vr_ip *ip,
        struct vr_flow *flow_p)
{
    unsigned short *t_hdr, sport, dport;
    unsigned short nh_id;

    struct vr_icmp *icmph;

    t_hdr = (unsigned short *)((char *)ip + (ip->ip_hl * 4));

    if (ip->ip_proto == VR_IP_PROTO_ICMP) {
        icmph = (struct vr_icmp *)t_hdr;
        if (vr_icmp_error(icmph)) {
            if ((unsigned char *)ip == pkt_network_header(pkt)) {
                vr_inet_proto_flow(router, vrf, pkt, vlan,
                        (struct vr_ip *)(icmph + 1), flow_p);
                vr_inet_flow_swap(flow_p);
            }

            return 0;
        } else if (vr_icmp_echo(icmph)) {
            sport = icmph->icmp_eid;
            dport = VR_ICMP_TYPE_ECHO_REPLY;
        } else {
            sport = 0;
            dport = icmph->icmp_type;
        }
    } else {
        sport = *t_hdr;
        dport = *(t_hdr + 1);
    }

    nh_id = vr_inet_flow_nexthop(pkt, vlan);
    vr_inet_fill_flow(flow_p, nh_id, ip->ip_saddr, ip->ip_daddr,
            ip->ip_proto, sport, dport);

    return 0;
}

static int
vr_inet_form_flow(struct vrouter *router, unsigned short vrf, 
        struct vr_packet *pkt, uint16_t vlan, struct vr_flow *flow_p)
{
    int ret;
    struct vr_ip *ip = (struct vr_ip *)pkt_network_header(pkt);

    if (vr_ip_transport_header_valid(ip)) {
        ret = vr_inet_proto_flow(router, vrf, pkt, vlan, ip, flow_p);
    } else {
        ret = vr_inet_fragment_flow(router, vrf, pkt, vlan, flow_p);
        if (ret < 0)
            vr_pfree(pkt, VP_DROP_FRAGMENTS);
    }

    return ret;
}

static bool
vr_inet_should_trap(struct vr_packet *pkt, struct vr_flow *flow_p)
{
    uint32_t proto_port;

    /*
     * dhcp packet handling:
     *
     * for now we handle dhcp requests from only VMs and that too only
     * for VMs that are not in the fabric VRF. dhcp refresh packets will
     * anyway hit the route entry and get trapped from there.
     */
    if (vif_is_virtual(pkt->vp_if) && vif_dhcp_enabled(pkt->vp_if)) {
        proto_port = (flow_p->flow4_proto << VR_FLOW_PROTO_SHIFT) |
            flow_p->flow4_sport;
        if (proto_port == VR_UDP_DHCP_CPORT) {
            return true;
        }
    }

    return false;
}

flow_result_t
vr_inet_flow_lookup(struct vrouter *router, struct vr_packet *pkt,
                    struct vr_forwarding_md *fmd)
{
    int ret;
    bool lookup = false;
    struct vr_flow flow, *flow_p = &flow;
    struct vr_ip *ip = (struct vr_ip *)pkt_network_header(pkt);

    /*
     * if the packet has already done one round of flow lookup, there
     * is no point in doing it again, eh?
     */
    if (pkt->vp_flags & VP_FLAG_FLOW_SET)
        return FLOW_FORWARD;

    ret = vr_inet_form_flow(router, fmd->fmd_dvrf, pkt, fmd->fmd_vlan, flow_p);
    if (ret < 0)
        return FLOW_CONSUMED;

    /* no flow lookup for multicast or broadcast ip */
    if (IS_BMCAST_IP(ip->ip_daddr)) {
        /* but then we have to trap some packets */
        if (vr_inet_should_trap(pkt, flow_p)) {
            return FLOW_TRAP;
        }
        return FLOW_FORWARD;
    }

    /*
     * if the interface is policy enabled, or if somebody else (eg:nexthop)
     * has requested for a policy lookup, packet has to go through a lookup
     */
    if ((pkt->vp_if->vif_flags & VIF_FLAG_POLICY_ENABLED) ||
            (pkt->vp_flags & VP_FLAG_FLOW_GET)) {
        lookup = true;
    }

    if (lookup) {
        if (vr_ip_fragment_head(ip)) {
            vr_fragment_add(router, fmd->fmd_dvrf, ip, flow_p->flow4_sport,
                    flow_p->flow4_dport);
        }

        return vr_flow_lookup(router, flow_p, pkt, fmd);
    }

    return FLOW_FORWARD;
}


int
vr_ip_input(struct vrouter *router, struct vr_packet *pkt,
            struct vr_forwarding_md *fmd)
{
    struct vr_ip *ip;

    ip = (struct vr_ip *)pkt_data(pkt);
    if (ip->ip_version == 4 && ip->ip_hl < 5) 
        goto corrupt_pkt;

    /*
     * interface is in a mode where it wants all packets to be received
     * without doing lookups to figure out whether packets were destined
     * to me or not
     */
    if (pkt->vp_flags & VP_FLAG_TO_ME)
        return vr_ip_rcv(router, pkt, fmd);
    
    if (!vr_flow_forward(router, pkt, fmd))
        return 0;

    return vr_forward(router, pkt, fmd);
corrupt_pkt:
    vr_pfree(pkt, VP_DROP_INVALID_PROTOCOL);
    return 0;
}

bool
vr_has_to_fragment(struct vr_interface *vif, struct vr_packet *pkt,
        unsigned int tun_len)
{
    unsigned int len;
    struct vr_ip *ip;
    struct vr_tcp *tcp;
    unsigned int mtu = vif_get_mtu(vif);

    if (pkt_is_gso(pkt)) {
        len = vr_pgso_size(pkt);
        if (len > mtu)
            return true;

        ip = (struct vr_ip *)pkt_network_header(pkt);
        if (!ip)
            return false;

        len += (ip->ip_hl * 4);

        if (ip->ip_proto == VR_IP_PROTO_TCP) {
            tcp = (struct vr_tcp *)((unsigned char *)ip + (ip->ip_hl * 4));
            len += (tcp->tcp_offset * 4);
        }
    } else {
        len = pkt_len(pkt);
    }

    if ((len + tun_len) > mtu)
        return true;

    return false;
}

int
vr_myip(struct vr_interface *vif, unsigned int ip)
{
    struct vr_route_req rt;
    struct vr_nexthop *nh;
    uint32_t rt_prefix;

    if (vif->vif_type != VIF_TYPE_PHYSICAL)
        return 1;


    rt.rtr_req.rtr_family = AF_INET;
    rt.rtr_req.rtr_vrf_id = vif->vif_vrf;
    rt.rtr_req.rtr_prefix = (uint8_t*)&rt_prefix;

    *(uint32_t*)rt.rtr_req.rtr_prefix = (ip);
    rt.rtr_req.rtr_prefix_len = IP4_PREFIX_LEN;
    rt.rtr_req.rtr_prefix_size = 4;
    rt.rtr_req.rtr_nh_id = 0;
    rt.rtr_req.rtr_marker_size = 0;

    nh = vr_inet_route_lookup(vif->vif_vrf, &rt);

    if (!nh || nh->nh_type != NH_RCV)
        return 0;

    return 1;
}


unsigned int
vr_inet_route_flags(unsigned int vrf, unsigned int ip)
{
    struct vr_route_req rt;
    uint32_t rt_prefix;

    memset(&rt, 0 , sizeof(rt));
    rt.rtr_req.rtr_family = AF_INET;
    rt.rtr_req.rtr_vrf_id = vrf;
    rt.rtr_req.rtr_prefix = (uint8_t*)&rt_prefix;
    *(uint32_t*)rt.rtr_req.rtr_prefix = (ip);
    rt.rtr_req.rtr_prefix_size = 4;
    rt.rtr_req.rtr_prefix_len = IP4_PREFIX_LEN;

    (void)vr_inet_route_lookup(vrf, &rt);

    return rt.rtr_req.rtr_label_flags;
}

bool
vr_ip_well_known_packet(struct vr_packet *pkt)
{
    unsigned char *data = pkt_data(pkt);
    struct vr_ip *iph;
    struct vr_udp *udph;

    if ((pkt->vp_type != VP_TYPE_IP) ||
         (!(pkt->vp_flags & VP_FLAG_MULTICAST)))
        return false;

    iph = (struct vr_ip *)data;
    if ((iph->ip_proto == VR_IP_PROTO_UDP) &&
                              vr_ip_transport_header_valid(iph)) {
        udph = (struct vr_udp *)(data + iph->ip_hl * 4);
        if (udph->udp_sport == htons(VR_DHCP_SRC_PORT))
            return true;
    }
    return false;
}

