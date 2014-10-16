/*
 * vr_proto_ip.c -- IP protocol handling
 *
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#include <vr_os.h>
#include <vr_types.h>
#include <vr_packet.h>
#include "vr_mpls.h"
#include "vr_vxlan.h"
#include "vr_mcast.h"
#include "vr_ip_mtrie.h"

extern struct vr_nexthop *(*vr_inet_route_lookup)(unsigned int,
                struct vr_route_req *, struct vr_packet *);
extern int vr_mpls_input(struct vrouter *, struct vr_packet *,
        struct vr_forwarding_md *);

struct vr_nexthop *vr_inet_src_lookup(unsigned short, struct vr_ip *, struct vr_packet *);
int vr_forward(struct vrouter *, unsigned short, struct vr_packet *, struct vr_forwarding_md *);
unsigned int vr_udp_input(struct vrouter *, struct vr_packet *,
    struct vr_forwarding_md *);
int vr_ip_input(struct vrouter *, unsigned short, struct vr_packet *,
    struct vr_forwarding_md *);
unsigned int vr_gre_input(struct vrouter *, struct vr_packet *,
        struct vr_forwarding_md *);
void vr_ip_update_csum(struct vr_packet *, unsigned int, unsigned int);
unsigned int vr_route_flags(unsigned int, unsigned int);

static unsigned short vr_ip_id;

unsigned short
vr_generate_unique_ip_id()
{
    vr_ip_id++;
    if (!vr_ip_id)
        vr_ip_id++;

    return vr_ip_id;
}

/* 
 * Calculates ICMP6 checksum
 * buffer is pointer to ip6 header, all values other than src, dst and plen are ZERO
 * bytes is total length of ip6 header, icmp header and icmp option 
 */
uint16_t
vr_icmp6_checksum (void * buffer, int bytes) {
   uint32_t   total;
   uint16_t * ptr;
   int        num_words;

   total = 0;
   ptr   = (uint16_t *) buffer;
   num_words = (bytes + 1) / 2; 

   while (num_words--) total += *ptr++;

   /*
    *   Fold in any carries
    *   - the addition may cause another carry so we loop
    */
   while (total & 0xffff0000) total = (total >> 16) + (total & 0xffff);

   return (uint16_t) total;
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
    if (!vr_ip_is_ip6(ip)) {
        pkt->vp_type = VP_TYPE_IP;
        rt.rtr_req.rtr_prefix = (uint8_t*)&rt_prefix;
        *(uint32_t*)rt.rtr_req.rtr_prefix = (ip->ip_saddr);
        rt.rtr_req.rtr_prefix_size = 4;
        rt.rtr_req.rtr_prefix_len = IP4_PREFIX_LEN;
    } else {
        ip6 = (struct vr_ip6 *)pkt_data(pkt);
        pkt->vp_type = VP_TYPE_IP6;
        rt.rtr_req.rtr_prefix = (uint8_t*)&rt_prefix;
        rt.rtr_req.rtr_prefix_size = 16;
        memcpy(rt.rtr_req.rtr_prefix, ip6->ip6_src, 16);
        rt.rtr_req.rtr_prefix_len = IP6_PREFIX_LEN;
    }
    rt.rtr_req.rtr_src_size = rt.rtr_req.rtr_marker_size = 0;
    rt.rtr_req.rtr_nh_id = 0;

    nh = vr_inet_route_lookup(vrf, &rt, pkt);

    return nh;
}

int
vr_forward(struct vrouter *router, unsigned short vrf,
        struct vr_packet *pkt, struct vr_forwarding_md *fmd)
{
    struct vr_route_req rt;
    struct vr_nexthop *nh;
    struct vr_ip *ip;
    struct vr_ip6 *ip6, *outer_ip6;
    struct vr_icmp *icmph;
    struct vr_forwarding_md rt_fmd;
    struct vr_interface *vif;
    int family = AF_INET, status, encap_len = 0;
    short plen;
    uint32_t rt_prefix[4];

    if (pkt->vp_flags & VP_FLAG_MULTICAST) { 
        return vr_mcast_forward(router, vrf, pkt, fmd);
    }

    ip = (struct vr_ip *)pkt_data(pkt);
    if (vr_ip_is_ip6(ip)) {
        family = AF_INET6;
        ip6 = (struct vr_ip6 *)pkt_data(pkt);
        pkt->vp_type = VP_TYPE_IP6;
    } else {
        pkt->vp_type = VP_TYPE_IP;
    }
 
    rt.rtr_req.rtr_vrf_id = vrf;
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
    rt.rtr_req.rtr_src_size = rt.rtr_req.rtr_marker_size = 0;

    nh = vr_inet_route_lookup(vrf, &rt, pkt);
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
               nh = vr_inet_route_lookup(vrf, &rt, pkt);
           }
       }
    }
    
    status =  nh_output(vrf, pkt, nh, fmd);

    return status;
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
        }
    }

    if (unhandled) {
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
                            return vr_flow_inet_input(pkt->vp_nh->nh_router,
                                pkt->vp_nh->nh_vrf, pkt, VR_ETH_PROTO_IP, fmd);
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

int
vr_ip_input(struct vrouter *router, unsigned short vrf, 
        struct vr_packet *pkt, struct vr_forwarding_md *fmd)
{
    struct vr_ip *ip;

    ip = (struct vr_ip *)pkt_data(pkt);
    if (ip->ip_version == 4 && ip->ip_hl < 5) 
        goto corrupt_pkt;

    return vr_forward(router, vrf, pkt, fmd);

corrupt_pkt:
    vr_pfree(pkt, VP_DROP_INVALID_PROTOCOL);
    return 0;
}

void
vr_ip_update_csum(struct vr_packet *pkt, unsigned int ip_inc, unsigned int inc)
{
    struct vr_ip *ip;
    struct vr_tcp *tcp;
    struct vr_udp *udp;
    unsigned int csum;
    unsigned short *csump;

    ip = (struct vr_ip *)pkt_data(pkt);
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


    rt.rtr_req.rtr_vrf_id = vif->vif_vrf;
    rt.rtr_req.rtr_prefix = (uint8_t*)&rt_prefix;

    *(uint32_t*)rt.rtr_req.rtr_prefix = (ip);
    rt.rtr_req.rtr_prefix_len = IP4_PREFIX_LEN;
    rt.rtr_req.rtr_prefix_size = 4;
    rt.rtr_req.rtr_src_size = rt.rtr_req.rtr_marker_size = 0;
    rt.rtr_req.rtr_nh_id = 0;

    nh = vr_inet_route_lookup(vif->vif_vrf, &rt, NULL);

    if (!nh || nh->nh_type != NH_RCV)
        return 0;

    return 1;
}
