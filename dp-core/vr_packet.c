/*
 * vr_packet.c -- packet handling helpers
 *
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#include <vr_os.h>
#include <vr_packet.h>

struct vr_packet *
pkt_copy(struct vr_packet *pkt, unsigned short off, unsigned short len)
{
    struct vr_packet *pkt_c;
    unsigned short head_space;

    /*
     * one eth header for agent, and one more for packets from
     * tun interfaces
     */
    head_space = (2 * sizeof(struct vr_eth)) + sizeof(struct agent_hdr);
    pkt_c = vr_palloc(head_space + len);
    if (!pkt_c)
        return pkt_c;

    pkt_c->vp_data += head_space;
    pkt_c->vp_tail += head_space;
    if (vr_pcopy(pkt_data(pkt_c), pkt, off, len) < 0) {
        vr_pfree(pkt_c, VP_DROP_MISC);
        return NULL;
    }
    pkt_pull_tail(pkt_c, len);

    pkt_c->vp_if = pkt->vp_if;
    pkt_c->vp_flags = pkt->vp_flags;
    pkt_c->vp_cpu = pkt->vp_cpu;
    pkt_c->vp_network_h = 0;

    return pkt_c;
}

bool
vr_ip_proto_pull(struct vr_ip *iph)
{
    unsigned char proto = iph->ip_proto;

    if ((proto == VR_IP_PROTO_TCP) ||
            (proto == VR_IP_PROTO_UDP) ||
            (proto == VR_IP_PROTO_ICMP)) {
        return true;
    }

    return false;
}

/**
 * vr_ip_transport_parse - parse IP packet to reach the L4 header
 */
int
vr_ip_transport_parse(struct vr_ip *iph, struct vr_ip6 *ip6h,
                      struct tcphdr **tcphp, unsigned int frag_size,
                      void (do_tcp_mss_adj)(struct tcphdr *, unsigned short,
                                          unsigned char),
                      unsigned int *hlenp,
                      unsigned short *th_csump,
                      unsigned int *tcph_pull_lenp,
                      unsigned int *pull_lenp)
{
    unsigned short ip_proto;
    bool thdr_valid = false;
    unsigned int hlen = 0, tcph_pull_len = 0;
    unsigned int pull_len = *pull_lenp;
    struct vr_tcp *tcph = NULL;
    unsigned short th_csum = 0;
    struct vr_icmp *icmph = NULL;
    struct vr_ip *icmp_pl_iph = NULL;


    /* Note: iph is set for both ipv4 and ipv6 cases */
    if (iph) {
        if (vr_ip_is_ip6(iph)) {
            ip_proto = ip6h->ip6_nxt;
            hlen = sizeof(struct vr_ip6);
            thdr_valid = true;
        } else {
            ip_proto = iph->ip_proto;
            /*
             * Account for IP options
             */
            thdr_valid = vr_ip_transport_header_valid(iph);
            if (thdr_valid) {
                hlen = iph->ip_hl * 4;
                pull_len += (hlen - sizeof(struct vr_ip));
            }
        }

        if (thdr_valid) {
            tcph_pull_len = pull_len;
            if (ip_proto == VR_IP_PROTO_TCP) {
                pull_len += sizeof(struct vr_tcp);
            } else if (ip_proto == VR_IP_PROTO_UDP) {
                pull_len += sizeof(struct vr_udp);
            } else if ((ip_proto == VR_IP_PROTO_ICMP) ||
                       (ip_proto == VR_IP_PROTO_ICMP6)) {
                pull_len += sizeof(struct vr_icmp);
            }

            if (frag_size < pull_len) {
                return PKT_RET_SLOW_PATH;
            }

            if (ip_proto == VR_IP_PROTO_TCP) {
                /*
                 * Account for TCP options
                 */
                tcph = (struct vr_tcp *)((char *)iph + hlen);

                /*
                 * If SYN, do TCP MSS adjust using passed callback, or send it
                 * to the slow path.
                 */
                if ((ntohs(tcph->tcp_offset_r_flags) & VR_TCP_FLAG_SYN) &&
                        vr_to_vm_mss_adj) {
                    if (do_tcp_mss_adj) {
                        /* Kernel will never get here, it will return slow path */
                        do_tcp_mss_adj((struct tcphdr *)tcph,
                                            VROUTER_L2_OVERLAY_LEN, hlen);
                    } else {
                        return PKT_RET_SLOW_PATH;
                    }
                }

                if ((VR_TCP_OFFSET(tcph->tcp_offset_r_flags) * 4) >
                        (sizeof(struct vr_tcp))) {
                    pull_len += ((VR_TCP_OFFSET(tcph->tcp_offset_r_flags) * 4) -
                                    (sizeof(struct vr_tcp)));

                    if (frag_size < pull_len) {
                        return PKT_RET_SLOW_PATH;
                    }
                }
                th_csum = tcph->tcp_csum;
            } else if (ip_proto == VR_IP_PROTO_ICMP) {
                icmph = (struct vr_icmp *)((unsigned char *)iph + hlen);
                th_csum = icmph->icmp_csum;
                if (vr_icmp_error(icmph)) {
                    pull_len += sizeof(struct vr_ip);
                    if (frag_size < pull_len)
                        return PKT_RET_SLOW_PATH;
                    icmp_pl_iph = (struct vr_ip *)(icmph + 1);
                    pull_len += (icmp_pl_iph->ip_hl * 4) - sizeof(struct vr_ip);
                    if (frag_size < pull_len)
                        return PKT_RET_SLOW_PATH;
                    if (vr_ip_proto_pull(icmp_pl_iph)) {
                        if (icmp_pl_iph->ip_proto == VR_IP_PROTO_TCP)
                            pull_len += sizeof(struct vr_tcp);
                        else if (icmp_pl_iph->ip_proto == VR_IP_PROTO_UDP)
                            pull_len += sizeof(struct vr_udp);
                        else
                            pull_len += sizeof(struct vr_icmp);

                        if (frag_size < pull_len)
                            return PKT_RET_SLOW_PATH;

                        if (icmp_pl_iph->ip_proto == VR_IP_PROTO_TCP) {
                            th_csum = ((struct vr_tcp *)
                                        ((unsigned char *)icmp_pl_iph +
                                        icmp_pl_iph->ip_hl * 4))->tcp_csum;
                        } else if (icmp_pl_iph->ip_proto == VR_IP_PROTO_UDP) {
                            th_csum = ((struct vr_udp *)
                                        ((unsigned char *)icmp_pl_iph +
                                        icmp_pl_iph->ip_hl * 4))->udp_csum;
                        } else if (icmp_pl_iph->ip_proto == VR_IP_PROTO_ICMP) {
                            th_csum = ((struct vr_icmp *)
                                        ((unsigned char *)icmp_pl_iph +
                                        icmp_pl_iph->ip_hl * 4))->icmp_csum;
                        }
                    }
                }
            } else if (iph->ip_proto == VR_IP_PROTO_UDP) {
                th_csum = ((struct vr_udp *)
                            ((unsigned char *)iph + hlen))->udp_csum;
            } else if (ip_proto == VR_IP_PROTO_ICMP6) {
                icmph = (struct vr_icmp *)((unsigned char *)ip6h + hlen);
                if (icmph->icmp_type == VR_ICMP6_TYPE_NEIGH_SOL) {
                    /* ICMP options size for neighbor solicit is 24 bytes */
                    pull_len += 24;
                } else if (icmph->icmp_type == VR_ICMP6_TYPE_ROUTER_SOL) {
                    pull_len += 8;
                }

                if (frag_size < pull_len)
                    return PKT_RET_SLOW_PATH;
            }
        }
    }

    if (hlenp)
        *hlenp = hlen;
    if (th_csump)
        *th_csump = th_csum;
    if (tcph_pull_lenp)
        *tcph_pull_lenp = tcph_pull_len;
    if (tcphp)
        *tcphp = (struct tcphdr *)tcph;
    *pull_lenp = pull_len;

    return 0;
}
