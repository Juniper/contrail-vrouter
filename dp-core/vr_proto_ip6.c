/*
 * vr_proto_ip6.c -- ip6 handler
 *
 * Copyright (c) 2014, Juniper Networks, Inc.
 * All rights reserved
 */
#include <vr_os.h>
#include <vr_types.h>
#include <vr_packet.h>

#include <vr_datapath.h>
#include <vr_ip_mtrie.h>
#include <vr_bridge.h>

#define SOURCE_LINK_LAYER_ADDRESS_OPTION    1
#define TARGET_LINK_LAYER_ADDRESS_OPTION    2

struct vr_neighbor_option {
    uint8_t vno_type;
    uint8_t vno_length;
    uint8_t vno_value[0];
} __attribute__((packed));


static int
vr_v6_prefix_is_ll(uint8_t prefix[])
{
    if ((prefix[0] == 0xFE) && (prefix[1] == 0x80)) {
        return true;
    }
    return false;
}


/*
 * buffer is pointer to ip6 header, all values other than src, dst and
 * plen are ZERO. bytes is total length of ip6 header, icmp header and
 * icmp option
 */
uint16_t
vr_icmp6_checksum(void *buffer, unsigned int bytes)
{
   uint32_t total;
   uint16_t *ptr;
   int num_words;

   total = 0;
   ptr   = (uint16_t *)buffer;
   num_words = (bytes + 1) / 2;

   while (num_words--)
       total += *ptr++;

   /*
    *   Fold in any carries
    *   - the addition may cause another carry so we loop
    */
   while (total & 0xffff0000)
       total = (total >> 16) + (total & 0xffff);

   return (uint16_t)total;
}

static bool
vr_icmp6_input(struct vrouter *router, struct vr_packet *pkt,
               struct vr_forwarding_md *fmd)
{
    bool handled = true;
    struct vr_icmp *icmph;

    icmph = (struct vr_icmp *)pkt_data(pkt);
    switch (icmph->icmp_type) {

    case VR_ICMP6_TYPE_ROUTER_SOL:
        vr_trap(pkt, fmd->fmd_dvrf, AGENT_TRAP_L3_PROTOCOLS, NULL);
        break;

    default:
        handled = false;
        break;
    }

    return handled;
}

int
vr_ip6_input(struct vrouter *router, struct vr_packet *pkt,
             struct vr_forwarding_md *fmd)
{
    struct vr_ip6 *ip6;
    unsigned short *t_hdr, sport, dport;

    ip6 = (struct vr_ip6 *)pkt_network_header(pkt);
    t_hdr = (unsigned short *)((char *)ip6 + sizeof(struct vr_ip6));

    if (!pkt_pull(pkt, sizeof(struct vr_ip6))) {
        vr_pfree(pkt, VP_DROP_PULL);
        return 0;
    }

    switch (ip6->ip6_nxt) {
    case VR_IP_PROTO_ICMP6:
        if (vr_icmp6_input(router, pkt, fmd))
            return 0;
        break;

    case VR_IP_PROTO_UDP:
        sport = *t_hdr;
        dport = *(t_hdr + 1);
        if (vif_is_virtual(pkt->vp_if)) {
            if ((sport == VR_DHCP6_SPORT) && (dport == VR_DHCP6_DPORT))
                return vr_trap(pkt, fmd->fmd_dvrf, AGENT_TRAP_L3_PROTOCOLS, NULL);
        }
        break;

    default:
        break;
    }

    if (!pkt_push(pkt, sizeof(struct vr_ip6))) {
        vr_pfree(pkt, VP_DROP_PUSH);
        return 0;
    }

    return vr_forward(router, pkt, fmd);
}

int
vr_ip6_neighbor_solicitation_input(struct vr_packet *pkt, struct vr_forwarding_md *fmd,
                                   int pkt_src)
{
    struct vr_ip6 *ip6;
    struct vr_neighbor_option *nopt;
    struct vr_icmp *icmph;
    char dst_mac[VR_ETHER_ALEN], src_mac[VR_ETHER_ALEN];
    mac_response_t ndisc_result;
    uint32_t rt_prefix[4], pull_len;
    struct vr_route_req rt;
    int drop_reason;
    struct vr_eth *eth;

    if (pkt->vp_type != VP_TYPE_IP6)
        return 0;

    ip6 = (struct vr_ip6 *)pkt_data(pkt);
    if (!ip6)
        goto drop;

    if (ip6->ip6_nxt != VR_IP_PROTO_ICMP6)
        return 0;

    /* Link local neighbour discovery is bridged */
    if (vr_v6_prefix_is_ll(ip6->ip6_dst))
        return 0;

    pull_len = sizeof(*ip6);
    icmph = (struct vr_icmp *)(pkt_data(pkt) + pull_len);
    if (!icmph)
        goto drop;

    if (icmph->icmp_type != VR_ICMP6_TYPE_NEIGH_SOL) {
        pkt_push(pkt, pull_len);
        return 0;
    }

    pull_len += sizeof(*icmph) + VR_IP6_ADDRESS_LEN;
    nopt = (struct vr_neighbor_option *)(pkt_data(pkt) + pull_len);
    if (!nopt)
        goto drop;

    if (nopt->vno_type != SOURCE_LINK_LAYER_ADDRESS_OPTION) {
        pkt_push(pkt, pull_len);
        return 0;
    }

    VR_MAC_COPY(dst_mac, nopt->vno_value);
    /* We let DAD packets bridged */
    if (IS_MAC_ZERO(dst_mac)) {
        pkt_push(pkt, pull_len);
        return 0;
    }

    rt.rtr_req.rtr_vrf_id = fmd->fmd_dvrf;
    rt.rtr_req.rtr_family = AF_INET6;
    rt.rtr_req.rtr_prefix = (uint8_t *)&rt_prefix;
    memcpy(rt.rtr_req.rtr_prefix, icmph->icmp_data, 16);
    rt.rtr_req.rtr_prefix_size = 16;
    rt.rtr_req.rtr_prefix_len = IP6_PREFIX_LEN;
    rt.rtr_req.rtr_nh_id = 0;
    rt.rtr_req.rtr_label_flags = 0;

    vr_inet_route_lookup(fmd->fmd_dvrf, &rt);

    ndisc_result = vr_get_l3_stitching_info(pkt, &rt, fmd, src_mac,
                                          dst_mac, pkt_src, &drop_reason);
    if (ndisc_result == MR_PROXY) {
        memcpy(ip6->ip6_dst, ip6->ip6_src, sizeof(ip6->ip6_src));
        memcpy(ip6->ip6_src, &icmph->icmp_data, sizeof(ip6->ip6_src));
        /* Mimic a different source ip */
        ip6->ip6_src[15] = 0xFF;

        /* Update ICMP header and options */
        icmph->icmp_type = VR_ICMP6_TYPE_NEIGH_AD;
        icmph->icmp_eid = htons(0x4000);

        /* length in units of 8 octets */
        nopt->vno_type = TARGET_LINK_LAYER_ADDRESS_OPTION;
        nopt->vno_length = (sizeof(struct vr_neighbor_option) + VR_ETHER_ALEN) / 8;
        VR_MAC_COPY(nopt->vno_value, src_mac);

        icmph->icmp_csum =
        ~(vr_icmp6_checksum(ip6, sizeof(struct vr_ip6) +
                    sizeof(struct vr_icmp) + VR_IP6_ADDRESS_LEN +
                    nopt->vno_length));


        eth = (struct vr_eth *)pkt_push(pkt, VR_ETHER_HLEN);

        /* Update Ethernet headr */
        VR_MAC_COPY(eth->eth_dmac, dst_mac);
        VR_MAC_COPY(eth->eth_smac, src_mac);
        eth->eth_proto = htons(VR_ETH_PROTO_IP6);
    }

    return vr_handle_mac_response(pkt, fmd, ndisc_result, drop_reason);

drop:
    vr_pfree(pkt, VP_DROP_INVALID_PACKET);
    return 1;
}

bool
vr_ip6_dhcp_packet(struct vr_packet *pkt)
{
    unsigned char *data = pkt_data(pkt);
    struct vr_ip6 *ip6;
    struct vr_udp *udph = NULL;

    if ((pkt->vp_type != VP_TYPE_IP6) ||
         (!(pkt->vp_flags & VP_FLAG_MULTICAST)))
        return false;

    ip6 = (struct vr_ip6 *)data;

    if (vr_v6_prefix_is_ll(ip6->ip6_dst))
            return false;

    /* 0xFF02 is the multicast address used for NDP, DHCPv6 etc */
    if (ip6->ip6_dst[0] == 0xFF && ip6->ip6_dst[1] == 0x02) {
        /*
         * Bridge neighbor solicit for link-local addresses
         */
        if (ip6->ip6_nxt == VR_IP_PROTO_UDP)
            udph = (struct vr_udp *)((char *)ip6 + sizeof(struct vr_ip6));
        if (udph && (udph->udp_sport == htons(VR_DHCP6_SRC_PORT)))
            return true;
    }

    return false;
}

bool
vr_ip6_well_known_packet(struct vr_packet *pkt)
{
    unsigned char *data = pkt_data(pkt);
    struct vr_ip6 *ip6;
    struct vr_icmp *icmph = NULL;

    if ((pkt->vp_type != VP_TYPE_IP6) ||
         (!(pkt->vp_flags & VP_FLAG_MULTICAST)))
        return false;

    ip6 = (struct vr_ip6 *)data;

    if (vr_v6_prefix_is_ll(ip6->ip6_dst))
        return false;

    /* 0xFF02 is the multicast address used for NDP, DHCPv6 etc */
    if (ip6->ip6_dst[0] == 0xFF && ip6->ip6_dst[1] == 0x02) {
        /*
         * Bridge neighbor solicit for link-local addresses
         */
        if (ip6->ip6_nxt == VR_IP_PROTO_ICMP6)
            icmph = (struct vr_icmp *)((char *)ip6 + sizeof(struct vr_ip6));
        if (icmph && (icmph->icmp_type == VR_ICMP6_TYPE_NEIGH_SOL))
            return false;

        return true;
    }

    return false;
}

