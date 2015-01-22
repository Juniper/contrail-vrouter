/*
 * vr_proto_ip6.c -- ip6 handler
 *
 * Copyright (c) 2014, Juniper Networks, Inc.
 * All rights reserved
 */
#include <vr_os.h>
#include <vr_types.h>
#include <vr_packet.h>

#include <vr_interface.h>
#include <vr_datapath.h>
#include <vr_ip_mtrie.h>
#include <vr_bridge.h>

static int
vr_v6_prefix_is_ll(uint8_t prefix[])
{
    if ((prefix[0] == 0xFE) && (prefix[1] == 0x80)) {
        return true;
    }
    return false;
}


/* TODO: consolidate all sum calculation routines */
static inline uint16_t
vr_sum(unsigned char *buf, unsigned int length)
{
   int num_words;
   uint32_t total;
   uint16_t *ptr;

   total = 0;
   ptr = (uint16_t *)buf;
   num_words = (length + 1) / 2;

   while (num_words--)
       total += *ptr++;

   while (total & 0xffff0000)
       total = (total >> 16) + (total & 0xffff);

   return (uint16_t)total;
}

static inline uint16_t
vr_ip6_pseudo_header_sum(struct vr_ip6 *ip6)
{
   struct vr_ip6_pseudo ip6_ph;

   memcpy(ip6_ph.ip6_src, ip6->ip6_src, VR_IP6_ADDRESS_LEN);
   memcpy(ip6_ph.ip6_dst, ip6->ip6_dst, VR_IP6_ADDRESS_LEN);
   /*
    * XXX: length should be the length of (l4 header + data). But here, we
    * use the ip6 payload length, assuming that there are no extension
    * headers. This asusmption has to be fixed when we extend ipv6 support.
    */
   ip6_ph.ip6_l4_length = ip6->ip6_plen;
   ip6_ph.ip6_zero = 0;
   ip6_ph.ip6_zero_nh = (ip6->ip6_nxt << 24);

   return vr_sum((unsigned char *)&ip6_ph, sizeof(ip6_ph));
}

uint16_t
vr_icmp6_checksum(struct vr_ip6 *ip6, struct vr_icmp *icmph)
{
    uint16_t sum[2];

    sum[0] = vr_ip6_pseudo_header_sum(ip6);

    icmph->icmp_csum = 0;
    sum[1] = vr_sum((unsigned char *)icmph, ntohs(ip6->ip6_plen));

    return vr_sum((unsigned char *)sum, sizeof(sum));
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

void
vr_neighbor_proxy(struct vr_packet *pkt, struct vr_forwarding_md *fmd,
        unsigned char *dmac)
{
    struct vr_eth *eth;
    struct vr_ip6 *ip6;
    struct vr_icmp *icmph;
    struct vr_neighbor_option *nopt;
    struct vr_interface *vif = pkt->vp_if;


    icmph = (struct vr_icmp *)pkt_data(pkt);
    nopt = (struct vr_neighbor_option *)((unsigned char *)icmph +
            sizeof(*icmph) + VR_IP6_ADDRESS_LEN);

    eth = (struct vr_eth *)pkt_push(pkt, sizeof(*ip6) + sizeof(*eth));
    if (!eth) {
        vr_pfree(pkt, VP_DROP_PUSH);
        return;
    }
    ip6 = (struct vr_ip6 *)((unsigned char *)eth + sizeof(*eth));


    /* Update Ethernet headr */
    VR_MAC_COPY(eth->eth_dmac, nopt->vno_value);
    VR_MAC_COPY(eth->eth_smac, dmac);
    eth->eth_proto = htons(VR_ETH_PROTO_IP6);

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
    VR_MAC_COPY(nopt->vno_value, dmac);


    icmph->icmp_csum =
        ~(vr_icmp6_checksum(ip6, icmph));

    vr_bridge_input(vif->vif_router, pkt, fmd);

    return;
}

mac_response_t
vm_neighbor_request(struct vr_interface *vif, struct vr_packet *pkt,
        struct vr_forwarding_md *fmd, unsigned char *dmac)
{
    uint32_t rt6_prefix[4], pull_len;
    unsigned char mac[VR_ETHER_ALEN];

    struct vr_icmp *icmph;
    struct vr_route_req rt;
    struct vr_neighbor_option *nopt;

    icmph = (struct vr_icmp *)pkt_data(pkt);
    pull_len = sizeof(*icmph) + VR_IP6_ADDRESS_LEN;
    nopt = (struct vr_neighbor_option *)(pkt_data(pkt) + pull_len);
    /* We let DAD packets bridged */
    if (IS_MAC_ZERO(nopt->vno_value))
        return MR_NOT_ME;


    memset(&rt, 0, sizeof(rt));
    rt.rtr_req.rtr_vrf_id = fmd->fmd_dvrf;
    rt.rtr_req.rtr_family = AF_INET6;
    rt.rtr_req.rtr_prefix = (uint8_t *)&rt6_prefix;
    memcpy(rt.rtr_req.rtr_prefix, icmph->icmp_data, 16);
    rt.rtr_req.rtr_prefix_size = 16;
    rt.rtr_req.rtr_prefix_len = IP6_PREFIX_LEN;
    rt.rtr_req.rtr_mac = mac;

    vr_inet_route_lookup(fmd->fmd_dvrf, &rt);

    if (rt.rtr_req.rtr_label_flags & VR_RT_ARP_PROXY_FLAG)
        return vr_get_proxy_mac(pkt, fmd, &rt, dmac);

    return MR_FLOOD;
}

int
vr_neighbor_input(struct vr_packet *pkt, struct vr_forwarding_md *fmd)
{
    int handled = 1;
    uint32_t pull_len;
    unsigned char dmac[VR_ETHER_ALEN];
    mac_response_t ndisc_result;

    struct vr_ip6 *ip6;
    struct vr_icmp *icmph;
    struct vr_packet *pkt_c;
    struct vr_neighbor_option *nopt;
    struct vr_interface *vif = pkt->vp_if;

    pull_len = sizeof(*ip6);
    if (pkt->vp_len < pull_len) {
        vr_pfree(pkt, VP_DROP_INVALID_PACKET);
        return handled;
    }

    ip6 = (struct vr_ip6 *)pkt_data(pkt);
    if (ip6->ip6_nxt != VR_IP_PROTO_ICMP6)
        return !handled;

    /* Link local neighbour discovery is bridged */
    if (vr_v6_prefix_is_ll(ip6->ip6_dst))
        return !handled;

    if (pkt->vp_len < pull_len + sizeof(struct vr_icmp))
        goto drop;

    pkt_pull(pkt, pull_len);
    icmph = (struct vr_icmp *)pkt_data(pkt);
    if (icmph->icmp_type != VR_ICMP6_TYPE_NEIGH_SOL) {
        pkt_push(pkt, pull_len);
        return !handled;
    }

    if (pkt->vp_len < (sizeof(struct vr_icmp) + VR_IP6_ADDRESS_LEN +
                sizeof(struct vr_neighbor_option)))
        goto drop;

    pull_len = sizeof(*icmph) + VR_IP6_ADDRESS_LEN;
    if (pkt->vp_len < (pull_len + sizeof(struct vr_neighbor_option)))
        goto drop;

    nopt = (struct vr_neighbor_option *)(pkt_data(pkt) + pull_len);
    if (pkt->vp_len < (pull_len + (nopt->vno_length * 8)))
        goto drop;

    if (nopt->vno_type != SOURCE_LINK_LAYER_ADDRESS_OPTION)
        goto drop;

    ndisc_result = vif->vif_mac_request(vif, pkt, fmd, dmac);
    switch (ndisc_result) {
    case MR_PROXY:
        vr_neighbor_proxy(pkt, fmd, dmac);
        break;

    case MR_XCONNECT:
        vif_xconnect(pkt->vp_if, pkt, fmd);
        break;

    case MR_TRAP_X:
        pkt_c = vr_pclone(pkt);
        if (pkt_c)
            vif_xconnect(pkt->vp_if, pkt_c, fmd);

        vr_trap(pkt, fmd->fmd_dvrf, AGENT_TRAP_ARP, NULL);
        break;

    case MR_TRAP:
        vr_trap(pkt, fmd->fmd_dvrf, AGENT_TRAP_ARP, NULL);
        break;

    case MR_DROP:
        vr_pfree(pkt, VP_DROP_INVALID_ARP);
        break;

    case MR_FLOOD:
    default:
        handled = false;
        break;
    }

    if (!handled)
        pkt_push(pkt, pull_len);

    return handled;

drop:
    vr_pfree(pkt, VP_DROP_INVALID_PACKET);
    return handled;
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
    struct vr_udp *udph = NULL;
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
        if (ip6->ip6_nxt == VR_IP_PROTO_ICMP6) {
            icmph = (struct vr_icmp *)((char *)ip6 + sizeof(struct vr_ip6));
            if (icmph && (icmph->icmp_type == VR_ICMP6_TYPE_ROUTER_SOL))
                return true;
        } else if (ip6->ip6_nxt == VR_IP_PROTO_UDP) {
            udph = (struct vr_udp *)((char *)ip6 + sizeof(struct vr_ip6));
            if (udph && (udph->udp_sport == htons(VR_DHCP6_SRC_PORT)))
                return true;
        }
    }

    return false;
}

