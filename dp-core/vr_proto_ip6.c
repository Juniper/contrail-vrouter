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
#include <vr_fragment.h>

static bool
vr_ip6_fragment_tail(struct vr_ip6 *ip6)
{
    struct vr_ip6_frag *v6_frag;
    unsigned short frag, offset;
    bool more;

    if (ip6->ip6_nxt != VR_IP6_PROTO_FRAG)
        return false;

    v6_frag = (struct vr_ip6_frag *)(ip6 + 1);
    frag = ntohs(v6_frag->ip6_frag_offset);
    more = (frag & VR_IP6_MF) ? true : false;
    offset = frag > VR_IP6_FRAG_OFFSET_BITS;

    if (!more && offset)
        return true;

    return false;
}

struct vr_nexthop *
vr_inet6_ip_lookup(unsigned short vrf, uint8_t *ip6)
{
    uint32_t rt_prefix[4];

    struct vr_route_req rt;

    rt.rtr_req.rtr_vrf_id = vrf;
    rt.rtr_req.rtr_prefix = (uint8_t*)&rt_prefix;
    memcpy(rt.rtr_req.rtr_prefix, ip6, 16);
    rt.rtr_req.rtr_prefix_size = 16;
    rt.rtr_req.rtr_prefix_len = IP6_PREFIX_LEN;
    rt.rtr_req.rtr_family = AF_INET6;
    rt.rtr_req.rtr_marker_size = 0;
    rt.rtr_req.rtr_nh_id = 0;

    return vr_inet_route_lookup(vrf, &rt);
}


/*
 * The Icmp6 packet is considered DAD, if the source IP address in the
 * IPV6 header is NULL, and if no source link layer option is specified
 * after the Target address
 */
static bool
vr_icmp6_pkt_dad(struct vr_packet *pkt)
{
    struct vr_ip6 *ip6;

    ip6 = (struct vr_ip6 *)pkt_network_header(pkt);
    if ((!ip6) || (ip6->ip6_version != 6))
        return false;

    if (!vr_v6_prefix_null(ip6->ip6_src))
        return false;

    /* VR_IP6_ADDRESS_LEN is for Target address */
    if (pkt_len(pkt) > (sizeof(struct vr_icmp) + VR_IP6_ADDRESS_LEN))
        return false;

    return true;
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

void
vr_inet6_fill_flow_from_req(struct vr_flow *flow_p, vr_flow_req *req)
{
    uint64_t *dst;

    vr_fill_flow_common(flow_p, req->fr_flow_nh_id, req->fr_flow_proto,
            req->fr_flow_sport, req->fr_flow_dport, AF_INET6, VR_FLOW_KEY_ALL);

    dst = (uint64_t *)(flow_p->flow6_sip);
    *dst = req->fr_flow_sip_u;
    *(dst + 1) = req->fr_flow_sip_l;
    *(dst + 2) = req->fr_flow_dip_u;
    *(dst + 3) = req->fr_flow_dip_l;

    return;
}

void
vr_inet6_fill_rflow_from_req(struct vr_flow *flow_p, vr_flow_req *req)
{
    uint64_t *dst;

    vr_fill_flow_common(flow_p, req->fr_rflow_nh_id, req->fr_flow_proto,
            req->fr_rflow_sport, req->fr_rflow_dport, AF_INET6, VR_FLOW_KEY_ALL);

    dst = (uint64_t *)(flow_p->flow6_sip);
    *dst = req->fr_rflow_sip_u;
    *(dst + 1) = req->fr_rflow_sip_l;
    *(dst + 2) = req->fr_rflow_dip_u;
    *(dst + 3) = req->fr_rflow_dip_l;

    return;
}

void
vr_inet6_fill_flow(struct vr_flow *flow_p, unsigned short nh_id,
        unsigned char *ip, uint8_t proto, uint16_t sport, uint16_t dport,
        uint8_t valid_fkey_params)
{
    memset(flow_p, 0, VR_FLOW_IPV6_HASH_SIZE);
    valid_fkey_params &= VR_FLOW_KEY_ALL;

    vr_fill_flow_common(flow_p, nh_id, proto, sport, dport,
                        AF_INET6, valid_fkey_params);

    if (valid_fkey_params & VR_FLOW_KEY_SRC_IP)
        memcpy(flow_p->flow_ip, ip, VR_IP6_ADDRESS_LEN);

    if (valid_fkey_params & VR_FLOW_KEY_DST_IP)
        memcpy(flow_p->flow_ip + VR_IP6_ADDRESS_LEN,
               ip + VR_IP6_ADDRESS_LEN, VR_IP6_ADDRESS_LEN);

    return;
}

static void
vr_inet6_flow_swap(struct vr_flow *key_p)
{
    unsigned short port;
    uint8_t ip6_addr[VR_IP6_ADDRESS_LEN];

    if (key_p->flow6_proto != VR_IP_PROTO_ICMP6) {
        port = key_p->flow6_sport;
        key_p->flow6_sport = key_p->flow6_dport;
        key_p->flow6_dport = port;
    }

    memcpy(ip6_addr, key_p->flow6_sip, VR_IP6_ADDRESS_LEN);
    memcpy(key_p->flow6_sip, key_p->flow6_dip, VR_IP6_ADDRESS_LEN);
    memcpy(key_p->flow6_dip, ip6_addr, VR_IP6_ADDRESS_LEN);

    return;
}

bool
vr_inet6_flow_is_fat_flow(struct vrouter *router, struct vr_packet *pkt,
        struct vr_flow_entry *fe)
{
    if (!fe->fe_key.flow6_sport || !fe->fe_key.flow6_dport) {
        if ((fe->fe_key.flow6_proto == VR_IP_PROTO_TCP) ||
                (fe->fe_key.flow6_proto == VR_IP_PROTO_UDP) ||
                (fe->fe_key.flow6_proto == VR_IP_PROTO_SCTP)) {
            return true;
        }
    }

    return false;
}


static int
vr_inet6_proto_flow(struct vrouter *router, unsigned short vrf,
        struct vr_packet *pkt, uint16_t vlan, struct vr_ip6 *ip6,
        struct vr_flow *flow_p, uint8_t valid_fkey_params)
{
    int ret = 0;
    uint8_t ip6_nxt;
    unsigned short *t_hdr, sport, dport;
    unsigned short nh_id;
    struct vr_ip6_frag *v6_frag;

    struct vr_icmp *icmph;
    fat_flow_port_mask_t port_mask;

    t_hdr = (unsigned short *)((char *)ip6 + sizeof(struct vr_ip6));
    ip6_nxt = ip6->ip6_nxt;

    if (ip6_nxt == VR_IP6_PROTO_FRAG) {
        v6_frag = (struct vr_ip6_frag *)(ip6 + 1);
        ip6_nxt = v6_frag->ip6_frag_nxt;
        t_hdr = (unsigned short *)(v6_frag + 1);
    }

    if (ip6_nxt == VR_IP_PROTO_ICMP6) {
        icmph = (struct vr_icmp *)t_hdr;
        if (vr_icmp6_error(icmph)) {
            if ((unsigned char *)ip6 == pkt_network_header(pkt)) {
                ret = vr_inet6_form_flow(router, vrf, pkt, vlan,
                        (struct vr_ip6 *)(icmph + 1), flow_p, valid_fkey_params);
                if (ret)
                    return ret;

                vr_inet6_flow_swap(flow_p);
            } else {
                return -1;
            }

            return 0;
        } else if ((icmph->icmp_type == VR_ICMP6_TYPE_ECHO_REQ) ||
            (icmph->icmp_type == VR_ICMP6_TYPE_ECHO_REPLY)) {
            sport = icmph->icmp_eid;
            dport = ntohs(VR_ICMP6_TYPE_ECHO_REPLY);
        } else if ((icmph->icmp_type == VR_ICMP6_TYPE_NEIGH_SOL) ||
                (icmph->icmp_type == VR_ICMP6_TYPE_NEIGH_AD)) {
            pkt->vp_flags |= VP_FLAG_FLOW_SET;
            return 0;
        } else {
            sport = 0;
            dport = icmph->icmp_type;
        }
    } else if ((ip6_nxt == VR_IP_PROTO_TCP) ||
            (ip6_nxt == VR_IP_PROTO_UDP) ||
            (ip6_nxt == VR_IP_PROTO_SCTP)) {
        sport = *t_hdr;
        dport = *(t_hdr + 1);
    } else {
        sport = 0;
        dport = 0;
    }

    port_mask = vr_flow_fat_flow_lookup(router, pkt, ip6_nxt,
            sport, dport);
    switch (port_mask) {
    case SOURCE_PORT_MASK:
        sport = 0;
        break;

    case DESTINATION_PORT_MASK:
        dport = 0;
        break;

    case ALL_PORT_MASK:
        sport = dport = 0;
        break;

    default:
        break;
    }

    nh_id = vr_inet_flow_nexthop(pkt, vlan);
    vr_inet6_fill_flow(flow_p, nh_id, (unsigned char *)&ip6->ip6_src,
            ip6_nxt, sport, dport, valid_fkey_params);

    return 0;
}

static int
vr_inet6_fragment_flow(struct vrouter *router, unsigned short vrf,
        struct vr_packet *pkt, uint16_t vlan, struct vr_ip6 *ip6,
        struct vr_flow *flow_p, uint8_t valid_fkey_params)
{
    uint16_t sport, dport;
    unsigned short nh_id;
    struct vr_fragment *frag;
    struct vr_ip6_frag *v6_frag;

    frag = vr_fragment_get(router, vrf,
            (struct vr_ip *)(pkt_network_header(pkt)));
    if (!frag) {
        return -1;
    }

    v6_frag = (struct vr_ip6_frag *)(ip6 + 1);

    frag->f_received += (ntohs(ip6->ip6_plen) - sizeof(struct vr_ip6_frag));
    if (vr_ip6_fragment_tail(ip6)) {
        frag->f_expected = (((ntohs(v6_frag->ip6_frag_offset)) >>
            VR_IP6_FRAG_OFFSET_BITS) * 8) +
            ntohs(ip6->ip6_plen) - sizeof(struct vr_ip6_frag);
    }

    sport = frag->f_sport;
    dport = frag->f_dport;
    if (frag->f_received == frag->f_expected) {
        vr_fragment_del(router->vr_fragment_table, frag);
    }

    nh_id = vr_inet_flow_nexthop(pkt, vlan);
    vr_inet6_fill_flow(flow_p, nh_id, (unsigned char *)&ip6->ip6_src,
            v6_frag->ip6_frag_nxt, sport, dport, valid_fkey_params);

    return 0;
}

int
vr_inet6_form_flow(struct vrouter *router, unsigned short vrf,
        struct vr_packet *pkt, uint16_t vlan, struct vr_ip6 *ip6,
        struct vr_flow *flow_p, uint8_t valid_fkey_params)
{
    int ret = 0;

    if (vr_ip6_transport_header_valid(ip6)) {
        ret = vr_inet6_proto_flow(router, vrf, pkt, vlan, ip6, flow_p,
                valid_fkey_params);
    } else {
        ret = vr_inet6_fragment_flow(router, vrf, pkt, vlan, ip6,
                                        flow_p, valid_fkey_params);
    }

    return ret;

}


flow_result_t
vr_inet6_flow_lookup(struct vrouter *router, struct vr_packet *pkt,
                    struct vr_forwarding_md *fmd)
{
    int ret;
    bool lookup = false;
    struct vr_flow flow, *flow_p = &flow;
    struct vr_ip6 *ip6 = (struct vr_ip6 *)pkt_network_header(pkt);
    struct vr_packet *pkt_c;

    /*
     * if the packet has already done one round of flow lookup, there
     * is no point in doing it again, eh?
     */
    if (pkt->vp_flags & VP_FLAG_FLOW_SET)
        return FLOW_FORWARD;

    /*
     * if the interface is policy enabled, or if somebody else (eg:nexthop)
     * has requested for a policy lookup, packet has to go through a lookup
     */
    if ((pkt->vp_if->vif_flags & VIF_FLAG_POLICY_ENABLED) ||
            (pkt->vp_flags & VP_FLAG_FLOW_GET)) {
        lookup = true;
    }

    if (!lookup)
        return FLOW_FORWARD;

    ret = vr_inet6_form_flow(router, fmd->fmd_dvrf, pkt, fmd->fmd_vlan,
                                             ip6, flow_p, VR_FLOW_KEY_ALL);
    if (ret < 0) {
        if (!vr_ip6_transport_header_valid(ip6) && vr_enqueue_to_assembler) {
            vr_enqueue_to_assembler(router, pkt, fmd);
        } else {
            vr_pfree(pkt, VP_DROP_MISC);
        }
        return FLOW_CONSUMED;
    }

    if (pkt->vp_flags & VP_FLAG_FLOW_SET)
        return FLOW_FORWARD;

    if (vr_ip6_fragment_head(ip6)) {
        vr_v6_fragment_add(router, fmd->fmd_dvrf, ip6, flow_p->flow6_sport,
                flow_p->flow6_dport);
        if (vr_enqueue_to_assembler){
            pkt_c = vr_pclone(pkt);
            if (pkt_c) {
                vr_enqueue_to_assembler(router, pkt_c, fmd);
            }
        }
    }

    return vr_flow_lookup(router, flow_p, pkt, fmd);
}


int
vr_ip6_input(struct vrouter *router, struct vr_packet *pkt,
             struct vr_forwarding_md *fmd)
{
    struct vr_ip6 *ip6;
    unsigned short *t_hdr, sport, dport;

    ip6 = (struct vr_ip6 *)pkt_network_header(pkt);
    if (fmd->fmd_dscp < 0)
        fmd->fmd_dscp = vr_inet6_get_tos(ip6);

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
    uint16_t adv_flags = 0;

    struct vr_eth *eth;
    struct vr_ip6 *ip6;
    struct vr_icmp *icmph;
    struct vr_neighbor_option *nopt;


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

    /* Update ICMP header and options */
    icmph->icmp_type = VR_ICMP6_TYPE_NEIGH_AD;
    adv_flags |= VR_ICMP6_NEIGH_AD_FLAG_SOLCITED;
    if (fmd->fmd_flags & FMD_FLAG_MAC_IS_MY_MAC)
        adv_flags |= VR_ICMP6_NEIGH_AD_FLAG_ROUTER;

    icmph->icmp_eid = htons(adv_flags);

    /* length in units of 8 octets */
    nopt->vno_type = TARGET_LINK_LAYER_ADDRESS_OPTION;
    nopt->vno_length = (sizeof(struct vr_neighbor_option) + VR_ETHER_ALEN) / 8;
    VR_MAC_COPY(nopt->vno_value, dmac);

    icmph->icmp_csum =
        ~(vr_icmp6_checksum(ip6, icmph));

    vr_mac_reply_send(pkt, fmd);

    return;
}

mac_response_t
vm_neighbor_request(struct vr_interface *vif, struct vr_packet *pkt,
        struct vr_forwarding_md *fmd, unsigned char *dmac)
{
    uint32_t rt6_prefix[4];
    unsigned char mac[VR_ETHER_ALEN];
    struct vr_icmp *icmph;
    struct vr_route_req rt;

    if (fmd->fmd_vlan != VLAN_ID_INVALID)
        return MR_FLOOD;

    /* We let DAD packets bridged */
    if (vr_icmp6_pkt_dad(pkt))
        return MR_NOT_ME;


    memset(&rt, 0, sizeof(rt));
    rt.rtr_req.rtr_vrf_id = fmd->fmd_dvrf;
    rt.rtr_req.rtr_family = AF_INET6;
    rt.rtr_req.rtr_prefix = (uint8_t *)&rt6_prefix;
    rt.rtr_req.rtr_prefix_size = 16;
    rt.rtr_req.rtr_prefix_len = IP6_PREFIX_LEN;
    rt.rtr_req.rtr_mac = mac;

    icmph = (struct vr_icmp *)pkt_data(pkt);
    memcpy(rt.rtr_req.rtr_prefix, icmph->icmp_data, 16);

    vr_inet_route_lookup(fmd->fmd_dvrf, &rt);

    if ((vif->vif_flags & VIF_FLAG_MAC_PROXY) ||
            (rt.rtr_req.rtr_label_flags & VR_RT_ARP_PROXY_FLAG)) {
        return vr_get_proxy_mac(pkt, fmd, &rt, dmac);
    }

    return MR_FLOOD;
}

int
vr_neighbor_input(struct vr_packet *pkt, struct vr_forwarding_md *fmd,
        unsigned char *eth_dmac)
{
    int handled = 1;
    uint32_t pull_len;
    unsigned char dmac[VR_ETHER_ALEN];
    mac_response_t ndisc_result;
    struct vr_ip6 *ip6;
    struct vr_icmp *icmph;
    struct vr_packet *pkt_c;
    struct vr_interface *vif = pkt->vp_if;

    pull_len = sizeof(*ip6);
    if (pkt->vp_len < pull_len) {
        vr_pfree(pkt, VP_DROP_INVALID_PACKET);
        return handled;
    }

    ip6 = (struct vr_ip6 *)pkt_data(pkt);
    if (ip6->ip6_nxt != VR_IP_PROTO_ICMP6)
        return !handled;

    if (pkt->vp_len < pull_len + sizeof(struct vr_icmp))
        goto drop;

    pkt_pull(pkt, pull_len);
    icmph = (struct vr_icmp *)pkt_data(pkt);
    if (icmph->icmp_type != VR_ICMP6_TYPE_NEIGH_SOL) {
        pkt_push(pkt, pull_len);
        return !handled;
    }

    VR_MAC_COPY(dmac, eth_dmac);

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

    case MR_MIRROR:
        pkt_c = vr_pclone(pkt);
        if (pkt_c)
            vr_trap(pkt_c, fmd->fmd_dvrf, AGENT_TRAP_ARP, NULL);

        handled = false;
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

l4_pkt_type_t
vr_ip6_well_known_packet(struct vr_packet *pkt)
{
    unsigned char *data = pkt_data(pkt);
    struct vr_ip6 *ip6;
    struct vr_udp *udph = NULL;
    struct vr_icmp *icmph = NULL;

    if ((pkt->vp_type != VP_TYPE_IP6) ||
         (!(pkt->vp_flags & VP_FLAG_MULTICAST)))
        return L4_TYPE_UNKNOWN;

    ip6 = (struct vr_ip6 *)data;

    if (vr_v6_prefix_is_ll(ip6->ip6_dst))
        return L4_TYPE_UNKNOWN;

    /* 0xFF02 is the multicast address used for NDP, DHCPv6 etc */
    if (ip6->ip6_dst[0] == 0xFF && ip6->ip6_dst[1] == 0x02) {
        /*
         * Bridge neighbor solicit for link-local addresses
         */
        if (ip6->ip6_nxt == VR_IP_PROTO_ICMP6) {
            icmph = (struct vr_icmp *)((char *)ip6 + sizeof(struct vr_ip6));
            if (icmph && (icmph->icmp_type == VR_ICMP6_TYPE_ROUTER_SOL))
                return L4_TYPE_ROUTER_SOLICITATION;
            if (icmph && (icmph->icmp_type == VR_ICMP6_TYPE_NEIGH_SOL))
                return L4_TYPE_NEIGHBOUR_SOLICITATION;
            if (icmph && (icmph->icmp_type == VR_ICMP6_TYPE_NEIGH_AD))
                return L4_TYPE_NEIGHBOUR_ADVERTISEMENT;
        }

        if (ip6->ip6_nxt == VR_IP_PROTO_UDP) {
            udph = (struct vr_udp *)((char *)ip6 + sizeof(struct vr_ip6));
            if (udph && (udph->udp_sport == htons(VR_DHCP6_SRC_PORT)))
                return L4_TYPE_DHCP_REQUEST;
        }
    }

    return L4_TYPE_UNKNOWN;
}

