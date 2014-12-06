/*
 * vr_datapath.c -- data path inside the router
 *
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#include <vr_os.h>
#include <vr_bridge.h>
#include <vr_datapath.h>
#include <vr_packet.h>
#include <vr_mirror.h>

extern unsigned int vr_inet_route_flags(unsigned int, unsigned int);

static inline bool
vr_grat_arp(struct vr_arp *sarp)
{
    if (sarp->arp_spa == sarp->arp_dpa)
        return true;
    return false;
}

static int 
vr_v6_prefix_is_ll(uint8_t prefix[])  
{
    if ((prefix[0] == 0xFE) && (prefix[1] == 0x80)) {
        return true;
    }
    return false;
}


static int
vr_arp_request_treatment(struct vr_interface *vif, struct vr_arp *arp,
                                                   struct vr_nexthop **ret_nh)
{
    struct vr_route_req rt;
    struct vr_nexthop *nh;
    uint32_t rt_prefix;

    /*
     * Packet from VM :
     *       - If no source address DROP
     *       - If L3 route exists (VR_ETH_PROTO_VLAN)ROXY
     *       - If no L3 route FLOOD
     *       - If no route DROP
     *       - If GRAT ARP, ideally should be flooded to hosts behind TOR
     *             but dropped as of now
     *
     * Packet from Vhost
     *       - If to Link Local IP PROXY
     *       - else Xconnect including GRAT
     *
     * Packet from Fabric
     *       - If to Vhost IP Proxy
     *       - If grat ARP Trap to Agent and Xconnect
     *       - else DROP
     *
     * Packet from Xen or VGW, PROXY
     */

    if (vif_mode_xconnect(vif))
        return PKT_ARP_XCONNECT;


    if (vif_is_virtual(vif))
        /*
         * some OSes send arp queries with zero SIP before taking ownership
         * of the DIP
         */
        if (!arp->arp_spa)
            return PKT_ARP_DROP;

    if (vif->vif_type == VIF_TYPE_XEN_LL_HOST ||
            vif->vif_type == VIF_TYPE_GATEWAY)
        return PKT_ARP_PROXY;

    if (vif->vif_type == VIF_TYPE_HOST) {
        if (IS_LINK_LOCAL_IP(arp->arp_dpa))
            return PKT_ARP_PROXY;
    }

    if (vr_grat_arp(arp) && (vif->vif_type == VIF_TYPE_PHYSICAL)) {
        return PKT_ARP_TRAP_XCONNECT;
    }

    rt.rtr_req.rtr_vrf_id = vif->vif_vrf;
    rt.rtr_req.rtr_prefix = (uint8_t*)&rt_prefix;
    *(uint32_t*)rt.rtr_req.rtr_prefix = (arp->arp_dpa);
    rt.rtr_req.rtr_prefix_size = 4;
    rt.rtr_req.rtr_prefix_len = 32;
    rt.rtr_req.rtr_nh_id = 0;
    rt.rtr_req.rtr_label_flags = 0;
    rt.rtr_req.rtr_marker_size = 0;

    nh = vr_inet_route_lookup(vif->vif_vrf, &rt, NULL);

    if (vr_grat_arp(arp) && vif_is_virtual(vif)) {
        if (rt.rtr_req.rtr_label_flags & VR_RT_ARP_TRAP_FLAG) {
            return PKT_ARP_TRAP;
        }
        return PKT_ARP_DROP;
    }

    if (!nh || nh->nh_type == NH_DISCARD)
        return PKT_ARP_DROP;

    if (rt.rtr_req.rtr_label_flags & VR_RT_HOSTED_FLAG)
        return PKT_ARP_PROXY;

    /*
     * If an L3VPN route is learnt, we need to proxy
     */
    if (vif_is_virtual(vif)) {
        if (nh->nh_type == NH_TUNNEL)
            return PKT_ARP_PROXY;
        /*
         * If not l3 vpn route, we default to flooding
         */
        if ((nh->nh_type == NH_COMPOSITE) &&
                (nh->nh_flags & NH_FLAG_MCAST)) {
            if (ret_nh)
                *ret_nh = nh;
            return PKT_ARP_FLOOD;
        }
    }

    if (vif->vif_type == VIF_TYPE_HOST)
        return PKT_ARP_XCONNECT;

    return PKT_ARP_DROP;
}

static int
vr_handle_arp_request(unsigned short vrf, struct vr_arp *sarp,
                      struct vr_packet *pkt, struct vr_forwarding_md *fmd)
{
    struct vr_packet *cloned_pkt;
    struct vr_interface *vif = pkt->vp_if;
    unsigned short proto = htons(VR_ETH_PROTO_ARP);
    struct vr_eth *eth;
    unsigned short *eth_proto;
    unsigned short pull_tail_len = VR_ETHER_HLEN;
    struct vr_arp *arp;
    unsigned int dpa;
    int arp_result;
    struct vr_nexthop *nh;

    arp_result = vr_arp_request_treatment(vif, sarp, &nh);

    switch (arp_result) {
    case PKT_ARP_PROXY:

        pkt_reset(pkt);

        eth = (struct vr_eth *)pkt_data(pkt);
        memcpy(eth->eth_dmac, sarp->arp_sha, VR_ETHER_ALEN);
        memcpy(eth->eth_smac, vif->vif_mac, VR_ETHER_ALEN);
        eth_proto = &eth->eth_proto;
        if (vif_is_vlan(vif)) {
            if (vif->vif_ovlan_id) {
                *eth_proto = htons(VR_ETH_PROTO_VLAN);
                eth_proto++;
                *eth_proto = htons(vif->vif_ovlan_id);
                eth_proto++;
                pull_tail_len += sizeof(struct vr_vlan_hdr);
            }
        }
        memcpy(eth_proto, &proto, sizeof(proto));

        arp = (struct vr_arp *)pkt_pull_tail(pkt, pull_tail_len);

        sarp->arp_op = htons(VR_ARP_OP_REPLY);
        memcpy(sarp->arp_sha, vif->vif_mac, VR_ETHER_ALEN);
        memcpy(sarp->arp_dha, eth->eth_dmac, VR_ETHER_ALEN);
        dpa = sarp->arp_dpa;
        memcpy(&sarp->arp_dpa, &sarp->arp_spa, sizeof(sarp->arp_dpa));
        memcpy(&sarp->arp_spa, &dpa, sizeof(sarp->arp_spa));

        memcpy(arp, sarp, sizeof(*sarp));
        pkt_pull_tail(pkt, sizeof(*arp));

        vif->vif_tx(vif, pkt);
        break;
    case PKT_ARP_XCONNECT:
        vif_xconnect(vif, pkt);
        break;
    case PKT_ARP_TRAP_XCONNECT:
        cloned_pkt = vr_pclone(pkt);
        if (cloned_pkt) {
            vr_preset(cloned_pkt);
            vif_xconnect(vif, cloned_pkt);
        }
        vr_trap(pkt, vrf, AGENT_TRAP_ARP, NULL);
        break;
    case PKT_ARP_TRAP:
        vr_preset(pkt);
        vr_trap(pkt, vrf, AGENT_TRAP_ARP, NULL);
        break;
    case PKT_ARP_FLOOD:
        if (nh) {
            vr_preset(pkt);
            nh_output(vrf, pkt, nh, fmd);
            break;
        }
        /* Fall through */
    case PKT_ARP_DROP:
    default:
        vr_pfree(pkt, VP_DROP_ARP_NOT_ME);
    }

    return 0;
}

/*
 * arp responses from vhostX need to be cross connected. nothing
 * needs to be done for arp responses from VMs, while responses
 * from fabric needs to be Xconnected and sent to agent
 */
static int
vr_handle_arp_reply(unsigned short vrf, struct vr_arp *sarp,
                    struct vr_packet *pkt, struct vr_forwarding_md *fmd)
{
    struct vr_interface *vif = pkt->vp_if;
    struct vr_packet *cloned_pkt;
    unsigned int rt_flags;

    if (vif_mode_xconnect(vif) || vif->vif_type == VIF_TYPE_HOST)
        return vif_xconnect(vif, pkt);

    if (vif->vif_type != VIF_TYPE_PHYSICAL) {
        if (vif_is_virtual(vif)) {
            rt_flags = vr_inet_route_flags(vrf, sarp->arp_dpa);
            if (rt_flags & VR_RT_ARP_TRAP_FLAG) {
                vr_preset(pkt);
                return vr_trap(pkt, vrf, AGENT_TRAP_ARP, NULL);
            }
        }
        vr_pfree(pkt, VP_DROP_INVALID_IF);
        return 0;
    }


    cloned_pkt = vr_pclone(pkt);
    if (cloned_pkt) {
        vr_preset(cloned_pkt);
        vif_xconnect(vif, cloned_pkt);
    }

    return vr_trap(pkt, vrf, AGENT_TRAP_ARP, NULL);
}

/*
 * This funciton parses the ethernet packet and assigns the
 * pkt->vp_type, network protocol of the packet. The ethernet header can
 * start from an offset from vp_data
 */
int
vr_pkt_type(struct vr_packet *pkt, unsigned short offset)
{
    unsigned char *eth = pkt_data(pkt) + offset;
    unsigned short eth_proto;
    int pull_len, pkt_len = pkt_head_len(pkt) - offset;
    struct vr_vlan_hdr *vlan;

    pull_len = VR_ETHER_HLEN;
    if (pkt_len < pull_len)
        return -1;

    pkt->vp_flags &= ~(VP_FLAG_MULTICAST);

    /* L2 broadcast/multicast packets are multicast packets */
    if (IS_MAC_BMCAST(eth))
        pkt->vp_flags |= VP_FLAG_MULTICAST;

    eth_proto = ntohs(*(unsigned short *)(eth + VR_ETHER_PROTO_OFF));
    while (eth_proto == VR_ETH_PROTO_VLAN) {
        if (pkt_len < (pull_len + sizeof(*vlan)))
            return -1;
        vlan = (struct vr_vlan_hdr *)(eth + pull_len);
        eth_proto = ntohs(vlan->vlan_proto);
        pull_len += sizeof(*vlan);
    }


    pkt_set_network_header(pkt, pkt->vp_data + offset + pull_len);
    pkt->vp_type = vr_eth_proto_to_pkt_type(eth_proto);

    return 0;
}

int
vr_arp_input(unsigned short vrf, struct vr_packet *pkt,
                            struct vr_forwarding_md *fmd)
{
    struct vr_arp sarp;

    memcpy(&sarp, pkt_data(pkt), sizeof(struct vr_arp));
    switch (ntohs(sarp.arp_op)) {
    case VR_ARP_OP_REQUEST:
        vr_handle_arp_request(vrf, &sarp, pkt, fmd);
        break;

    case VR_ARP_OP_REPLY:
        vr_handle_arp_reply(vrf, &sarp, pkt, fmd);
        break;

    default:
        vr_pfree(pkt, VP_DROP_INVALID_ARP);
    }

    return 1;
}

int
vr_trap(struct vr_packet *pkt, unsigned short trap_vrf,
        unsigned short trap_reason, void *trap_param)
{
    struct vr_interface *vif = pkt->vp_if;
    struct vrouter *router = vif->vif_router;
    struct agent_send_params params;

    if (router->vr_agent_if && router->vr_agent_if->vif_send) {
        params.trap_vrf = trap_vrf;
        params.trap_reason = trap_reason;
        params.trap_param = trap_param;
        return router->vr_agent_if->vif_send(router->vr_agent_if, pkt,
                        &params);
    } else {
        vr_pfree(pkt, VP_DROP_TRAP_NO_IF);
    }

    return 0;
}

static inline bool
vr_my_pkt(unsigned char *pkt_mac, struct vr_interface *vif)
{
    /*
     * Packet is destined to us if:
     * 1) IF destination MAC is our Mac
     * 2) If VIF is service interface
     */
    if (VR_MAC_CMP(pkt_mac, vif->vif_mac) || vif_is_service(vif))
        return true;

    return false;
}

/*
 * vr_interface_input() is invoked if a packet ingresses an interface.
 * This function demultiplexes the packet to right input
 * function depending on the protocols enabled on the VIF
 */
unsigned int
vr_virtual_input(unsigned short vrf, struct vr_interface *vif,
                       struct vr_packet *pkt, unsigned short vlan_id)
{
    struct vr_forwarding_md fmd;
    unsigned char *data = pkt_data(pkt);
    int reason, handled = 0;
    unsigned short pull_len, overlay_len = VROUTER_L2_OVERLAY_LEN;
    bool my_pkt;

    vr_init_forwarding_md(&fmd);
    fmd.fmd_vlan = vlan_id;

    if (vif->vif_flags & VIF_FLAG_MIRROR_RX) {
        fmd.fmd_dvrf = vif->vif_vrf;
        vr_mirror(vif->vif_router, vif->vif_mirror_id, pkt, &fmd);
    }

    if (vr_pkt_type(pkt, 0) < 0) {
        vif_drop_pkt(vif, pkt, 1);
        return 0;
    }

    my_pkt = vr_my_pkt(data, vif);

    pull_len = pkt_get_network_header_off(pkt) - pkt_head_space(pkt);
    pkt_pull(pkt, pull_len);
    pkt_set_inner_network_header(pkt, pkt_get_network_header_off(pkt));

    if (pkt->vp_type == VP_TYPE_IP || pkt->vp_type == VP_TYPE_IP6) {
        if (my_pkt)
            overlay_len = VROUTER_OVERLAY_LEN;
        if (vr_from_vm_mss_adj && vr_pkt_from_vm_tcp_mss_adj) {
            if ((reason = vr_pkt_from_vm_tcp_mss_adj(pkt, overlay_len))) {
                vr_pfree(pkt, reason);
                return 0;
            }
        }
    }

    if (my_pkt) {
        handled = vr_l3_input(vrf, pkt, &fmd);
        if (handled)
            return 0;
    }

    if (pkt_push(pkt, pull_len)) {
        handled = vr_l2_input(vrf, pkt, &fmd);
        if (handled)
            return 0;
    }

    vif_drop_pkt(vif, pkt, 1);
    return 0;
}

unsigned int
vr_fabric_input(struct vr_interface *vif, struct vr_packet *pkt,
                unsigned short vlan_id)
{
    int handled = 0;
    unsigned short pull_len;
    struct vr_forwarding_md fmd;

    if (vr_pkt_type(pkt, 0) < 0) {
        vif_drop_pkt(vif, pkt, 1);
        return 0;
    }

    pull_len = pkt_get_network_header_off(pkt) - pkt_head_space(pkt);

    vr_init_forwarding_md(&fmd);
    fmd.fmd_vlan = vlan_id;

    pkt_pull(pkt, pull_len);
    handled = vr_l3_input(vif->vif_vrf, pkt, &fmd);
    if (!handled)
        return vif_xconnect(vif, pkt);

    return 0;
}


int
vr_l3_input(unsigned short vrf, struct vr_packet *pkt,
                              struct vr_forwarding_md *fmd)
{
    struct vr_interface *vif = pkt->vp_if;

    if (pkt->vp_type == VP_TYPE_IP) {
        vr_flow_inet_input(vif->vif_router, vrf, pkt, VR_ETH_PROTO_IP, fmd);
        return 1;
    } else if (pkt->vp_type == VP_TYPE_IP6) {
         vr_flow_inet6_input(vif->vif_router, vrf, pkt, VR_ETH_PROTO_IP6, fmd);
         return 1;
    } else if (pkt->vp_type == VP_TYPE_ARP) {
        return vr_arp_input(vrf, pkt, fmd);
    }
    return 0;
}

unsigned int
vr_l2_input(unsigned short vrf, struct vr_packet *pkt,
            struct vr_forwarding_md *fmd)
{
    int pull_len;
    struct vr_interface *vif = pkt->vp_if;


    /* if non-vlan tagged and L3 enabled */
    if ((fmd->fmd_vlan == VLAN_ID_INVALID) &&
        (vif->vif_flags & VIF_FLAG_L3_ENABLED)) {

        /* Go to L3 header for L3 processing */
        pull_len = pkt_get_network_header_off(pkt) - pkt_head_space(pkt);
        if (!pkt_pull(pkt, pull_len)) {
            vr_pfree(pkt, VP_DROP_INVALID_PACKET);
            return 1;
        }

        /* If Arp or L3 well known packet from Virtual VIF */
        if ((pkt->vp_type == VP_TYPE_ARP) ||
                (vif_is_virtual(vif) && vr_l3_well_known_packet(vrf, pkt))) {
            if (vr_l3_input(vrf, pkt, fmd))
                return 1;
        }

        /* Restore back the L2 headers */
        if (!pkt_push(pkt, pull_len)) {
            vr_pfree(pkt, VP_DROP_PULL);
            return 1;
        }
    }

    if (!(vif->vif_flags & VIF_FLAG_L2_ENABLED))
        return 0;

    pkt->vp_flags |= VP_FLAG_L2_PAYLOAD;
    vr_bridge_input(pkt->vp_if->vif_router, vrf, pkt, fmd);
    return 1;
}


int
vr_tor_input(unsigned short vrf, struct vr_packet *pkt,
        struct vr_forwarding_md *fmd)
{
    struct vr_route_req rt;
    struct vr_arp *arp;
    struct vr_interface *vif = pkt->vp_if;
    struct vr_nexthop *nh;
    unsigned int rt_prefix, pull_len;
    struct vr_eth *eth;


    if (pkt->vp_type == VP_TYPE_IP) {
        pull_len = pkt_get_network_header_off(pkt) - pkt_head_space(pkt);
        if (pkt_pull(pkt, pull_len) < 0) {
            vr_pfree(pkt, VP_DROP_PULL);
            return 1;
        }
        if (vr_l3_well_known_packet(vrf, pkt)) {
            vr_trap(pkt, vrf,  AGENT_TRAP_L3_PROTOCOLS, NULL);
            return 1;
        }
        pkt_push(pkt, pull_len);
    } else if (pkt->vp_type == VP_TYPE_ARP) {
        arp = (struct vr_arp *)pkt_network_header(pkt);

        /* Dnot handle ARP reply */
        if (arp->arp_op == VR_ARP_OP_REPLY) {
            goto unhandled;
        }

        rt.rtr_req.rtr_vrf_id = vrf;
        rt.rtr_req.rtr_prefix = (uint8_t *)&rt_prefix;
        *(uint32_t*)rt.rtr_req.rtr_prefix = arp->arp_dpa;
        rt.rtr_req.rtr_prefix_size = 4;
        rt.rtr_req.rtr_prefix_len = 32;
        rt.rtr_req.rtr_nh_id = 0;
        rt.rtr_req.rtr_label_flags = 0;
        rt.rtr_req.rtr_marker_size = 0;

        nh = vr_inet_route_lookup(vrf, &rt, NULL);
        if (!nh || nh->nh_type ==  NH_DISCARD)
            goto unhandled;

        if (rt.rtr_req.rtr_label_flags & VR_RT_HOSTED_FLAG) {
            eth = (struct vr_eth *)pkt_data(pkt);
            VR_MAC_COPY(eth->eth_dmac, eth->eth_smac);
            VR_MAC_COPY(eth->eth_smac, vif->vif_mac);
            arp->arp_op = htons(VR_ARP_OP_REPLY);
            VR_MAC_COPY(arp->arp_dha, arp->arp_sha);
            VR_MAC_COPY(arp->arp_sha, vif->vif_mac);
            arp->arp_dpa = arp->arp_spa;
            arp->arp_spa = rt_prefix;
            vr_bridge_input(vrouter_get(0), vrf, pkt, NULL);
            return 1;
        }
    }

unhandled:
    return 0;
}

bool
vr_l3_well_known_packet(unsigned short vrf, struct vr_packet *pkt)
{
    unsigned char *data = pkt_data(pkt);
    struct vr_ip *iph;
    struct vr_ip6 *ip6;
    struct vr_udp *udph;
    struct vr_icmp *icmph = NULL;

    if (!(pkt->vp_flags & VP_FLAG_MULTICAST))
        return false;

    if (pkt->vp_type == VP_TYPE_IP) {
        iph = (struct vr_ip *)data;
        if ((iph->ip_proto == VR_IP_PROTO_UDP) &&
                              vr_ip_transport_header_valid(iph)) {
            udph = (struct vr_udp *)(data + iph->ip_hl * 4);
            if (udph->udp_sport == htons(VR_DHCP_SRC_PORT))
                return true;
        }
    } else if (pkt->vp_type == VP_TYPE_IP6) {
        ip6 = (struct vr_ip6 *)data;
        // Bridge link-local traffic
        if (vr_v6_prefix_is_ll(ip6->ip6_dst))
            return false;

        // 0xFF02 is the multicast address used for NDP, DHCPv6 etc
        if (ip6->ip6_dst[0] == 0xFF && ip6->ip6_dst[1] == 0x02) {
            /*
             * Bridge neighbor solicit for link-local addresses
             */
            if (ip6->ip6_nxt == VR_IP_PROTO_ICMP6) {
                icmph = (struct vr_icmp *)((char *)ip6 +
                        sizeof(struct vr_ip6));
            }
            if (icmph && (icmph->icmp_type == VR_ICMP6_TYPE_NEIGH_SOL)
                          && vr_v6_prefix_is_ll(icmph->icmp_data)) {
                return false;
            }
        }
        return true;
    }
    return false;
}

int
vr_trap_l2_well_known_packets(unsigned short vrf, struct vr_packet *pkt,
                              struct vr_forwarding_md *fmd)
{

    if (vif_is_virtual(pkt->vp_if) && well_known_mac(pkt_data(pkt))) {
        vr_trap(pkt, vrf,  AGENT_TRAP_L2_PROTOCOLS, NULL);
        return 1;   
    }

    return 0;
}



/*
 * Function to remove vlan from ethernet header. As it modifies vr_packet
 * structure and not skb, one is expected to invoke vr_pset_data() to
 * modify the data pointer of skb.
 */

int
vr_untag_pkt(struct vr_packet *pkt)
{
    struct vr_eth *eth;
    unsigned char *new_eth;

    eth = (struct vr_eth *)pkt_data(pkt);
    if (eth->eth_proto != htons(VR_ETH_PROTO_VLAN))
        return 0;

    new_eth = pkt_pull(pkt, VR_VLAN_HLEN);
    if (!new_eth)
        return -1;

    memmove(new_eth, eth, (2 * VR_ETHER_ALEN));
    return 0;
}

/*
 * Function to add vlan tag to ethernet header. As it modifies vr_packet
 * structure and not skb, one is expected to invoke vr_pset_data() to
 * modify the data pointer of skb
 */
int
vr_tag_pkt(struct vr_packet *pkt, unsigned short vlan_id)
{
    struct vr_eth *new_eth, *eth;
    unsigned short *vlan_tag;

    eth = (struct vr_eth *)pkt_data(pkt);
    if (eth->eth_proto == htons(VR_ETH_PROTO_VLAN))
        return 0;

    new_eth = (struct vr_eth *)pkt_push(pkt, VR_VLAN_HLEN);
    if (!new_eth)
        return -1;

    memmove(new_eth, eth, (2 * VR_ETHER_ALEN));
    new_eth->eth_proto = htons(VR_ETH_PROTO_VLAN);
    vlan_tag = (unsigned short *)(new_eth + 1);
    *vlan_tag = htons(vlan_id);
    return 0;
}

