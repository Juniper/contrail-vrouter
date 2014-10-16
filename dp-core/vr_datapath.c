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

extern struct vr_nexthop *(*vr_inet_route_lookup)(unsigned int,
                struct vr_route_req *, struct vr_packet *);

unsigned char vr_bcast_mac[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

int vr_arp_input(unsigned short, struct vr_packet *, struct vr_forwarding_md *);

int vr_l3_input(unsigned short, struct vr_packet *,
                              struct vr_forwarding_md *);
int vr_reach_l3_hdr(struct vr_packet *, unsigned short *);

extern unsigned int vr_route_flags(unsigned int, unsigned int);

static inline bool
vr_grat_arp(struct vr_arp *sarp)
{
    if (sarp->arp_spa == sarp->arp_dpa)
        return true;
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

    if (vr_grat_arp(arp)) {
        if (vif->vif_type == VIF_TYPE_PHYSICAL)
            return PKT_ARP_TRAP_XCONNECT;
        return PKT_ARP_DROP;
    }

    rt.rtr_req.rtr_vrf_id = vif->vif_vrf;
    rt.rtr_req.rtr_prefix = (uint8_t*)&rt_prefix;
    *(uint32_t*)rt.rtr_req.rtr_prefix = (arp->arp_dpa);
    rt.rtr_req.rtr_prefix_size = 4;
    rt.rtr_req.rtr_prefix_len = 32;
    rt.rtr_req.rtr_nh_id = 0;
    rt.rtr_req.rtr_label_flags = 0;
    rt.rtr_req.rtr_src_size = rt.rtr_req.rtr_marker_size = 0;

    nh = vr_inet_route_lookup(vif->vif_vrf, &rt, NULL);
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
                (nh->nh_flags & NH_FLAG_COMPOSITE_EVPN)) {
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
    case PKT_ARP_FLOOD:
        if (nh) {
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

    if (vif_mode_xconnect(vif) || vif->vif_type == VIF_TYPE_HOST)
        return vif_xconnect(vif, pkt);

    if (vif->vif_type != VIF_TYPE_PHYSICAL) {
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

int
vr_pkt_type(struct vr_packet *pkt)
{
    unsigned char *data = pkt_data(pkt);
    unsigned char *eth = data;
    unsigned short eth_proto;
    struct vr_vlan_hdr *vlan;
    unsigned short pull_len;

    pull_len = VR_ETHER_HLEN;
    if (pkt_head_len(pkt) < pull_len)
        return -1;

    eth_proto = ntohs(*(unsigned short *)(eth + VR_ETHER_PROTO_OFF));
    while (eth_proto == VR_ETH_PROTO_VLAN) {
        if (pkt_head_len(pkt) < (pull_len + sizeof(*vlan)))
            return -1;
        vlan = (struct vr_vlan_hdr *)(pkt_data(pkt) + pull_len);
        eth_proto = ntohs(vlan->vlan_proto);
        pull_len += sizeof(*vlan);
    }

    pkt_set_network_header(pkt, pkt->vp_data + pull_len);
    if (eth_proto == VR_ETH_PROTO_IP)
        pkt->vp_type = VP_TYPE_IP;
    else if (eth_proto == VR_ETH_PROTO_IP6)
        pkt->vp_type = VP_TYPE_IP6;
    else if (eth_proto == VR_ETH_PROTO_ARP)
        pkt->vp_type = VP_TYPE_ARP;
    else
        pkt->vp_type = VP_TYPE_L2;

    return 0;
}

int
vr_arp_input(unsigned short vrf, struct vr_packet *pkt,
             struct vr_forwarding_md *fmd)
{
    struct vr_arp sarp;

    if (!pkt_get_network_header_off(pkt)) {
        vr_pfree(pkt, VP_DROP_INVALID_PACKET);
        return 1;
    }

    memcpy(&sarp, pkt_network_header(pkt), sizeof(struct vr_arp));
    switch (ntohs(sarp.arp_op)) {
    case VR_ARP_OP_REQUEST:
        vr_handle_arp_request(vrf, &sarp, pkt, fmd);
        break;

    case VR_ARP_OP_REPLY:
        /* ARP reply from virual interface need not be processed */
        if (vif_is_virtual(pkt->vp_if))
            return 0;
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
    int handled = 0;
    unsigned short pull_len;

    vr_init_forwarding_md(&fmd);
    fmd.fmd_vlan = vlan_id;

    if (vif->vif_flags & VIF_FLAG_MIRROR_RX) {
        fmd.fmd_dvrf = vif->vif_vrf;
        vr_mirror(vif->vif_router, vif->vif_mirror_id, pkt, &fmd);
    }

    if (vr_pkt_type(pkt) < 0) {
        vif_drop_pkt(vif, pkt, 1);
        return 0;
    }

    pull_len = pkt_get_network_header_off(pkt) - pkt_head_space(pkt);
    if (vr_my_pkt(data, vif)) {
        pkt_pull(pkt, pull_len);
        handled = vr_l3_input(vrf, pkt, &fmd);
        if (handled)
            return 0;
    }

    if (vr_l2_input(vrf, pkt, &fmd))
            return 0;

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

    if (vr_pkt_type(pkt) < 0) {
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
    int reason;
    struct vr_interface *vif = pkt->vp_if;

    if (pkt->vp_type == VP_TYPE_IP) {
        pkt_set_inner_network_header(pkt, pkt->vp_data);
        if (vr_from_vm_mss_adj && vr_pkt_from_vm_tcp_mss_adj &&
            vif_is_virtual(vif)) {
            if ((reason = vr_pkt_from_vm_tcp_mss_adj(pkt, VROUTER_OVERLAY_LEN))) {
                vr_pfree(pkt, reason);
                return 1;
            }
        }
        vr_flow_inet_input(vif->vif_router, vrf, pkt, VR_ETH_PROTO_IP, fmd);
        return 1;
    } else if (pkt->vp_type == VP_TYPE_IP6) {
        pkt_set_inner_network_header(pkt, pkt->vp_data);
        if (vr_from_vm_mss_adj && vr_pkt_from_vm_tcp_mss_adj &&
            vif_is_virtual(vif)) {
            if ((reason = vr_pkt_from_vm_tcp_mss_adj(pkt, VROUTER_OVERLAY_LEN))) {
                vr_pfree(pkt, reason);
                return 1;
            }
        }
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
    int pull_len = 0;
    int reason;
    struct vr_interface *vif = pkt->vp_if;

    /* Only non-vlan tagged are L3 packets */
    if (fmd->fmd_vlan == VLAN_ID_INVALID) {
        if (IS_MAC_BMCAST(pkt_data(pkt)) &&
                (vif->vif_flags & VIF_FLAG_L3_ENABLED)) {
            if (pkt->vp_type == VP_TYPE_ARP || 
                    vr_l3_well_known_packet(vrf, pkt)) {
                if (vr_l3_input(vrf, pkt, fmd))
                    return 1;
            }
        }
    }

    if (!(vif->vif_flags & VIF_FLAG_L2_ENABLED))
        return 0;

    /* Even in L2 mode we will have to adjust the MSS for TCP*/
    if (pkt->vp_type == VP_TYPE_IP) {
        if (!pkt_get_network_header_off(pkt)) {
            vr_pfree(pkt, VP_DROP_INVALID_PACKET);
            return 1;
        }

        pull_len = pkt_get_network_header_off(pkt) - pkt_head_space(pkt);
        if (!pkt_pull(pkt, pull_len)) {
            vr_pfree(pkt, VP_DROP_INVALID_PACKET);
            return 1;
        }
        /* Mark the network header if an L3 packet */
        pkt_set_network_header(pkt, pkt->vp_data);
        pkt_set_inner_network_header(pkt, pkt->vp_data);
        if (vr_from_vm_mss_adj && vr_pkt_from_vm_tcp_mss_adj &&
                            vif_is_virtual(vif)) {
            if ((reason = vr_pkt_from_vm_tcp_mss_adj(pkt, VROUTER_OVERLAY_LEN_IN_L2_MODE))) {
                vr_pfree(pkt, reason);
                return 1;
            }
        }
    }
        
    /* Restore back the L2 headers */
    if (!pkt_push(pkt, pull_len)) {
        vr_pfree(pkt, VP_DROP_PULL);
        return 1;
    }

    /* Mark the packet as L2 */
    pkt->vp_type = VP_TYPE_L2;
    vr_bridge_input(pkt->vp_if->vif_router, vrf, pkt, fmd);
    return 1;
}

bool
vr_l3_well_known_packet(unsigned short vrf, struct vr_packet *pkt)
{
    unsigned char *data = pkt_data(pkt);
    struct vr_ip *iph;
    struct vr_ip6 *ip6;
    struct vr_udp *udph;
    unsigned char *l3_hdr;

    l3_hdr = pkt_network_header(pkt);
    if (vif_is_virtual(pkt->vp_if) && IS_MAC_BMCAST(data)) {
        iph = (struct vr_ip *)l3_hdr;
        if (!vr_ip_is_ip6(iph)) {
            if ((iph->ip_proto == VR_IP_PROTO_UDP) &&
                              vr_ip_transport_header_valid(iph)) {
                udph = (struct vr_udp *)(l3_hdr + iph->ip_hl * 4);
                if (udph->udp_sport == htons(68)) {
                    return true;
                }
            }
        } else { //IPv6
            ip6 = (struct vr_ip6 *)l3_hdr;
            // 0xFF02 is the multicast address used for NDP, DHCPv6 etc
            if (ip6->ip6_dst[0] == 0xFF && ip6->ip6_dst[1] == 0x02) {
                return true;
            }
        }
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
