/*
 * vr_datapath.c -- data path inside the router
 *
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#include <vr_os.h>
#include <vr_types.h>
#include <vr_packet.h>

unsigned char vr_bcast_mac[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
unsigned char vr_well_known_mac_infix[] = { 0x80, 0xc2 };

unsigned int vr_arp_input(struct vrouter *, unsigned short,
        struct vr_packet *);
int bridge_entry_del(struct rtable_fspec *, struct vr_route_req *);
unsigned int vr_l3_input(unsigned short, struct vr_packet *,
                              struct vr_forwarding_md *);
int vr_reach_l3_hdr(struct vr_packet *, unsigned short *);

extern unsigned int vr_route_flags(unsigned int, unsigned int);

static inline bool
well_known_mac(unsigned char *dmac)
{
    if (!memcmp(&dmac[VR_ETHER_PROTO_MAC_OFF], vr_well_known_mac_infix,
                            VR_ETHER_PROTO_MAC_LEN)) 
        if (!*dmac || (*dmac == 0x1))
            return true;

    return false;
}

static inline bool
vr_grat_arp(struct vr_arp *sarp)
{
    if (sarp->arp_spa == sarp->arp_dpa)
        return true;
    return false;
}

static int
vr_handle_arp_request(struct vrouter *router, unsigned short vrf,
        struct vr_arp *sarp, struct vr_packet *pkt)
{
    struct vr_packet *cloned_pkt;
    struct vr_interface *vif = pkt->vp_if;
    unsigned short proto = htons(VR_ETH_PROTO_ARP);
    unsigned short *eth_proto;
    unsigned short pull_tail_len = VR_ETHER_HLEN;
    struct vr_eth *eth;
    struct vr_arp *arp;
    unsigned int dpa, rt_flags;
    bool should_proxy = false;

    /* 
     * still @ l2 level, and hence we can use the mode of the interface
     * to figure out whether we need to xconnect or not. in the xconnect
     * mode, just pass it to the peer so that he can handle the arp requests
     */
    if (vif_mode_xconnect(vif))
        return vif_xconnect(vif, pkt);

    should_proxy = vr_should_proxy(vif, sarp->arp_dpa, sarp->arp_spa);

    /*
     * if vr should not proxy, all the other arp requests should go out on
     * the physical interface
     */
    if (vif->vif_type == VIF_TYPE_HOST && !should_proxy)
       return vif_xconnect(vif, pkt);

    /*
     * grat arp from
     *
     * VMs - need to be dropped
     * Fabric - need to be xconnected and also sent to agent
     * Vhost - xconnected above
     */
    if (vr_grat_arp(sarp)) {
        if (vif_is_virtual(vif)) {
            rt_flags = vr_route_flags(vif->vif_vrf, sarp->arp_dpa);
            if (rt_flags & VR_RT_ARP_TRAP_FLAG) {
                vr_preset(pkt);
                return vr_trap(pkt, vrf, AGENT_TRAP_ARP, NULL);
            }

            vr_pfree(pkt, VP_DROP_GARP_FROM_VM);
            return 0;
        }

        cloned_pkt = vr_pclone(pkt);
        if (cloned_pkt) {
            vr_preset(cloned_pkt);
            vif_xconnect(vif, cloned_pkt);
        }

        return vr_trap(pkt, vrf, AGENT_TRAP_ARP, NULL);
    }

    if (should_proxy) {
        pkt_reset(pkt);

        eth = (struct vr_eth *)pkt_data(pkt);
        memcpy(eth->eth_dmac, sarp->arp_sha, VR_ETHER_ALEN);
        memcpy(eth->eth_smac, vif->vif_mac, VR_ETHER_ALEN);
        eth_proto = &eth->eth_proto;
        if (vif_is_vlan(vif)) {
            if (vif->vif_vlan_id) {
                *eth_proto = htons(VR_ETH_PROTO_VLAN);
                eth_proto++;
                *eth_proto = htons(vif->vif_vlan_id);
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
    } else {
        /* requests for which vr doesn't have to do anything */
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
vr_handle_arp_reply(struct vrouter *router, unsigned short vrf,
        struct vr_arp *sarp, struct vr_packet *pkt)
{
    unsigned int rt_flags;
    struct vr_interface *vif = pkt->vp_if;
    struct vr_packet *cloned_pkt;

    if (vif_mode_xconnect(vif) || vif->vif_type == VIF_TYPE_HOST)
        return vif_xconnect(vif, pkt);

    if (vif->vif_type != VIF_TYPE_PHYSICAL) {
        if (vif->vif_type == VIF_TYPE_VIRTUAL) {
            rt_flags = vr_route_flags(vif->vif_vrf, sarp->arp_dpa);
            if (rt_flags & VR_RT_ARP_TRAP_FLAG) {
                vr_preset(pkt);
                return vr_trap(pkt, vrf, AGENT_TRAP_ARP, NULL);
            }
        }

        /* ...else, just drop */
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

unsigned int
vr_arp_input(struct vrouter *router, unsigned short vrf,
        struct vr_packet *pkt)
{
    struct vr_arp sarp;

    memcpy(&sarp, pkt_data(pkt), sizeof(struct vr_arp));
    switch (ntohs(sarp.arp_op)) {
    case VR_ARP_OP_REQUEST:
        vr_handle_arp_request(router, vrf, &sarp, pkt);
        break;

    case VR_ARP_OP_REPLY:
        vr_handle_arp_reply(router, vrf, &sarp, pkt);
        break;

    default:
        vr_pfree(pkt, VP_DROP_INVALID_ARP);
    }

    return 0;
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

int
vr_reach_l3_hdr(struct vr_packet *pkt, unsigned short *eproto)
{
    unsigned char *data = pkt_data(pkt);
    unsigned char *eth = data;
    unsigned short eth_proto;
    struct vr_vlan_hdr *vlan;
    unsigned short pull_len = 0;

    data = pkt_pull(pkt, VR_ETHER_HLEN);
    if (!data) {
        return -1;
    }

    pull_len += VR_ETHER_HLEN;

    eth_proto = ntohs(*(unsigned short *)(eth + VR_ETHER_PROTO_OFF));
    while (eth_proto == VR_ETH_PROTO_VLAN) {
        vlan = (struct vr_vlan_hdr *)data;
        eth_proto = ntohs(vlan->vlan_proto);
        data = pkt_pull(pkt, sizeof(*vlan));
        if (!data) {
            return -1;
        }
        pull_len += sizeof(*vlan);
    }

    if (eproto)
        *eproto = eth_proto;

    return pull_len;
}

unsigned int
vr_l3_input(unsigned short vrf, struct vr_packet *pkt,
                              struct vr_forwarding_md *fmd)
{

    unsigned char *data = pkt_data(pkt);
    unsigned char *eth = data;
    unsigned char *dmac = &eth[VR_ETHER_DMAC_OFF];
    unsigned short eth_proto = 0;
    int reason;
    int pull_len;
    struct vr_interface *vif = pkt->vp_if;
    struct vrouter *router = vif->vif_router;
    /*
     * we will optimise for the most likely case i.e that of IPv4. need
     * to see what needs to happen for v6 when it comes
     */

    pull_len = vr_reach_l3_hdr(pkt, &eth_proto);
    if (pull_len < 0) {
        vif_drop_pkt(vif, pkt, 1);
        return 0;
    }

    data = pkt_data(pkt);
    if (!data) {
        vif_drop_pkt(vif, pkt, 1);
        return 0;
    }

    pkt_set_network_header(pkt, pkt->vp_data);
    pkt_set_inner_network_header(pkt, pkt->vp_data);
    if (eth_proto == VR_ETH_PROTO_IP) {
        if (vr_from_vm_mss_adj && vr_pkt_from_vm_tcp_mss_adj && 
                                             vif_is_virtual(vif)) {
            if ((reason = vr_pkt_from_vm_tcp_mss_adj(pkt, VROUTER_OVERLAY_LEN))) {
                vr_pfree(pkt, reason);
                return 0;
            }
         }
         return vr_flow_inet_input(router, vrf, pkt, eth_proto, fmd);
    } else if (eth_proto == VR_ETH_PROTO_ARP)
        return vr_arp_input(router, vrf, pkt);

    /* rest of the stuff is for slow path and we should be ok doing this */
    if (well_known_mac(dmac))
        return vr_trap(pkt, vrf,  AGENT_TRAP_L2_PROTOCOLS, NULL);

    /* Get the L2 headers back */
    if (!pkt_push(pkt, pull_len)) {
        vif_drop_pkt(vif, pkt, 1);
        return 0;
    }

    /* The packets is not handled. Might need to be bridged ..*/
    return PKT_RET_FALLBACK_BRIDGING;
}
