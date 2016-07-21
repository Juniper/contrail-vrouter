/*
 * vr_datapath.c -- data path inside the router
 *
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#include <vr_os.h>
#include <vr_bridge.h>
#include <vr_packet.h>
#include <vr_interface.h>
#include <vr_datapath.h>
#include <vr_mirror.h>
#include <vr_bridge.h>
#include <vr_packet.h>

extern unsigned int vr_inet_route_flags(unsigned int, unsigned int);
extern struct vr_vrf_stats *(*vr_inet_vrf_stats)(unsigned short,
                                                 unsigned int);
mac_response_t
vr_get_proxy_mac(struct vr_packet *pkt, struct vr_forwarding_md *fmd,
        struct vr_route_req *rt, unsigned char *dmac)
{
    bool from_fabric, stitched, flood;
    bool to_gateway, no_proxy, to_vcp;

    unsigned char *resp_mac;
    struct vr_nexthop *nh = NULL;
    struct vr_interface *vif = pkt->vp_if;
    struct vr_vrf_stats *stats;

    from_fabric = stitched = flood = to_gateway = to_vcp = no_proxy = false;

    stats = vr_inet_vrf_stats(fmd->fmd_dvrf, pkt->vp_cpu);
    /* here we will not check for stats, but will check before use */

    if (vif->vif_type == VIF_TYPE_PHYSICAL)
        from_fabric = true;

    if (vif->vif_flags & VIF_FLAG_NO_ARP_PROXY)
        no_proxy = true;

    if (rt->rtr_req.rtr_label_flags & VR_RT_ARP_FLOOD_FLAG)
        flood = true;

    if (vr_gateway_nexthop(rt->rtr_nh))
        to_gateway = true;

    /*
     * the no_proxy flag is set for the vcp ports. From such ports
     * vrouter should proxy only for the gateway ip.
     */
    if (no_proxy && !to_gateway)
        return MR_DROP;

    if (from_fabric) {
        if (vr_nexthop_is_vcp(rt->rtr_nh)) {
            to_vcp = true;
        }
    }

    resp_mac = vif->vif_mac;
    if (rt->rtr_req.rtr_index != VR_BE_INVALID_INDEX) {
        if ((nh = vr_bridge_lookup(fmd->fmd_dvrf, rt))) {
            resp_mac = rt->rtr_req.rtr_mac;
            stitched = true;
        }
    }

     /* If ECMP source, we force routing */
     if (fmd->fmd_ecmp_src_nh_index != -1) {
         resp_mac = vif->vif_mac;
         fmd->fmd_ecmp_src_nh_index = -1;
     }


    /*
     * situations that are handled here (from_fabric)
     *
     * . arp request from vm, but not proxied at the source because of lack
     *   of information at the source. only the compute that hosts the
     *   destination should respond, and that too only if the mac information
     *   is present (and hence the ENCAP check).
     *
     * . arp request from a baremetal arriving at a TSN, which if posesses the
     *   mac information for the destination vm, should proxy. If it does not
     *   hold the mac information, the request should be flooded
     *
     * . arp request from the uplink port of a vcp
     */
    if (from_fabric) {
        if (flood && !stitched) {
            if (stats)
                stats->vrf_arp_physical_flood++;
            return MR_FLOOD;
        }

        /*
         * arp requests to gateway coming from the fabric should be dropped
         * unless the request was for the TSN DNS service (which appears as
         * the gateway, with the current set of checks). We should not respond
         * for gateway ip if we are TSN and the request came from baremetal.
         * TSN does not have gateway route and hence the to_gateway will be
         * true only for the DNS ip.
         */
        if (to_gateway) {
            if (fmd->fmd_src != TOR_SOURCE) {
                return MR_DROP;
            }
        }

        /*
         * we should proxy if the vm is hosted by us, in which case nh will be
         * of ENCAP type. we should also proxy for a host in vcp port. In all
         * other cases, we should proxy only if
         *
         * i am a TSN(fmd->fmd_src),
         * i amd the dns IP or
         * i have the mac information (nh - (mostly tunnel)) and
         * the originator is a bare metal (fmd->fmd_src)
         */
        if (to_vcp || to_gateway ||
                (nh && ((nh->nh_type == NH_ENCAP) ||
                (fmd->fmd_src == TOR_SOURCE)))) {
            if (stats)
                stats->vrf_arp_physical_stitch++;
        } else {
            if (stats)
                stats->vrf_arp_physical_flood++;
            return MR_FLOOD;
        }
    } else {

        if (!stitched && flood) {
            /*
             * if there is no stitching information, but flood flag is set
             * we should flood
             */
            if (stats)
                stats->vrf_arp_virtual_flood++;
            return MR_FLOOD;
        }

        if (stats) {
            if (stitched) {
                stats->vrf_arp_virtual_stitch++;
            } else {
                stats->vrf_arp_virtual_proxy++;
            }
        }
    }

    VR_MAC_COPY(dmac, resp_mac);

    return MR_PROXY;
}

static void
vr_arp_proxy(struct vr_arp *sarp, struct vr_packet *pkt,
        struct vr_forwarding_md *fmd, unsigned char *dmac)
{
    struct vr_eth *eth;
    struct vr_arp *arp;
    struct vr_forwarding_md fmd_new;
    struct vr_interface *vif = pkt->vp_if;
    struct vr_route_req rt;
    bool vif_tx = false;
    struct vr_nexthop *nh;

    eth = (struct vr_eth *)pkt_push(pkt, sizeof(*eth));
    if (!eth) {
        vr_pfree(pkt, VP_DROP_PUSH);
        return;
    }

    memcpy(eth->eth_dmac, sarp->arp_sha, VR_ETHER_ALEN);
    memcpy(eth->eth_smac, dmac, VR_ETHER_ALEN);
    eth->eth_proto = htons(VR_ETH_PROTO_ARP);

    arp = (struct vr_arp *)(pkt_data(pkt) + sizeof(*eth));
    arp->arp_hw = htons(VR_ARP_HW_TYPE_ETHER);
    arp->arp_proto = htons(VR_ETH_PROTO_IP);
    arp->arp_hwlen = VR_ETHER_ALEN;
    arp->arp_protolen = VR_IP_ADDRESS_LEN;
    arp->arp_op = htons(VR_ARP_OP_REPLY);
    memcpy(arp->arp_sha, dmac, VR_ETHER_ALEN);
    memcpy(arp->arp_dha, sarp->arp_sha, VR_ETHER_ALEN);
    memcpy(&arp->arp_dpa, &sarp->arp_spa, sizeof(sarp->arp_spa));
    memcpy(&arp->arp_spa, &sarp->arp_dpa, sizeof(sarp->arp_dpa));

    vr_init_forwarding_md(&fmd_new);
    fmd_new.fmd_dvrf = fmd->fmd_dvrf;
    vr_pkt_type(pkt, 0, &fmd_new);

    /*
     * XXX: for vcp ports, there won't be bridge table entries. to avoid
     * doing vr_bridge_input, we check for the flag NO_ARP_PROXY and
     * and if set, directly send out on that interface
     */


    if (vif_is_vhost(vif) ||
            (vif->vif_flags & VIF_FLAG_NO_ARP_PROXY)) {
        vif_tx = true;
    } else {

        rt.rtr_req.rtr_label_flags = 0;
        rt.rtr_req.rtr_index = VR_BE_INVALID_INDEX;
        rt.rtr_req.rtr_mac_size = VR_ETHER_ALEN;
        rt.rtr_req.rtr_mac =(int8_t *) arp->arp_dha;
        rt.rtr_req.rtr_vrf_id = fmd_new.fmd_dvrf;
        nh = vr_bridge_lookup(fmd->fmd_dvrf, &rt);
        if (!nh || !(nh->nh_flags & NH_FLAG_VALID)) {
            vr_pfree(pkt, VP_DROP_INVALID_NH);
            return;
        }
        if (rt.rtr_req.rtr_label_flags & VR_BE_LABEL_VALID_FLAG)
            fmd_new.fmd_label = rt.rtr_req.rtr_label;

        if (vif_is_virtual(vif) && (nh->nh_dev != vif)) {
            vif_tx = true;
        }
    }

    if (vif_tx)
        vif->vif_tx(vif, pkt, &fmd_new);
    else
        nh_output(pkt, nh, &fmd_new);
    return;
}

static int
vr_handle_arp_request(struct vr_arp *sarp, struct vr_packet *pkt,
                      struct vr_forwarding_md *fmd)
{
    bool handled = true;
    unsigned char dmac[VR_ETHER_ALEN];
    mac_response_t arp_result;

    struct vr_packet *pkt_c;
    struct vr_interface *vif = pkt->vp_if;

    arp_result = vif->vif_mac_request(vif, pkt, fmd, dmac);
    switch (arp_result) {
    case MR_PROXY:
        vr_arp_proxy(sarp, pkt, fmd, dmac);
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

        /* Flood the original packet*/
        handled = false;
        break;

    case MR_DROP:
        vr_pfree(pkt, VP_DROP_INVALID_ARP);
        break;

    case MR_FLOOD:
    default:
        /*
         * If the packet is from Service Instance VM, we dont flood the
         * packet any where
         */
        if (!vif_is_service(pkt->vp_if)) {
            handled = false;
        } else {
            vr_pfree(pkt, VP_DROP_INVALID_ARP);
        }
        break;

    }

    return handled;
}

/*
 * ARP responses
 *    on fabric network: Both kernel and Agent are interested
 *    on fabric interface for VN : not handled
 *    from Virtual interface: If destined "to me" - trap to Agent
 *       else flood as well
 *
 */
static int
vr_handle_arp_reply(struct vr_arp *sarp, struct vr_packet *pkt,
                    struct vr_forwarding_md *fmd)
{
    struct vr_interface *vif = pkt->vp_if;
    struct vr_packet *cloned_pkt;
    int handled = 1;

    /*
     * If Vhost or fabric in cross connct mode, simply cross connect the
     * packet
     */
    if (vif_mode_xconnect(vif) || vif->vif_type == VIF_TYPE_HOST) {
        vif_xconnect(vif, pkt, fmd);
        return handled;
    }

    if (vif_is_virtual(vif)) {

        /*
         * If packet is destined "to me": packet is just trapped to
         * Agent. If multicast: paket would be Trapped and marked as
         * unhandled, so that caller continues to do original action. If
         * unicast, and not destined "to me" it is a case of unknown
         * unicast, and is not trapped to agent and caller takes the
         * aciton
         */

        if (fmd->fmd_to_me) {
            cloned_pkt = pkt;
        } else if (pkt->vp_flags & VP_FLAG_MULTICAST) {
            cloned_pkt = vr_pclone(pkt);

            /* If cloning fails, just trap original */
            if (cloned_pkt)
                handled = 0;
            else
                cloned_pkt = pkt;
        } else {
            return !handled;
        }

        /* If destined to me, Agent is interested in it */
        vr_preset(cloned_pkt);
        vr_trap(cloned_pkt, fmd->fmd_dvrf, AGENT_TRAP_ARP, NULL);
        return handled;
    }

    if (vif_is_fabric(vif)) {

        /* If a tunneled packet, dont handle */
        if (fmd->fmd_label >= 0)
            return !handled;

        /*
         * in gro cases, fmd label won't be set. Hence, resort to the
         * following check to identify whether the packet was tunneled
         */
        if (fmd->fmd_dvrf != vif->vif_vrf)
            return !handled;

        /* If fabric: Agent and kernel are interested in it */
        cloned_pkt = vr_pclone(pkt);
        if (cloned_pkt) {
            vr_preset(cloned_pkt);
            vif_xconnect(vif, cloned_pkt, fmd);
        }

        vr_trap(pkt, fmd->fmd_dvrf, AGENT_TRAP_ARP, NULL);

        return handled;
    }

    /* Any other Response can be dropped */
    vr_pfree(pkt, VP_DROP_INVALID_IF);

    return handled;
}

/*
 * handle unicast arp requests and neighbor refreshes. In many cases,
 * we wouldn't like the unicast arp requests from gateway (such as MX)
 * to reach the VMs and change the gateway mac to ip(6) binding, since
 * for vms the gateway is always agent. We would like such requests
 * to go only if the mode is l2
 */
int
vif_plug_mac_request(struct vr_interface *vif, struct vr_packet *pkt,
        struct vr_forwarding_md *fmd)
{
    int nheader, handled = 1;

    if (pkt->vp_flags & VP_FLAG_MULTICAST)
        goto unhandled;

    nheader = pkt_network_header(pkt) - pkt_data(pkt);
    if (nheader < 0 || (pkt->vp_data + nheader > pkt->vp_end))
        goto unhandled;

    if (pkt->vp_type == VP_TYPE_ARP) {
        if (pkt->vp_len < (nheader + sizeof(struct vr_arp)))
            goto unhandled;

        pkt_pull(pkt, nheader);

        handled = vr_arp_input(pkt, fmd);
        if (!handled) {
            pkt_push(pkt, nheader);
        }
        return handled;
    } else if (pkt->vp_type == VP_TYPE_IP6) {
        if (pkt->vp_len < (nheader + sizeof(struct vr_ip6) +
                    sizeof(struct vr_icmp) + VR_IP6_ADDRESS_LEN +
                    sizeof(struct vr_neighbor_option) + VR_ETHER_ALEN))
            goto unhandled;

        pkt_pull(pkt, nheader);

        handled = vr_neighbor_input(pkt, fmd);
        if (!handled) {
            pkt_push(pkt, nheader);
        }
        return handled;
    }

unhandled:
    return !handled;
}

/*
 * This funciton parses the ethernet packet and assigns the
 * pkt->vp_type, network protocol of the packet. The ethernet header can
 * start from an offset from vp_data
 */
int
vr_pkt_type(struct vr_packet *pkt, unsigned short offset,
            struct vr_forwarding_md *fmd)
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
        if (fmd && (fmd->fmd_vlan == VLAN_ID_INVALID))
            fmd->fmd_vlan = vlan->vlan_tag & 0xFFF;
        eth_proto = ntohs(vlan->vlan_proto);
        pull_len += sizeof(*vlan);
    }


    pkt_set_network_header(pkt, pkt->vp_data + offset + pull_len);
    pkt_set_inner_network_header(pkt, pkt->vp_data + offset + pull_len);
    pkt->vp_type = vr_eth_proto_to_pkt_type(eth_proto);

    return 0;
}

int
vr_arp_input(struct vr_packet *pkt, struct vr_forwarding_md *fmd)
{
    int handled = 1;
    struct vr_arp sarp;

    /* If vlan tagged packet, we let the VM handle the ARP packets */
    if ((pkt->vp_type != VP_TYPE_ARP) || (fmd->fmd_vlan != VLAN_ID_INVALID))
        return !handled;

    if (pkt->vp_len < sizeof(struct vr_arp)) {
        vr_pfree(pkt, VP_DROP_INVALID_ARP);
        return handled;
    }

    memcpy(&sarp, pkt_data(pkt), sizeof(struct vr_arp));

    switch (ntohs(sarp.arp_op)) {
    case VR_ARP_OP_REQUEST:
        return vr_handle_arp_request(&sarp, pkt, fmd);

    case VR_ARP_OP_REPLY:
        return vr_handle_arp_reply(&sarp, pkt, fmd);
        break;

    default:
        vr_pfree(pkt, VP_DROP_INVALID_ARP);
    }

    return handled;
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

unsigned int
vr_reinject_packet(struct vr_packet *pkt, struct vr_forwarding_md *fmd)
{
    struct vr_interface *vif = pkt->vp_if;
    int handled;

    if (pkt->vp_nh) {
        /* If nexthop does not have valid data, drop it */
        if (!(pkt->vp_nh->nh_flags & NH_FLAG_VALID)) {
            vr_pfree(pkt, VP_DROP_INVALID_NH);
            return 0;
        }

        return pkt->vp_nh->nh_reach_nh(pkt, pkt->vp_nh, fmd);
    }

    if (vif_is_vhost(vif)) {
        handled = vr_l3_input(pkt, fmd);
        if (!handled)
            vif_drop_pkt(vif, pkt, 1);
        return 0;
    }


    return vr_bridge_input(vif->vif_router, pkt, fmd);
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
    struct vr_forwarding_md fmd, mfmd;

    vr_init_forwarding_md(&fmd);
    fmd.fmd_vlan = vlan_id;
    fmd.fmd_dvrf = vrf;
    if (pkt->vp_priority != VP_PRIORITY_INVALID) {
        fmd.fmd_dotonep = pkt->vp_priority;
        pkt->vp_priority = VP_PRIORITY_INVALID;
    }

    if (vr_pkt_type(pkt, 0, &fmd) < 0) {
        vif_drop_pkt(vif, pkt, 1);
        return 0;
    }

    if (vif->vif_flags & VIF_FLAG_MIRROR_RX) {
        mfmd = fmd;
        mfmd.fmd_dvrf = vif->vif_vrf;
        vr_mirror(vif->vif_router, vif->vif_mirror_id, pkt, &mfmd,
                MIRROR_TYPE_PORT_RX);
    }


    /*
     * we really do not allow any broadcast packets from interfaces
     * that are part of transparent service chain, since transparent
     * service chain bridges packets across vrf (and hence loops can
     * happen)
     */
    if ((pkt->vp_flags & VP_FLAG_MULTICAST) &&
            (vif_is_service(vif)) && (pkt->vp_type != VP_TYPE_ARP)) {
        vif_drop_pkt(vif, pkt, 1);
        return 0;
    }

    if (!vr_flow_forward(pkt->vp_if->vif_router, pkt, &fmd))
        return 0;

    vr_bridge_input(vif->vif_router, pkt, &fmd);
    return 0;

}

unsigned int
vr_fabric_input(struct vr_interface *vif, struct vr_packet *pkt,
                unsigned short vlan_id)
{
    int handled = 0;
    unsigned short pull_len;
    struct vr_forwarding_md fmd;

    vr_init_forwarding_md(&fmd);
    fmd.fmd_vlan = vlan_id;
    fmd.fmd_dvrf = vif->vif_vrf;

    if (vr_pkt_type(pkt, 0, &fmd) < 0) {
        vif_drop_pkt(vif, pkt, 1);
        return 0;
    }

    if (pkt->vp_type == VP_TYPE_IP6)
        return vif_xconnect(vif, pkt, &fmd);

    /*
     * On Fabric only ARP packets are specially handled. Rest all BUM
     * traffic can be cross connected
     */
    if ((pkt->vp_type != VP_TYPE_ARP) &&
            (pkt->vp_flags & VP_FLAG_MULTICAST)) {
        return vif_xconnect(vif, pkt, &fmd);
    }

    pull_len = pkt_get_network_header_off(pkt) - pkt_head_space(pkt);
    pkt_pull(pkt, pull_len);

    if (pkt->vp_type == VP_TYPE_IP || pkt->vp_type == VP_TYPE_IP6)
        handled = vr_l3_input(pkt, &fmd);
    else if (pkt->vp_type == VP_TYPE_ARP)
        handled = vr_arp_input(pkt, &fmd);

    if (!handled) {
        pkt_push(pkt, pull_len);
        return vif_xconnect(vif, pkt, &fmd);
    }

    return 0;
}

int
vr_l3_input(struct vr_packet *pkt, struct vr_forwarding_md *fmd)
{
    struct vr_interface *vif = pkt->vp_if;

    if (pkt->vp_type == VP_TYPE_IP) {
        vr_ip_input(vif->vif_router, pkt, fmd);
        return 1;
    } else if (pkt->vp_type == VP_TYPE_IP6) {
         vr_ip6_input(vif->vif_router, pkt, fmd);
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
    uint8_t priority = 0;
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
    if (pkt->vp_priority != VP_PRIORITY_INVALID)
        priority = pkt->vp_priority;

    *vlan_tag = htons((priority << VR_VLAN_PRIORITY_SHIFT) | vlan_id);
    return 0;
}

void
vr_vlan_set_priority(struct vr_packet *pkt)
{
    struct vr_eth *eth;
    struct vr_vlan_hdr *vlan;

    eth = (struct vr_eth *)pkt_data(pkt);
    if (eth->eth_proto == htons(VR_ETH_PROTO_VLAN)) {
        vlan = (struct vr_vlan_hdr *)(eth + 1);
        if (pkt->vp_priority != VP_PRIORITY_INVALID) {
            vlan->vlan_tag |=
                htons((pkt->vp_priority << VR_VLAN_PRIORITY_SHIFT));
        }
    }

    return;
}

int
vr_gro_input(struct vr_packet *pkt, struct vr_nexthop *nh)
{
    unsigned short *nh_id, *vif_id;
    int handled = 1;

    if (!vr_gro_process)
        return !handled;

    nh_id = (unsigned short *)pkt_push(pkt, sizeof(*nh_id));
    if (!nh_id) {
        vr_pfree(pkt, VP_DROP_PUSH);
        return handled;
    }
    *nh_id = nh->nh_id;

    vif_id = (unsigned short *)pkt_push(pkt, sizeof(*vif_id));
    if (!vif_id) {
        vr_pfree(pkt, VP_DROP_PUSH);
        return handled;
    }
    *vif_id = pkt->vp_if->vif_idx;

    handled = vr_gro_process(pkt, nh->nh_dev, (nh->nh_family == AF_BRIDGE));
    return handled;
}
