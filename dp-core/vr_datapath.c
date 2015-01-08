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
#include <vr_bridge.h>

extern unsigned int vr_inet_route_flags(unsigned int, unsigned int);
extern struct vr_vrf_stats *(*vr_inet_vrf_stats)(unsigned short,
                                                 unsigned int);


static inline bool
vr_grat_arp(struct vr_arp *sarp)
{
    if (sarp->arp_spa == sarp->arp_dpa)
        return true;
    return false;
}

/*
 * src_mac is the mac that should be sent in ARP response which could be
 * the result of stithcing/proxy
 * dst_mac is the mac of he ARP request that we received
 * pkt_ingress_type identifies who is the source of ARP
 */
mac_response_t
vr_get_l3_stitching_info(struct vr_packet *pkt, struct vr_route_req *rt,
                         struct vr_forwarding_md *fmd, char *src_mac,
                         char *dst_mac, int pkt_ingress_type, int *drop_reason)
{
    struct vr_interface *vif = pkt->vp_if;
    struct vr_nexthop *nh;
    struct vr_vrf_stats *stats;

    stats = vr_inet_vrf_stats(fmd->fmd_dvrf, pkt->vp_cpu);

    if (vif_is_virtual(vif)) {
        /*
         * Request from VM:
         * If Proxy Bit Set -
         *    - If stitched : Proxy with Stitched MAC
         *    - If not stitched : Proxy with VIF's Mac
         * If no route is found : Drop the request
         * IF route is found and not proxied : Flood
         *
         */
        if (rt->rtr_req.rtr_label_flags & VR_RT_ARP_PROXY_FLAG) {
            if (rt->rtr_req.rtr_index == VR_BE_INVALID_INDEX) {
                if (stats)
                    stats->vrf_arp_virtual_proxy++;
                goto proxy;
            }

            rt->rtr_req.rtr_mac = src_mac;
            if (vr_bridge_lookup(fmd->fmd_dvrf, rt)) {
                if (stats)
                    stats->vrf_arp_virtual_stitch++;
                goto stitch;
            }
        }

        if (stats)
            stats->vrf_arp_virtual_flood++;
        return MR_FLOOD;

    }

    /*
     * Request from Physical:
     * If from Fabric n/w : Proxy
     * if Proxy bit  set:
     *  - If the VM is hosted on this node (Encap NH) : Proxy with VM's MAC
     *  - If from Tor, meant for DNS server (Rcv NH) : Proy with VIF's MAC
     *  - else : Flood
     */
    if (vif->vif_type == VIF_TYPE_PHYSICAL) {
        if (rt->rtr_req.rtr_label_flags & VR_RT_ARP_PROXY_FLAG) {
            if (rt->rtr_req.rtr_index != VR_BE_INVALID_INDEX) {
                rt->rtr_req.rtr_mac = src_mac;
                if ((nh = vr_bridge_lookup(fmd->fmd_dvrf, rt))) {

                    /* Tor/Non Tor case :
                     *   Stitch the Mac if VM is hosted in the
                     *   same compute node
                     * Tor Case :
                     *   Stitch the Mac if there is a tunnel to
                     *   other compute node
                     */
                    if ((nh->nh_type == NH_ENCAP) ||
                            ((pkt_ingress_type == PKT_SRC_TOR_REPL_TREE) &&
                                 nh->nh_type == NH_TUNNEL)) {
                        if (stats)
                            stats->vrf_arp_physical_stitch++;
                        goto stitch;
                    }
                }
            } else {
                nh = rt->rtr_nh;
                if (pkt_ingress_type == PKT_SRC_TOR_REPL_TREE) {
                    if (nh->nh_type == NH_ENCAP) {
                        if (stats)
                            stats->vrf_arp_tor_proxy++;
                        goto proxy;
                    }
                }
            }
        }
        if (stats)
            stats->vrf_arp_physical_flood++;
        return MR_FLOOD;
    }

    *drop_reason = VP_DROP_ARP_NO_WHERE_TO_GO;
    return MR_DROP;

proxy:
    VR_MAC_COPY(src_mac, vif->vif_mac);

stitch:
    memset(rt, 0, sizeof(*rt));
    rt->rtr_req.rtr_index = VR_BE_INVALID_INDEX;
    rt->rtr_req.rtr_mac_size = VR_ETHER_ALEN;
    rt->rtr_req.rtr_mac = dst_mac;
    rt->rtr_req.rtr_vrf_id = fmd->fmd_dvrf;
    if (!vr_bridge_lookup(fmd->fmd_dvrf, rt)) {
        *drop_reason = VP_DROP_ARP_REPLY_NO_ROUTE;
        return MR_DROP;
    }
    nh = rt->rtr_nh;
    if ((!nh) || ((nh->nh_type != NH_ENCAP) &&
                    (nh->nh_type != NH_TUNNEL))) {
        *drop_reason = VP_DROP_ARP_REPLY_NO_ROUTE;
        return MR_DROP;
    }
    if (rt->rtr_req.rtr_label_flags & VR_RT_LABEL_VALID_FLAG)
        fmd->fmd_label = rt->rtr_req.rtr_label;
    pkt->vp_nh = nh;
    return MR_PROXY;
}

int
vr_handle_mac_response(struct vr_packet *pkt, struct vr_forwarding_md *fmd,
                        mac_response_t result, int drop_reason)
{
    struct vr_packet *cloned_pkt;

    switch (result) {
    case MR_PROXY:
        pkt->vp_nh->nh_arp_response(pkt, pkt->vp_nh, fmd);
        break;
    case MR_XCONNECT:
        vif_xconnect(pkt->vp_if, pkt);
        break;
    case MR_TRAP_X:
        cloned_pkt = vr_pclone(pkt);
        if (cloned_pkt) {
            vr_preset(cloned_pkt);
            vif_xconnect(pkt->vp_if, cloned_pkt);
        }
        vr_trap(pkt, fmd->fmd_dvrf, AGENT_TRAP_ARP, NULL);
        break;
    case MR_TRAP:
        vr_preset(pkt);
        vr_trap(pkt, fmd->fmd_dvrf, AGENT_TRAP_ARP, NULL);
        break;
    case MR_FLOOD:
        return 0;
    case MR_DROP:
    default:
        vr_pfree(pkt, drop_reason);
    }

    return 1;
}

static int
vr_handle_arp_request(struct vr_arp *sarp, struct vr_packet *pkt,
                      struct vr_forwarding_md *fmd, int arp_ingress_type)
{
    int drop_reason = VP_DROP_ARP_NO_WHERE_TO_GO;
    mac_response_t arp_result;
    bool grat_arp, l3_proxy = false;
    struct vr_route_req rt;
    uint32_t rt_prefix, dpa;
    struct vr_eth *eth;
    struct vr_arp *arp;
    struct vr_interface *vif = pkt->vp_if;
    char arp_src_mac[VR_ETHER_ALEN];

    if (vif_mode_xconnect(vif)) {
        arp_result = MR_XCONNECT;
        goto result;
    }

    if (vif->vif_type == VIF_TYPE_XEN_LL_HOST ||
            vif->vif_type == VIF_TYPE_GATEWAY) {
        arp_result = MR_PROXY;
        VR_MAC_COPY(arp_src_mac, vif->vif_mac);
        goto result;
    }

    /* All link local IP's have to be proxied */
    if (vif->vif_type == VIF_TYPE_HOST) {
        if (IS_LINK_LOCAL_IP(sarp->arp_dpa)) {
            l3_proxy = true;
            arp_result = MR_PROXY;
            VR_MAC_COPY(arp_src_mac, vif->vif_mac);
        } else {
            arp_result = MR_XCONNECT;
        }
        goto result;
    }

    grat_arp = vr_grat_arp(sarp);
    /*
     * Grat ARP from Fabric need to be cross connected to Vhost
     * and Flooded Flooded if received from another compute node
     * or BMS
     */

    if (vif->vif_type == VIF_TYPE_PHYSICAL) {
        if (!arp_ingress_type) {
            if (grat_arp)
                arp_result = MR_TRAP_X;
            else
                arp_result = MR_XCONNECT;
            goto result;
        } else {
            if (grat_arp) {
                arp_result = MR_FLOOD;
                goto result;
            }
        }
    }

    memset(&rt, 0, sizeof(rt));
    rt.rtr_req.rtr_index = VR_BE_INVALID_INDEX;
    rt.rtr_req.rtr_vrf_id = fmd->fmd_dvrf;
    rt.rtr_req.rtr_prefix = (uint8_t*)&rt_prefix;
    *(uint32_t*)rt.rtr_req.rtr_prefix = (sarp->arp_dpa);
    rt.rtr_req.rtr_prefix_size = 4;
    rt.rtr_req.rtr_prefix_len = 32;

    vr_inet_route_lookup(fmd->fmd_dvrf, &rt);

    if (vif_is_virtual(vif)) {
        /*
         * Grat ARP from VM need to be Trapped to Agent if Trap Set
         * else need to be flooded
         */
        if (grat_arp) {
            if (rt.rtr_req.rtr_label_flags & VR_RT_ARP_TRAP_FLAG)
                arp_result = MR_TRAP;
            else
                arp_result = MR_FLOOD;
            goto result;
        }
    }

    arp_result = vr_get_l3_stitching_info(pkt, &rt, fmd, arp_src_mac,
                                          sarp->arp_sha, arp_ingress_type,
                                          &drop_reason);
result:
    if (arp_result == MR_PROXY) {
        pkt_reset(pkt);
        eth = (struct vr_eth *)pkt_data(pkt);
        if (!eth) {
            drop_reason = VP_DROP_HEAD_SPACE_RESERVE_FAIL;
            arp_result = MR_DROP;
            goto done;
        }

        memcpy(eth->eth_dmac, sarp->arp_sha, VR_ETHER_ALEN);
        memcpy(eth->eth_smac, arp_src_mac, VR_ETHER_ALEN);
        eth->eth_proto = htons(VR_ETH_PROTO_ARP);

        arp = (struct vr_arp *)pkt_pull_tail(pkt, VR_ETHER_HLEN);

        sarp->arp_op = htons(VR_ARP_OP_REPLY);
        memcpy(sarp->arp_sha, arp_src_mac, VR_ETHER_ALEN);
        memcpy(sarp->arp_dha, eth->eth_dmac, VR_ETHER_ALEN);
        dpa = sarp->arp_dpa;
        memcpy(&sarp->arp_dpa, &sarp->arp_spa, sizeof(sarp->arp_dpa));
        memcpy(&sarp->arp_spa, &dpa, sizeof(sarp->arp_spa));

        memcpy(arp, sarp, sizeof(*sarp));
        pkt_pull_tail(pkt, sizeof(*arp));

        if (l3_proxy) {
            vif->vif_tx(vif, pkt);
            return 1;
        }
    }
done:
    return vr_handle_mac_response(pkt, fmd, arp_result, drop_reason);
}

/*
 * arp responses from vhostX need to be cross connected. nothing
 * needs to be done for arp responses from VMs, while responses
 * from fabric needs to be Xconnected and sent to agent
 */
static int
vr_handle_arp_reply(struct vr_arp *sarp, struct vr_packet *pkt,
                    struct vr_forwarding_md *fmd)
{
    struct vr_interface *vif = pkt->vp_if;
    struct vr_packet *cloned_pkt;

    if (vif_mode_xconnect(vif) || vif->vif_type == VIF_TYPE_HOST)
        return vif_xconnect(vif, pkt);

    if (vif->vif_type != VIF_TYPE_PHYSICAL) {
        if (vif_is_virtual(vif)) {
            vr_preset(pkt);
            return vr_trap(pkt, fmd->fmd_dvrf, AGENT_TRAP_ARP, NULL);
        }
        vr_pfree(pkt, VP_DROP_INVALID_IF);
        return 0;
    }


    cloned_pkt = vr_pclone(pkt);
    if (cloned_pkt) {
        vr_preset(cloned_pkt);
        vif_xconnect(vif, cloned_pkt);
    }

    return vr_trap(pkt, fmd->fmd_dvrf, AGENT_TRAP_ARP, NULL);
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
vr_arp_input(struct vr_packet *pkt, struct vr_forwarding_md *fmd,
             int arp_ingress_type)
{
    struct vr_arp sarp;

    /* If vlan tagged packet, we let the VM handle the ARP packets */
    if ((pkt->vp_type != VP_TYPE_ARP) || (fmd->fmd_vlan != VLAN_ID_INVALID))
        return 0;

    memcpy(&sarp, pkt_data(pkt), sizeof(struct vr_arp));

    switch (ntohs(sarp.arp_op)) {
    case VR_ARP_OP_REQUEST:
        return vr_handle_arp_request(&sarp, pkt, fmd, arp_ingress_type);
        break;

    case VR_ARP_OP_REPLY:
        vr_handle_arp_reply(&sarp, pkt, fmd);
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

unsigned int
vr_reinject_packet(struct vr_packet *pkt, struct vr_forwarding_md *fmd)
{
    struct vr_interface *vif = pkt->vp_if;
    int handled;

    vr_printf("%s: from %d in vrf %d type %d data %d network %d\n",
            __FUNCTION__, pkt->vp_if->vif_idx, fmd->fmd_dvrf,
            pkt->vp_type, pkt->vp_data, pkt->vp_network_h);

    if (pkt->vp_nh)
        return pkt->vp_nh->nh_reach_nh(pkt, pkt->vp_nh, fmd);

    if (vif->vif_type == VIF_TYPE_HOST) {
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
    struct vr_forwarding_md fmd;

    vr_init_forwarding_md(&fmd);
    fmd.fmd_vlan = vlan_id;
    fmd.fmd_dvrf = vrf;

    if (vif->vif_flags & VIF_FLAG_MIRROR_RX) {
        fmd.fmd_dvrf = vif->vif_vrf;
        vr_mirror(vif->vif_router, vif->vif_mirror_id, pkt, &fmd);
    }

    if (vr_pkt_type(pkt, 0, &fmd) < 0) {
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
        return vif_xconnect(vif, pkt);

    pull_len = pkt_get_network_header_off(pkt) - pkt_head_space(pkt);


    pkt_pull(pkt, pull_len);
    if (pkt->vp_type == VP_TYPE_IP || pkt->vp_type == VP_TYPE_IP6)
        handled = vr_l3_input(pkt, &fmd);
    else if (pkt->vp_type == VP_TYPE_ARP)
        handled = vr_arp_input(pkt, &fmd, 0);

    if (!handled) {
        pkt_push(pkt, pull_len);
        return vif_xconnect(vif, pkt);
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

