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
#include "vr_hash.h"

#define VR_DPDK_RX_BURST_SZ 32

#ifndef unlikely
#define likely(expr) __builtin_expect(!!(expr), 1)
#define unlikely(expr) __builtin_expect(!!(expr), 0)
#endif

#if defined(__linux__) && !defined(__KERNEL__)
__thread int cpuid_per_thread;

static inline int get_cpuid(void)
{
    return cpuid_per_thread;
}

static inline void rte_prefetch0(const volatile void *p)
{
        asm volatile ("prefetcht0 %[p]" : : [p] "m" (*(const volatile char *)p));
}
#endif

#define VR_DPDK_RX_BURST_SZ 32

extern unsigned int vr_inet_route_flags(unsigned int, unsigned int);
extern struct vr_vrf_stats *(*vr_inet_vrf_stats)(unsigned short,
                                                 unsigned int);
mac_response_t
vr_get_proxy_mac(struct vr_packet *pkt, struct vr_forwarding_md *fmd,
        struct vr_route_req *rt, unsigned char *dmac)
{
    bool from_fabric, stitched, flood, over_lay, hosted_vm;
    bool to_gateway, no_proxy, to_vcp;

    unsigned char *resp_mac;
    struct vr_nexthop *nh = NULL, *l3_nh = NULL;
    struct vr_interface *vif = pkt->vp_if;
    struct vr_vrf_stats *stats;

    over_lay = true;
    from_fabric = stitched = flood = hosted_vm = false;
    to_gateway = to_vcp = no_proxy = false;

    stats = vr_inet_vrf_stats(fmd->fmd_dvrf, pkt->vp_cpu);
    /* here we will not check for stats, but will check before use */

    if (vif->vif_flags & VIF_FLAG_MAC_PROXY) {
        resp_mac = vif->vif_mac;
        goto proxy_selected;
    }

    if (vif->vif_type == VIF_TYPE_PHYSICAL)
        from_fabric = true;

    if (vif->vif_flags & VIF_FLAG_NO_ARP_PROXY)
        no_proxy = true;

    if (rt->rtr_req.rtr_label_flags & VR_RT_ARP_FLOOD_FLAG)
        flood = true;

    if (vif_is_vhost(vif) || (from_fabric && (fmd->fmd_label == -1) &&
                (fmd->fmd_dvrf == vif->vif_vrf)))
        over_lay = false;

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


    l3_nh = rt->rtr_nh;
    resp_mac = vif->vif_mac;
    if (rt->rtr_req.rtr_index != VR_BE_INVALID_INDEX) {
        if ((nh = vr_bridge_lookup(fmd->fmd_dvrf, rt))) {
            resp_mac = rt->rtr_req.rtr_mac;
            stitched = true;
        }
    }

    if (!over_lay)
        nh = l3_nh;

    if (vr_hosted_nexthop(nh))
        hosted_vm = true;


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
            if ((fmd->fmd_src != TOR_SOURCE) && (fmd->fmd_src !=
                        TOR_EVPN_SOURCE)) {
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
        if (to_vcp || to_gateway || hosted_vm ||
                (fmd->fmd_src == TOR_SOURCE) ||
                (fmd->fmd_src == TOR_EVPN_SOURCE)) {
            if (stats)
                stats->vrf_arp_physical_stitch++;
        } else {
            if (stats)
                stats->vrf_arp_physical_flood++;

            if (!over_lay)
                return MR_XCONNECT;

            return MR_FLOOD;
        }
    } else if (!vif_is_vhost(vif)) {

proxy_selected:
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
                fmd->fmd_flags |= FMD_FLAG_MAC_IS_MY_MAC;
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

    vr_mac_reply_send(pkt, fmd);

    return;
}

static int
vr_handle_arp_request(struct vr_arp *sarp, struct vr_packet *pkt,
                      struct vr_forwarding_md *fmd, unsigned char *eth_dmac)
{
    bool handled = true;
    unsigned char dmac[VR_ETHER_ALEN];
    mac_response_t arp_result;

    struct vr_packet *pkt_c;
    struct vr_interface *vif = pkt->vp_if;
    VR_MAC_COPY(dmac, eth_dmac);

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
        cloned_pkt = pkt_cow(pkt, AGENT_PKT_HEAD_SPACE);
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
    unsigned char eth_dmac[VR_ETHER_ALEN];

    if (pkt->vp_flags & VP_FLAG_MULTICAST)
        goto unhandled;

    nheader = pkt_network_header(pkt) - pkt_data(pkt);
    if (nheader < 0 || (pkt->vp_data + nheader > pkt->vp_end))
        goto unhandled;

    VR_MAC_COPY(eth_dmac, pkt_data(pkt));

    if (pkt->vp_type == VP_TYPE_ARP) {
        if (pkt->vp_len < (nheader + sizeof(struct vr_arp)))
            goto unhandled;

        pkt_pull(pkt, nheader);

        handled = vr_arp_input(pkt, fmd, eth_dmac);
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

        handled = vr_neighbor_input(pkt, fmd, eth_dmac);
        if (!handled) {
            pkt_push(pkt, nheader);
        }
        return handled;
    }

unhandled:
    return !handled;
}

void
vr_mac_reply_send(struct vr_packet *pkt, struct vr_forwarding_md *fmd)
{
    bool vif_tx = false;
    struct vr_forwarding_md fmd_new;
    struct vr_route_req rt;
    struct vr_nexthop *nh = NULL;
    struct vr_interface *vif = pkt->vp_if;

    vr_init_forwarding_md(&fmd_new);
    fmd_new.fmd_dvrf = fmd->fmd_dvrf;
    vr_pkt_type(pkt, 0, &fmd_new);

    /* Disable the flow processing for response packets */
    pkt->vp_flags |= VP_FLAG_FLOW_SET;

    /*
     * XXX: for vcp ports, there won't be bridge table entries. to avoid
     * doing vr_bridge_input, we check for the flag NO_ARP_PROXY and
     * and if set, directly send out on that interface
     * Incase of service instance with scaling of more than one, reply
     * can not be bridged as the destination mac address might point to
     * any of the primary/secondary. In this case, reply is forced
     * to go on the receiving VIF
     */
    if (vif_is_vhost(vif) || vif_is_fabric(vif) ||
            (vif->vif_flags & (VIF_FLAG_NO_ARP_PROXY | VIF_FLAG_MAC_PROXY))) {
        vif_tx = true;
    } else {
        rt.rtr_req.rtr_label_flags = 0;
        rt.rtr_req.rtr_index = VR_BE_INVALID_INDEX;
        rt.rtr_req.rtr_mac_size = VR_ETHER_ALEN;
        rt.rtr_req.rtr_mac = pkt_data(pkt);
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
    if (eth_proto == VR_ETH_PROTO_PBB) {

        if (pkt_len < (pull_len + sizeof(struct vr_pbb_itag)))
            return -1;
        pull_len += sizeof(struct vr_pbb_itag);

        if (pkt_len < (pull_len + VR_ETHER_HLEN))
            return -1;

        pkt->vp_type = vr_eth_proto_to_pkt_type(eth_proto);
        return 0;
    }

    while (eth_proto == VR_ETH_PROTO_VLAN) {
        if (pkt_len < (pull_len + sizeof(*vlan)))
            return -1;
        vlan = (struct vr_vlan_hdr *)(eth + pull_len);
        /*
         * consider the packet as vlan tagged only if it is provider
         * vlan tag. Customers vlan tag, Vrouter is not bothered off
         */
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
        unsigned char *eth_dmac)
{
    int handled = 1;
    struct vr_arp sarp;

    if (pkt->vp_type != VP_TYPE_ARP)
        return !handled;

    if (pkt->vp_len < sizeof(struct vr_arp)) {
        vr_pfree(pkt, VP_DROP_INVALID_ARP);
        return handled;
    }

    memcpy(&sarp, pkt_data(pkt), sizeof(struct vr_arp));

    switch (ntohs(sarp.arp_op)) {
    case VR_ARP_OP_REQUEST:
        return vr_handle_arp_request(&sarp, pkt, fmd, eth_dmac);

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

    if (vif_is_vhost(vif) ||
            (vif_is_fabric(vif) && (fmd->fmd_label < 0))) {
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
                 struct vr_packet *pkt, struct vr_forwarding_md *fmd,
                 unsigned short vlan_id)
{
    fmd->fmd_vlan = vlan_id;
    fmd->fmd_dvrf = vrf;
    if (pkt->vp_priority != VP_PRIORITY_INVALID) {
        fmd->fmd_dotonep = pkt->vp_priority;
        pkt->vp_priority = VP_PRIORITY_INVALID;
    }

    if (vr_pkt_type(pkt, 0, fmd) < 0) {
        vif_drop_pkt(vif, pkt, 1);
        return 0;
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

    if (!vr_flow_forward(pkt->vp_if->vif_router, pkt, fmd, NULL))
        return 0;

    vr_bridge_input(vif->vif_router, pkt, fmd);

    return 0;
}

#if defined(__linux__) && !defined(__KERNEL__)
static struct vr_flow_entry ***flow_cache_base_addr;
static uint64_t zero64 = 0;

/* Initialize flow_cache_base_addr on loading code segment */
static void __attribute__((constructor, used))
flow_cache_base_addr_init(void)
{
    flow_cache_base_addr = get_flow_cache_base_addr();
    return;
}
#endif

unsigned int
vr_virtual_input_bulk(unsigned short vrf, struct vr_interface *vif,
                      struct vr_packet **pkt, struct vr_forwarding_md **fmd,
                      unsigned short *vlan_id, uint32_t n)
{
    uint32_t i, k = 0;
    struct vr_packet *pkts[VR_DPDK_RX_BURST_SZ];
    struct vr_forwarding_md *fmds[VR_DPDK_RX_BURST_SZ];
    unsigned int ret = 0;
#if defined(__linux__) && !defined(__KERNEL__)
    struct vr_ip *ip;
    uint32_t hashval, index;
    uint64_t *ip1, *ip1_saved;
    uint64_t ip2, ip2_saved;
    uint32_t *ip3;
    int cpuid;
    struct vr_flow flow, *flow_p = &flow;
    struct vr_flow_entry *fe, **fe_p;
    unsigned int fe_index;
    unsigned int ip_inc_diff_cksum = 0;
    uint32_t new_stats;
    bool forwarded;

    cpuid = get_cpuid();
#endif

    for (i = 0; i < n; i++) {
        fmd[i]->fmd_vlan = vlan_id[i];
        fmd[i]->fmd_dvrf = vrf;
        if (pkt[i]->vp_priority != VP_PRIORITY_INVALID) {
            fmd[i]->fmd_dotonep = pkt[i]->vp_priority;
            pkt[i]->vp_priority = VP_PRIORITY_INVALID;
        }

        if (vr_pkt_type(pkt[i], 0, fmd[i]) < 0) {
            vif_drop_pkt(vif, pkt[i], 1);
            continue;
        }

        /*
         * we really do not allow any broadcast packets from interfaces
         * that are part of transparent service chain, since transparent
         * service chain bridges packets across vrf (and hence loops can
         * happen)
         */
        if ((pkt[i]->vp_flags & VP_FLAG_MULTICAST) &&
                (vif_is_service(vif)) && (pkt[i]->vp_type != VP_TYPE_ARP)) {
            vif_drop_pkt(vif, pkt[i], 1);
            continue;
        }

#if defined(__linux__) && !defined(__KERNEL__)
        /* won't cache flows if vif_idx >= VR_FLOW_VIF_MAX_IDX because of cache size */
        if (vif->vif_idx >= VR_FLOW_VIF_MAX_IDX) {
            if (!vr_flow_forward(pkt[i]->vp_if->vif_router, pkt[i], fmd[i], NULL))
                continue;
        } else if (likely(pkt[i]->vp_type == VP_TYPE_IP)) {
            ip = (struct vr_ip *)pkt_network_header(pkt[i]);

            hashval = vr_hash(&ip->ip_saddr, 12, 0);
            hashval = vr_hash_2words(hashval, ip->ip_proto, 0);
            index = hashval & VR_FLOW_CACHE_SIZE_MASK;
            fe_p = *flow_cache_base_addr + (cpuid * VR_FLOW_VIF_MAX_IDX + vif->vif_idx)* VR_FLOW_CACHE_SIZE
                                         + index;
            fe = *fe_p;
            if (fe) {
                rte_prefetch0(&fe->fe_key);
            } else {
                ip1_saved = &zero64;
                ip2_saved = 0;
            }
            ip1 = (uint64_t *)&ip->ip_saddr;
            ip3 = (uint32_t *)&ip2;
            *ip3 = *(uint32_t *)(ip1 + 1);
            ip3++;
            *ip3 = ip->ip_proto;
            if (fe) {
                ip1_saved = (uint64_t *)&fe->fe_key.flow4_sip;
                ip3 = (uint32_t *)&ip2_saved;
                *ip3 = *(uint32_t *)&fe->fe_key.flow4_sport;
                ip3++;
                *ip3 = fe->fe_key.flow4_proto;
            }

            forwarded = false;
            if (unlikely((!fe) || (*ip1 != *ip1_saved) || (ip2 != ip2_saved))) {
                bool result = vr_flow_forward(pkt[i]->vp_if->vif_router, pkt[i], fmd[i], &fe_index);
                if (!result) {
                    *fe_p = NULL;
                    fe = NULL;
                    continue;
                } else {
                    *fe_p = vr_flow_get_entry(pkt[i]->vp_if->vif_router, fe_index);
                    fe = *fe_p;
                }
                forwarded = true;
            }

            if (!forwarded && fe) {
                /* Update flow entry tcp state */
                if (ip->ip_proto == VR_IP_PROTO_TCP)
                    vr_flow_tcp_digest(pkt[i]->vp_if->vif_router, fe, pkt[i], fmd[i]);

                /* Update flow entry stats */
                new_stats = vr_sync_add_and_fetch_32u(&fe->fe_stats.flow_bytes, pkt_len(pkt[i]));
                if (new_stats < pkt_len(pkt[i]))
                    fe->fe_stats.flow_bytes_oflow++;

                new_stats = vr_sync_add_and_fetch_32u(&fe->fe_stats.flow_packets, 1);
                if (!new_stats)
                    fe->fe_stats.flow_packets_oflow++;

                /* Decrease ttl by one and recalculate ip checksum */
                if (fe->fe_ttl && (fe->fe_ttl != ip->ip_ttl)) {
                    ip_inc_diff_cksum = 0;
                    vr_incremental_diff(ip->ip_ttl, fe->fe_ttl, &ip_inc_diff_cksum);
                    ip->ip_ttl = fe->fe_ttl;

                    if (ip_inc_diff_cksum)
                        vr_ip_incremental_csum(ip, ip_inc_diff_cksum);
                }
            }
        } else if (pkt[i]->vp_type == VP_TYPE_IP6) {
            if (!vr_flow_forward(pkt[i]->vp_if->vif_router, pkt[i], fmd[i], NULL))
                continue;
        }
#else
        if (!vr_flow_forward(pkt[i]->vp_if->vif_router, pkt[i], fmd[i], NULL))
            continue;
#endif

        pkts[k] = pkt[i];
        fmds[k] = fmd[i];
        k++;
    }

    ret = vr_bridge_input_bulk(vif->vif_router, pkts, fmds, k);
    return ret;
}

unsigned int
vr_fabric_input(struct vr_interface *vif, struct vr_packet *pkt,
                struct vr_forwarding_md *fmd, unsigned short vlan_id)
{
    int handled = 0;
    unsigned short pull_len;
    unsigned char *data, eth_dmac[VR_ETHER_ALEN];

    fmd->fmd_vlan = vlan_id;
    fmd->fmd_dvrf = vif->vif_vrf;

    if (vr_pkt_type(pkt, 0, fmd) < 0) {
        vif_drop_pkt(vif, pkt, 1);
        return 0;
    }

    if (pkt->vp_type == VP_TYPE_IP6)
        return vif_xconnect(vif, pkt, fmd);

    /*
     * On Fabric only ARP packets are specially handled. Rest all BUM
     * traffic can be cross connected
     */
    if ((pkt->vp_type != VP_TYPE_ARP) &&
            (pkt->vp_flags & VP_FLAG_MULTICAST)) {
        return vif_xconnect(vif, pkt, fmd);
    }

    data = pkt_data(pkt);
    pull_len = pkt_get_network_header_off(pkt) - pkt_head_space(pkt);
    pkt_pull(pkt, pull_len);

    if (pkt->vp_type == VP_TYPE_IP || pkt->vp_type == VP_TYPE_IP6) {
        handled = vr_l3_input(pkt, fmd);
    } else if (pkt->vp_type == VP_TYPE_ARP) {
        VR_MAC_COPY(eth_dmac, data);
        handled = vr_arp_input(pkt, fmd, eth_dmac);
    }

    if (!handled) {
        pkt_push(pkt, pull_len);
        return vif_xconnect(vif, pkt, fmd);
    }

    return 0;
}

unsigned int
vr_fabric_input_bulk(struct vr_interface *vif, struct vr_packet **pkt,
                     struct vr_forwarding_md **fmd, unsigned short *vlan_id, uint32_t n)
{
    int handled = 0;
    unsigned short pull_len;
    unsigned char *data, eth_dmac[VR_ETHER_ALEN];
    unsigned int ret = 0;
    uint32_t i;

    for (i = 0; i < n; i++) {
        fmd[i]->fmd_vlan = vlan_id[i];
        fmd[i]->fmd_dvrf = vif->vif_vrf;

        if (vr_pkt_type(pkt[i], 0, fmd[i]) < 0) {
            vif_drop_pkt(vif, pkt[i], 1);
            continue;
        }

        if (pkt[i]->vp_type == VP_TYPE_IP6) {
            ret = vif_xconnect(vif, pkt[i], fmd[i]);
            continue;
        }

        /*
         * On Fabric only ARP packets are specially handled. Rest all BUM
         * traffic can be cross connected
         */
        if ((pkt[i]->vp_type != VP_TYPE_ARP) &&
                (pkt[i]->vp_flags & VP_FLAG_MULTICAST)) {
            ret = vif_xconnect(vif, pkt[i], fmd[i]);
            continue;
        }

        data = pkt_data(pkt[i]);
        pull_len = pkt_get_network_header_off(pkt[i]) - pkt_head_space(pkt[i]);
        pkt_pull(pkt[i], pull_len);

        if (pkt[i]->vp_type == VP_TYPE_IP || pkt[i]->vp_type == VP_TYPE_IP6) {
            handled = vr_l3_input(pkt[i], fmd[i]);
        } else if (pkt[i]->vp_type == VP_TYPE_ARP) {
            VR_MAC_COPY(eth_dmac, data);
            handled = vr_arp_input(pkt[i], fmd[i], eth_dmac);
        }

        if (!handled) {
            pkt_push(pkt[i], pull_len);
            ret = vif_xconnect(vif, pkt[i], fmd[i]);
            continue;
        }
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
vr_tag_pkt(struct vr_packet **pkt, unsigned short vlan_id, bool force_tag)
{
    uint8_t priority = 0;
    struct vr_packet *tmp_pkt;
    struct vr_eth *new_eth, *eth;
    unsigned short *vlan_tag;

    eth = (struct vr_eth *)pkt_data(*pkt);
    if (!force_tag) {
        if (eth->eth_proto == htons(VR_ETH_PROTO_VLAN))
            return 0;
    }

    if (pkt_head_space(*pkt) < VR_VLAN_HLEN) {
        tmp_pkt = vr_pexpand_head(*pkt, VR_VLAN_HLEN - pkt_head_space(*pkt));
        if (!tmp_pkt) {
            return -1;
        }
        *pkt = tmp_pkt;
    }

    new_eth = (struct vr_eth *)pkt_push(*pkt, VR_VLAN_HLEN);
    if (!new_eth)
        return -1;

    memmove(new_eth, eth, (2 * VR_ETHER_ALEN));
    new_eth->eth_proto = htons(VR_ETH_PROTO_VLAN);
    vlan_tag = (unsigned short *)(new_eth + 1);
    if ((*pkt)->vp_priority != VP_PRIORITY_INVALID)
        priority = (*pkt)->vp_priority;

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
    unsigned short push_len = 0;
    int handled = 1;
    struct vr_gro *gro;

    if (!vr_gro_process) {
        handled = 0;
        goto not_handled;
    }

    gro = (struct vr_gro *)pkt_push(pkt, sizeof(*gro));
    if (!gro) {
        handled = 0;
        goto not_handled;
    }
    push_len += sizeof(*gro);

    gro->vg_vif_id = pkt->vp_if->vif_idx;
    gro->vg_nh_id = nh->nh_id;

    handled = vr_gro_process(pkt, nh->nh_dev, (nh->nh_family == AF_BRIDGE));
not_handled:
    if (!handled) {
        pkt_pull(pkt, push_len);
    }

    return handled;
}

int
__vr_pbb_decode(struct vr_eth *eth, int len, struct vr_forwarding_md *fmd)
{
    int pbb_size = sizeof(struct vr_eth) + sizeof(struct vr_pbb_itag);

    if (!eth || !fmd || (len < pbb_size))
        return -1;

    if (ntohs(eth->eth_proto) != VR_ETH_PROTO_PBB)
        return -1;

    /* Copy the PBB mac addresses to fmd */
    VR_MAC_COPY(fmd->fmd_smac, eth->eth_smac);
    VR_MAC_COPY(fmd->fmd_dmac, eth->eth_dmac);

    return pbb_size;
}

int
vr_pbb_decode(struct vr_packet *pkt, struct vr_forwarding_md *fmd)
{
    int pbb_size, decode_error = 1;

    pbb_size = __vr_pbb_decode((struct vr_eth *)pkt_data(pkt),
            pkt_head_len(pkt), fmd);
    if (pbb_size <= 0) {
        vr_pfree(pkt, VP_DROP_INVALID_PACKET);
        return decode_error;
    }

    if (!pkt_pull(pkt, pbb_size)) {
        vr_pfree(pkt, VP_DROP_PULL);
        return decode_error;
    }

    /* Get the inner ether type and header pointers */
    if (vr_pkt_type(pkt, 0, fmd) < 0) {
        vr_pfree(pkt, VP_DROP_INVALID_PACKET);
        return decode_error;
    }

    return !decode_error;
}
