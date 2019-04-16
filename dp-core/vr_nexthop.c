/*
 * vr_nexthop.c -- data path nexthop management
 *
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#include <vr_os.h>
#include <vr_types.h>
#include <vr_packet.h>
#include <vr_interface.h>
#include <vr_nexthop.h>
#include <vr_vxlan.h>

#include "vr_message.h"
#include "vr_sandesh.h"
#include "vr_bridge.h"
#include "vr_btable.h"
#include "vr_datapath.h"
#include "vr_route.h"
#include "vr_hash.h"
#include "vr_mirror.h"
#include "vr_offloads_dp.h"

extern bool vr_has_to_fragment(struct vr_interface *, struct vr_packet *,
        unsigned int);
extern struct vr_vrf_stats *(*vr_inet_vrf_stats)(unsigned short, unsigned int);
extern struct vr_nexthop *vr_inet6_ip_lookup(unsigned short, uint8_t *);
extern struct vr_nexthop *vr_inet_ip_lookup(unsigned short, uint32_t);
extern struct vr_nexthop *vr_inet_src_lookup(unsigned short,
        struct vr_packet *);
extern l4_pkt_type_t vr_ip6_well_known_packet(struct vr_packet *);
extern l4_pkt_type_t vr_ip_well_known_packet(struct vr_packet *);


struct vr_nexthop *ip4_default_nh;
struct vr_nexthop *ip6_default_nh;

unsigned int vr_nexthops = VR_DEF_NEXTHOPS;

struct vr_nexthop *
__vrouter_get_nexthop(struct vrouter *router, unsigned int index)
{
    if (!router || index >= router->vr_max_nexthops)
        return NULL;

    return *(struct vr_nexthop **)vr_btable_get(router->vr_nexthops, index);
}

struct vr_nexthop *
vrouter_get_nexthop(unsigned int rid, unsigned int index)
{
    struct vr_nexthop *nh;
    struct vrouter *router;

    router = vrouter_get(rid);
    nh = __vrouter_get_nexthop(router, index);
    if (nh)
        (void)vr_sync_add_and_fetch_32u(&nh->nh_users, 1);

    return nh;
}

static int
__vrouter_set_nexthop(struct vrouter *router, unsigned int index,
        struct vr_nexthop *nh)
{
    struct vr_nexthop **nh_p;

    nh_p = (struct vr_nexthop **)vr_btable_get(router->vr_nexthops, index);
    if (!nh_p)
        return -EINVAL;

    *nh_p = nh;
    return 0;
}

static bool
vr_l2_control_data_add(struct vr_packet **pkt)
{

    unsigned int *data;
    struct vr_packet *tmp_pkt;

    if (pkt_head_space(*pkt) < VR_L2_CTRL_DATA_LEN) {
        tmp_pkt = vr_pexpand_head(*pkt, VR_L2_CTRL_DATA_LEN -
                                                pkt_head_space(*pkt));
        if (!tmp_pkt)
            return false;
        *pkt = tmp_pkt;
    }

    data = (unsigned int *)pkt_push(*pkt, VR_L2_CTRL_DATA_LEN);
    if (!data)
        return false;

    *data = VR_L2_CTRL_DATA;
    return true;
}


static void
vrouter_free_nexthop(struct vr_nexthop *nh)
{
    if (nh->nh_type == NH_COMPOSITE) {
        if (nh->nh_component_nh) {
            vr_free(nh->nh_component_nh, VR_NEXTHOP_COMPONENT_OBJECT);
            nh->nh_component_nh = NULL;
        }

        if (nh->nh_component_ecmp) {
            nh->nh_component_ecmp_cnt = 0;
            vr_free(nh->nh_component_ecmp, VR_NEXTHOP_COMPONENT_OBJECT);
            nh->nh_component_ecmp = NULL;
        }

    } else if ((nh->nh_type == NH_TUNNEL) &&
            (nh->nh_flags & NH_FLAG_TUNNEL_UDP) &&
            (nh->nh_family == AF_INET6)) {
        if (nh->nh_udp_tun6_sip) {
            vr_free(nh->nh_udp_tun6_sip, VR_NETWORK_ADDRESS_OBJECT);
            nh->nh_udp_tun6_sip = NULL;
        }

        if (nh->nh_udp_tun6_dip) {
            vr_free(nh->nh_udp_tun6_dip, VR_NETWORK_ADDRESS_OBJECT);
            nh->nh_udp_tun6_dip = NULL;
        }
    }

    if (nh->nh_dev) {
        vrouter_put_interface(nh->nh_dev);
    }

    vr_free(nh, VR_NEXTHOP_OBJECT);
    return;
}

static void
vrouter_free_nexthop_cb(struct vrouter *router, void *data)
{
    struct vr_defer_data *vdd = (struct vr_defer_data *)data;

    if (!vdd)
        return;

    vrouter_free_nexthop((struct vr_nexthop *)vdd->vdd_data);
    return;
}

static int
vrouter_free_nexthop_defer(struct vr_nexthop *nh)
{
    struct vr_defer_data *defer;

    defer = vr_get_defer_data(sizeof(*defer));
    if (!defer)
        return -ENOMEM;

    defer->vdd_data = nh;
    vr_defer(nh->nh_router, vrouter_free_nexthop_cb, (void *)defer);

    return 0;
}

void
vrouter_put_nexthop(struct vr_nexthop *nh)
{
    int i, component_cnt;
    struct vr_nexthop *cnh;
    unsigned int ref_cnt;

    if (!nh)
        return;

    /* This function might get invoked with zero ref_cnt */
    ref_cnt = nh->nh_users;
    if (ref_cnt) {
        ref_cnt = vr_sync_sub_and_fetch_32u(&nh->nh_users, 1);
    }

    if (!ref_cnt ) {

        /* If indirect, lets de-ref the direct nh too */
        if ((nh->nh_flags & NH_FLAG_INDIRECT) && nh->nh_direct_nh) {
            cnh = nh->nh_direct_nh;
            nh->nh_direct_nh = NULL;
            vrouter_put_nexthop(cnh);
        }

        /* If composite de-ref the internal nexthops */
        if (nh->nh_type == NH_COMPOSITE) {
            component_cnt = nh->nh_component_cnt;
            nh->nh_component_cnt = 0;
            for (i = 0; i < component_cnt; i++) {
                if (nh->nh_component_nh[i].cnh) {
                    cnh = nh->nh_component_nh[i].cnh;
                    nh->nh_component_nh[i].cnh = NULL;
                    vrouter_put_nexthop(cnh);
                }
            }
        }

        if (vr_not_ready) {
            vrouter_free_nexthop(nh);
        } else {
            if (vrouter_free_nexthop_defer(nh)) {
                vr_delay_op();
                vrouter_free_nexthop(nh);
            }
        }
    }

    return;
}

static int
vrouter_add_nexthop(struct vr_nexthop *nh)
{
    struct vrouter *router = vrouter_get(nh->nh_rid);

    if (!router || nh->nh_id >= router->vr_max_nexthops)
        return -EINVAL;

    /*
     * NH change just copies the field
     * over to nexthop, incase of change
     * just return
     */
    if (__vrouter_get_nexthop(router, nh->nh_id))
        return 0;

    nh->nh_users++;
    return __vrouter_set_nexthop(router, nh->nh_id, nh);
}

static void
nh_del(struct vr_nexthop *nh)
{
    struct vrouter *router = vrouter_get(nh->nh_rid);

    if (!router || nh->nh_id >= router->vr_max_nexthops)
        return;

    __vrouter_set_nexthop(router, nh->nh_id, NULL);
    vrouter_put_nexthop(nh);

    return;
}

bool
vr_gateway_nexthop(struct vr_nexthop *nh)
{
    if (nh) {
        if (!nh->nh_dev)
            return false;

        if ((nh->nh_type == NH_ENCAP) &&
                (nh->nh_dev->vif_type == VIF_TYPE_AGENT))
            return true;
    }

    return false;
}


bool
vr_hosted_nexthop(struct vr_nexthop *nh)
{
    if (nh) {
        if (!nh->nh_dev)
            return false;

        if ((nh->nh_type == NH_ENCAP) && vif_is_virtual(nh->nh_dev))
            return true;
    }

    return false;
}

static int
nh_tunnel_loop_detect_handle(struct vr_packet *pkt, struct vr_nexthop *nh,
                                    struct vr_forwarding_md *fmd, uint32_t dip)
{
    if (!pkt || !nh || !fmd || !dip)
        return 0;

    if ((!fmd->fmd_outer_src_ip) || !vif_is_fabric(pkt->vp_if))
        return 0;

    if (nh->nh_type != NH_TUNNEL)
        return 0;

    if (fmd->fmd_outer_src_ip == dip) {
        PKT_LOG(VP_DROP_PKT_LOOP, pkt, 0, VR_NEXTHOP_C, __LINE__);
        vr_pfree(pkt, VP_DROP_PKT_LOOP);
        return 1;
    }

    return 0;
}


static nh_processing_t
nh_resolve(struct vr_packet *pkt, struct vr_nexthop *nh,
           struct vr_forwarding_md *fmd)
{
    struct vr_vrf_stats *stats;
    struct vr_packet *pkt_clone;

    stats = vr_inet_vrf_stats(fmd->fmd_dvrf, pkt->vp_cpu);
    if (stats)
        stats->vrf_resolves++;

    if (pkt->vp_if->vif_bridge) {
        /*
         * bridge is set only for vhost/physical interface, and this
         * path will be hit only for packets from vhost, in which case
         * we already know everything that has to be known i.e. we know
         * the outgoing device and the mac address (which was already
         * resolved as part of the arp request from host
         */
        pkt_clone = vr_pclone(pkt);
        if (pkt_clone) {
            vr_preset(pkt_clone);
            vif_xconnect(pkt->vp_if, pkt_clone, fmd);
        }
    }

    /* will trap the packet to agent to create a route */
    vr_trap(pkt, fmd->fmd_dvrf, AGENT_TRAP_RESOLVE, NULL);

    return NH_PROCESSING_COMPLETE;
}

static nh_processing_t
nh_vrf_translate(struct vr_packet *pkt, struct vr_nexthop *nh,
                 struct vr_forwarding_md *fmd)
{
    struct vr_vrf_stats *stats;

    stats = vr_inet_vrf_stats(nh->nh_vrf, pkt->vp_cpu);
    if (stats)
        stats->vrf_vrf_translates++;

    fmd->fmd_dvrf = nh->nh_vrf;
    if (nh->nh_family == AF_INET)
        return vr_forward(nh->nh_router, pkt, fmd);

    if (pkt->vp_type == VP_TYPE_PBB) {
        if (vr_pbb_decode(pkt, fmd))
            return 0;
    }

    vr_bridge_input(nh->nh_router, pkt, fmd);

    return NH_PROCESSING_COMPLETE;
}

static nh_processing_t
nh_l2_rcv(struct vr_packet *pkt, struct vr_nexthop *nh,
          struct vr_forwarding_md *fmd)
{
    unsigned char eth_dmac[VR_ETHER_ALEN], *data;
    int pull_len, handled = 0;
    struct vr_vrf_stats *stats;

    stats = vr_inet_vrf_stats(fmd->fmd_dvrf, pkt->vp_cpu);
    if (stats)
        stats->vrf_l2_receives++;

    data = pkt_data(pkt);
    fmd->fmd_to_me = 1;
    pull_len = pkt_get_network_header_off(pkt) - pkt_head_space(pkt);
    if (!pkt_pull(pkt, pull_len)) {
        PKT_LOG(VP_DROP_PULL, pkt, 0, VR_NEXTHOP_C, __LINE__);
        vr_pfree(pkt, VP_DROP_PULL);
        return NH_PROCESSING_COMPLETE;
    }

    /*
     * there should not be any unicast ARP requests destined to "my mac".
     * The ARP response destined to "my mac" incase of ARP request being
     * generated by Agent for some features
     */
    if (pkt->vp_type == VP_TYPE_IP6) {
        VR_MAC_COPY(eth_dmac, data);
        handled = vr_neighbor_input(pkt, fmd, eth_dmac);
        if (!handled)
            handled = vr_l3_input(pkt, fmd);
    } else if (pkt->vp_type == VP_TYPE_IP) {
        handled = vr_l3_input(pkt, fmd);
    } else if (pkt->vp_type == VP_TYPE_ARP) {
        VR_MAC_COPY(eth_dmac, data);
        handled = vr_arp_input(pkt, fmd, eth_dmac);
    }

    if (!handled){
        PKT_LOG(VP_DROP_INVALID_PROTOCOL, pkt, 0, VR_NEXTHOP_C, __LINE__);
        vr_pfree(pkt, VP_DROP_INVALID_PROTOCOL);
    }
    return NH_PROCESSING_COMPLETE;
}

static nh_processing_t
nh_l3_rcv(struct vr_packet *pkt, struct vr_nexthop *nh,
          struct vr_forwarding_md *fmd)
{
    struct vr_vrf_stats *stats;

    stats = vr_inet_vrf_stats(fmd->fmd_dvrf, pkt->vp_cpu);
    if (stats)
        stats->vrf_receives++;

    if (nh->nh_family == AF_INET)
        return vr_ip_rcv(nh->nh_router, pkt, fmd);
    else {
        PKT_LOG(VP_DROP_INVALID_PROTOCOL, pkt, 0, VR_NEXTHOP_C, __LINE__);
        vr_pfree(pkt, VP_DROP_INVALID_PROTOCOL);
    }
    return NH_PROCESSING_COMPLETE;
}

static int
nh_push_mpls_header(struct vr_packet *pkt, unsigned int label,
        struct vr_forwarding_class_qos *qos, bool is_bottom_label)
{
    uint32_t exp_qos = 0;
    unsigned int *lbl;
    unsigned int ttl;
    unsigned int label_pos = 0;

    lbl = (unsigned int *)pkt_push(pkt, sizeof(unsigned int));
    if (!lbl)
        return -ENOSPC;

    /* Use the ttl from packet. If not ttl,
     * initialise to some arbitrary value */
    ttl = pkt->vp_ttl;
    if (!ttl) {
        ttl = 64;
    }

    if (qos) {
        exp_qos = qos->vfcq_mpls_qos;
        exp_qos <<= VR_MPLS_EXP_QOS_SHIFT;
    }
    if (is_bottom_label) {
	label_pos = 1;
    }
    *lbl = htonl((label << VR_MPLS_LABEL_SHIFT) | exp_qos |
            (label_pos << 8) | ttl);

    return 0;
}

/*
 * nh_udp_tunnel_helper - helper function to use for UDP tunneling. Used
 * by mirroring and MPLS over UDP. Returns true on success, false otherwise.
 */
static bool
nh_udp_tunnel_helper(struct vr_packet *pkt, unsigned short sport,
        unsigned short dport, unsigned int sip,
        unsigned int dip, struct vr_forwarding_class_qos *qos)
{
    struct vr_ip *ip;
    struct vr_udp *udp;

    /* Udp Header */
    udp = (struct vr_udp *)pkt_push(pkt, sizeof(struct vr_udp));
    if (!udp) {
        return false;
    }

    udp->udp_sport = sport;
    udp->udp_dport = dport;
    udp->udp_length = htons(pkt_len(pkt));
    udp->udp_csum = 0;

    /* And now the IP header */
    ip = (struct vr_ip *)pkt_push(pkt, sizeof(struct vr_ip));
    if (!ip) {
        return false;
    }

    ip->ip_version = 4;
    ip->ip_hl = 5;
    if (qos) {
        ip->ip_tos = VR_IP_DSCP(qos->vfcq_dscp);
        pkt->vp_queue = qos->vfcq_queue_id;
        pkt->vp_priority = qos->vfcq_dotonep_qos;
    } else {
        ip->ip_tos = 0;
    }
    ip->ip_id = htons(vr_generate_unique_ip_id());
    ip->ip_frag_off = 0;

    if (vr_pkt_is_diag(pkt)) {
        ip->ip_ttl = pkt->vp_ttl;
    } else {
        ip->ip_ttl = 64;
    }

    ip->ip_proto = VR_IP_PROTO_UDP;
    ip->ip_saddr = sip;
    ip->ip_daddr = dip;
    ip->ip_len = htons(pkt_len(pkt));

    /*
     * header checksum
     */
    ip->ip_csum = 0;
    ip->ip_csum = vr_ip_csum(ip);

    return true;
}

static bool
nh_udp_tunnel6_helper(struct vr_packet *pkt, struct vr_nexthop *nh,
                        uint8_t *sip, uint16_t sport, uint16_t dport)
{
    struct vr_ip6 *ip6;
    struct vr_udp *udp;

    if (!sip)
        sip = nh->nh_udp_tun6_sip;

    /* udp Header */
    udp = (struct vr_udp *)pkt_push(pkt, sizeof(struct vr_udp));
    if (!udp) {
        return false;
    }

    udp->udp_sport = sport;
    udp->udp_dport = dport;
    udp->udp_length = htons(pkt_len(pkt));
    udp->udp_csum = 0;

    /* And now the IP6 header */
    ip6 = (struct vr_ip6 *)pkt_push(pkt, sizeof(struct vr_ip6));
    if (!ip6) {
        return false;
    }

    ip6->ip6_version = 6;
    ip6->ip6_priority_l = 0;
    ip6->ip6_priority_h = 0;
    ip6->ip6_flow_l = 0;
    ip6->ip6_flow_h = 0;
    ip6->ip6_plen = htons(pkt_len(pkt) - sizeof(struct vr_ip6));
    ip6->ip6_nxt = VR_IP_PROTO_UDP;
    ip6->ip6_hlim = 64;

    memcpy(ip6->ip6_src, sip, VR_IP6_ADDRESS_LEN);
    memcpy(ip6->ip6_dst, nh->nh_udp_tun6_dip, VR_IP6_ADDRESS_LEN);


    return true;
}

static bool
nh_pbb_tunnel_helper(struct vrouter *router, struct vr_packet **pkt,
        struct vr_forwarding_md *fmd, uint8_t *dmac, uint8_t *smac,
        uint32_t isid)
{
    int pbb_head_space;
    struct vr_pbb_itag *pbb_itag;
    struct vr_eth *eth;
    struct vr_packet *expanded_pkt;

    pbb_head_space = sizeof(struct vr_pbb_itag) + VR_ETHER_HLEN;

    if (pkt_head_space(*pkt) < pbb_head_space) {
        expanded_pkt = vr_pexpand_head(*pkt, pbb_head_space - pkt_head_space(*pkt));
        if (!expanded_pkt)
            return false;
        *pkt = expanded_pkt;
    }

    pbb_itag = (struct vr_pbb_itag *)pkt_push(*pkt, sizeof(*pbb_itag));
    if (!pbb_itag)
        return false;
    pbb_itag->pbbi_pcp = pbb_itag->pbbi_dei = 0;
    pbb_itag->pbbi_uca = pbb_itag->pbbi_res = 0;
    pbb_itag->pbbi_isid = (htonl(isid) >> 8) & 0xFFFFFF;

    eth = (struct vr_eth *)pkt_push(*pkt, VR_ETHER_HLEN);
    if(!eth)
        return false;

    VR_MAC_COPY(eth->eth_dmac, dmac);
    VR_MAC_COPY(eth->eth_smac, smac);
    eth->eth_proto = htons(VR_ETH_PROTO_PBB);

    return true;
}

static bool
nh_vxlan_tunnel_helper(struct vrouter *router, struct vr_packet **pkt,
        struct vr_forwarding_md *fmd, unsigned int sip, unsigned int dip)
{
    unsigned short udp_src_port = VR_VXLAN_UDP_SRC_PORT;

    struct vr_vxlan *vxlanh;
    struct vr_packet *expanded_pkt;
    struct vr_forwarding_class_qos *qos;

    if (pkt_head_space(*pkt) < VR_VXLAN_HDR_LEN) {
        expanded_pkt = vr_pexpand_head(*pkt, VR_VXLAN_HDR_LEN - pkt_head_space(*pkt));
        if (!expanded_pkt) {
            return false;
        }
        *pkt = expanded_pkt;
    }

    if (fmd->fmd_udp_src_port)
        udp_src_port = fmd->fmd_udp_src_port;

    /*
     * The UDP source port is a hash of the inner headers
     */
    if ((!fmd->fmd_udp_src_port) && vr_get_udp_src_port) {
        udp_src_port = vr_get_udp_src_port(*pkt, fmd, fmd->fmd_dvrf);
        if (udp_src_port == 0) {
         return false;
        }
    }

    vr_fmd_update_label_type(fmd, VR_LABEL_TYPE_VXLAN_ID);

    /* Add the vxlan header */
    vxlanh = (struct vr_vxlan *)pkt_push(*pkt, sizeof(struct vr_vxlan));
    vxlanh->vxlan_vnid = htonl(fmd->fmd_label << VR_VXLAN_VNID_SHIFT);
    vxlanh->vxlan_flags = htonl(VR_VXLAN_IBIT);

    qos = vr_qos_get_forwarding_class(router, *pkt, fmd);
    return nh_udp_tunnel_helper(*pkt, htons(udp_src_port),
            htons(VR_VXLAN_UDP_DST_PORT), sip, dip, qos);
}

static struct vr_packet *
nh_mcast_clone(struct vr_packet *pkt, unsigned short head_room)
{
    struct vr_packet *clone_pkt;

    /* Clone the packet */
    clone_pkt = vr_pclone(pkt);
    if (!clone_pkt) {
        return NULL;
    }

    /* Increase the head space by the head_room */
    if (vr_pcow(&clone_pkt, head_room)) {
        PKT_LOG(VP_DROP_PCOW_FAIL, pkt, 0, VR_NEXTHOP_C, __LINE__);
        vr_pfree(clone_pkt, VP_DROP_PCOW_FAIL);
        return NULL;
    }

    /* Copy the ttl from old packet */
    clone_pkt->vp_ttl = pkt->vp_ttl;

    return clone_pkt;
}

static int
nh_composite_ecmp_validate_src(struct vr_packet *pkt, struct vr_nexthop *nh,
                               struct vr_forwarding_md *fmd, void *ret_data)
{
    int i;
    int status = NH_SOURCE_INVALID;
    unsigned int inner_ecmp_index = -1;/* reset to invalid */
    struct vr_nexthop *cnh = NULL;

    /* the first few checks are straight forward */
    if (!fmd)
        return NH_SOURCE_INVALID;

    if ((fmd->fmd_ecmp_src_nh_index >= 0) &&
            (fmd->fmd_ecmp_src_nh_index < nh->nh_component_cnt)) {
        cnh = nh->nh_component_nh[fmd->fmd_ecmp_src_nh_index].cnh;
    }

    /*
     * when the 'supposed' source goes down, cnh is null, in which
     * case validate the source against other present nexthops. follow
     * the same logic if the component validate source returns invalid
     * source, which could mean that source has moved
     */
    if (!cnh || (!cnh->nh_validate_src) ||
            (NH_SOURCE_INVALID == cnh->nh_validate_src(pkt, cnh, fmd, NULL))) {
        for (i = 0; i < nh->nh_component_cnt; i++) {
            if (i == fmd->fmd_ecmp_src_nh_index)
                continue;

            cnh = nh->nh_component_nh[i].cnh;
            /* If direct nexthop is not valid, dont process it */
            if (!cnh || !(cnh->nh_flags & NH_FLAG_VALID) ||
                                            !cnh->nh_validate_src)
                continue;

            /*
             * if the source has moved to a present and valid source,
             * return mismatch
             */
            status = cnh->nh_validate_src(pkt, cnh, fmd, &inner_ecmp_index);
            if (status == NH_SOURCE_VALID) {
                if (ret_data) {
                    *(unsigned int *)ret_data = i;
		        }
                return NH_SOURCE_MISMATCH;
            }
            /*
             * Handle multi level ECMP,
             * inner ecmp returns NH_SOURCE_MISMATCH, return the
             * same error. copy inner_ecmp_value for NH mismatch case only.
             */
            if (status == NH_SOURCE_MISMATCH) {
                if (ret_data) {
                    *(unsigned int *)ret_data = inner_ecmp_index;
		        }
                return NH_SOURCE_MISMATCH;
            }
        }

        /* if everything else fails, source is indeed invalid */
        return NH_SOURCE_INVALID;
    }

    /* source is validated by validate_src */
    return NH_SOURCE_VALID;
}

/*
 * nh_ecmp_config_hash is two byte value. The configurable hash as such is
 * 5 bit field. We store agent added configurable hash values in the first
 * byte and convert them to Flow flags and store them in second byte
 */
static void
nh_ecmp_store_ecmp_config_hash(vr_nexthop_req *req, struct vr_nexthop *nh)
{
    unsigned char hash;
    unsigned short flow_hash;
    int i;

    if (!nh || (nh->nh_type != NH_COMPOSITE) ||
       (!(nh->nh_flags & NH_FLAG_COMPOSITE_ECMP))) {
        return;
    }

    if (!req || !req->nhr_ecmp_config_hash) {
        nh->nh_ecmp_config_hash = ((VR_FLOW_KEY_ALL << 8) & 0xFF00);
        return;
    }

    flow_hash = 0;
    hash = req->nhr_ecmp_config_hash & NH_ECMP_CONFIG_HASH_MASK;

    for (i = 0; i < NH_ECMP_CONFIG_HASH_BITS; i++) {
        switch (hash & (1 << i)) {
        case NH_ECMP_CONFIG_HASH_PROTO:
            flow_hash |= VR_FLOW_KEY_PROTO;
            break;
        case NH_ECMP_CONFIG_HASH_SRC_IP:
            flow_hash |= VR_FLOW_KEY_SRC_IP;
            break;
        case NH_ECMP_CONFIG_HASH_SRC_PORT:
            flow_hash |= VR_FLOW_KEY_SRC_PORT;
            break;
        case NH_ECMP_CONFIG_HASH_DST_IP:
            flow_hash |= VR_FLOW_KEY_DST_IP;
            break;
        case NH_ECMP_CONFIG_HASH_DST_PORT:
            flow_hash |= VR_FLOW_KEY_DST_PORT;
            break;
        default:
            break;
        }
    }

    /* In the nh, store flow hash values in the second byte */
    nh->nh_ecmp_config_hash = hash | ((flow_hash << 8) & 0xFF00);

    return;
}


/*
 * Returns the ecmp nh index based on the reverse flows information. If
 * the reverse flow is created because of a packet on Fabric,
 * rflow_src_info contains tunnel's source IP, if created because of a
 * packet on VMI, it contains VMI's index. The ecmp nh is chosen in such
 * a way that packet is given to same reverse flow source
 */
static int
nh_composite_ecmp_select_by_rflow(struct vr_packet *pkt,
        struct vr_nexthop *nh, struct vr_forwarding_md *fmd,
        uint32_t rflow_src_info)
{
    int index;
    uint32_t ip;
    struct vr_nexthop *cnh;

    ip = fmd->fmd_outer_src_ip;
    fmd->fmd_outer_src_ip = rflow_src_info;
    for (index = 0; index < nh->nh_component_cnt; index++) {
        cnh = nh->nh_component_nh[index].cnh;
        if (!cnh || !(cnh->nh_flags & NH_FLAG_VALID))
            continue;

        /*
         * Make use of tunnel's nh_validate_src as it validates the
         * tunnel source
         */
        if ((cnh->nh_type == NH_TUNNEL) && cnh->nh_validate_src) {
            if (NH_SOURCE_VALID == cnh->nh_validate_src(pkt, cnh, fmd, NULL))
                break;
        }

        /*
         * nh_validate_src cant be used as it compares VIF pointer for
         * encap. Validate the index explicitly
         */
        if (cnh->nh_type == NH_ENCAP) {
            if (cnh->nh_dev->vif_idx == rflow_src_info)
                break;
        }
    }

    fmd->fmd_outer_src_ip = ip;
    if (index == nh->nh_component_cnt)
       index = -1;

    return index;
}

static int
nh_composite_ecmp_select_nh(struct vr_packet *pkt, struct vr_nexthop *nh,
        struct vr_forwarding_md *fmd)
{
    bool hash_computed = false;
    int ret = -1, ecmp_index = -1;
    unsigned int hash, hash_ecmp, count, rflow_src_info;

    struct vr_flow flow, *flowp = &flow;
    struct vr_flow_entry *fe = NULL;
    struct vr_nexthop *cnh = NULL;
    struct vr_component_nh *cnhp = nh->nh_component_nh;

    if (!nh || !fmd || (!nh->nh_component_cnt))
        return ret;

    count = nh->nh_component_cnt;

    if (fmd->fmd_flow_index >= 0) {
        fe = vr_flow_get_entry(nh->nh_router, fmd->fmd_flow_index);
        if (fe) {
            flowp = &fe->fe_key;
            /*
             * If the ecmp index is explicitly configured as -1, the
             * index need to be chosen as the one matchig with reverse
             * flow's source.
             */
            if (fmd->fmd_ecmp_nh_index == -1) {
                rflow_src_info = vr_flow_get_rflow_src_info(nh->nh_router, fe);
                if (rflow_src_info != (unsigned int)-1) {
                    ecmp_index = nh_composite_ecmp_select_by_rflow(pkt,
                            nh, fmd, rflow_src_info);
                }
            }
        }
    }

    if (!fe) {

        /*
         * If the flow entry does not exist, apply the configured
         * hash parameters to select candidate nexthop
         */
        hash = (nh->nh_ecmp_config_hash >> 8) & NH_ECMP_CONFIG_HASH_MASK;
        if (pkt->vp_type == VP_TYPE_IP) {
            ret = vr_inet_get_flow_key(nh->nh_router, pkt, fmd, flowp, hash);
            if (ret < 0)
                return ret;
        } else if (pkt->vp_type == VP_TYPE_IP6) {
            ret = vr_inet6_get_flow_key(nh->nh_router, fmd->fmd_dvrf, pkt,
                                     fmd->fmd_vlan, flowp, hash);
            if (ret < 0)
                return ret;
        } else {
            /*
             * packet can be hashed on ethernet header and VRF to identify
             * the component
             */
            hash_ecmp = vr_hash(pkt_data(pkt), VR_ETHER_HLEN, 0);
            hash_ecmp = vr_hash_2words(hash_ecmp, fmd->fmd_dvrf, 0);
            hash_computed = true;
        }
    }


    if (ecmp_index == -1) {
        if (!hash_computed)
            hash_ecmp = vr_hash(flowp, flowp->flow_key_len, 0);
        hash = hash_ecmp % count;
        ecmp_index = cnhp[hash].cnh_ecmp_index;
        cnh = cnhp[hash].cnh;
        if (!cnh) {
            if (nh->nh_component_ecmp_cnt) {
                cnhp = nh->nh_component_ecmp;
                hash_ecmp %= nh->nh_component_ecmp_cnt;
                ecmp_index = cnhp[hash_ecmp].cnh_ecmp_index;
                if (!(cnh = cnhp[hash_ecmp].cnh))
                    return -1;
            }
        }
    }

    if (fe)
        return vr_flow_update_ecmp_index(nh->nh_router, fe, ecmp_index, fmd);

    fmd->fmd_ecmp_nh_index = ecmp_index;

    return 0;
}

static nh_processing_t
nh_composite_ecmp(struct vr_packet *pkt, struct vr_nexthop *nh,
                  struct vr_forwarding_md *fmd)
{
    int ret = 0, drop_reason = VP_DROP_INVALID_NH;
    struct vr_nexthop *member_nh = NULL;
    struct vr_vrf_stats *stats;

    stats = vr_inet_vrf_stats(fmd->fmd_dvrf, pkt->vp_cpu);
    if (stats)
        stats->vrf_ecmp_composites++;

    if (!fmd) {
        drop_reason = VP_DROP_NO_FMD;
        PKT_LOG(drop_reason, pkt, 0, VR_NEXTHOP_C, __LINE__);
        goto drop;
    }

    if ((fmd->fmd_ecmp_nh_index >= 0) &&
            (fmd->fmd_ecmp_nh_index < nh->nh_component_cnt)) {
        member_nh = nh->nh_component_nh[fmd->fmd_ecmp_nh_index].cnh;
    }

    if (!member_nh) {
        ret = nh_composite_ecmp_select_nh(pkt, nh, fmd);
        if (ret)
            goto drop;

        member_nh = nh->nh_component_nh[fmd->fmd_ecmp_nh_index].cnh;
        if (!member_nh)
            goto drop;
    }
    /*
     * this composite nh does not have vpn mpls label which should be
     * derived from routelook only, so not overriding label retrieved from
     * route lookup for label unicast composite nh case
     */
    if (!(nh->nh_flags & NH_FLAG_COMPOSITE_LU_ECMP)) {
        vr_fmd_set_label(fmd, nh->nh_component_nh[fmd->fmd_ecmp_nh_index].cnh_label,
               VR_LABEL_TYPE_UNKNOWN);
    }
    nh_output(pkt, member_nh, fmd);
    return NH_PROCESSING_COMPLETE;

drop:
    vr_pfree(pkt, drop_reason);
    return NH_PROCESSING_COMPLETE;
}


/*
 * This function validate the source  of the tunnel incase of L2
 * multicast
 */

static int
nh_composite_mcast_validate_src(struct vr_packet *pkt, struct vr_nexthop *nh,
                                struct vr_forwarding_md *fmd, void *ret_flags)
{
    int i, j;
    struct vr_nexthop *dir_nh, *fabric_nh;
    unsigned int tun_dip;

    /*
     * If multicast packet is received on fabric interface, we need to
     * validate whether the source of this packet is in the distribution
     * tree. If source is not in the list, packet needs to be dropped.
     */

    /* Valid if source is VM */
    if (pkt->vp_if->vif_type != VIF_TYPE_PHYSICAL)
        return NH_SOURCE_VALID;

    /* If there is no source IP to compare treat it as invalid source */
    if (!fmd->fmd_outer_src_ip)
        return NH_SOURCE_INVALID;

    for(j = 0; j < nh->nh_component_cnt; j++) {
        fabric_nh = nh->nh_component_nh[j].cnh;

        if (!fabric_nh || !(fabric_nh->nh_flags & NH_FLAG_VALID))
            continue;

        if (fabric_nh->nh_type != NH_COMPOSITE ||
            !(fabric_nh->nh_flags & (NH_FLAG_COMPOSITE_FABRIC |
              NH_FLAG_COMPOSITE_EVPN | NH_FLAG_COMPOSITE_TOR)))
            continue;

        for (i = 0; i < fabric_nh->nh_component_cnt; i++) {
            dir_nh = fabric_nh->nh_component_nh[i].cnh;

            /* If direct nexthop is not valid, dont process it */
            if ((!dir_nh) || !(dir_nh->nh_flags & NH_FLAG_VALID))
                continue;

            if (dir_nh->nh_type != NH_TUNNEL)
                continue;

            tun_dip = 0;
            if (dir_nh->nh_flags & NH_FLAG_TUNNEL_GRE)
                tun_dip = dir_nh->nh_gre_tun_dip;
            else if (dir_nh->nh_flags & NH_FLAG_TUNNEL_UDP_MPLS)
                tun_dip = dir_nh->nh_udp_tun_dip;
            else if (dir_nh->nh_flags & NH_FLAG_TUNNEL_VXLAN)
                tun_dip = dir_nh->nh_vxlan_tun_dip;

            /* If source is in districution tree, it is valid */
            if (tun_dip && fmd->fmd_outer_src_ip &&
                      fmd->fmd_outer_src_ip == tun_dip) {

                if (ret_flags)
                    *((unsigned int *)ret_flags) = fabric_nh->nh_flags;

                return NH_SOURCE_VALID;
            }
        }
    }

    if (!(nh->nh_flags & NH_FLAG_VALIDATE_MCAST_SRC)) {
        *((unsigned int *)ret_flags) = NH_FLAG_VALIDATE_MCAST_SRC;
        return NH_SOURCE_VALID;
    }

    return NH_SOURCE_INVALID;
}

static int
nh_handle_unknown_unicast(struct vr_packet *pkt, struct vr_eth *eth,
        struct vr_forwarding_md *fmd, unsigned int pkt_src)
{
    int handled = 1, pull_len;
    struct vr_route_req rt;
    struct vr_nexthop *nh;

    /*
     * If packet is from VM or from TOR, we must have done a look up
     * already in bridge before coming to this processing
     */
    if (!pkt_src || (pkt_src == PKT_SRC_TOR_REPL_TREE))
        return !handled;

    rt.rtr_req.rtr_label_flags = 0;
    rt.rtr_req.rtr_index = VR_BE_INVALID_INDEX;
    rt.rtr_req.rtr_mac_size = VR_ETHER_ALEN;
    rt.rtr_req.rtr_mac = eth->eth_dmac;
    rt.rtr_req.rtr_vrf_id = fmd->fmd_dvrf;

    nh = vr_bridge_lookup(fmd->fmd_dvrf, &rt);
    if (!nh || nh->nh_type != NH_ENCAP)
        return !handled;

    /* Get the packet to eth header */
    pull_len = (uintptr_t)eth - (uintptr_t)pkt_data(pkt);
    if (pull_len)
        pkt_pull(pkt, pull_len);

    nh_output(pkt, nh, fmd);

    return handled;
}

static int
nh_handle_mcast_control_pkt(struct vr_packet *pkt, struct vr_eth *eth,
        struct vr_forwarding_md *fmd, unsigned int pkt_src, bool *flood_to_vms)
{
    int handled = 1;
    unsigned char eth_dmac[VR_ETHER_ALEN];
    bool flood = false;
    unsigned short trap, rt_flags, drop_reason, pull_len  = 0;
    l4_pkt_type_t l4_type = L4_TYPE_UNKNOWN;
    struct vr_arp *sarp;
    struct vr_nexthop *src_nh;
    struct vr_ip6 *ip6;

    struct vr_packet *pkt_c = NULL;

    /*
     * The vlan tagged packets are meant to be handled only by VM's
     */
    if (fmd->fmd_vlan != VLAN_ID_INVALID)
        return !handled;

    pull_len = pkt_get_network_header_off(pkt) - pkt_head_space(pkt);
    if (!pkt_pull(pkt, pull_len)) {
        drop_reason = VP_DROP_PULL;
        PKT_LOG(drop_reason, pkt, 0, VR_NEXTHOP_C, __LINE__);
        goto drop;
    }

    rt_flags = vr_bridge_route_flags(fmd->fmd_dvrf, eth->eth_smac);

    if (pkt->vp_type == VP_TYPE_ARP) {

        if ((pkt_src == PKT_SRC_INGRESS_REPL_TREE) &&
                (rt_flags & VR_BE_EVPN_CONTROL_PROCESSING_FLAG)) {
            fmd->fmd_src = TOR_EVPN_SOURCE;
        }

        VR_MAC_COPY(eth_dmac, eth->eth_dmac);
        handled = vr_arp_input(pkt, fmd, eth_dmac);
        if (handled)
            return handled;

        /*
         * If not handled, packet needs to be flooded. If the ARP is
         * from MX, VM's should not see this ARP as VM's always need to
         * see Agent as gateway
         */

        if (pkt_src) {
            sarp = (struct vr_arp *)pkt_data(pkt);
            src_nh = vr_inet_ip_lookup(fmd->fmd_dvrf, sarp->arp_spa);
            if (vr_gateway_nexthop(src_nh)) {
                *flood_to_vms = false;
            }
        }

        goto unhandled;
    }

    if ((pkt->vp_type != VP_TYPE_IP) && (pkt->vp_type != VP_TYPE_IP6))
        goto unhandled;

    /*
     * V6 Ndisc, router solictation packets are ICMP packets. So we need
     * to parse to identify the type, unlike V4 ARP
     */
    if (pkt->vp_type == VP_TYPE_IP6) {
        l4_type = vr_ip6_well_known_packet(pkt);
    } else if (pkt_src == (PKT_SRC_TOR_REPL_TREE) ||
                (pkt_src == PKT_SRC_INGRESS_REPL_TREE)) {
        l4_type = vr_ip_well_known_packet(pkt);
    }

    /*
     * Special control packets need to be handled only if VM or BMS
     * behind OvsDB Tor or BMS behind Evpn Tor(which will have
     * VR_BE_EVPN_CONTROL_PROCESSING_FLAG)
     */
    if ((!pkt_src) || (pkt_src == PKT_SRC_TOR_REPL_TREE) ||
            ((pkt_src == PKT_SRC_INGRESS_REPL_TREE) &&
             (rt_flags & VR_BE_EVPN_CONTROL_PROCESSING_FLAG))) {

        /*
         * If packet is identified as known packet, we always trap
         * it to agent with the exception of DHCP. DHCP can be flooded
         * depending on the configuration on VMI or L2 route flags
         */
        if (l4_type != L4_TYPE_UNKNOWN) {

            trap = true;

            if (l4_type == L4_TYPE_DHCP_REQUEST) {
                if (rt_flags & VR_BE_FLOOD_DHCP_FLAG)
                    trap = false;
            } else if (l4_type == L4_TYPE_NEIGHBOUR_SOLICITATION) {
                trap = false;
            } else if (l4_type == L4_TYPE_NEIGHBOUR_ADVERTISEMENT) {
                flood = true;
            }

            if (trap && flood) {
                pkt_c = nh_mcast_clone(pkt, AGENT_PKT_HEAD_SPACE);
                if (!pkt_c) {
                    trap = false;
                }
            }

            if (trap) {
                if (flood) {
                    vr_trap(pkt_c, fmd->fmd_dvrf,
                            AGENT_TRAP_L3_PROTOCOLS, NULL);
                    goto unhandled;
                } else {
                    vr_trap(pkt, fmd->fmd_dvrf,
                            AGENT_TRAP_L3_PROTOCOLS, NULL);
                    return handled;
                }
            }
        }
    }

    if (l4_type == L4_TYPE_NEIGHBOUR_SOLICITATION) {
        VR_MAC_COPY(eth_dmac, eth->eth_dmac);
        handled = vr_neighbor_input(pkt, fmd, eth_dmac);
        if (handled)
            return handled;

        if (pkt_src) {
            ip6 = (struct vr_ip6 *)pkt_data(pkt);
            src_nh = vr_inet6_ip_lookup(fmd->fmd_dvrf, ip6->ip6_src);
            if (vr_gateway_nexthop(src_nh))
                *flood_to_vms = false;
        }
    }

unhandled:
    if (pull_len)
        pkt_push(pkt, pull_len);
    return 0;

drop:
    vr_pfree(pkt, drop_reason);
    return 1;
}

static nh_processing_t
nh_composite_mcast(struct vr_packet *pkt, struct vr_nexthop *nh,
                     struct vr_forwarding_md *fmd)
{

    int i, clone_size;
    bool flood_to_vms = true, l2_control_data = false;
    unsigned short drop_reason, label, pkt_vrf, pull_len = 0,
                   pbb_pull_len = 0;
    unsigned int tun_src, pkt_src, hashval, port_range, handled;
    mac_learn_t ml_res;
    struct vr_eth *eth = NULL;
    struct vr_nexthop *dir_nh;
    struct vr_packet *new_pkt;
    struct vr_vrf_stats *stats;
    // Context for the flag:
    // For 5.1, mcast source is outside contrail and only <*,G> is supported.
    // Until such a time when source can be inside contrail, multicast data
    // packets sourced from inside contrail has to be dropped.
    // Also, packets originating outside of contrail has pkt->vp_data pointing
    // to inner ethernet header (in case of VxLan tunneled packet).
    bool pull_header = true;

    stats = vr_inet_vrf_stats(fmd->fmd_dvrf, pkt->vp_cpu);
    if (stats)
        stats->vrf_l2_mcast_composites++;

    pkt_vrf = fmd->fmd_dvrf;
    drop_reason = VP_DROP_CLONED_ORIGINAL;

    if (!fmd) {
        drop_reason = VP_DROP_NO_FMD;
        PKT_LOG(drop_reason, pkt, 0, VR_NEXTHOP_C, __LINE__);
        goto drop;
    }

    /*
     * nh_validate_src identifies the format of the packet and source of
     * the packet too. Without this callback being defined we will not
     * be able to replicate the packet
     */
    if (!nh->nh_validate_src) {
        drop_reason = VP_DROP_MISC;
        PKT_LOG(drop_reason, pkt, 0, VR_NEXTHOP_C, __LINE__);
        goto drop;
    }

    tun_src = pkt_src = 0;
    if (nh->nh_validate_src(pkt, nh, fmd, &tun_src) == NH_SOURCE_INVALID) {
        drop_reason = VP_DROP_INVALID_MCAST_SOURCE;
        PKT_LOG(drop_reason, pkt, 0, VR_NEXTHOP_C, __LINE__);
        goto drop;
    }

    if (tun_src & NH_FLAG_COMPOSITE_EVPN)
        pkt_src = PKT_SRC_INGRESS_REPL_TREE;

    if (tun_src & NH_FLAG_COMPOSITE_FABRIC) {
        pkt_src = PKT_SRC_EDGE_REPL_TREE;
        if (nh->nh_family == AF_BRIDGE)
            pull_len = VR_VXLAN_HDR_LEN;
    }

    if (tun_src & NH_FLAG_VALIDATE_MCAST_SRC) {
        // Since source check is relaxed, tunnel source is hard-coded to
        // fabric.
        tun_src = NH_FLAG_COMPOSITE_FABRIC;
        pkt_src = PKT_SRC_EDGE_REPL_TREE;
        // In this case ethernet header pointer need not be adjusted.
        pull_header = false;
    }

    if (tun_src & NH_FLAG_COMPOSITE_TOR) {
        pkt_src = PKT_SRC_TOR_REPL_TREE;
        fmd->fmd_src = TOR_SOURCE;
    }

    if (nh->nh_family == AF_BRIDGE) {
        eth = (struct vr_eth *)pkt_data_at_offset(pkt,
                                pkt->vp_data + pull_len);

        if (ntohs(eth->eth_proto) == VR_ETH_PROTO_PBB) {
            pbb_pull_len = __vr_pbb_decode(eth, pkt_head_len(pkt) - pull_len, fmd);
            if (pbb_pull_len <= 0) {
                drop_reason = VP_DROP_INVALID_PACKET;
                PKT_LOG(drop_reason, pkt, 0, VR_NEXTHOP_C, __LINE__);
                goto drop;
            }

            if (vr_pkt_type(pkt, pbb_pull_len + pull_len, fmd) < 0) {
                drop_reason = VP_DROP_INVALID_PACKET;
                PKT_LOG(drop_reason, pkt, 0, VR_NEXTHOP_C, __LINE__);
                goto drop;
            }

            eth = (struct vr_eth *)(((char *)eth) + pbb_pull_len);
            if (nh->nh_flags & NH_FLAG_MAC_LEARN) {
                ml_res = vr_bridge_learn(nh->nh_router, pkt, eth, fmd);
                if (ml_res == MAC_TRAPPED)
                    return NH_PROCESSING_COMPLETE;
            }
        }

        handled = nh_handle_mcast_control_pkt(pkt, eth, fmd,
                                        pkt_src, &flood_to_vms);
        if (handled)
            return NH_PROCESSING_COMPLETE;

        if (flood_to_vms && !IS_MAC_BMCAST(eth->eth_dmac)) {
            handled = nh_handle_unknown_unicast(pkt, eth, fmd, pkt_src);
            if (handled)
                return NH_PROCESSING_COMPLETE;
        }


        /*
         * The packet can come to this nexthp either from Fabric or from VM.
         * Incase of Fabric, the packet would contain the Vxlan header and
         * control information. From VM, it contains neither of them
         */

        if (!fmd->fmd_udp_src_port) {
            if (hashrnd_inited == 0) {
                get_random_bytes(&vr_hashrnd, sizeof(vr_hashrnd));
                hashrnd_inited = 1;
            }
            hashval = vr_hash(eth, sizeof(struct vr_eth), vr_hashrnd);
            /* Include the VRF to calculate the hash */
            hashval = vr_hash_2words(hashval, fmd->fmd_dvrf, vr_hashrnd);

            /*
             * Convert the hash value to a value in the port range that we want
             * for dynamic UDP ports
             */
            port_range = VR_MUDP_PORT_RANGE_END - VR_MUDP_PORT_RANGE_START;
            fmd->fmd_udp_src_port = (uint16_t) (((uint64_t) hashval * port_range) >> 32);

            if (fmd->fmd_udp_src_port > port_range) {
               /*
                * Shouldn't happen...
                */
                fmd->fmd_udp_src_port = 0;
            }

            fmd->fmd_udp_src_port += VR_MUDP_PORT_RANGE_START;
        }

        if (vr_fmd_l2_control_data_is_enabled(fmd))
            l2_control_data = true;
    }

    if (!nh->nh_component_cnt) {
        drop_reason = VP_DROP_DISCARD;
        PKT_LOG(drop_reason, pkt, 0, VR_NEXTHOP_C, __LINE__);
        goto drop;
    }

    label = fmd->fmd_label;

    for (i = 0; i < nh->nh_component_cnt; i++) {
        clone_size = 0;
        dir_nh = nh->nh_component_nh[i].cnh;

        /* We need to copy back the original label from Bridge lookaup
         * as previous iteration would have manipulated that
         */
        vr_fmd_set_label(fmd, label, VR_LABEL_TYPE_UNKNOWN);
        fmd->fmd_dvrf = pkt_vrf;
        vr_fmd_update_l2_control_data(fmd, false);

        /* If direct nexthop is not valid, dont process it */
        if ((!dir_nh) || !(dir_nh->nh_flags & NH_FLAG_VALID) ||
                                (dir_nh->nh_type != NH_COMPOSITE))
            continue;

        if (dir_nh->nh_flags & NH_FLAG_COMPOSITE_ENCAP) {
            if (!flood_to_vms)
                continue;

            if (!(new_pkt = nh_mcast_clone(pkt, 0))) {
                drop_reason = VP_DROP_MCAST_CLONE_FAIL;
                PKT_LOG(drop_reason, pkt, 0, VR_NEXTHOP_C, __LINE__);
                break;
            }

            pull_len = pbb_pull_len;
            if (nh->nh_family == AF_BRIDGE &&
                    (pkt_src == PKT_SRC_EDGE_REPL_TREE)) {
                if (pull_header) {
                    pull_len += VR_VXLAN_HDR_LEN;
                }
            }

            if (pull_len && !pkt_pull(new_pkt, pull_len)) {
                vr_pfree(new_pkt, VP_DROP_PULL);
                PKT_LOG(drop_reason, pkt, 0, VR_NEXTHOP_C, __LINE__);
                break;
            }
        } else if (dir_nh->nh_flags & NH_FLAG_COMPOSITE_FABRIC) {
            if (pkt_src == PKT_SRC_INGRESS_REPL_TREE)
                continue;

            if (pkt_src != PKT_SRC_EDGE_REPL_TREE) {
                if (nh->nh_family == AF_BRIDGE) {
                    clone_size += VR_L2_MCAST_PKT_HEAD_SPACE;
                    if (dir_nh->nh_flags & NH_FLAG_TUNNEL_PBB)
                        clone_size += VR_ETHER_HLEN + sizeof(struct vr_pbb_itag);
                } else {
                    clone_size += VR_L3_MCAST_PKT_HEAD_SPACE;
                }
            }

            /* Create head space for L2 Mcast header */
            if (!(new_pkt = nh_mcast_clone(pkt, clone_size))) {
                drop_reason = VP_DROP_MCAST_CLONE_FAIL;
                PKT_LOG(drop_reason, pkt, 0, VR_NEXTHOP_C, __LINE__);
                break;
            }
            if (!pull_header) {
                // Recover header space to write tunnel header when sending to
                // other computes. Assumption is that multicast data packet was
                // received from outside contrail using vxlan header.
                pkt_push(new_pkt, VR_VXLAN_HDR_LEN);
            }
            fmd->fmd_dvrf = dir_nh->nh_vrf;

        } else if (dir_nh->nh_flags & NH_FLAG_COMPOSITE_EVPN) {

            /* We replicate only if received from VM and Ovs TOR*/
            if ((!pkt_src)|| (pkt_src == PKT_SRC_TOR_REPL_TREE)) {

                /* Create head space for non Vxlan header */
                clone_size = VR_L3_MCAST_PKT_HEAD_SPACE;
                if (nh->nh_flags & NH_FLAG_L2_CONTROL_DATA)
                    clone_size += VR_L2_CTRL_DATA_LEN;
                if (dir_nh->nh_flags & NH_FLAG_TUNNEL_PBB)
                    clone_size += VR_ETHER_HLEN + sizeof(struct vr_pbb_itag);

                if (!(new_pkt = nh_mcast_clone(pkt, clone_size))) {
                    drop_reason = VP_DROP_MCAST_CLONE_FAIL;
                    PKT_LOG(drop_reason, pkt, 0, VR_NEXTHOP_C, __LINE__);
                    break;
                }
                fmd->fmd_dvrf = dir_nh->nh_vrf;
            } else {
                continue;
            }

            if (l2_control_data)
                vr_fmd_update_l2_control_data(fmd, true);

        } else if (dir_nh->nh_flags & NH_FLAG_COMPOSITE_TOR) {

            /* Create head space for Vxlan header */
            clone_size = VR_L2_MCAST_PKT_HEAD_SPACE - VR_L2_CTRL_DATA_LEN;
            if (!(new_pkt = nh_mcast_clone(pkt, clone_size))) {
                drop_reason = VP_DROP_MCAST_CLONE_FAIL;
                PKT_LOG(drop_reason, pkt, 0, VR_NEXTHOP_C, __LINE__);
                break;
            }

            if (pkt_src == PKT_SRC_EDGE_REPL_TREE) {

                pull_len = VR_VXLAN_HDR_LEN + pbb_pull_len;
                if (!pkt_pull(new_pkt, pull_len)) {
                    vr_pfree(new_pkt, VP_DROP_PULL);
                    PKT_LOG(drop_reason, pkt, 0, VR_NEXTHOP_C, __LINE__);
                    break;
                }
            }
            fmd->fmd_dvrf = dir_nh->nh_vrf;

        } else {
            continue;
        }

        nh_output(new_pkt, dir_nh, fmd);
    }

    /* Original packet needs to be unconditionally dropped */
drop:
    vr_pfree(pkt, drop_reason);
    return NH_PROCESSING_COMPLETE;
}


static nh_processing_t
nh_composite_encap(struct vr_packet *pkt, struct vr_nexthop *nh,
                   struct vr_forwarding_md *fmd)
{
    int i;
    struct vr_vrf_stats *stats;
    struct vr_nexthop *dir_nh;
    unsigned short drop_reason;
    struct vr_packet *new_pkt;

    drop_reason = VP_DROP_CLONED_ORIGINAL;
    stats = vr_inet_vrf_stats(fmd->fmd_dvrf, pkt->vp_cpu);
    if (stats)
        stats->vrf_encap_composites++;

    if (!nh->nh_component_cnt) {
        drop_reason = VP_DROP_DISCARD;
        PKT_LOG(drop_reason, pkt, 0, VR_NEXTHOP_C, __LINE__);
        goto drop;
    }

    if (!fmd) {
        drop_reason = VP_DROP_NO_FMD;
        PKT_LOG(drop_reason, pkt, 0, VR_NEXTHOP_C, __LINE__);
        goto drop;
    }

    for (i = 0; i < nh->nh_component_cnt; i++) {
       dir_nh = nh->nh_component_nh[i].cnh;

        /* If direct nexthop is not valid, dont process it */
        if ((!dir_nh) || !(dir_nh->nh_flags & NH_FLAG_VALID))
            continue;

        /* Dont give back the packet to same VM */
        if (dir_nh->nh_dev == pkt->vp_if)
            continue;

        /* There would be enought head space to clone it with zero size */
        if (!(new_pkt = nh_mcast_clone(pkt, 0))) {
            drop_reason = VP_DROP_MCAST_CLONE_FAIL;
            PKT_LOG(drop_reason, pkt, 0, VR_NEXTHOP_C, __LINE__);
            break;
        }
        fmd->fmd_dvrf = dir_nh->nh_dev->vif_vrf;
        nh_output(new_pkt, dir_nh, fmd);
    }

    /* Original packet needs to be unconditionally dropped */
drop:
    vr_pfree(pkt, drop_reason);
    return NH_PROCESSING_COMPLETE;
}

static nh_processing_t
nh_composite_tor(struct vr_packet *pkt, struct vr_nexthop *nh,
                 struct vr_forwarding_md *fmd)
{
    int i;
    struct vr_vrf_stats *stats;
    struct vr_nexthop *dir_nh;
    unsigned short drop_reason;
    struct vr_packet *new_pkt;

    drop_reason = VP_DROP_CLONED_ORIGINAL;
    stats = vr_inet_vrf_stats(fmd->fmd_dvrf, pkt->vp_cpu);
    if (stats)
        stats->vrf_evpn_composites++;

    if (!nh->nh_component_cnt) {
        drop_reason = VP_DROP_DISCARD;
        PKT_LOG(drop_reason, pkt, 0, VR_NEXTHOP_C, __LINE__);
        goto drop;
    }

    if (!fmd) {
        drop_reason = VP_DROP_NO_FMD;
        PKT_LOG(drop_reason, pkt, 0, VR_NEXTHOP_C, __LINE__);
        goto drop;
    }

    for (i = 0; i < nh->nh_component_cnt; i++) {
        dir_nh = nh->nh_component_nh[i].cnh;

        /* If direct nexthop is not valid, dont process it */
        if ((!dir_nh) || !(dir_nh->nh_flags & NH_FLAG_VALID))
            continue;

        if (dir_nh->nh_type != NH_TUNNEL)
            continue;

        /* Dont forward to same source */
        if (fmd->fmd_outer_src_ip && fmd->fmd_outer_src_ip ==
            dir_nh->nh_udp_tun_dip)
            continue;

        /*
         * Enough head spaces are created in the previous nexthop
         * handling. Just cow the packet with zero size to get different
         * buffer space
         */
        new_pkt = nh_mcast_clone(pkt, 0);
        if (!new_pkt) {
            drop_reason = VP_DROP_MCAST_CLONE_FAIL;
            PKT_LOG(drop_reason, pkt, 0, VR_NEXTHOP_C, __LINE__);
            break;
        }

        vr_fmd_set_label(fmd, nh->nh_component_nh[i].cnh_label,
                VR_LABEL_TYPE_UNKNOWN);
        fmd->fmd_dvrf = dir_nh->nh_dev->vif_vrf;
        nh_output(new_pkt, dir_nh, fmd);
    }

    /* Original packet needs to be unconditionally dropped */
drop:
    vr_pfree(pkt, drop_reason);
    return NH_PROCESSING_COMPLETE;
}

static nh_processing_t
nh_composite_evpn(struct vr_packet *pkt, struct vr_nexthop *nh,
                  struct vr_forwarding_md *fmd)
{
    int i;
    bool l2_control_data = false;
    struct vr_vrf_stats *stats;
    struct vr_nexthop *dir_nh;
    unsigned short drop_reason;
    struct vr_packet *new_pkt;
    uint8_t eth_mac[VR_ETHER_ALEN];

    drop_reason = VP_DROP_CLONED_ORIGINAL;
    stats = vr_inet_vrf_stats(fmd->fmd_dvrf, pkt->vp_cpu);
    if (stats)
        stats->vrf_evpn_composites++;

    if (!nh->nh_component_cnt) {
        drop_reason = VP_DROP_DISCARD;
        PKT_LOG(drop_reason, pkt, 0, VR_NEXTHOP_C, __LINE__);
        goto drop;
    }

    if (!fmd) {
        drop_reason = VP_DROP_NO_FMD;
        PKT_LOG(drop_reason, pkt, 0, VR_NEXTHOP_C, __LINE__);
        goto drop;
    }

    if (nh->nh_flags & NH_FLAG_TUNNEL_PBB)
        vr_mcast_mac_from_isid(pkt->vp_if->vif_isid, eth_mac);

    if (vr_fmd_l2_control_data_is_enabled(fmd)) {
        l2_control_data = true;
        vr_fmd_update_l2_control_data(fmd, false);
    }

    for (i = 0; i < nh->nh_component_cnt; i++) {
        dir_nh = nh->nh_component_nh[i].cnh;

        /* If direct nexthop is not valid, dont process it */
        if ((!dir_nh) || !(dir_nh->nh_flags & NH_FLAG_VALID))
            continue;

        if (dir_nh->nh_type != NH_TUNNEL)
            continue;

        /*
         * Enough head spaces are created in the previous nexthop
         * handling. Just cow the packet with zero size to get different
         * buffer space
         */
        new_pkt = nh_mcast_clone(pkt, 0);
        if (!new_pkt) {
            drop_reason = VP_DROP_MCAST_CLONE_FAIL;
            PKT_LOG(drop_reason, pkt, 0, VR_NEXTHOP_C, __LINE__);
            break;
        }

        if (nh->nh_flags & NH_FLAG_TUNNEL_PBB) {
            if (!nh_pbb_tunnel_helper(nh->nh_router, &new_pkt, fmd,
                    eth_mac, pkt->vp_if->vif_pbb_mac, pkt->vp_if->vif_isid)) {
                PKT_LOG(VP_DROP_PUSH, pkt, 0, VR_NEXTHOP_C, __LINE__);
                vr_pfree(new_pkt, VP_DROP_PUSH);
                continue;
            }
        }

        if (l2_control_data && !vr_l2_control_data_add(&new_pkt)) {
            drop_reason = VP_DROP_PULL;
            PKT_LOG(drop_reason, pkt, 0, VR_NEXTHOP_C, __LINE__);
            break;
        }

        vr_fmd_set_label(fmd, nh->nh_component_nh[i].cnh_label,
                VR_LABEL_TYPE_UNKNOWN);
        fmd->fmd_dvrf = dir_nh->nh_dev->vif_vrf;
        nh_output(new_pkt, dir_nh, fmd);
    }

    /* Original packet needs to be unconditionally dropped */
drop:
    vr_pfree(pkt, drop_reason);
    return NH_PROCESSING_COMPLETE;
}

static nh_processing_t
nh_composite_fabric(struct vr_packet *pkt, struct vr_nexthop *nh,
                    struct vr_forwarding_md *fmd)
{
    int i;
    int32_t label;
    unsigned int dip, sip;
    int8_t eth_mac[VR_ETHER_ALEN];
    struct vr_vrf_stats *stats;
    struct vr_nexthop *dir_nh;
    unsigned short drop_reason, pkt_vrf;
    struct vr_packet *new_pkt;

    drop_reason = VP_DROP_CLONED_ORIGINAL;
    stats = vr_inet_vrf_stats(fmd->fmd_dvrf, pkt->vp_cpu);
    if (stats)
        stats->vrf_fabric_composites++;

    if (!nh->nh_component_cnt) {
        drop_reason = VP_DROP_DISCARD;
        PKT_LOG(drop_reason, pkt, 0, VR_NEXTHOP_C, __LINE__);
        goto drop;
    }

    if (!fmd) {
        drop_reason = VP_DROP_NO_FMD;
        PKT_LOG(drop_reason, pkt, 0, VR_NEXTHOP_C, __LINE__);
        goto drop;
    }

    /*
     * Packet can be L2 or L3 with or without control information. It is
     * always ensured before coming to this nexthop that packet headers
     * along with control inforation is in first buffer. So it can be
     * safely cow'd for the required length
     */

    label = fmd->fmd_label;
    pkt_vrf = fmd->fmd_dvrf;
    if (nh->nh_flags & NH_FLAG_TUNNEL_PBB)
        vr_mcast_mac_from_isid(pkt->vp_if->vif_isid, eth_mac);

    for (i = 0; i < nh->nh_component_cnt; i++) {
        dir_nh = nh->nh_component_nh[i].cnh;
        fmd->fmd_dvrf = pkt_vrf;

        /* If direct nexthop is not valid, dont process it */
        if ((!dir_nh) || !(dir_nh->nh_flags & NH_FLAG_VALID))
            continue;

        if (dir_nh->nh_type != NH_TUNNEL)
            continue;

        /*
         * Take the right tunnel source. The dst is also our own
         * address
         */
        sip = dip = 0;
        if (dir_nh->nh_flags & NH_FLAG_TUNNEL_GRE) {
            sip = dir_nh->nh_gre_tun_sip;
            dip = dir_nh->nh_gre_tun_dip;
        } else if (dir_nh->nh_flags & NH_FLAG_TUNNEL_UDP_MPLS) {
            sip = dir_nh->nh_udp_tun_sip;
            dip = dir_nh->nh_udp_tun_dip;
        } else {
            drop_reason = VP_DROP_INVALID_NH;
            PKT_LOG(drop_reason, pkt, 0, VR_NEXTHOP_C, __LINE__);
            break;
        }

        /* Dont forward to same source */
        if (fmd->fmd_outer_src_ip && fmd->fmd_outer_src_ip == dip)
            continue;

        /* Dont flood back on ingress physical interface on the fabric. */
        if (vif_is_vlan(pkt->vp_if)) {
            if (vif_is_vlan(dir_nh->nh_dev) &&
                pkt->vp_if->vif_parent == dir_nh->nh_dev->vif_parent)
                continue;
            else if (pkt->vp_if->vif_parent == dir_nh->nh_dev)
                continue;
        }

        /*
         * Enough head spaces are created in the previous nexthop
         * handling. Just cow the packet with zero size to get different
         * buffer space
         */
        new_pkt = nh_mcast_clone(pkt, 0);
        if (!new_pkt) {
            drop_reason = VP_DROP_MCAST_CLONE_FAIL;
            PKT_LOG(drop_reason, pkt, 0, VR_NEXTHOP_C, __LINE__);
            break;
        }

        /* If from VM or Tor add vxlan header */
        if (vif_is_virtual(new_pkt->vp_if) ||
                        (fmd->fmd_src == TOR_SOURCE)) {
            /*
             * The L2 multicast bridge entry will have VNID as label. If fmd
             * does not valid label/vnid, skip the processing
             */
            if (label < 0) {
                PKT_LOG(VP_DROP_INVALID_LABEL, pkt, 0, VR_NEXTHOP_C, __LINE__);
                vr_pfree(new_pkt, VP_DROP_INVALID_LABEL);
                break;
            }

            if (nh->nh_flags & NH_FLAG_TUNNEL_PBB) {
                if (!nh_pbb_tunnel_helper(nh->nh_router, &new_pkt, fmd, eth_mac,
                              pkt->vp_if->vif_pbb_mac, pkt->vp_if->vif_isid)) {
                    PKT_LOG(VP_DROP_PUSH, pkt, 0, VR_NEXTHOP_C, __LINE__);
                    vr_pfree(new_pkt, VP_DROP_PUSH);
                    continue;
                }
            }

            if (nh->nh_family == AF_BRIDGE) {
                /*
                 * Add vxlan encapsulation. The vxlan id need to be taken
                 * from Bridge entry
                 */
                vr_fmd_set_label(fmd, label, VR_LABEL_TYPE_UNKNOWN);
                fmd->fmd_dvrf = dir_nh->nh_dev->vif_vrf;
                if (nh_vxlan_tunnel_helper(nh->nh_router, &new_pkt,
                                        fmd, sip, sip) == false) {
                    PKT_LOG(VP_DROP_PUSH, pkt, 0, VR_NEXTHOP_C, __LINE__);
                    vr_pfree(new_pkt, VP_DROP_PUSH);
                    break;
                }
            }
        }

        if (nh->nh_family == AF_BRIDGE) {
            if (vr_l2_control_data_add(&new_pkt) == false) {
                PKT_LOG(VP_DROP_PUSH, pkt, 0, VR_NEXTHOP_C, __LINE__);
                vr_pfree(new_pkt, VP_DROP_PUSH);
                break;
            }
            vr_fmd_update_l2_control_data(fmd, false);
        }

        /* MPLS label for outer header encapsulation */
        vr_fmd_set_label(fmd, nh->nh_component_nh[i].cnh_label,
                VR_LABEL_TYPE_UNKNOWN);
        fmd->fmd_dvrf = dir_nh->nh_dev->vif_vrf;
        nh_output(new_pkt, dir_nh, fmd);
    }

    /* Original packet needs to be unconditionally dropped */
drop:
    vr_pfree(pkt, drop_reason);
    return NH_PROCESSING_COMPLETE;
}

static nh_processing_t
nh_discard(struct vr_packet *pkt, struct vr_nexthop *nh,
           struct vr_forwarding_md *fmd)
{
    struct vr_vrf_stats *stats;

    stats = vr_inet_vrf_stats(fmd->fmd_dvrf, pkt->vp_cpu);
    if (stats)
        stats->vrf_discards++;

    PKT_LOG(VP_DROP_DISCARD, pkt, 0, VR_NEXTHOP_C, __LINE__);
    vr_pfree(pkt, VP_DROP_DISCARD);
    return NH_PROCESSING_COMPLETE;
}

static uint8_t *
nh_generate_mirroring_sip(struct vr_nexthop *nh,
        struct vr_packet *pkt, struct vr_forwarding_md *fmd)
{
    uint16_t intf_id;
    mirror_type_t mtype;
    struct vr_interface *vif = NULL;

    mtype = vr_fmd_get_mirror_type(fmd);

    if (mtype == MIRROR_TYPE_PORT_RX) {
        vif = pkt->vp_if;
    } else if (mtype == MIRROR_TYPE_PORT_TX) {
        intf_id = vr_fmd_get_mirror_if_id(fmd);
        if (intf_id != FMD_MIRROR_INVALID_DATA)
            vif = __vrouter_get_interface(vrouter_get(nh->nh_rid), intf_id);
    }

    if (!vif)
        return NULL;

    if (nh->nh_family == AF_INET)
        return (uint8_t *)&vif->vif_ip;
    else if (nh->nh_family == AF_INET6)
        return vif->vif_ip6;

    return NULL;
}

static nh_processing_t
nh_udp_tunnel(struct vr_packet *pkt, struct vr_nexthop *nh,
              struct vr_forwarding_md *fmd)
{
    int ret = -1;
    uint8_t *vif_ip = NULL;
    uint16_t sport = 0;
    unsigned int head_space, hash;
    uint32_t sip = 0, port_range;
    struct vr_packet *tmp;
    struct vr_ip *ip;
    struct vr_ip6 *ip6;
    struct vr_udp *udp;
    struct vr_vrf_stats *stats;
    struct vr_forwarding_class_qos *qos;
    struct vr_flow flow, *flowp = &flow;

    if (!fmd)
        goto send_fail;

    head_space = sizeof(struct vr_udp) + VR_ETHER_HLEN;

    if (nh->nh_family == AF_INET)
        head_space += sizeof(struct vr_ip);
    else if (nh->nh_family == AF_INET6)
        head_space += sizeof(struct vr_ip6);
    else
        goto send_fail;

    if (pkt_head_space(pkt) < head_space) {
        tmp = vr_pexpand_head(pkt, head_space - pkt_head_space(pkt));
        if (!tmp) {
            goto send_fail;
        }
        pkt = tmp;
    }

    if (pkt->vp_type == VP_TYPE_IP) {
        ret = vr_inet_get_flow_key(nh->nh_router, pkt, fmd,
                                     flowp, VR_FLOW_KEY_ALL);
    } else if (pkt->vp_type == VP_TYPE_IP6) {
        ret = vr_inet6_get_flow_key(nh->nh_router, fmd->fmd_dvrf, pkt,
                                 fmd->fmd_vlan, flowp, VR_FLOW_KEY_ALL);
    }

    if (!ret) {
        hash = vr_hash(flowp, flowp->flow_key_len, 0);
        port_range = VR_UDP_PORT_RANGE_END - VR_UDP_PORT_RANGE_START;
        sport = (uint16_t)
            (((uint64_t ) hash * port_range) >> 32);
        sport += VR_UDP_PORT_RANGE_START;
    }

    if (nh->nh_flags & NH_FLAG_TUNNEL_SIP_COPY) {
        vif_ip = nh_generate_mirroring_sip(nh, pkt, fmd);
    }

    if (nh->nh_family == AF_INET) {

        if (vif_ip)
            sip = *(uint32_t *)vif_ip;

        if (!sip)
            sip = nh->nh_udp_tun_sip;

        if (!sport)
            sport = ntohs(nh->nh_udp_tun_sport);

        qos = vr_qos_get_forwarding_class(nh->nh_router, pkt, fmd);
        if (nh_udp_tunnel_helper(pkt, htons(sport),
                    nh->nh_udp_tun_dport, sip,
                    nh->nh_udp_tun_dip, qos) == false) {
            goto send_fail;
        }

        if (pkt_len(pkt) > ((1 << sizeof(ip->ip_len) * 8)))
            goto send_fail;

        ip = (struct vr_ip *)(pkt_data(pkt));
        udp = (struct vr_udp *)((char *)ip + ip->ip_hl * 4);
        udp->udp_csum = vr_ip_partial_csum(ip);
        pkt->vp_flags |= VP_FLAG_CSUM_PARTIAL;

        pkt->vp_type = VP_TYPE_IP;

    } else if (nh->nh_family == AF_INET6) {

        if (!sport)
            sport = ntohs(nh->nh_udp_tun6_sport);

        if (nh_udp_tunnel6_helper(pkt, nh, vif_ip, htons(sport),
                   nh->nh_udp_tun6_dport) == false) {
            goto send_fail;
        }

        ip6 = (struct vr_ip6 *)(pkt_data(pkt));
        udp = (struct vr_udp *)((char *)ip6 + sizeof(struct vr_ip6));
        udp->udp_csum = vr_ip6_partial_csum(ip6);
        pkt->vp_flags |= VP_FLAG_CSUM_PARTIAL;

        pkt->vp_type = VP_TYPE_IP6;
    }

    fmd->fmd_udp_src_port = sport;

    pkt_set_network_header(pkt, pkt->vp_data);

    /*
     * Incase of mirroring set the inner network header to the newly added
     * header so that this is fragmented and checksummed
     */
    pkt_set_inner_network_header(pkt, pkt->vp_data);

    stats = vr_inet_vrf_stats(fmd->fmd_dvrf, pkt->vp_cpu);
    if (stats)
        stats->vrf_udp_tunnels++;

    vr_forward(vrouter_get(nh->nh_rid), pkt, fmd);

    return NH_PROCESSING_COMPLETE;

send_fail:
    PKT_LOG(VP_DROP_PUSH, pkt, flowp, VR_NEXTHOP_C, __LINE__);
    vr_pfree(pkt, VP_DROP_PUSH);
    return NH_PROCESSING_COMPLETE;
}

/*
 * nh_vxlan_tunnel - tunnel packet with VXLAN header
 */
static nh_processing_t
nh_vxlan_tunnel(struct vr_packet *pkt, struct vr_nexthop *nh,
                struct vr_forwarding_md *fmd)
{
    struct vr_interface *vif;
    struct vr_vrf_stats *stats;
    unsigned short reason = VP_DROP_PUSH;
    struct vr_packet *tmp_pkt;
    struct vr_df_trap_arg trap_arg;
    unsigned short overhead_len;

    if (!fmd) {
        reason = VP_DROP_NO_FMD;
        PKT_LOG(reason, pkt, 0, VR_NEXTHOP_C, __LINE__);
        goto send_fail;
    }

    if (fmd->fmd_label < 0) {
        reason = VP_DROP_INVALID_LABEL;
        PKT_LOG(reason, pkt, 0, VR_NEXTHOP_C, __LINE__);
        goto send_fail;
    }

    stats = vr_inet_vrf_stats(fmd->fmd_dvrf, pkt->vp_cpu);
    if (stats)
        stats->vrf_vxlan_tunnels++;

    if (nh_tunnel_loop_detect_handle(pkt, nh, fmd, nh->nh_vxlan_tun_dip))
        return NH_PROCESSING_COMPLETE;

    if (vr_perfs)
        pkt->vp_flags |= VP_FLAG_GSO;

    if (nh->nh_flags & NH_FLAG_L3_VXLAN) {
        struct vr_eth *eth;

        /* Preset the pkt to make it point to L2 header */
        vr_preset(pkt);

        if (!nh->nh_dev || IS_MAC_ZERO(nh->nh_dev->vif_mac)) {
            reason = VP_DROP_INTERFACE_DROP;
            PKT_LOG(reason, pkt, 0, VR_NEXTHOP_C, __LINE__);
            goto send_fail;
        }

        eth = (struct vr_eth *)pkt_data(pkt);
        VR_MAC_COPY(eth->eth_dmac, nh->nh_vxlan_tun_l3_mac);
        VR_MAC_COPY(eth->eth_smac, nh->nh_dev->vif_mac);
    }

    overhead_len = VR_VXLAN_HDR_LEN;
    if ((pkt->vp_type == VP_TYPE_IP) || (pkt->vp_type == VP_TYPE_IP6)) {
        if (vr_has_to_fragment(nh->nh_dev, pkt, overhead_len) &&
                vr_ip_dont_fragment_set(pkt)) {
            if (pkt->vp_flags & VP_FLAG_MULTICAST) {
                reason = VP_DROP_MCAST_DF_BIT;
                PKT_LOG(reason, pkt, 0, VR_NEXTHOP_C, __LINE__);
                goto send_fail;
            }

            trap_arg.df_mtu = vif_get_mtu(nh->nh_dev) -
                (overhead_len + pkt_get_network_header_off(pkt) - pkt->vp_data);
            trap_arg.df_flow_index = fmd->fmd_flow_index;
            vr_trap(pkt, fmd->fmd_dvrf, AGENT_TRAP_HANDLE_DF, (void *)&trap_arg);
            return NH_PROCESSING_COMPLETE;
        }
    }

    if (nh_vxlan_tunnel_helper(nh->nh_router, &pkt, fmd, nh->nh_vxlan_tun_sip,
                nh->nh_vxlan_tun_dip) == false)
        goto send_fail;

    pkt_set_network_header(pkt, pkt->vp_data);

    if (pkt->vp_type == VP_TYPE_IPOIP)
        pkt->vp_type = VP_TYPE_IP;
    else if (pkt->vp_type == VP_TYPE_IP6OIP)
        pkt->vp_type = VP_TYPE_IP6;

    /*
     * Change the packet type
     */
    if (pkt->vp_type == VP_TYPE_IP6)
        pkt->vp_type = VP_TYPE_IP6OIP;
    else if (pkt->vp_type == VP_TYPE_IP)
        pkt->vp_type = VP_TYPE_IPOIP;
    else
        pkt->vp_type = VP_TYPE_IP;

    if (pkt_head_space(pkt) < nh->nh_vxlan_tun_encap_len) {
        tmp_pkt = vr_pexpand_head(pkt, nh->nh_vxlan_tun_encap_len - pkt_head_space(pkt));
        if (!tmp_pkt) {
            goto send_fail;
        }
        pkt = tmp_pkt;
    }

    /* slap l2 header */
    vif = nh->nh_dev;
    if (nh->nh_flags & NH_FLAG_CRYPT_TRAFFIC) {
        if (!nh->nh_crypt_dev) {
            reason = VP_DROP_NO_CRYPT_PATH; 
            PKT_LOG(reason, pkt, 0, VR_NEXTHOP_C, __LINE__);
            goto send_fail;
        }
        vif = nh->nh_crypt_dev;
    }
    if (vif->vif_set_rewrite(vif, &pkt, fmd,
                nh->nh_data, nh->nh_udp_tun_encap_len) < 0) {
        goto send_fail;
    }

    vif->vif_tx(vif, pkt, fmd);

    return NH_PROCESSING_COMPLETE;

send_fail:
    vr_pfree(pkt, reason);
    return NH_PROCESSING_COMPLETE;

}

static nh_processing_t
nh_pbb_tunnel(struct vr_packet *pkt, struct vr_nexthop *nh,
        struct vr_forwarding_md *fmd)
{
    struct vr_vrf_stats *stats;

    if (vr_fmd_etree_is_enabled(fmd)) {
        if ((!vr_fmd_etree_is_root(fmd)) &&
                    (!(nh->nh_flags & NH_FLAG_ETREE_ROOT))) {
            PKT_LOG(VP_DROP_LEAF_TO_LEAF, pkt, 0, VR_NEXTHOP_C, __LINE__);
            vr_pfree(pkt, VP_DROP_LEAF_TO_LEAF);
            return NH_PROCESSING_COMPLETE;
        }
    }

    stats = vr_inet_vrf_stats(fmd->fmd_dvrf, pkt->vp_cpu);
    if (stats)
        stats->vrf_pbb_tunnels++;

    if (!nh_pbb_tunnel_helper(nh->nh_router, &pkt, fmd, nh->nh_pbb_mac,
            pkt->vp_if->vif_pbb_mac, pkt->vp_if->vif_isid)) {
            PKT_LOG(VP_DROP_PUSH, pkt, 0, VR_NEXTHOP_C, __LINE__);
            vr_pfree(pkt, VP_DROP_PUSH);
        return NH_PROCESSING_COMPLETE;
    }
    vr_fmd_set_label(fmd, nh->nh_pbb_label, VR_LABEL_TYPE_UNKNOWN);

    return NH_PROCESSING_INCOMPLETE;
}

static int
nh_pbb_tunnel_validate_src(struct vr_packet *pkt, struct vr_nexthop *nh,
        struct vr_forwarding_md *fmd, void *ret_data)
{
    bool root = false;

    if (nh->nh_flags & NH_FLAG_ETREE_ROOT)
        root = true;
    vr_fmd_update_etree_root(fmd,root);

    if (VR_MAC_CMP(nh->nh_pbb_mac, fmd->fmd_smac)) {
        return NH_SOURCE_VALID;
    }

    return NH_SOURCE_INVALID;
}

static int
nh_mpls_udp_tunnel_validate_src(struct vr_packet *pkt, struct vr_nexthop *nh,
                                struct vr_forwarding_md *fmd, void *ret_data)
{
    if (fmd->fmd_outer_src_ip == nh->nh_udp_tun_dip)
        return NH_SOURCE_VALID;

    return NH_SOURCE_INVALID;
}

static int
nh_vxlan_tunnel_validate_src(struct vr_packet *pkt, struct vr_nexthop *nh,
                                struct vr_forwarding_md *fmd, void *ret_data)
{
    if (fmd->fmd_outer_src_ip == nh->nh_udp_tun_dip)
        return NH_SOURCE_VALID;

    return NH_SOURCE_INVALID;
}


/*
 * nh_mpls_udp_tunnel - tunnel packet with MPLS label in UDP.
 */
static nh_processing_t
nh_mpls_udp_tunnel(struct vr_packet *pkt, struct vr_nexthop *nh,
                   struct vr_forwarding_md *fmd)
{
    unsigned int tun_sip, tun_dip, overhead_len, mudp_head_space;
    uint16_t tun_encap_len, udp_src_port = VR_MPLS_OVER_UDP_SRC_PORT;
    unsigned short reason = VP_DROP_PUSH;

    int tun_encap_rewrite;
    struct vr_forwarding_class_qos *qos;
    struct vr_interface *vif;
    struct vr_vrf_stats *stats;
    struct vr_packet *tmp_pkt;
    struct vr_df_trap_arg trap_arg;
    unsigned int label_count = 0;
    uint32_t transport_label = 0;

    /*
     * If we are testing MPLS over UDP using the vr_mudp sysctl, use the
     * values from the GRE tunnel nexthop below. Otherwise, use the values
     * from the UDP tunnel nexthop.
     */
    if (vr_mudp) {
        tun_sip = nh->nh_gre_tun_sip;
        tun_dip = nh->nh_gre_tun_dip;
        tun_encap_len = nh->nh_gre_tun_encap_len;
    } else {
        tun_sip = nh->nh_udp_tun_sip;
        tun_dip = nh->nh_udp_tun_dip;
        tun_encap_len = nh->nh_udp_tun_encap_len;
        transport_label = nh->nh_udp_tun_label;
    }

    stats = vr_inet_vrf_stats(fmd->fmd_dvrf, pkt->vp_cpu);
    if (stats) {
        if (nh->nh_flags & NH_FLAG_TUNNEL_MPLS_O_MPLS) {
            stats->vrf_udp_mpls_over_mpls_tunnels++;
        } else {
            stats->vrf_udp_mpls_tunnels++;
        }
    }

    if (!fmd || fmd->fmd_label < 0) {
        vr_forward(nh->nh_router, pkt, fmd);
        return NH_PROCESSING_COMPLETE;
    }

    vr_fmd_update_label_type(fmd, VR_LABEL_TYPE_MPLS);

    if (nh_tunnel_loop_detect_handle(pkt, nh, fmd, tun_dip))
        return NH_PROCESSING_COMPLETE;

    if (fmd->fmd_udp_src_port)
        udp_src_port = fmd->fmd_udp_src_port;

    /*
     * The UDP source port is a hash of the inner IP src/dst address and
     * vrf.
     */
    if ((!fmd->fmd_udp_src_port)  && vr_get_udp_src_port) {
        udp_src_port = vr_get_udp_src_port(pkt, fmd, fmd->fmd_dvrf);
        if (udp_src_port == 0) {
            reason = VP_DROP_PULL;
            PKT_LOG(reason, pkt, 0, VR_NEXTHOP_C, __LINE__);
            goto send_fail;
        }
    }

    if (nh->nh_flags & NH_FLAG_TUNNEL_MPLS_O_MPLS) {
        label_count = 2;
    } else {
        label_count = 1;
    }
    /* Calculate the head space for mpls,udp ip and eth */
    mudp_head_space = (label_count*VR_MPLS_HDR_LEN) +
                sizeof(struct vr_ip) + sizeof(struct vr_udp);
    if (vr_fmd_l2_control_data_is_enabled(fmd))
        mudp_head_space += VR_L2_CTRL_DATA_LEN;

    if ((pkt->vp_type == VP_TYPE_IP) || (pkt->vp_type == VP_TYPE_IP6)) {
        overhead_len = mudp_head_space;
        if (vr_has_to_fragment(nh->nh_dev, pkt, overhead_len) &&
                vr_ip_dont_fragment_set(pkt)) {
            if (pkt->vp_flags & VP_FLAG_MULTICAST) {
                reason = VP_DROP_MCAST_DF_BIT;
                PKT_LOG(reason, pkt, 0, VR_NEXTHOP_C, __LINE__);
                goto send_fail;
            }
            trap_arg.df_mtu = vif_get_mtu(nh->nh_dev) -
                (overhead_len + pkt_get_network_header_off(pkt) - pkt->vp_data);
            trap_arg.df_flow_index = fmd->fmd_flow_index;
            vr_trap(pkt, fmd->fmd_dvrf, AGENT_TRAP_HANDLE_DF, (void *)&trap_arg);
            return NH_PROCESSING_COMPLETE;
        }
    }

    mudp_head_space += tun_encap_len;

    if (pkt_head_space(pkt) < mudp_head_space) {
        tmp_pkt = vr_pexpand_head(pkt, mudp_head_space - pkt_head_space(pkt));
        if (!tmp_pkt)
            goto send_fail;

        pkt = tmp_pkt;
    }

    if (vr_fmd_l2_control_data_is_enabled(fmd)) {
        if (!vr_l2_control_data_add(&pkt))
            goto send_fail;
    }

    qos = vr_qos_get_forwarding_class(nh->nh_router, pkt, fmd);
    if (nh_push_mpls_header(pkt, fmd->fmd_label, qos, true) < 0)
        goto send_fail;
    if (nh->nh_flags & NH_FLAG_TUNNEL_MPLS_O_MPLS) {
        /* insert outer label (transport label) */
        if (nh_push_mpls_header(pkt, transport_label, qos, false) < 0)
            goto send_fail;
    }


    if (vr_perfs)
        pkt->vp_flags |= VP_FLAG_GSO;


    if (pkt->vp_type == VP_TYPE_IPOIP)
        pkt->vp_type = VP_TYPE_IP;
    else if (pkt->vp_type == VP_TYPE_IP6OIP)
        pkt->vp_type = VP_TYPE_IP6;

    /*
     * Change the packet type
     */
    if (pkt->vp_type == VP_TYPE_IP6)
        pkt->vp_type = VP_TYPE_IP6OIP;
    else if (pkt->vp_type == VP_TYPE_IP)
        pkt->vp_type = VP_TYPE_IPOIP;
    else
        pkt->vp_type = VP_TYPE_IP;

    if (nh_udp_tunnel_helper(pkt, htons(udp_src_port),
                             htons(VR_MPLS_OVER_UDP_DST_PORT),
                             tun_sip, tun_dip, qos) == false) {
        goto send_fail;
    }

    pkt_set_network_header(pkt, pkt->vp_data);

    /* slap l2 header */
    vif = nh->nh_dev;
    if (nh->nh_flags & NH_FLAG_CRYPT_TRAFFIC) {
        if (!nh->nh_crypt_dev) {
            reason = VP_DROP_NO_CRYPT_PATH; 
            PKT_LOG(reason, pkt, 0, VR_NEXTHOP_C, __LINE__);
            goto send_fail;
        }
        vif = nh->nh_crypt_dev;
    }
    tun_encap_rewrite = vif->vif_set_rewrite(vif, &pkt, fmd,
            nh->nh_data, tun_encap_len);
    if (tun_encap_rewrite < 0) {
        goto send_fail;
    }

    vif->vif_tx(vif, pkt, fmd);

    return NH_PROCESSING_COMPLETE;

send_fail:
    vr_pfree(pkt, reason);
    return NH_PROCESSING_COMPLETE;

}

static int
nh_gre_tunnel_validate_src(struct vr_packet *pkt, struct vr_nexthop *nh,
                           struct vr_forwarding_md *fmd, void *ret_data)
{
    if (fmd->fmd_outer_src_ip == nh->nh_gre_tun_dip)
        return NH_SOURCE_VALID;

    return NH_SOURCE_INVALID;
}

static nh_processing_t
nh_gre_tunnel(struct vr_packet *pkt, struct vr_nexthop *nh,
              struct vr_forwarding_md *fmd)
{
    int overhead_len, gre_head_space;
    unsigned short drop_reason = VP_DROP_INVALID_NH;
    unsigned int id;

    int tun_encap_rewrite;
    struct vr_forwarding_class_qos *qos;
    struct vr_gre *gre_hdr;
    struct vr_ip *ip;
    struct vr_interface *vif;
    struct vr_vrf_stats *stats;
    struct vr_packet *tmp_pkt;
    struct vr_df_trap_arg trap_arg;
    unsigned int label_count = 0;

    if (vr_mudp && vr_perfs) {
        return nh_mpls_udp_tunnel(pkt, nh, fmd);
    }

    stats = vr_inet_vrf_stats(fmd->fmd_dvrf, pkt->vp_cpu);
    if (stats) {
        if (nh->nh_flags & NH_FLAG_TUNNEL_MPLS_O_MPLS) {
            stats->vrf_udp_mpls_over_mpls_tunnels++;
        } else {
            stats->vrf_gre_mpls_tunnels++;
        }
    }

    /*
     * When the packet encounters a tunnel nexthop with policy enabled,
     * the forwarding metadata (and hence the label filled up by vr_forward)
     * is lost as packets are queued in the flow entry. Note also the fact
     * that nh_output sets pkt->vp_nh to the looked up NH. So, once the
     * flow queue is flushed, we will not do vr_forward again and hence we
     * will not have label information. For those packets, we need to do
     * vr_forward again. One practical example of where this can happen is
     * when ECMP source initiates traffic to a target in a remote (not in
     * the same) server. vr_forward->tunnel_nh->nh_output sets pkt->vp_nh
     * (source is ECMP)->pass through flow lookup->
     */
    if (!fmd || fmd->fmd_label < 0) {
        vr_forward(nh->nh_router, pkt, fmd);
        return NH_PROCESSING_COMPLETE;
    }

    vr_fmd_update_label_type(fmd, VR_LABEL_TYPE_MPLS);

    if (nh_tunnel_loop_detect_handle(pkt, nh, fmd, nh->nh_gre_tun_dip))
        return NH_PROCESSING_COMPLETE;

    if (vr_perfs)
        pkt->vp_flags |= VP_FLAG_GSO;

    if (pkt->vp_type == VP_TYPE_IP) {
        ip = (struct vr_ip *)pkt_network_header(pkt);
        id = ip->ip_id;
    } else {
        id = htons(vr_generate_unique_ip_id());
    }

    if (nh->nh_flags & NH_FLAG_TUNNEL_MPLS_O_MPLS) {
        label_count = 2;
    } else {
        label_count = 1;
    }

    gre_head_space = (label_count *VR_MPLS_HDR_LEN) + sizeof(struct vr_ip) +
        sizeof(struct vr_gre);
    if (vr_fmd_l2_control_data_is_enabled(fmd))
        gre_head_space += VR_L2_CTRL_DATA_LEN;

    if ((pkt->vp_type == VP_TYPE_IP) || (pkt->vp_type == VP_TYPE_IP6)) {
        /*
         * If there are any L2 headers lets add those as well. For L3
         * unicast, following will add no extra overhead
         */
        overhead_len = gre_head_space;
        if (vr_has_to_fragment(nh->nh_dev, pkt, overhead_len) &&
                vr_ip_dont_fragment_set(pkt)) {
            if (pkt->vp_flags & VP_FLAG_MULTICAST) {
                drop_reason = VP_DROP_MCAST_DF_BIT;
                PKT_LOG(drop_reason, pkt, 0, VR_NEXTHOP_C, __LINE__);
                goto send_fail;
            }

            trap_arg.df_mtu = vif_get_mtu(nh->nh_dev) -
                (overhead_len + pkt_get_network_header_off(pkt) - pkt->vp_data);
            trap_arg.df_flow_index = fmd->fmd_flow_index;
            vr_trap(pkt, fmd->fmd_dvrf, AGENT_TRAP_HANDLE_DF, (void *)&trap_arg);
            return NH_PROCESSING_COMPLETE;
        }
    }

    gre_head_space += nh->nh_gre_tun_encap_len;

    if (pkt_head_space(pkt) < gre_head_space) {
        tmp_pkt = vr_pexpand_head(pkt, gre_head_space - pkt_head_space(pkt));
        if (!tmp_pkt) {
            drop_reason = VP_DROP_HEAD_ALLOC_FAIL;
            PKT_LOG(drop_reason, pkt, 0, VR_NEXTHOP_C, __LINE__);
            goto send_fail;
        }
        pkt = tmp_pkt;
    }

    if (vr_fmd_l2_control_data_is_enabled(fmd)) {
        if (!vr_l2_control_data_add(&pkt))
            goto send_fail;
    }

    qos = vr_qos_get_forwarding_class(nh->nh_router, pkt, fmd);
    if (nh_push_mpls_header(pkt, fmd->fmd_label, qos, true) < 0)
        goto send_fail;
    if (nh->nh_flags & NH_FLAG_TUNNEL_MPLS_O_MPLS) {
        /* insert outer label (transport label) */
        if (nh_push_mpls_header(pkt, nh->nh_gre_tun_label, qos, false) < 0)
            goto send_fail;
    }

    gre_hdr = (struct vr_gre *)pkt_push(pkt, sizeof(struct vr_gre));
    if (!gre_hdr) {
        drop_reason = VP_DROP_PUSH;
        PKT_LOG(drop_reason, pkt, 0, VR_NEXTHOP_C, __LINE__);
        goto send_fail;
    }

    gre_hdr->gre_flags = 0;
    gre_hdr->gre_proto = VR_GRE_PROTO_MPLS_NO;

    ip = (struct vr_ip *)pkt_push(pkt, sizeof(struct vr_ip));
    if (!ip) {
        drop_reason = VP_DROP_PUSH;
        PKT_LOG(drop_reason, pkt, 0, VR_NEXTHOP_C, __LINE__);
        goto send_fail;
    }
    pkt_set_network_header(pkt, pkt->vp_data);

    if (pkt->vp_type == VP_TYPE_IPOIP)
        pkt->vp_type = VP_TYPE_IP;
    else if (pkt->vp_type == VP_TYPE_IP6OIP)
        pkt->vp_type = VP_TYPE_IP6;

    if (pkt->vp_type == VP_TYPE_IP6)
        pkt->vp_type = VP_TYPE_IP6OIP;
    else  if (pkt->vp_type == VP_TYPE_IP)
        pkt->vp_type = VP_TYPE_IPOIP;
    else
        pkt->vp_type = VP_TYPE_IP;

    ip->ip_version = 4;
    ip->ip_hl = 5;
    if (qos) {
        ip->ip_tos = VR_IP_DSCP(qos->vfcq_dscp);
        pkt->vp_queue = qos->vfcq_queue_id;
        pkt->vp_priority = qos->vfcq_dotonep_qos;
    } else {
        ip->ip_tos = 0;
    }

    ip->ip_id = id;
    ip->ip_frag_off = 0;

    if (vr_pkt_is_diag(pkt)) {
        ip->ip_ttl = pkt->vp_ttl;
    } else {
        ip->ip_ttl = 64;
    }

    ip->ip_proto = VR_IP_PROTO_GRE;
    ip->ip_saddr = nh->nh_gre_tun_sip;
    ip->ip_daddr = nh->nh_gre_tun_dip;
    ip->ip_len = htons(pkt_len(pkt));
    /* checksum will be calculated for tunneled packet in linux_xmit_segment */
    if (!vr_pkt_type_is_overlay(pkt->vp_type)) {
        ip->ip_csum = 0;
        ip->ip_csum = vr_ip_csum(ip);
    }

    /* slap l2 header */
    vif = nh->nh_dev;
    if (nh->nh_flags & NH_FLAG_CRYPT_TRAFFIC) {
        if (!nh->nh_crypt_dev) {
            drop_reason = VP_DROP_NO_CRYPT_PATH; 
            PKT_LOG(drop_reason, pkt, 0, VR_NEXTHOP_C, __LINE__);
            goto send_fail;
        }
        vif = nh->nh_crypt_dev;
    }
    tun_encap_rewrite = vif->vif_set_rewrite(vif, &pkt, fmd,
            nh->nh_data, nh->nh_gre_tun_encap_len);
    if (tun_encap_rewrite < 0) {
        drop_reason = VP_DROP_PUSH;
        PKT_LOG(drop_reason, pkt, 0, VR_NEXTHOP_C, __LINE__);
        goto send_fail;
    }
    vif->vif_tx(vif, pkt, fmd);
    return NH_PROCESSING_COMPLETE;

send_fail:
    vr_pfree(pkt, drop_reason);
    return NH_PROCESSING_COMPLETE;
}


/*
 * Returns 0 - Completion of pkt handling
 *        <0 - Error in pkt handling
 */
int
nh_output(struct vr_packet *pkt, struct vr_nexthop *nh,
          struct vr_forwarding_md *fmd)
{
    bool need_flow_lookup = false;
    nh_processing_t res;

    if (!pkt->vp_ttl) {
        vr_trap(pkt, fmd->fmd_dvrf, AGENT_TRAP_ZERO_TTL, NULL);
        return 0;
    }

    pkt->vp_nh = nh;


    /* If nexthop does not have valid data, drop it */
    if (!(nh->nh_flags & NH_FLAG_VALID)) {
        PKT_LOG(VP_DROP_INVALID_NH, pkt, 0, VR_NEXTHOP_C, __LINE__);
        vr_pfree(pkt, VP_DROP_INVALID_NH);
        return 0;
    }

    if ((pkt->vp_type == VP_TYPE_IP) || (pkt->vp_type == VP_TYPE_IP6)) {
        /*
         * If the packet has not gone through flow lookup once
         * (!VP_FLAG_FLOW_SET), we need to determine whether it has to undergo
         * flow lookup now or not. There are two cases:
         *
         * 1. when policy flag is set in the nexthop, and
         * 2. when the source is an ECMP (For bridged packets this ECMP
         *      is avoided)
         *
         * When the source is an ECMP, we would like the packet to reach the
         * same place from where it came from, and hence a flow has to be setup
         * so that DP knows where to send the packet to (from an ECMP NH).
         * Typical example for this situation is when the packet reaches the
         * target VM's server from an ECMP-ed service chain.
         */
         if (!(pkt->vp_flags & VP_FLAG_FLOW_SET)) {
             if (nh->nh_flags & (NH_FLAG_POLICY_ENABLED |
                         NH_FLAG_FLOW_LOOKUP)) {
                 need_flow_lookup = true;
             }

             if (need_flow_lookup) {
                 pkt->vp_flags |= VP_FLAG_FLOW_GET;
                 /*
                  * after vr_flow_forward returns, pkt->vp_nh could have changed
                  * since in NAT cases the new destination should have been
                  * looked up.
                  */
                 if (!vr_flow_forward(nh->nh_router, pkt, fmd))
                     return 0;

                 /* pkt->vp_nh could have changed after vr_flow_forward */
                 if (!pkt->vp_nh) {
                     PKT_LOG(VP_DROP_INVALID_NH, pkt, 0, VR_NEXTHOP_C, __LINE__);
                     vr_pfree(pkt, VP_DROP_INVALID_NH);
                     return 0;
                 }

                 if (nh != pkt->vp_nh) {
                     return nh_output(pkt, pkt->vp_nh, fmd);
                 }
             }
        }
    }

    res = nh->nh_reach_nh(pkt, nh, fmd);
    if (res == NH_PROCESSING_COMPLETE)
        return 0;

    if ((nh->nh_flags & NH_FLAG_INDIRECT) && nh->nh_direct_nh)
        return nh_output(pkt, nh->nh_direct_nh, fmd);
    else
        vr_pfree(pkt, VP_DROP_INVALID_NH);

    return 0;
}

static nh_processing_t
nh_encap_l2(struct vr_packet *pkt, struct vr_nexthop *nh,
            struct vr_forwarding_md *fmd)
{
    int8_t eth_mac[VR_ETHER_ALEN], *pbb_self_mac = eth_mac;
    struct vr_interface *vif;
    struct vr_vrf_stats *stats;
    struct vr_forwarding_class_qos *qos;

    if (vr_fmd_etree_is_enabled(fmd)) {
        if ((!vr_fmd_etree_is_root(fmd)) &&
                    (!(nh->nh_flags & NH_FLAG_ETREE_ROOT))) {
            PKT_LOG(VP_DROP_LEAF_TO_LEAF, pkt, 0, VR_NEXTHOP_C, __LINE__);
            vr_pfree(pkt, VP_DROP_LEAF_TO_LEAF);
            return NH_PROCESSING_COMPLETE;
        }
    }

    /* No GRO for multicast and user packets */
    if ((pkt->vp_flags & VP_FLAG_MULTICAST) ||
            (fmd->fmd_vlan != VLAN_ID_INVALID)) {
        vr_pkt_unset_gro(pkt);
    }

    vif = nh->nh_dev;
    if (!vif) {
        PKT_LOG(VP_DROP_INVALID_IF, pkt, 0, VR_NEXTHOP_C, __LINE__);
        vr_pfree(pkt, VP_DROP_INVALID_IF);
        return NH_PROCESSING_COMPLETE;
    }

    if (!IS_MAC_ZERO(fmd->fmd_dmac) &&
            !IS_MAC_ZERO(vif->vif_pbb_mac)) {

        if (IS_MAC_BMCAST(fmd->fmd_dmac))
            vr_mcast_mac_from_isid(vif->vif_isid, pbb_self_mac);
        else
            pbb_self_mac = vif->vif_pbb_mac;

        if (!VR_MAC_CMP(fmd->fmd_dmac, pbb_self_mac)) {
            PKT_LOG(VP_DROP_BMAC_ISID_MISMATCH, pkt, 0, VR_NEXTHOP_C, __LINE__);
            vr_pfree(pkt, VP_DROP_BMAC_ISID_MISMATCH);
            return NH_PROCESSING_COMPLETE;
        }
    }

    stats = vr_inet_vrf_stats(fmd->fmd_dvrf, pkt->vp_cpu);

    if (vif_is_fabric(vif)) {
        if (!(pkt->vp_flags & VP_FLAG_GROED)) {
            qos = vr_qos_get_forwarding_class(nh->nh_router, pkt, fmd);
            if (qos) {
                if (pkt->vp_type == VP_TYPE_IP) {
                    vr_inet_set_tos((struct vr_ip *)pkt_network_header(pkt),
                            VR_IP_DSCP(qos->vfcq_dscp));
                } else if (pkt->vp_type == VP_TYPE_IP6) {
                    vr_inet6_set_tos((struct vr_ip6 *)pkt_network_header(pkt),
                            qos->vfcq_dscp);
                }
                pkt->vp_queue = qos->vfcq_queue_id;
                pkt->vp_priority = qos->vfcq_dotonep_qos;
            }
        }
    }

    if (vr_pkt_is_gro(pkt) && vif_is_virtual(vif) &&
            (!(vif->vif_flags & VIF_FLAG_MIRROR_TX))) {
        if (vr_gro_input(pkt, nh)) {
            if (stats)
                stats->vrf_gros++;
            return NH_PROCESSING_COMPLETE;
        }
    }

    /*
     * If for some reason, we have GRO flag set and we have not invoked
     * the GRO, we need to unset
     */
    vr_pkt_unset_gro(pkt);

    if (stats)
        stats->vrf_l2_encaps++;

    vif->vif_tx(vif, pkt, fmd);

    return NH_PROCESSING_COMPLETE;
}

static int
nh_encap_validate_src(struct vr_packet *pkt, struct vr_nexthop *nh,
                         struct vr_forwarding_md *fmd, void *ret_data)
{
    bool root = false;

    if (nh->nh_flags & NH_FLAG_ETREE_ROOT)
        root = true;
    vr_fmd_update_etree_root(fmd,root);

    if (pkt->vp_if == nh->nh_dev)
        return NH_SOURCE_VALID;

    return NH_SOURCE_INVALID;
}

static nh_processing_t
nh_encap_l3_mcast(struct vr_packet *pkt, struct vr_nexthop *nh,
                    struct vr_forwarding_md *fmd)
{
    uint8_t *ptr;
    unsigned short dreason = VP_DROP_INVALID_IF;
    struct vr_interface *vif;
    struct vr_ip *ip;
    struct vr_eth *eth;

    vif = nh->nh_dev;
    if (!vif)
        goto drop;

    ip = (struct vr_ip *)pkt_network_header(pkt);
    if (vr_ip_is_ip4(ip)) {
        pkt->vp_type = VP_TYPE_IP;
        eth = (struct vr_eth *)pkt_push(pkt, sizeof(struct vr_eth));
        if (!eth) {
            dreason = VP_DROP_PUSH;
            PKT_LOG(dreason, pkt, 0, VR_NEXTHOP_C, __LINE__);
            goto drop;
        }

        VR_MAC_COPY(eth->eth_smac, vif->vif_mac);
        eth->eth_proto = htons(VR_ETH_PROTO_IP);
        ptr = (uint8_t *)eth->eth_dmac;
        *(unsigned int *)(ptr + 2) = ip->ip_daddr;

        ptr[0] = 1;
        ptr[1] = 0;
        ptr[2] = 0x5E;
        ptr[3] = 0x07F & ptr[3];


        vif->vif_tx(vif, pkt, fmd);

    } else {
        dreason = VP_DROP_INVALID_PROTOCOL;
        PKT_LOG(dreason, pkt, 0, VR_NEXTHOP_C, __LINE__);
        goto drop;
    }

    return NH_PROCESSING_COMPLETE;

drop:
    vr_pfree(pkt, dreason);
    return NH_PROCESSING_COMPLETE;
}

static nh_processing_t
nh_encap_l3(struct vr_packet *pkt, struct vr_nexthop *nh,
                    struct vr_forwarding_md *fmd)
{
    int rewrite_len;
    unsigned short *proto_p;

    struct vr_ip *ip;
    struct vr_interface *vif;
    struct vr_vrf_stats *stats;
    struct vr_forwarding_class_qos *qos = NULL;

    stats = vr_inet_vrf_stats(fmd->fmd_dvrf, pkt->vp_cpu);

    vif = nh->nh_dev;
    if (!vif) {
        PKT_LOG(VP_DROP_INVALID_IF, pkt, 0, VR_NEXTHOP_C, __LINE__);
        vr_pfree(pkt, VP_DROP_INVALID_IF);
        return NH_PROCESSING_COMPLETE;
    }

    if (vif_is_fabric(vif)) {
        if (!(pkt->vp_flags & VP_FLAG_GROED)) {
            qos = vr_qos_get_forwarding_class(nh->nh_router, pkt, fmd);
            if (qos) {
                pkt->vp_queue = qos->vfcq_queue_id;
                pkt->vp_priority = qos->vfcq_dotonep_qos;
            }
        }
    }

    ip = (struct vr_ip *)pkt_network_header(pkt);
    if (vr_ip_is_ip6(ip)) {
        pkt->vp_type = VP_TYPE_IP6;
        if (qos)
            vr_inet6_set_tos((struct vr_ip6 *)ip, qos->vfcq_dscp);
    } else if (vr_ip_is_ip4(ip)) {
        pkt->vp_type = VP_TYPE_IP;
        if (qos)
            vr_inet_set_tos(ip, VR_IP_DSCP(qos->vfcq_dscp));
    } else {
        PKT_LOG(VP_DROP_INVALID_PROTOCOL, pkt, 0, VR_NEXTHOP_C, __LINE__);
        vr_pfree(pkt, VP_DROP_INVALID_PROTOCOL);
        return NH_PROCESSING_COMPLETE;
    }

    if (vr_pkt_is_diag(pkt)) {
        vr_pkt_unset_gro(pkt);
        if (stats)
            stats->vrf_diags++;
    }

    if (vr_pkt_is_gro(pkt) && vif_is_virtual(vif) &&
            (!(vif->vif_flags & VIF_FLAG_MIRROR_TX))) {
        if (vr_gro_input(pkt, nh)) {
            if (stats) {
                stats->vrf_gros++;
            }
            return NH_PROCESSING_COMPLETE;
        }
    }

    /*
     * If for some reason, we have GRO flag set and we have not invoked
     * the GRO, we need to unset
     */
    vr_pkt_unset_gro(pkt);

    rewrite_len = vif->vif_set_rewrite(vif, &pkt, fmd, nh->nh_data, nh->nh_encap_len);
    if (rewrite_len < 0) {
        PKT_LOG(VP_DROP_REWRITE_FAIL, pkt, 0, VR_NEXTHOP_C, __LINE__);
        vr_pfree(pkt, VP_DROP_REWRITE_FAIL);
        return NH_PROCESSING_COMPLETE;
    }

    if (rewrite_len) {
        proto_p = (unsigned short *)(pkt_data(pkt) + nh->nh_encap_len - 2);
        if (pkt->vp_type == VP_TYPE_IP6)
            *proto_p = htons(VR_ETH_PROTO_IP6);
        else
            *proto_p = htons(VR_ETH_PROTO_IP);
    }

    /*
     * Look if this is the Diag packet to trap to agent
     */
    if (vr_pkt_is_diag(pkt)) {
        pkt->vp_if = vif;
        vr_pset_data(pkt, pkt->vp_data);
        vr_trap(pkt, fmd->fmd_dvrf, AGENT_TRAP_DIAG, &vif->vif_idx);
        return NH_PROCESSING_COMPLETE;
    }

    if (stats) {
        stats->vrf_encaps++;
    }

    vif->vif_tx(vif, pkt, fmd);

    return NH_PROCESSING_COMPLETE;
}

static int
vr_nexthop_delete(vr_nexthop_req *req)
{
    struct vr_nexthop *nh;
    int ret = 0;

    nh = vrouter_get_nexthop(req->nhr_rid, req->nhr_id);
    if (!nh) {
        ret = -EINVAL;
    } else {
        vr_offload_nexthop_del(nh);
        vrouter_put_nexthop(nh);
        nh->nh_destructor(nh);
    }

    ret = vr_send_response(ret);

    return ret;
}

static int
nh_resolve_add(struct vr_nexthop *nh, vr_nexthop_req *req)
{
    nh->nh_reach_nh = nh_resolve;
    return 0;
}

static int
nh_l2_rcv_add(struct vr_nexthop *nh, vr_nexthop_req *req)
{
    nh->nh_reach_nh = nh_l2_rcv;
    return 0;
}

static int
nh_rcv_add(struct vr_nexthop *nh, vr_nexthop_req *req)
{
    int ret = 0;
    struct vr_interface *vif, *old_vif;

    old_vif = nh->nh_dev;

    vif = vrouter_get_interface(nh->nh_rid, req->nhr_encap_oif_id);
    if (!vif) {
        ret = -ENODEV;
        goto exit_add;
    }

    /*
     * We need to delete the reference to old_vif only after new vif is
     * added to NH
     */
    nh->nh_dev = vif;
    if (old_vif)
        vrouter_put_interface(old_vif);

exit_add:
    if (nh->nh_dev) {
        nh->nh_reach_nh = nh_l3_rcv;
    }

    return ret;
}

static int
nh_vrf_translate_add(struct vr_nexthop *nh, vr_nexthop_req *req)
{
    nh->nh_reach_nh = nh_vrf_translate;
    return 0;
}

static int
nh_composite_mcast_validate(struct vr_component_nh *component_nh,
        vr_nexthop_req *req)
{
    unsigned int i;
    bool l2_seen = false, l3_seen = false;
    struct vr_nexthop *tmp_nh;

    if (req->nhr_family == AF_INET)
        l3_seen = true;
    else if (req->nhr_family == AF_BRIDGE)
        l2_seen = true;

    /* Fabric and EVPN nexthop*/
    if (req->nhr_flags & (NH_FLAG_COMPOSITE_FABRIC |
                NH_FLAG_COMPOSITE_EVPN | NH_FLAG_COMPOSITE_TOR)) {

        if (!l3_seen && !l2_seen)
            return -1;

        for (i = 0; i < req->nhr_nh_list_size; i++) {
            tmp_nh = component_nh[i].cnh;
            if (!tmp_nh)
                continue;
            if (tmp_nh->nh_type != NH_TUNNEL)
                return -1;
            if (tmp_nh->nh_flags & NH_FLAG_TUNNEL_UDP)
                return -1;

            /* Tor nexthop can only have Vxlan encap tunnels */
            if (req->nhr_flags & NH_FLAG_COMPOSITE_TOR) {
                if ((tmp_nh->nh_flags & NH_FLAG_TUNNEL_VXLAN) == 0)
                    return -1;
            }
        }
    }

    /* Composite Encap */
    if (req->nhr_flags & NH_FLAG_COMPOSITE_ENCAP) {

        for (i = 0; i < req->nhr_nh_list_size; i++) {
            tmp_nh = component_nh[i].cnh;
            if (!tmp_nh)
                continue;

            if (tmp_nh->nh_type != NH_ENCAP)
                return -1;

            if (tmp_nh->nh_family == AF_INET) {
                if (l2_seen)
                    return -1;

                if (!(tmp_nh->nh_flags & NH_FLAG_MCAST))
                    return -1;
            } else if (tmp_nh->nh_family == AF_BRIDGE) {
                if (l3_seen)
                    return -1;

                if (tmp_nh->nh_flags & NH_FLAG_MCAST)
                    return -1;
            } else {
                return -1;
            }
        }
    }

    /* L2 and L3 multicast */
    if (req->nhr_flags & NH_FLAG_MCAST) {

        if (!l3_seen && !l2_seen)
            return -1;

        for (i = 0; i < req->nhr_nh_list_size; i++) {
            tmp_nh = component_nh[i].cnh;
            /* NULL component NH is valid */
            if (!tmp_nh)
                continue;

            /* IT can contain only Fabric and L2ENCAP composite */
            if (tmp_nh->nh_type != NH_COMPOSITE)
                return -1;

            if (!(tmp_nh->nh_flags &
                   (NH_FLAG_COMPOSITE_FABRIC | NH_FLAG_COMPOSITE_EVPN |
                    NH_FLAG_COMPOSITE_TOR | NH_FLAG_COMPOSITE_ENCAP))) {
                return -1;
            }

        }
    }

    return 0;
}

static int
nh_composite_add(struct vr_nexthop *nh, vr_nexthop_req *req)
{
    int ret = 0;
    unsigned int i, j = 0, active = 0;
    struct vr_nexthop *tmp_nh;
    struct vr_component_nh *component_nh = NULL, *component_ecmp = NULL;

    if (req->nhr_nh_list_size != req->nhr_label_list_size) {
        ret = -EINVAL;
        goto exit_add;
    }

    if (req->nhr_nh_list_size) {
        component_nh = vr_zalloc(req->nhr_nh_list_size *
                sizeof(struct vr_component_nh), VR_NEXTHOP_COMPONENT_OBJECT);
        if (!component_nh) {
            ret = -ENOMEM;
            goto exit_add;
        }

        for (i = 0; i < req->nhr_nh_list_size; i++) {
            component_nh[i].cnh = vrouter_get_nexthop(req->nhr_rid,
                    req->nhr_nh_list[i]);
            component_nh[i].cnh_label = req->nhr_label_list[i];
            if (component_nh[i].cnh)
                active++;

            if (req->nhr_flags & NH_FLAG_COMPOSITE_ECMP) {
                component_nh[i].cnh_ecmp_index = i;
            } else {
                component_nh[i].cnh_ecmp_index = -1;
            }
        }

        if (nh_composite_mcast_validate(component_nh, req)) {
            ret = -EINVAL;
            goto exit_add;
        }

        if (req->nhr_flags & NH_FLAG_COMPOSITE_ECMP) {
            if (active) {
                component_ecmp =
                    vr_zalloc(active * sizeof(struct vr_component_nh),
                            VR_NEXTHOP_COMPONENT_OBJECT);
                if (!component_ecmp) {
                    ret = -ENOMEM;
                    goto exit_add;
                }
            }

            for (i = 0; i < req->nhr_nh_list_size; i++) {
                if (component_nh[i].cnh) {
                    memcpy(&component_ecmp[j++], &component_nh[i],
                            sizeof(struct vr_component_nh));
                    /* this happens implicitly */
                    /* nh->nh_component_ecmp[j++].cnh_ecmp_index = i */
                }
            }
        }
    }

    nh->nh_validate_src = NULL;
    /* Delete the old nexthops first */
    if (nh->nh_component_cnt && nh->nh_component_nh) {
        for (i = 0; i < nh->nh_component_cnt; i++) {
            if (nh->nh_component_nh[i].cnh)
                vrouter_put_nexthop(nh->nh_component_nh[i].cnh);
        }
        vr_free(nh->nh_component_nh, VR_NEXTHOP_COMPONENT_OBJECT);
        nh->nh_component_nh = NULL;
        nh->nh_component_cnt = 0;

        if (nh->nh_component_ecmp) {
            vr_free(nh->nh_component_ecmp, VR_NEXTHOP_COMPONENT_OBJECT);
            nh->nh_component_ecmp = NULL;
            nh->nh_component_ecmp_cnt = 0;
        }
    }

    /* Nh list of size 0 is valid */
    if (req->nhr_nh_list_size == 0)
        goto exit_add;

    nh->nh_component_nh = component_nh;
    if (component_ecmp) {
        nh->nh_component_ecmp = component_ecmp;
    }
    nh->nh_component_cnt = req->nhr_nh_list_size;

exit_add:
    /* This needs to be the last */
    if (req->nhr_flags & NH_FLAG_MCAST) {
        nh->nh_reach_nh = nh_composite_mcast;
        nh->nh_validate_src = nh_composite_mcast_validate_src;
    } else if (req->nhr_flags & NH_FLAG_COMPOSITE_ECMP) {
        nh->nh_reach_nh = nh_composite_ecmp;
        nh->nh_validate_src = nh_composite_ecmp_validate_src;
        if (!ret) {
            nh_ecmp_store_ecmp_config_hash(req, nh);
            nh->nh_component_ecmp_cnt = j;
        }
    } else if (req->nhr_flags & NH_FLAG_COMPOSITE_FABRIC) {
        nh->nh_reach_nh = nh_composite_fabric;
    } else if (req->nhr_flags & NH_FLAG_COMPOSITE_EVPN) {
        nh->nh_reach_nh = nh_composite_evpn;
    } else if (req->nhr_flags & NH_FLAG_COMPOSITE_ENCAP) {
        nh->nh_reach_nh = nh_composite_encap;
    } else if (req->nhr_flags & NH_FLAG_COMPOSITE_TOR) {
        nh->nh_reach_nh = nh_composite_tor;
    }

    if (ret) {
        if (component_nh) {
            for (i = 0; i < req->nhr_nh_list_size; i++) {
                tmp_nh = component_nh[i].cnh;
                if (tmp_nh)
                    vrouter_put_nexthop(tmp_nh);
            }

            vr_free(component_nh, VR_NEXTHOP_COMPONENT_OBJECT);
        }

        if (component_ecmp) {
            vr_free(component_ecmp, VR_NEXTHOP_COMPONENT_OBJECT);
        }
    }

    return ret;
}

static inline void
nh_tunnel_set_reach_nh(struct vr_nexthop *nh)
{
    bool dev = false;

    if (nh->nh_dev) {
        dev = true;
    }

    if (nh->nh_flags & NH_FLAG_TUNNEL_GRE) {
        if (dev) {
            nh->nh_reach_nh = nh_gre_tunnel;
        }
    } else if (nh->nh_flags & NH_FLAG_TUNNEL_UDP) {
        nh->nh_reach_nh = nh_udp_tunnel;
    } else if (nh->nh_flags & NH_FLAG_TUNNEL_UDP_MPLS) {
        if (dev) {
            nh->nh_reach_nh = nh_mpls_udp_tunnel;
        }
    } else if (nh->nh_flags & NH_FLAG_TUNNEL_VXLAN) {
        if (dev) {
            nh->nh_reach_nh = nh_vxlan_tunnel;
        }
    } else if (nh->nh_flags & NH_FLAG_TUNNEL_PBB) {
        nh->nh_reach_nh = nh_pbb_tunnel;
    }

    return;
}

static int
nh_tunnel_add(struct vr_nexthop *nh, vr_nexthop_req *req)
{
    int ret = 0;
    struct vr_interface *vif, *old_vif = NULL;
    struct vr_interface *crypt_vif = NULL, *old_crypt_vif = NULL;

    if (req->nhr_family == AF_INET6) {
        if (!req->nhr_tun_sip6 || !req->nhr_tun_dip6) {
            ret = -EINVAL;
            goto exit_add;
        }
    } else if (req->nhr_family == AF_INET) {
        if (!req->nhr_tun_sip || !req->nhr_tun_dip) {
            ret = -EINVAL;
            goto exit_add;
        }
    }

    old_vif = nh->nh_dev;
    vif = vrouter_get_interface(nh->nh_rid, req->nhr_encap_oif_id);
    old_crypt_vif = nh->nh_crypt_dev;
    crypt_vif = vrouter_get_interface(nh->nh_rid, req->nhr_encap_crypt_oif_id);
    nh->nh_crypt_dev = crypt_vif;
    if (old_crypt_vif) {
        vrouter_put_interface(old_crypt_vif);
    }

    if (nh->nh_flags & NH_FLAG_TUNNEL_GRE) {
        if (!vif) {
            ret = -ENODEV;
            goto exit_add;
        }

        nh->nh_gre_tun_sip = req->nhr_tun_sip;
        nh->nh_gre_tun_dip = req->nhr_tun_dip;
        nh->nh_gre_tun_encap_len = req->nhr_encap_size;
        nh->nh_validate_src = nh_gre_tunnel_validate_src;
        nh->nh_dev = vif;
        if (nh->nh_flags & NH_FLAG_TUNNEL_MPLS_O_MPLS) {
            nh->nh_gre_tun_label = req->nhr_transport_label;
        }
    } else if (nh->nh_flags & NH_FLAG_TUNNEL_UDP) {
        if (req->nhr_family == AF_INET) {
            nh->nh_udp_tun_sip = req->nhr_tun_sip;
            nh->nh_udp_tun_dip = req->nhr_tun_dip;
            nh->nh_udp_tun_sport = req->nhr_tun_sport;
            nh->nh_udp_tun_dport = req->nhr_tun_dport;
            nh->nh_udp_tun_encap_len = req->nhr_encap_size;
        } else if (req->nhr_family == AF_INET6) {
            if (!nh->nh_udp_tun6_sip) {
                nh->nh_udp_tun6_sip = vr_malloc(VR_IP6_ADDRESS_LEN,
                        VR_NETWORK_ADDRESS_OBJECT);
                if (!nh->nh_udp_tun6_sip) {
                    ret = -ENOMEM;
                    goto exit_error;
                }
            }
            memcpy(nh->nh_udp_tun6_sip, req->nhr_tun_sip6, VR_IP6_ADDRESS_LEN);

            if (!nh->nh_udp_tun6_dip) {
                nh->nh_udp_tun6_dip = vr_malloc(VR_IP6_ADDRESS_LEN,
                        VR_NETWORK_ADDRESS_OBJECT);
                if (!nh->nh_udp_tun6_dip) {
                    ret = -ENOMEM;
                    goto exit_error;
                }
            }
            memcpy(nh->nh_udp_tun6_dip, req->nhr_tun_dip6,
                    VR_IP6_ADDRESS_LEN);
            nh->nh_udp_tun6_sport = req->nhr_tun_sport;
            nh->nh_udp_tun6_dport = req->nhr_tun_dport;
            nh->nh_udp_tun6_encap_len = req->nhr_encap_size;
        } else {
            ret = -EINVAL;
            goto exit_error;
        }

        /* VIF should be null, but lets clean if one is found */
        if (vif)
            vrouter_put_interface(vif);
    } else if (nh->nh_flags & NH_FLAG_TUNNEL_UDP_MPLS) {
        if (!vif) {
            ret = -ENODEV;
            goto exit_add;
        }

        nh->nh_udp_tun_sip = req->nhr_tun_sip;
        nh->nh_udp_tun_dip = req->nhr_tun_dip;
        nh->nh_udp_tun_encap_len = req->nhr_encap_size;
        nh->nh_validate_src = nh_mpls_udp_tunnel_validate_src;
        nh->nh_dev = vif;
        if (nh->nh_flags & NH_FLAG_TUNNEL_MPLS_O_MPLS) {
            nh->nh_udp_tun_label = req->nhr_transport_label;
        }
    } else if (nh->nh_flags & NH_FLAG_TUNNEL_VXLAN) {
        if (!vif) {
            ret = -ENODEV;
            goto exit_add;
        }

        nh->nh_vxlan_tun_sip = req->nhr_tun_sip;
        nh->nh_vxlan_tun_dip = req->nhr_tun_dip;
        nh->nh_vxlan_tun_encap_len = req->nhr_encap_size;
        nh->nh_validate_src = nh_vxlan_tunnel_validate_src;
        nh->nh_dev = vif;
        if (nh->nh_flags & NH_FLAG_L3_VXLAN) {
            if ((req->nhr_rw_dst_mac_size != VR_ETHER_ALEN) ||
                    (IS_MAC_ZERO(req->nhr_rw_dst_mac))) {
                ret = -EINVAL;
                goto exit_add;
            }
            VR_MAC_COPY(nh->nh_vxlan_tun_l3_mac, req->nhr_rw_dst_mac);
        }
    } else if (nh->nh_flags & NH_FLAG_TUNNEL_PBB) {
        if (!(nh->nh_flags & NH_FLAG_INDIRECT)) {
            ret = -EINVAL;
            goto exit_add;
        }

        if ((req->nhr_pbb_mac_size != VR_ETHER_ALEN) ||
                (IS_MAC_ZERO(req->nhr_pbb_mac))) {
            ret = -EINVAL;
            goto exit_add;
        }

        nh->nh_pbb_label = -1;
        if (req->nhr_label_list_size)
            nh->nh_pbb_label = req->nhr_label_list[0];

        VR_MAC_COPY(nh->nh_pbb_mac, req->nhr_pbb_mac);
        nh->nh_validate_src = nh_pbb_tunnel_validate_src;
        if (vif) {
            vrouter_put_interface(vif);
        }
    } else {
        /* Reference to VIf should be cleaned */
        if (vif)
            vrouter_put_interface(vif);
        if (crypt_vif)
            vrouter_put_interface(crypt_vif);

        return -EINVAL;
    }

    memcpy(nh->nh_data, req->nhr_encap, req->nhr_encap_size);
    if (old_vif)
        vrouter_put_interface(old_vif);

exit_add:
    nh_tunnel_set_reach_nh(nh);

exit_error:
    return ret;
}

static int
nh_indirect_add(struct vr_nexthop *nh, vr_nexthop_req *req)
{
    struct vr_nexthop *old_nh, *direct_nh = NULL;

    /*
     * Following check needs to be enahnced every time we make a new
     * indirect nexthop
     */
    if ((nh->nh_type != NH_TUNNEL) ||
            (!(nh->nh_flags & NH_FLAG_TUNNEL_PBB)))
        return -EINVAL;

    /*
     * Lets allow without direct nh for greater convenience of adds,
     * changes, but only one direct nh
     */
    if ((unsigned int)req->nhr_nh_list_size > 1)
        return -EINVAL;

    if (req->nhr_nh_list_size) {
        direct_nh = vrouter_get_nexthop(req->nhr_rid, req->nhr_nh_list[0]);
        if (!direct_nh)
            return -EINVAL;
    }

    /* Remove the old nh */
    old_nh = nh->nh_direct_nh;
    nh->nh_direct_nh = direct_nh;
    if (old_nh)
        vrouter_put_nexthop(old_nh);

    return 0;
}

static int
nh_encap_add(struct vr_nexthop *nh, vr_nexthop_req *req)
{
    int ret = 0;
    struct vr_interface *vif, *old_vif;

    old_vif = nh->nh_dev;

    if ((req->nhr_family != AF_INET) && (req->nhr_family != AF_BRIDGE)) {
        ret = -EINVAL;
        goto exit_add;
    }

    if ((req->nhr_family == AF_BRIDGE) && (req->nhr_flags & NH_FLAG_MCAST)) {
        ret = -EINVAL;
        goto exit_add;
    }

    if ((req->nhr_family == AF_INET) && !(req->nhr_flags & NH_FLAG_MCAST)) {
        if (req->nhr_encap_size < VR_ETHER_ALEN) {
            ret = -EINVAL;
            goto exit_add;
        }
    }

    vif = vrouter_get_interface(nh->nh_rid, req->nhr_encap_oif_id);
    if (!vif) {
        ret = -EINVAL;
        goto exit_add;
    }

    nh->nh_encap_family = req->nhr_encap_family;
    nh->nh_encap_len = req->nhr_encap_size;
    if (nh->nh_encap_len && nh->nh_data) {
        memcpy(nh->nh_data, req->nhr_encap, nh->nh_encap_len);
    }

    nh->nh_dev = vif;
    if (old_vif)
        vrouter_put_interface(old_vif);

exit_add:
    if (nh->nh_dev) {
        nh->nh_validate_src = nh_encap_validate_src;
        if (req->nhr_family == AF_BRIDGE) {
            nh->nh_reach_nh = nh_encap_l2;
        } else if (nh->nh_flags & NH_FLAG_MCAST) {
            nh->nh_reach_nh = nh_encap_l3_mcast;
        } else {
            nh->nh_reach_nh = nh_encap_l3;
        }
    }

    return ret;
}

static int
nh_discard_add(struct vr_nexthop *nh, vr_nexthop_req *req)
{
    nh->nh_family = req->nhr_family;
    nh->nh_type = NH_DISCARD;
    nh->nh_router = vrouter_get(0);
    nh->nh_reach_nh = nh_discard;
    return 0;
}

static bool
vr_nexthop_valid_request(vr_nexthop_req *req)
{
    struct vrouter *router = vrouter_get(req->nhr_rid);

    if (!router)
        return false;

    if ((unsigned int)req->nhr_id >= router->vr_max_nexthops)
        return false;

    if ((unsigned int)req->nhr_type >= NH_MAX)
        return false;

    return true;
}

static int
vr_nexthop_size(vr_nexthop_req *req)
{
    unsigned int size = sizeof(struct vr_nexthop);

    if ((req->nhr_type == NH_ENCAP) || (req->nhr_type == NH_TUNNEL))
        if (req->nhr_encap)
            size += req->nhr_encap_size;

    return size;
}

static bool
vr_nexthop_valid_change(vr_nexthop_req *req, struct vr_nexthop *nh)
{

    if (!(req->nhr_flags & NH_FLAG_VALID))
        return true;

    if (req->nhr_type != nh->nh_type)
        return false;

    if (req->nhr_encap_size &&
            req->nhr_encap_size != nh->nh_data_size)
        return false;

    /* Indirect to non-indirect and other way is not allowed */
    if ((req->nhr_flags & NH_FLAG_INDIRECT) ^
            (nh->nh_flags & NH_FLAG_INDIRECT))
        return false;

    return true;
}


int
vr_nexthop_add(vr_nexthop_req *req)
{
    int ret = 0, len = 0;
    bool invalid_to_valid = false, change = false;
    struct vr_nexthop *nh;
    struct vrouter *router = vrouter_get(req->nhr_rid);

    if (!vr_nexthop_valid_request(req) && (ret = -EINVAL))
        goto generate_resp;

    nh = __vrouter_get_nexthop(router, req->nhr_id);
    if (!nh) {
        len = vr_nexthop_size(req);
        if (len < 0) {
            ret = -EINVAL;
            goto generate_resp;
        }

        nh = vr_zalloc(len, VR_NEXTHOP_OBJECT);
        if (!nh) {
            ret = -ENOMEM;
            goto generate_resp;
        }

        nh->nh_data_size = len - sizeof(struct vr_nexthop);
    } else {
        change = true;
        /*
         * If modification of old_nh change the action to discard and ensure
         * everybody sees that
         */
        if (!vr_nexthop_valid_change(req, nh)) {
            ret = -EINVAL;
            goto generate_resp;
        }

        /* Lets track if invalid to valid change */
        if ((req->nhr_flags & NH_FLAG_VALID) &&
                !(nh->nh_flags & NH_FLAG_VALID))
            invalid_to_valid = true;

        /* If valid to invalid lets propogate flags immediately */
        if (!(req->nhr_flags & NH_FLAG_VALID) &&
                (nh->nh_flags & NH_FLAG_VALID))
            nh->nh_flags = req->nhr_flags;

        /* For a change lets always point to discard */
        nh->nh_reach_nh = nh_discard;
        vr_delay_op();
    }

    nh->nh_reach_nh = nh_discard;
    nh->nh_destructor = nh_del;
    nh->nh_type = req->nhr_type;
    nh->nh_family = req->nhr_family;
    nh->nh_id = req->nhr_id;
    nh->nh_rid = req->nhr_rid;
    nh->nh_router = vrouter_get(nh->nh_rid);
    nh->nh_vrf = req->nhr_vrf;
    nh->nh_direct_nh = NULL;

    /*
     * If invalid to valid, lets make it valid after the whole nexthop
     * is cookedup. For invalid to invalid, valid to valid, lets
     * copy the flags as is
     */
    if (invalid_to_valid)
        nh->nh_flags = (req->nhr_flags & ~NH_FLAG_VALID);
    else
        nh->nh_flags = req->nhr_flags;

    if (req->nhr_flags & NH_FLAG_VALID) {
        if (nh->nh_flags & NH_FLAG_INDIRECT) {
            ret = nh_indirect_add(nh, req);
            if (ret)
                goto error;
        }
        switch (nh->nh_type) {
        case NH_ENCAP:
            ret = nh_encap_add(nh, req);
            break;

        case NH_TUNNEL:
            ret = nh_tunnel_add(nh, req);
            break;

        case NH_RCV:
            ret = nh_rcv_add(nh, req);
            break;

        case NH_L2_RCV:
            ret = nh_l2_rcv_add(nh, req);
            break;

        case NH_RESOLVE:
            ret = nh_resolve_add(nh, req);
            break;

        case NH_DISCARD:
            ret = nh_discard_add(nh, req);
            break;

        case NH_COMPOSITE:
            ret = nh_composite_add(nh, req);
            break;

        case NH_VRF_TRANSLATE:
            ret = nh_vrf_translate_add(nh, req);
            break;

        default:
            ret = -EINVAL;
        }

    }

error:
    if (ret) {
        if (!change) {
            if (nh->nh_destructor) {
                nh->nh_destructor(nh);
            }
        }

        goto generate_resp;
    }

    /* Mark he nexthop valid after whole nexthop is cooked incase of
     * invalid to valid transition
     */
    if (invalid_to_valid)
        nh->nh_flags |= NH_FLAG_VALID;

    ret = vrouter_add_nexthop(nh);
    
    if (ret) {
        nh->nh_destructor(nh);
        goto generate_resp;
    }
    else /* notify hw offload of change, if enabled */
        ret = vr_offload_nexthop_add(nh);

    /* if offload failed, delete kernel entry for consistency */
    if (ret)
        nh->nh_destructor(nh);

generate_resp:
    ret = vr_send_response(ret);

    return ret;
}

unsigned int
vr_nexthop_req_get_size(void *req_p)
{
    int size = 4 * sizeof(vr_nexthop_req);
    vr_nexthop_req *req = (vr_nexthop_req *)req_p;

    size += req->nhr_encap_size;

    if (req->nhr_nh_list_size)
        size += (4 * req->nhr_nh_list_size);

    if (req->nhr_label_list_size)
        size += (4 * req->nhr_label_list_size);

    size += req->nhr_pbb_mac_size;

    if ((req->nhr_type == NH_TUNNEL) &&
            (req->nhr_flags & NH_FLAG_TUNNEL_UDP) &&
            (req->nhr_family == AF_INET6))
        size += (VR_IP6_ADDRESS_LEN * 2 * 4);

    return size;
}

/* we expect the caller to bzero req, before sending it here */
static int
vr_nexthop_make_req(vr_nexthop_req *req, struct vr_nexthop *nh)
{
    unsigned int i;
    unsigned char *encap = NULL;
    struct vr_nexthop *cnh;

    bool dump = false;

    if (req->h_op == SANDESH_OP_DUMP)
        dump = true;

    req->nhr_type = nh->nh_type;
    req->nhr_family = nh->nh_family;
    req->nhr_flags = nh->nh_flags;
    req->nhr_id = nh->nh_id;
    req->nhr_rid = nh->nh_rid;
    req->nhr_ref_cnt = nh->nh_users;
    req->nhr_nh_list_size = 0;
    req->nhr_vrf = nh->nh_vrf;

    if ((nh->nh_flags & NH_FLAG_INDIRECT) && (cnh = nh->nh_direct_nh)) {
        req->nhr_nh_list_size = 1;
        req->nhr_nh_list =
                vr_zalloc(req->nhr_nh_list_size * sizeof(unsigned int),
                        VR_NEXTHOP_REQ_LIST_OBJECT);
        if (!req->nhr_nh_list)
            return -ENOMEM;
        req->nhr_nh_list[0] = cnh->nh_id;
    }

    switch (nh->nh_type) {
    case NH_RCV:
        if (nh->nh_dev)
           req->nhr_encap_oif_id = nh->nh_dev->vif_idx;
        break;

    case NH_L2_RCV:
        if (nh->nh_dev)
           req->nhr_encap_oif_id = nh->nh_dev->vif_idx;
        break;

    case NH_ENCAP:
        if (nh->nh_dev)
            req->nhr_encap_oif_id = nh->nh_dev->vif_idx;

        req->nhr_encap_size = nh->nh_encap_len;
        req->nhr_encap_family = nh->nh_encap_family;
        if (req->nhr_encap_size)
            encap = nh->nh_data;
        break;

    case NH_COMPOSITE:
        req->nhr_nh_list_size = req->nhr_nh_count =  nh->nh_component_cnt;
        if (dump && (req->nhr_nh_list_size > VR_NEXTHOP_COMPONENT_DUMP_LIMIT))
            req->nhr_nh_list_size = VR_NEXTHOP_COMPONENT_DUMP_LIMIT;
        req->nhr_ecmp_config_hash = nh->nh_ecmp_config_hash &
                                         NH_ECMP_CONFIG_HASH_MASK;

        if (nh->nh_component_cnt) {
            req->nhr_nh_list =
                vr_zalloc(req->nhr_nh_list_size * sizeof(unsigned int),
                        VR_NEXTHOP_REQ_LIST_OBJECT);
            if (!req->nhr_nh_list)
                return -ENOMEM;

            req->nhr_label_list_size = req->nhr_nh_list_size;
            req->nhr_label_list =
                vr_zalloc(req->nhr_label_list_size * sizeof(unsigned int),
                        VR_NEXTHOP_REQ_LIST_OBJECT);
            /* don't bother about freeing. we will free it in req_destroy */
            if (!req->nhr_label_list)
                return -ENOMEM;

            for (i = 0; i < req->nhr_nh_list_size; i++) {
                if (nh->nh_component_nh[i].cnh)
                    req->nhr_nh_list[i] = nh->nh_component_nh[i].cnh->nh_id;
                else
                    req->nhr_nh_list[i] = -1;

                req->nhr_label_list[i] = nh->nh_component_nh[i].cnh_label;
            }
        }

        break;

    case NH_TUNNEL:
        if (nh->nh_crypt_dev)
            req->nhr_encap_crypt_oif_id = nh->nh_crypt_dev->vif_idx;
        req->nhr_encap_family = nh->nh_encap_family;
        if (nh->nh_flags & NH_FLAG_TUNNEL_GRE) {
            req->nhr_tun_sip = nh->nh_gre_tun_sip;
            req->nhr_tun_dip = nh->nh_gre_tun_dip;
            req->nhr_encap_size = nh->nh_gre_tun_encap_len;
            if (req->nhr_encap_size)
                encap = nh->nh_data;
            if (nh->nh_dev)
                req->nhr_encap_oif_id = nh->nh_dev->vif_idx;
            if (nh->nh_flags & NH_FLAG_TUNNEL_MPLS_O_MPLS) {
                req->nhr_transport_label = nh->nh_gre_tun_label;
            }
        } else if (nh->nh_flags & NH_FLAG_TUNNEL_UDP) {
            if (nh->nh_family == AF_INET) {
                req->nhr_tun_sip = nh->nh_udp_tun_sip;
                req->nhr_tun_dip = nh->nh_udp_tun_dip;
                req->nhr_encap_size = nh->nh_udp_tun_encap_len;
                req->nhr_tun_sport = nh->nh_udp_tun_sport;
                req->nhr_tun_dport = nh->nh_udp_tun_dport;
            } else if (nh->nh_family == AF_INET6) {
                if (req->nhr_tun_sip6_size && req->nhr_tun_sip6)
                    memcpy(req->nhr_tun_sip6, nh->nh_udp_tun6_sip,
                            VR_IP6_ADDRESS_LEN);
                if (req->nhr_tun_dip6_size && req->nhr_tun_dip6)
                    memcpy(req->nhr_tun_dip6, nh->nh_udp_tun6_dip,
                            VR_IP6_ADDRESS_LEN);
                req->nhr_encap_size = nh->nh_udp_tun6_encap_len;
                req->nhr_tun_sport = nh->nh_udp_tun6_sport;
                req->nhr_tun_dport = nh->nh_udp_tun6_dport;
            }

            if (req->nhr_encap_size)
                encap = nh->nh_data;
            if (nh->nh_dev)
                req->nhr_encap_oif_id = nh->nh_dev->vif_idx;
        } else if (nh->nh_flags & NH_FLAG_TUNNEL_UDP_MPLS) {
            req->nhr_tun_sip = nh->nh_udp_tun_sip;
            req->nhr_tun_dip = nh->nh_udp_tun_dip;
            req->nhr_encap_size = nh->nh_udp_tun_encap_len;
            if (req->nhr_encap_size)
                encap = nh->nh_data;
            if (nh->nh_dev)
                req->nhr_encap_oif_id = nh->nh_dev->vif_idx;
            if (nh->nh_flags & NH_FLAG_TUNNEL_MPLS_O_MPLS) {
                req->nhr_transport_label = nh->nh_udp_tun_label;
            }
        } else if (nh->nh_flags & NH_FLAG_TUNNEL_VXLAN) {
            req->nhr_tun_sip = nh->nh_vxlan_tun_sip;
            req->nhr_tun_dip = nh->nh_vxlan_tun_dip;
            req->nhr_encap_size = nh->nh_vxlan_tun_encap_len;
            if (req->nhr_encap_size)
                encap = nh->nh_data;
            if (nh->nh_dev)
                req->nhr_encap_oif_id = nh->nh_dev->vif_idx;
            if (nh->nh_flags & NH_FLAG_L3_VXLAN) {
                req->nhr_rw_dst_mac_size = VR_ETHER_ALEN;
                req->nhr_rw_dst_mac = vr_zalloc(req->nhr_rw_dst_mac_size,
                        VR_NEXTHOP_REQ_BMAC_OBJECT);
                if (!req->nhr_rw_dst_mac)
                    return -ENOMEM;
                VR_MAC_COPY(req->nhr_rw_dst_mac, nh->nh_vxlan_tun_l3_mac);
            }
        } else if (nh->nh_flags & NH_FLAG_TUNNEL_PBB) {
            if (nh->nh_pbb_label != -1) {
                req->nhr_label_list_size = 1;
                req->nhr_label_list =
                    vr_zalloc(req->nhr_nh_list_size * sizeof(unsigned int),
                                    VR_NEXTHOP_REQ_LIST_OBJECT);
                if (!req->nhr_label_list)
                    return -ENOMEM;
                req->nhr_label_list[0] = nh->nh_pbb_label;
            }

            req->nhr_pbb_mac_size = VR_ETHER_ALEN;
            req->nhr_pbb_mac = vr_zalloc(req->nhr_pbb_mac_size,
                    VR_NEXTHOP_REQ_BMAC_OBJECT);
            if (!req->nhr_pbb_mac)
                return -ENOMEM;
            VR_MAC_COPY(req->nhr_pbb_mac, nh->nh_pbb_mac);
        }

        break;
    }

    if (req->nhr_encap_size) {
        req->nhr_encap = vr_zalloc(req->nhr_encap_size,
                VR_NEXTHOP_REQ_ENCAP_OBJECT);
        if (req->nhr_encap) {
            memcpy(req->nhr_encap, encap,
                    req->nhr_encap_size);
        } else {
            req->nhr_encap_size = 0;
            return -ENOMEM;
        }
    }

    return 0;
}

static vr_nexthop_req *
vr_nexthop_req_get(struct vr_nexthop *nh)
{
    vr_nexthop_req *nhr;

    nhr = vr_zalloc(sizeof(vr_nexthop_req), VR_NEXTHOP_REQ_OBJECT);
    if (!nhr)
        return NULL;

    if ((nh->nh_type == NH_TUNNEL) &&
            (nh->nh_flags & NH_FLAG_TUNNEL_UDP) &&
            (nh->nh_family == AF_INET6)) {
        nhr->nhr_tun_sip6 = vr_malloc(VR_IP6_ADDRESS_LEN,
                VR_NETWORK_ADDRESS_OBJECT);
        if (!nhr->nhr_tun_sip6)
            goto fail;
        nhr->nhr_tun_sip6_size = VR_IP6_ADDRESS_LEN;

        nhr->nhr_tun_dip6 = vr_malloc(VR_IP6_ADDRESS_LEN,
                VR_NETWORK_ADDRESS_OBJECT);
        if (!nhr->nhr_tun_dip6)
            goto fail;
        nhr->nhr_tun_dip6_size = VR_IP6_ADDRESS_LEN;
    }

    return nhr;

fail:
    if (nhr->nhr_tun_sip6) {
        vr_free(nhr->nhr_tun_sip6, VR_IP6_ADDRESS_LEN);
        nhr->nhr_tun_sip6 = NULL;
    }

    if (nhr->nhr_tun_dip6) {
        vr_free(nhr->nhr_tun_dip6, VR_IP6_ADDRESS_LEN);
        nhr->nhr_tun_dip6 = NULL;
    }

    if (nhr) {
        vr_free(nhr, VR_NEXTHOP_REQ_OBJECT);
        nhr = NULL;
    }

    return nhr;
}

static void
vr_nexthop_req_destroy(vr_nexthop_req *req)
{
    if (!req)
        return;

    if (req->nhr_encap_size && req->nhr_encap) {
        vr_free(req->nhr_encap, VR_NEXTHOP_REQ_ENCAP_OBJECT);
        req->nhr_encap_size = 0;
        req->nhr_encap = NULL;
    }

    if (req->nhr_nh_list_size && req->nhr_nh_list) {
        vr_free(req->nhr_nh_list, VR_NEXTHOP_REQ_LIST_OBJECT);
        req->nhr_nh_list_size = 0;
        req->nhr_nh_list = NULL;
    }

    if (req->nhr_label_list_size && req->nhr_label_list) {
        vr_free(req->nhr_label_list, VR_NEXTHOP_REQ_LIST_OBJECT);
        req->nhr_label_list = NULL;
        req->nhr_label_list_size = 0;
    }

    if (req->nhr_tun_sip6) {
        vr_free(req->nhr_tun_sip6, VR_NETWORK_ADDRESS_OBJECT);
        req->nhr_tun_sip6 = NULL;
    }

    if (req->nhr_tun_dip6) {
        vr_free(req->nhr_tun_dip6, VR_NETWORK_ADDRESS_OBJECT);
        req->nhr_tun_dip6 = NULL;
    }

    if (req->nhr_pbb_mac) {
        vr_free(req->nhr_pbb_mac, VR_NEXTHOP_REQ_BMAC_OBJECT);
        req->nhr_pbb_mac = NULL;
        req->nhr_pbb_mac_size = 0;
    }

    vr_free(req, VR_NEXTHOP_REQ_OBJECT);
    return;
}

int
vr_nexthop_get(vr_nexthop_req *req)
{
    int ret = 0;
    struct vr_nexthop *nh = NULL;
    struct vrouter *router;
    vr_nexthop_req *resp = NULL;

    router = vrouter_get(req->nhr_rid);
    if (!router || (unsigned int)req->nhr_id >= router->vr_max_nexthops) {
        ret = -ENODEV;
        goto generate_response;
    }

    nh = __vrouter_get_nexthop(router, req->nhr_id);
    if (nh) {
        resp = vr_nexthop_req_get(nh);
        if (!resp) {
            ret = -ENOMEM;
            goto generate_response;
        }

        resp->h_op = SANDESH_OP_GET;
        if (resp)
            ret = vr_nexthop_make_req(resp, nh);
        else
            ret = -ENOMEM;
    } else
        ret = -ENOENT;

    /* Debug comparison to check if matching entry is programmed on NIC */
    if (!ret)
        vr_offload_nexthop_get(nh, resp);

generate_response:
    vr_message_response(VR_NEXTHOP_OBJECT_ID, ret < 0 ? NULL : resp, ret, false);
    if (resp)
        vr_nexthop_req_destroy(resp);

    return 0;
}

int
vr_nexthop_dump(vr_nexthop_req *r)
{
    int ret = 0;
    unsigned int i;
    vr_nexthop_req *resp = NULL;
    struct vr_message_dumper *dumper = NULL;
    struct vr_nexthop *nh;
    struct vrouter *router = vrouter_get(0);

    if (!router && (ret = -ENODEV))
        goto generate_response;

    if ((unsigned int)(r->nhr_marker) + 1 >= router->vr_max_nexthops)
        goto generate_response;

    dumper = vr_message_dump_init(r);
    if (!dumper && (ret = -ENOMEM))
        goto generate_response;

    for (i = (unsigned int)(r->nhr_marker + 1);
            i < router->vr_max_nexthops; i++) {
        nh = __vrouter_get_nexthop(router, i);
        if (nh) {
            resp = vr_nexthop_req_get(nh);
            if (!resp && (ret = -ENOMEM))
                goto generate_response;

            resp->h_op = SANDESH_OP_DUMP;
            ret = vr_nexthop_make_req(resp, nh);

            if (!ret)
                vr_offload_nexthop_get(nh, resp);

            if ((ret < 0) || ((ret = vr_message_dump_object(dumper,
                                VR_NEXTHOP_OBJECT_ID, resp)) <= 0)) {
                vr_nexthop_req_destroy(resp);
                break;
            }

            vr_nexthop_req_destroy(resp);
        }
    }

generate_response:
    vr_message_dump_exit(dumper, ret);
    return 0;
}

/*
 * called by sandesh_process based on type of the request
 */
void
vr_nexthop_req_process(void *s_req)
{
    int ret;
    vr_nexthop_req *req = (vr_nexthop_req *)s_req;

    switch (req->h_op) {
    case SANDESH_OP_ADD:
        ret = vr_nexthop_add(req);
        break;

    case SANDESH_OP_GET:
        ret = vr_nexthop_get(req);
        break;

    case SANDESH_OP_DEL:
        ret = vr_nexthop_delete(req);
        break;

    case SANDESH_OP_DUMP:
        ret = vr_nexthop_dump(req);
        break;

    default:
        ret = -EOPNOTSUPP;
        vr_send_response(ret);
        break;
    }
}

int
vr_is_local_ecmp_nh (struct vr_nexthop *nh)
{
    int i;

    if (!nh || (nh->nh_type != NH_COMPOSITE) ||
       (!(nh->nh_flags & NH_FLAG_COMPOSITE_ECMP))) {
        return 0;
    }
    for (i = 0; i < nh->nh_component_cnt; i++) {
         if (nh->nh_component_nh[i].cnh->nh_type != NH_ENCAP) {
             return 0;
         }
    }
    return 1;
}

struct vr_interface *
vr_get_ecmp_first_member_dev (struct vr_nexthop *nh)
{
    if (!nh || (nh->nh_type != NH_COMPOSITE) ||
       (!(nh->nh_flags & NH_FLAG_COMPOSITE_ECMP))) {
        return NULL;
    }
    return nh->nh_component_nh[0].cnh->nh_dev;
}

static void
nh_table_exit(struct vrouter *router, bool soft_reset)
{
    unsigned int i;
    struct vr_nexthop *nh;

    if (!router->vr_nexthops)
        return;

    for (i = 0; i < router->vr_max_nexthops; i++) {
        if (soft_reset && i == NH_DISCARD_ID)
            continue;
        nh = __vrouter_get_nexthop(router, i);
        if (nh)
            nh->nh_destructor(nh);
    }


    if (soft_reset == false) {
        /* Make the default nh point to NULL */
        ip4_default_nh = NULL;
        vr_btable_free(router->vr_nexthops);
        router->vr_max_nexthops = 0;
        router->vr_nexthops = NULL;
    }

    return;
}

static int
nh_allocate_discard(void)
{
    ip4_default_nh = vr_zalloc(sizeof(struct vr_nexthop), VR_NEXTHOP_OBJECT);
    if (!ip4_default_nh)
        return -ENOMEM;

    ip4_default_nh->nh_id = NH_DISCARD_ID;
    ip4_default_nh->nh_type = NH_DISCARD;
    ip4_default_nh->nh_router = vrouter_get(0);
    ip4_default_nh->nh_reach_nh = nh_discard;
    ip4_default_nh->nh_destructor = nh_del;
    ip4_default_nh->nh_flags = NH_FLAG_VALID;
    ip4_default_nh->nh_family = AF_INET;

    return vrouter_add_nexthop(ip4_default_nh);
}

static int
nh_table_init(struct vrouter *router)
{
    int ret;
    unsigned int table_memory;

    if (!router->vr_max_nexthops) {
        router->vr_max_nexthops = vr_nexthops;
        table_memory = router->vr_max_nexthops * sizeof(struct vr_nexthop *);
        router->vr_nexthops = vr_btable_alloc(router->vr_max_nexthops,
                sizeof(struct vr_nexthop *));
        if (!router->vr_nexthops)
            return vr_module_error(-ENOMEM, __FUNCTION__,
                    __LINE__, table_memory);
    }

    if (!ip4_default_nh) {
        ret = nh_allocate_discard();
        if (ret)
            return vr_module_error(ret, __FUNCTION__, __LINE__, 0);
    }

    return 0;
}

void
vr_nexthop_exit(struct vrouter *router, bool soft_reset)
{
    nh_table_exit(router, soft_reset);
    return;
}

int
vr_nexthop_init(struct vrouter *router)
{
    return nh_table_init(router);
}

/*
 * Called by offload module to update vrfstats with packets which have been
 * offloaded. Expect counters in host byte order.
 */
int
vr_nexthop_update_offload_vrfstats(uint32_t vrfid, uint32_t num_cntrs,
                               uint64_t *cntrs)
{
    uint64_t *dst_cntr;
    struct vr_vrf_stats *stats;

    if (!vr_inet_vrf_stats)
        return 0;

    /* hw offload stats always go to CPU 0 */
    stats = vr_inet_vrf_stats(vrfid, 0);
    if (stats && num_cntrs <= sizeof(struct vr_vrf_stats) / sizeof(uint64_t)) {
        dst_cntr = (uint64_t *)stats;
        while (num_cntrs-- > 0)
            *dst_cntr++ += *cntrs++;
    }

    return 0;
}
