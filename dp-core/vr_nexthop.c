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
        nh->nh_users++;

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
        ref_cnt = __sync_sub_and_fetch(&nh->nh_users, 1);
    }

    if (!ref_cnt ) {

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

static int
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
    return 0;
}

static int
nh_vrf_translate(struct vr_packet *pkt, struct vr_nexthop *nh,
                 struct vr_forwarding_md *fmd)
{
    struct vr_vrf_stats *stats;

    stats = vr_inet_vrf_stats(nh->nh_vrf, pkt->vp_cpu);
    if (stats)
        stats->vrf_vrf_translates++;

    fmd->fmd_dvrf = nh->nh_vrf;
    if (!(nh->nh_flags & NH_FLAG_VNID))
        return vr_forward(nh->nh_router, pkt, fmd);

    return vr_bridge_input(nh->nh_router, pkt, fmd);
}

static int
nh_l2_rcv(struct vr_packet *pkt, struct vr_nexthop *nh,
          struct vr_forwarding_md *fmd)
{
    struct vr_vrf_stats *stats;
    int pull_len, handled = 0;

    stats = vr_inet_vrf_stats(fmd->fmd_dvrf, pkt->vp_cpu);
    if (stats)
        stats->vrf_l2_receives++;

    fmd->fmd_to_me = 1;
    pull_len = pkt_get_network_header_off(pkt) - pkt_head_space(pkt);
    if (pkt_pull(pkt, pull_len) < 0) {
        vr_pfree(pkt, VP_DROP_PULL);
        return 0;
    }

    /*
     * there should not be any unicast ARP requests destined to "my mac".
     * The ARP response destined to "my mac" incase of ARP request being
     * generated by Agent for some features
     */
    if (pkt->vp_type == VP_TYPE_IP6) {
        handled = vr_neighbor_input(pkt, fmd);
        if (!handled)
            handled = vr_l3_input(pkt, fmd);
    } else if (pkt->vp_type == VP_TYPE_IP) {
        handled = vr_l3_input(pkt, fmd);
    } else if (pkt->vp_type == VP_TYPE_ARP) {
        handled = vr_arp_input(pkt, fmd);
    }

    if (!handled)
        vr_pfree(pkt, VP_DROP_INVALID_PROTOCOL);
    return 0;
}

static int
nh_l3_rcv(struct vr_packet *pkt, struct vr_nexthop *nh,
          struct vr_forwarding_md *fmd)
{
    struct vr_vrf_stats *stats;

    stats = vr_inet_vrf_stats(fmd->fmd_dvrf, pkt->vp_cpu);
    if (stats)
        stats->vrf_receives++;

    if (nh->nh_family == AF_INET)
        return vr_ip_rcv(nh->nh_router, pkt, fmd);
    else
        vr_pfree(pkt, VP_DROP_INVALID_PROTOCOL);

    return 0;
}


static int
nh_push_mpls_header(struct vr_packet *pkt, unsigned int label,
        struct vr_forwarding_class_qos *qos)
{
    uint32_t exp_qos = 0;
    unsigned int *lbl;
    unsigned int ttl;

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

    *lbl = htonl((label << VR_MPLS_LABEL_SHIFT) | exp_qos |
            VR_MPLS_STACK_BIT | ttl);

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
        pkt->vp_queue = qos->vfcq_queue_id + 1;
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
nh_udp_tunnel6_helper(struct vr_packet *pkt, struct vr_nexthop *nh)
{
    unsigned int v4_ip;
    uint8_t *sip = NULL;
    uint8_t sip6[VR_IP6_ADDRESS_LEN];

    struct vr_ip6 *ip6;
    struct vr_ip *ip;
    struct vr_udp *udp;

    if (nh->nh_flags & NH_FLAG_TUNNEL_SIP_COPY) {
        if (pkt->vp_type == VP_TYPE_IP6) {
            ip6 = (struct vr_ip6 *)pkt_network_header(pkt);

            if (pkt->vp_if->vif_type == VIF_TYPE_PHYSICAL)
                sip = ip6->ip6_dst;
            sip = ip6->ip6_src;

        } else if (pkt->vp_type == VP_TYPE_IP) {
            ip = (struct vr_ip *)pkt_network_header(pkt);

            v4_ip = ip->ip_saddr;
            if (pkt->vp_if->vif_type == VIF_TYPE_PHYSICAL)
                v4_ip = ip->ip_daddr;

            vr_inet6_generate_ip6(sip6, v4_ip);
            sip = sip6;
        }
    }

    /* udp Header */
    udp = (struct vr_udp *)pkt_push(pkt, sizeof(struct vr_udp));
    if (!udp) {
        return false;
    }

    udp->udp_sport = nh->nh_udp_tun6_sport;
    udp->udp_dport = nh->nh_udp_tun6_dport;
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

    if (!sip)
        sip = nh->nh_udp_tun6_sip;

    memcpy(ip6->ip6_src, sip, VR_IP6_ADDRESS_LEN);
    memcpy(ip6->ip6_dst, nh->nh_udp_tun6_dip, VR_IP6_ADDRESS_LEN);


    return true;
}

static bool
nh_vxlan_tunnel_helper(struct vrouter *router, struct vr_packet *pkt,
        struct vr_forwarding_md *fmd, unsigned int sip, unsigned int dip)
{
    unsigned short udp_src_port = VR_VXLAN_UDP_SRC_PORT;

    struct vr_vxlan *vxlanh;
    struct vr_packet *tmp_pkt;
    struct vr_forwarding_class_qos *qos;

    if (pkt_head_space(pkt) < VR_VXLAN_HDR_LEN) {
        tmp_pkt = vr_pexpand_head(pkt, VR_VXLAN_HDR_LEN - pkt_head_space(pkt));
        if (!tmp_pkt) {
            return false;
        }
        pkt = tmp_pkt;
    }

    if (fmd->fmd_udp_src_port)
        udp_src_port = fmd->fmd_udp_src_port;

    /*
     * The UDP source port is a hash of the inner headers
     */
    if ((!fmd->fmd_udp_src_port) && vr_get_udp_src_port) {
        udp_src_port = vr_get_udp_src_port(pkt, fmd, fmd->fmd_dvrf);
        if (udp_src_port == 0) {
         return false;
        }
    }

    vr_forwarding_md_update_label_type(fmd, VR_LABEL_TYPE_VXLAN_ID);

    /* Add the vxlan header */
    vxlanh = (struct vr_vxlan *)pkt_push(pkt, sizeof(struct vr_vxlan));
    vxlanh->vxlan_vnid = htonl(fmd->fmd_label << VR_VXLAN_VNID_SHIFT);
    vxlanh->vxlan_flags = htonl(VR_VXLAN_IBIT);

    qos = vr_qos_get_forwarding_class(router, pkt, fmd);
    return nh_udp_tunnel_helper(pkt, htons(udp_src_port),
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
    if (vr_pcow(clone_pkt, head_room)) {
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
    struct vr_nexthop *cnh;

    /* the first few checks are straight forward */
    if (!fmd || (uint8_t)fmd->fmd_ecmp_src_nh_index >= nh->nh_component_cnt)
        return NH_SOURCE_INVALID;

    cnh = nh->nh_component_nh[fmd->fmd_ecmp_src_nh_index].cnh;
    if (cnh && !cnh->nh_validate_src)
        return NH_SOURCE_INVALID;

    /*
     * when the 'supposed' source goes down, cnh is null, in which
     * case validate the source against other present nexthops. follow
     * the same logic if the component validate source returns invalid
     * source, which could mean that source has moved
     */
    if (!cnh || (NH_SOURCE_INVALID ==
                 cnh->nh_validate_src(pkt, cnh, fmd, NULL))) {
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
            if ((NH_SOURCE_VALID ==
                 cnh->nh_validate_src(pkt, cnh, fmd, NULL)))
                return NH_SOURCE_MISMATCH;
        }

        /* if everything else fails, source is indeed invalid */
        return NH_SOURCE_INVALID;
    }

    /* source is validated by validate_src */
    return NH_SOURCE_VALID;
}

static struct vr_nexthop *
nh_composite_ecmp_select_nh(struct vr_packet *pkt, struct vr_nexthop *nh,
        struct vr_forwarding_md *fmd)
{
    int ret, ecmp_index;
    unsigned int hash, hash_ecmp, count;

    struct vr_flow flow;
    struct vr_ip6 *ip6;
    struct vr_nexthop *cnh = NULL;
    struct vr_component_nh *cnhp = nh->nh_component_nh;

    if (!(count = nh->nh_component_cnt))
        return NULL;

    if (pkt->vp_type == VP_TYPE_IP) {
        ret = vr_inet_get_flow_key(nh->nh_router, pkt, fmd, &flow);
        if (ret < 0)
            return NULL;
    } else if (pkt->vp_type == VP_TYPE_IP6) {
        ip6 = (struct vr_ip6 *)pkt_network_header(pkt);
        ret = vr_inet6_form_flow(nh->nh_router, fmd->fmd_dvrf, pkt,
                fmd->fmd_vlan, ip6, &flow);
        if (ret < 0)
            return NULL;
    } else {
        return NULL;
    }

    hash = hash_ecmp = vr_hash(&flow, flow.flow_key_len, 0);
    hash %= count;
    ecmp_index = cnhp[hash].cnh_ecmp_index;
    cnh = cnhp[hash].cnh;
    if (!cnh) {
        if (nh->nh_component_ecmp_cnt) {
            cnhp = nh->nh_component_ecmp;
            hash_ecmp %= nh->nh_component_ecmp_cnt;
            ecmp_index = cnhp[hash_ecmp].cnh_ecmp_index;
            cnh = cnhp[hash_ecmp].cnh;
        }
    }

    if (cnh)
        fmd->fmd_ecmp_nh_index = ecmp_index;

    return cnh;
}

static int
nh_composite_ecmp(struct vr_packet *pkt, struct vr_nexthop *nh,
                  struct vr_forwarding_md *fmd)
{
    int ret = 0;
    struct vr_nexthop *member_nh = NULL;
    struct vr_vrf_stats *stats;

    stats = vr_inet_vrf_stats(fmd->fmd_dvrf, pkt->vp_cpu);
    if (stats)
        stats->vrf_ecmp_composites++;

    if (!fmd || fmd->fmd_ecmp_nh_index >= (short)nh->nh_component_cnt)
        goto drop;

    if (fmd->fmd_ecmp_nh_index >= 0) {
        member_nh = nh->nh_component_nh[fmd->fmd_ecmp_nh_index].cnh;
    } else if (fmd->fmd_flow_index < 0) {
        member_nh = nh_composite_ecmp_select_nh(pkt, nh, fmd);
    }

    if (!member_nh) {
        if (fmd->fmd_flow_index < 0) {
            vr_pfree(pkt, VP_DROP_INVALID_NH);
            return 0;
        } else {
            vr_trap(pkt, fmd->fmd_dvrf, AGENT_TRAP_ECMP_RESOLVE, &fmd->fmd_flow_index);
            return 0;
        }
    }

    vr_forwarding_md_set_label(fmd,
            nh->nh_component_nh[fmd->fmd_ecmp_nh_index].cnh_label,
            VR_LABEL_TYPE_UNKNOWN);
    return nh_output(pkt, member_nh, fmd);

drop:
    vr_pfree(pkt, VP_DROP_NO_FMD);
    return ret;
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
            else if (dir_nh->nh_flags &
                       (NH_FLAG_TUNNEL_UDP_MPLS | NH_FLAG_TUNNEL_VXLAN))
                tun_dip = dir_nh->nh_udp_tun_dip;

            /* If source is in districution tree, it is valid */
            if (tun_dip && fmd->fmd_outer_src_ip &&
                      fmd->fmd_outer_src_ip == tun_dip) {

                if (ret_flags)
                    *((unsigned int *)ret_flags) = fabric_nh->nh_flags;

                return NH_SOURCE_VALID;
            }
        }
    }

    return NH_SOURCE_INVALID;
}

static int
nh_handle_mcast_control_pkt(struct vr_packet *pkt, struct vr_forwarding_md *fmd,
        unsigned int pkt_src, bool *flood_to_vms)
{
    int handled = 1;
    bool flood = false;
    unsigned short trap, rt_flags, drop_reason, pull_len  = 0;

    l4_pkt_type_t l4_type = L4_TYPE_UNKNOWN;

    struct vr_eth *eth;
    struct vr_arp *sarp;
    struct vr_nexthop *src_nh;
    struct vr_ip6 *ip6;

    struct vr_packet *pkt_c = NULL;

    /*
     * The vlan tagged packets are meant to be handled only by VM's
     */
    if (fmd->fmd_vlan != VLAN_ID_INVALID)
        return !handled;

    eth = (struct vr_eth *)pkt_data(pkt);

    pull_len = pkt_get_network_header_off(pkt) - pkt_head_space(pkt);
    if (pkt_pull(pkt, pull_len) < 0) {
        drop_reason = VP_DROP_PULL;
        goto drop;
    }

    if (pkt->vp_type == VP_TYPE_ARP) {
        handled = vr_arp_input(pkt, fmd);
        if (handled)
            return handled;

        /*
         * If not handled, packet needs to be flooded. If the ARP is
         * from MX, VM's should not see this ARP as VM's always need to
         * Agentas gateway
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
    if (pkt->vp_type == VP_TYPE_IP6)
        l4_type = vr_ip6_well_known_packet(pkt);
    else if (pkt_src == PKT_SRC_TOR_REPL_TREE)
        l4_type = vr_ip_well_known_packet(pkt);


    /*
     * Special control packets need to be handled only if BMS
     */
    if ((pkt_src == PKT_SRC_TOR_REPL_TREE) || !pkt_src) {

        /*
         * If packet is identified as known packet, we always trap
         * it to agent with the exception of DHCP. DHCP can be flooded
         * depending on the configuration on VMI or L2 route flags
         */
        if (l4_type != L4_TYPE_UNKNOWN) {

            trap = true;

            if (l4_type == L4_TYPE_DHCP_REQUEST) {
                rt_flags = vr_bridge_route_flags(fmd->fmd_dvrf, eth->eth_smac);
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
        handled = vr_neighbor_input(pkt, fmd);
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

static int
nh_composite_mcast_l2(struct vr_packet *pkt, struct vr_nexthop *nh,
                     struct vr_forwarding_md *fmd)
{

    int i, clone_size;
    bool flood_to_vms = true;
    unsigned short drop_reason, label, pkt_vrf, pull_len;
    unsigned int tun_src, pkt_src, hashval, port_range, handled;

    struct vr_eth *eth = NULL;
    struct vr_nexthop *dir_nh;
    struct vr_packet *new_pkt;
    struct vr_vrf_stats *stats;

    stats = vr_inet_vrf_stats(fmd->fmd_dvrf, pkt->vp_cpu);
    if (stats)
        stats->vrf_l2_mcast_composites++;

    pkt_vrf = fmd->fmd_dvrf;
    drop_reason = VP_DROP_CLONED_ORIGINAL;

    if (!fmd) {
        drop_reason = VP_DROP_NO_FMD;
        goto drop;
    }

    tun_src = pkt_src = 0;
    if (nh->nh_validate_src) {
        if (nh->nh_validate_src(pkt, nh, fmd, &tun_src) == NH_SOURCE_INVALID) {
            drop_reason = VP_DROP_INVALID_MCAST_SOURCE;
            goto drop;
        }
        if (tun_src & NH_FLAG_COMPOSITE_EVPN)
            pkt_src = PKT_SRC_INGRESS_REPL_TREE;

        if (tun_src & NH_FLAG_COMPOSITE_TOR) {
            pkt_src = PKT_SRC_TOR_REPL_TREE;
            fmd->fmd_src = TOR_SOURCE;
        }

       if ((pkt->vp_if->vif_type == VIF_TYPE_PHYSICAL) &&
            ((pkt_src != PKT_SRC_INGRESS_REPL_TREE) &&
             (pkt_src != PKT_SRC_TOR_REPL_TREE))) {
           if (*(unsigned int *)pkt_data(pkt) != VR_L2_MCAST_CTRL_DATA) {
               drop_reason = VP_DROP_INVALID_PACKET;
               goto drop;
           }
           pkt_src = PKT_SRC_EDGE_REPL_TREE;
       }
    }

    if (pkt_src == PKT_SRC_EDGE_REPL_TREE) {
        eth = (struct vr_eth *)pkt_data_at_offset(pkt, pkt->vp_data +
                VR_L2_MCAST_CTRL_DATA_LEN + VR_VXLAN_HDR_LEN);
    } else {
        eth = (struct vr_eth *)pkt_data(pkt);
    }

    if (!eth) {
        drop_reason = VP_DROP_INVALID_PACKET;
        goto drop;
    }

    handled = nh_handle_mcast_control_pkt(pkt, fmd, pkt_src, &flood_to_vms);
    if (handled)
        return 0;


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
        hashval = vr_hash(pkt_data(pkt), sizeof(struct vr_eth), vr_hashrnd);
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

    label = fmd->fmd_label;
    for (i = 0; i < nh->nh_component_cnt; i++) {
        clone_size = 0;
        dir_nh = nh->nh_component_nh[i].cnh;

        /* We need to copy back the original label from Bridge lookaup
         * as previous iteration would have manipulated that
         */
        vr_forwarding_md_set_label(fmd, label, VR_LABEL_TYPE_UNKNOWN);
        fmd->fmd_dvrf = pkt_vrf;

        /* If direct nexthop is not valid, dont process it */
        if ((!dir_nh) || !(dir_nh->nh_flags & NH_FLAG_VALID) ||
                                (dir_nh->nh_type != NH_COMPOSITE))
            continue;

        if (dir_nh->nh_flags & NH_FLAG_COMPOSITE_ENCAP) {
            if (!flood_to_vms)
                continue;

            if (!(new_pkt = nh_mcast_clone(pkt, 0))) {
                drop_reason = VP_DROP_MCAST_CLONE_FAIL;
                break;
            }

            if (pkt_src == PKT_SRC_EDGE_REPL_TREE) {
                pull_len = VR_L2_MCAST_CTRL_DATA_LEN + VR_VXLAN_HDR_LEN;

                if (!pkt_pull(new_pkt, pull_len)) {
                    vr_pfree(new_pkt, VP_DROP_PULL);
                    break;
                }
            }
        } else if (dir_nh->nh_flags & NH_FLAG_COMPOSITE_FABRIC) {
            if (pkt_src == PKT_SRC_INGRESS_REPL_TREE)
                continue;

            /* Create head space for L2 Mcast header */
            if (!(new_pkt = nh_mcast_clone(pkt, VR_L2_MCAST_PKT_HEAD_SPACE))) {
                drop_reason = VP_DROP_MCAST_CLONE_FAIL;
                break;
            }
            fmd->fmd_dvrf = dir_nh->nh_vrf;

        } else if (dir_nh->nh_flags & NH_FLAG_COMPOSITE_EVPN) {

            /* We replicate only if received from VM and Ovs TOR*/
            if ((!pkt_src)|| (pkt_src == PKT_SRC_TOR_REPL_TREE)) {

                /* Create head space for Vxlan header */
                clone_size = VR_L2_MCAST_PKT_HEAD_SPACE - VR_L2_MCAST_CTRL_DATA_LEN;
                if (!(new_pkt = nh_mcast_clone(pkt, clone_size))) {
                    drop_reason = VP_DROP_MCAST_CLONE_FAIL;
                    break;
                }
                fmd->fmd_dvrf = dir_nh->nh_vrf;
            } else {
                continue;
            }

        } else if (dir_nh->nh_flags & NH_FLAG_COMPOSITE_TOR) {

            /* Create head space for Vxlan header */
            clone_size = VR_L2_MCAST_PKT_HEAD_SPACE - VR_L2_MCAST_CTRL_DATA_LEN;
            if (!(new_pkt = nh_mcast_clone(pkt, clone_size))) {
                drop_reason = VP_DROP_MCAST_CLONE_FAIL;
                break;
            }

            if (pkt_src == PKT_SRC_EDGE_REPL_TREE) {

                pull_len = VR_L2_MCAST_CTRL_DATA_LEN + VR_VXLAN_HDR_LEN;

                if (!pkt_pull(new_pkt, pull_len)) {
                    vr_pfree(new_pkt, VP_DROP_PULL);
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
    return 0;
}


static int
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

    if (!fmd) {
        drop_reason = VP_DROP_NO_FMD;
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
            break;
        }
        fmd->fmd_dvrf = dir_nh->nh_dev->vif_vrf;
        nh_output(new_pkt, dir_nh, fmd);
    }

    /* Original packet needs to be unconditionally dropped */
drop:
    vr_pfree(pkt, drop_reason);
    return 0;
}

static int
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

    if (!fmd) {
        drop_reason = VP_DROP_NO_FMD;
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
            break;
        }

        vr_forwarding_md_set_label(fmd, nh->nh_component_nh[i].cnh_label,
                VR_LABEL_TYPE_UNKNOWN);
        fmd->fmd_dvrf = dir_nh->nh_dev->vif_vrf;
        nh_output(new_pkt, dir_nh, fmd);
    }

    /* Original packet needs to be unconditionally dropped */
drop:
    vr_pfree(pkt, drop_reason);
    return 0;
}

static int
nh_composite_evpn(struct vr_packet *pkt, struct vr_nexthop *nh,
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

    if (!fmd) {
        drop_reason = VP_DROP_NO_FMD;
        goto drop;
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
            break;
        }

        vr_forwarding_md_set_label(fmd, nh->nh_component_nh[i].cnh_label,
                VR_LABEL_TYPE_UNKNOWN);
        fmd->fmd_dvrf = dir_nh->nh_dev->vif_vrf;
        nh_output(new_pkt, dir_nh, fmd);
    }

    /* Original packet needs to be unconditionally dropped */
drop:
    vr_pfree(pkt, drop_reason);
    return 0;
}

bool
vr_l2_mcast_control_data_add(struct vr_packet *pkt)
{

    unsigned int *data;

    if (pkt_head_space(pkt) < VR_L2_MCAST_CTRL_DATA_LEN) {
        pkt = vr_pexpand_head(pkt, VR_L2_MCAST_CTRL_DATA_LEN -
                                                pkt_head_space(pkt));
        if (!pkt)
            return false;
    }

    data = (unsigned int *)pkt_push(pkt, VR_L2_MCAST_CTRL_DATA_LEN);
    if (!data)
        return false;

    *data = VR_L2_MCAST_CTRL_DATA;
    return true;
}

static int
nh_composite_fabric(struct vr_packet *pkt, struct vr_nexthop *nh,
                    struct vr_forwarding_md *fmd)
{
    int i;
    struct vr_vrf_stats *stats;
    struct vr_nexthop *dir_nh;
    unsigned short drop_reason, pkt_vrf;
    struct vr_packet *new_pkt;
    unsigned int dip, sip;
    int32_t label;

    drop_reason = VP_DROP_CLONED_ORIGINAL;
    stats = vr_inet_vrf_stats(fmd->fmd_dvrf, pkt->vp_cpu);
    if (stats)
        stats->vrf_fabric_composites++;

    if (!fmd) {
        drop_reason = VP_DROP_NO_FMD;
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
            break;
        }

        /* Dont forward to same source */
        if (fmd->fmd_outer_src_ip && fmd->fmd_outer_src_ip == dip)
            continue;

        /*
         * Enough head spaces are created in the previous nexthop
         * handling. Just cow the packet with zero size to get different
         * buffer space
         */
        new_pkt = nh_mcast_clone(pkt, 0);
        if (!new_pkt) {
            drop_reason = VP_DROP_MCAST_CLONE_FAIL;
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
                vr_pfree(new_pkt, VP_DROP_INVALID_LABEL);
                break;
            }

            /*
             * Add vxlan encapsulation. The vxlan id need to be taken
             * from Bridge entry
             */
            vr_forwarding_md_set_label(fmd, label, VR_LABEL_TYPE_UNKNOWN);
            fmd->fmd_dvrf = dir_nh->nh_dev->vif_vrf;
            if (nh_vxlan_tunnel_helper(nh->nh_router, new_pkt,
                        fmd, sip, sip) == false) {
                vr_pfree(new_pkt, VP_DROP_PUSH);
                break;
            }

            if (vr_l2_mcast_control_data_add(new_pkt) == false) {
                vr_pfree(new_pkt, VP_DROP_PUSH);
                break;
            }
        }

        /* MPLS label for outer header encapsulation */
        vr_forwarding_md_set_label(fmd, nh->nh_component_nh[i].cnh_label,
                VR_LABEL_TYPE_UNKNOWN);
        fmd->fmd_dvrf = dir_nh->nh_dev->vif_vrf;
        nh_output(new_pkt, dir_nh, fmd);
    }

    /* Original packet needs to be unconditionally dropped */
drop:
    vr_pfree(pkt, drop_reason);
    return 0;
}

static int
nh_discard(struct vr_packet *pkt, struct vr_nexthop *nh,
           struct vr_forwarding_md *fmd)
{
    struct vr_vrf_stats *stats;

    stats = vr_inet_vrf_stats(fmd->fmd_dvrf, pkt->vp_cpu);
    if (stats)
        stats->vrf_discards++;

    vr_pfree(pkt, VP_DROP_DISCARD);
    return 0;
}

static int
nh_generate_sip(struct vr_nexthop *nh, struct vr_packet *pkt)
{
    struct vr_ip *iph;

    iph = (struct vr_ip *)pkt_network_header(pkt);
    if (pkt->vp_type == VP_TYPE_IP) {

        /*
         * If the packet is from fabric, it must be destined to a VM on
         * this compute, so lets use dest ip
         */
        if (pkt->vp_if->vif_type == VIF_TYPE_PHYSICAL)
            return iph->ip_daddr;

        return iph->ip_saddr;
    }

    return 0;
}

static int
nh_udp_tunnel(struct vr_packet *pkt, struct vr_nexthop *nh,
              struct vr_forwarding_md *fmd)
{
    unsigned int head_space;
    uint32_t sip = 0;

    struct vr_packet *tmp;
    struct vr_ip *ip;
    struct vr_ip6 *ip6;
    struct vr_udp *udp;
    struct vr_vrf_stats *stats;
    struct vr_forwarding_class_qos *qos;

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

    if (nh->nh_family == AF_INET) {
        if (nh->nh_flags & NH_FLAG_TUNNEL_SIP_COPY) {
            sip = nh_generate_sip(nh, pkt);
        }

        if (!sip) {
            sip = nh->nh_udp_tun_sip;
        }

        qos = vr_qos_get_forwarding_class(nh->nh_router, pkt, fmd);
        if (nh_udp_tunnel_helper(pkt, nh->nh_udp_tun_sport,
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

    } else if (nh->nh_family == AF_INET6) {
        if (nh_udp_tunnel6_helper(pkt, nh) == false) {
            goto send_fail;
        }

        ip6 = (struct vr_ip6 *)(pkt_data(pkt));
        udp = (struct vr_udp *)((char *)ip6 + sizeof(struct vr_ip6));
        udp->udp_csum = vr_ip6_partial_csum(ip6);
        pkt->vp_flags |= VP_FLAG_CSUM_PARTIAL;
    }


    pkt_set_network_header(pkt, pkt->vp_data);

    /*
     * Incase of mirroring set the inner network header to the newly added
     * header so that this is fragmented and checksummed
     */
    pkt_set_inner_network_header(pkt, pkt->vp_data);

    /* for now let the tunnel type be IP regardless of ip or ip6 */
    if (pkt->vp_type == VP_TYPE_IP6)
        pkt->vp_type = VP_TYPE_IP6OIP;
    else if (pkt->vp_type == VP_TYPE_IP)
        pkt->vp_type = VP_TYPE_IPOIP;
    else
        pkt->vp_type = VP_TYPE_IP;


    stats = vr_inet_vrf_stats(fmd->fmd_dvrf, pkt->vp_cpu);
    if (stats)
        stats->vrf_udp_tunnels++;

    vr_forward(vrouter_get(nh->nh_rid), pkt, fmd);

    return 0;

send_fail:
    vr_pfree(pkt, VP_DROP_PUSH);
    return 0;
}

/*
 * nh_vxlan_tunnel - tunnel packet with VXLAN header
 */
static int
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
        goto send_fail;
    }

    if (fmd->fmd_label < 0) {
        reason = VP_DROP_INVALID_LABEL;
        goto send_fail;
    }

    stats = vr_inet_vrf_stats(fmd->fmd_dvrf, pkt->vp_cpu);
    if (stats)
        stats->vrf_udp_mpls_tunnels++;

    if (vr_perfs)
        pkt->vp_flags |= VP_FLAG_GSO;

    overhead_len = VR_VXLAN_HDR_LEN;
    if ((pkt->vp_type == VP_TYPE_IP) || (pkt->vp_type == VP_TYPE_IP6)) {
        if (vr_has_to_fragment(nh->nh_dev, pkt, overhead_len) &&
                vr_ip_dont_fragment_set(pkt)) {
            if (pkt->vp_flags & VP_FLAG_MULTICAST) {
                reason = VP_DROP_MCAST_DF_BIT;
                goto send_fail;
            }

            trap_arg.df_mtu = vif_get_mtu(nh->nh_dev) -
                (overhead_len + pkt_get_network_header_off(pkt) - pkt->vp_data);
            trap_arg.df_flow_index = fmd->fmd_flow_index;
            return vr_trap(pkt, fmd->fmd_dvrf, AGENT_TRAP_HANDLE_DF, (void *)&trap_arg);
        }
    }

    if (nh_vxlan_tunnel_helper(nh->nh_router, pkt, fmd, nh->nh_udp_tun_sip,
                nh->nh_udp_tun_dip) == false)
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

    if (pkt_head_space(pkt) < nh->nh_udp_tun_encap_len) {
        tmp_pkt = vr_pexpand_head(pkt, nh->nh_udp_tun_encap_len - pkt_head_space(pkt));
        if (!tmp_pkt) {
            goto send_fail;
        }
        pkt = tmp_pkt;
    }

    /* slap l2 header */
    vif = nh->nh_dev;
    if (!vif->vif_set_rewrite(vif, pkt, fmd,
                nh->nh_data, nh->nh_udp_tun_encap_len)) {
        goto send_fail;
    }

    vif->vif_tx(vif, pkt, fmd);

    return 0;

send_fail:
    vr_pfree(pkt, reason);
    return 0;

}

static int
nh_mpls_udp_tunnel_validate_src(struct vr_packet *pkt, struct vr_nexthop *nh,
                                struct vr_forwarding_md *fmd, void *ret_data)
{
    if (fmd->fmd_outer_src_ip == nh->nh_udp_tun_dip)
        return NH_SOURCE_VALID;

    return NH_SOURCE_INVALID;
}


/*
 * nh_mpls_udp_tunnel - tunnel packet with MPLS label in UDP.
 */
static int
nh_mpls_udp_tunnel(struct vr_packet *pkt, struct vr_nexthop *nh,
                   struct vr_forwarding_md *fmd)
{
    unsigned int tun_sip, tun_dip, overhead_len, mudp_head_space;
    uint16_t tun_encap_len, udp_src_port = VR_MPLS_OVER_UDP_SRC_PORT;
    unsigned short reason = VP_DROP_PUSH;

    unsigned char *tun_encap;
    struct vr_forwarding_class_qos *qos;
    struct vr_interface *vif;
    struct vr_vrf_stats *stats;
    struct vr_packet *tmp_pkt;
    struct vr_df_trap_arg trap_arg;

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
    }

    stats = vr_inet_vrf_stats(fmd->fmd_dvrf, pkt->vp_cpu);
    if (stats)
        stats->vrf_udp_mpls_tunnels++;

    if (!fmd || fmd->fmd_label < 0)
        return vr_forward(nh->nh_router, pkt, fmd);

    vr_forwarding_md_update_label_type(fmd, VR_LABEL_TYPE_MPLS);

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
            goto send_fail;
        }
    }

    /* Calculate the head space for mpls,udp ip and eth */
    mudp_head_space = VR_MPLS_HDR_LEN + sizeof(struct vr_ip) + sizeof(struct vr_udp);

    if ((pkt->vp_type == VP_TYPE_IP) || (pkt->vp_type == VP_TYPE_IP6)) {
        overhead_len = mudp_head_space;
        if (vr_has_to_fragment(nh->nh_dev, pkt, overhead_len) &&
                vr_ip_dont_fragment_set(pkt)) {
            if (pkt->vp_flags & VP_FLAG_MULTICAST) {
                reason = VP_DROP_MCAST_DF_BIT;
                goto send_fail;
            }
            trap_arg.df_mtu = vif_get_mtu(nh->nh_dev) -
                (overhead_len + pkt_get_network_header_off(pkt) - pkt->vp_data);
            trap_arg.df_flow_index = fmd->fmd_flow_index;
            return vr_trap(pkt, fmd->fmd_dvrf, AGENT_TRAP_HANDLE_DF, (void *)&trap_arg);
        }
    }

    mudp_head_space += tun_encap_len;

    if (pkt_head_space(pkt) < mudp_head_space) {
        tmp_pkt = vr_pexpand_head(pkt, mudp_head_space - pkt_head_space(pkt));
        if (!tmp_pkt)
            goto send_fail;

        pkt = tmp_pkt;
    }

    qos = vr_qos_get_forwarding_class(nh->nh_router, pkt, fmd);
    if (nh_push_mpls_header(pkt, fmd->fmd_label, qos) < 0)
        goto send_fail;

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
    tun_encap = vif->vif_set_rewrite(vif, pkt, fmd,
            nh->nh_data, tun_encap_len);
    if (!tun_encap) {
        goto send_fail;
    }

    vif->vif_tx(vif, pkt, fmd);

    return 0;

send_fail:
    vr_pfree(pkt, reason);
    return 0;

}

static int
nh_gre_tunnel_validate_src(struct vr_packet *pkt, struct vr_nexthop *nh,
                           struct vr_forwarding_md *fmd, void *ret_data)
{
    if (fmd->fmd_outer_src_ip == nh->nh_gre_tun_dip)
        return NH_SOURCE_VALID;

    return NH_SOURCE_INVALID;
}

static int
nh_gre_tunnel(struct vr_packet *pkt, struct vr_nexthop *nh,
              struct vr_forwarding_md *fmd)
{
    int overhead_len, gre_head_space;
    unsigned short drop_reason = VP_DROP_INVALID_NH;
    unsigned int id;

    unsigned char *tun_encap;
    struct vr_forwarding_class_qos *qos;
    struct vr_gre *gre_hdr;
    struct vr_ip *ip;
    struct vr_interface *vif;
    struct vr_vrf_stats *stats;
    struct vr_packet *tmp_pkt;
    struct vr_df_trap_arg trap_arg;

    if (vr_mudp && vr_perfs) {
        return nh_mpls_udp_tunnel(pkt, nh, fmd);
    }

    stats = vr_inet_vrf_stats(fmd->fmd_dvrf, pkt->vp_cpu);
    if (stats)
        stats->vrf_gre_mpls_tunnels++;

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
    if (!fmd || fmd->fmd_label < 0)
        return vr_forward(nh->nh_router, pkt, fmd);

    vr_forwarding_md_update_label_type(fmd, VR_LABEL_TYPE_MPLS);

    if (vr_perfs)
        pkt->vp_flags |= VP_FLAG_GSO;

    if (pkt->vp_type == VP_TYPE_IP) {
        ip = (struct vr_ip *)pkt_network_header(pkt);
        id = ip->ip_id;
    } else {
        id = htons(vr_generate_unique_ip_id());
    }


    gre_head_space = VR_MPLS_HDR_LEN + sizeof(struct vr_ip) +
        sizeof(struct vr_gre);


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
                goto send_fail;
            }

            trap_arg.df_mtu = vif_get_mtu(nh->nh_dev) -
                (overhead_len + pkt_get_network_header_off(pkt) - pkt->vp_data);
            trap_arg.df_flow_index = fmd->fmd_flow_index;
            return vr_trap(pkt, fmd->fmd_dvrf, AGENT_TRAP_HANDLE_DF, (void *)&trap_arg);
        }
    }

    gre_head_space += nh->nh_gre_tun_encap_len;

    if (pkt_head_space(pkt) < gre_head_space) {
        tmp_pkt = vr_pexpand_head(pkt, gre_head_space - pkt_head_space(pkt));
        if (!tmp_pkt) {
            drop_reason = VP_DROP_HEAD_ALLOC_FAIL;
            goto send_fail;
        }
        pkt = tmp_pkt;
    }

    qos = vr_qos_get_forwarding_class(nh->nh_router, pkt, fmd);
    if (nh_push_mpls_header(pkt, fmd->fmd_label, qos) < 0)
        goto send_fail;

    gre_hdr = (struct vr_gre *)pkt_push(pkt, sizeof(struct vr_gre));
    if (!gre_hdr) {
        drop_reason = VP_DROP_PUSH;
        goto send_fail;
    }

    gre_hdr->gre_flags = 0;
    gre_hdr->gre_proto = VR_GRE_PROTO_MPLS_NO;

    ip = (struct vr_ip *)pkt_push(pkt, sizeof(struct vr_ip));
    if (!ip) {
        drop_reason = VP_DROP_PUSH;
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
        pkt->vp_queue = qos->vfcq_queue_id + 1;
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
    tun_encap = vif->vif_set_rewrite(vif, pkt, fmd,
            nh->nh_data, nh->nh_gre_tun_encap_len);
    if (!tun_encap) {
        drop_reason = VP_DROP_PUSH;
        goto send_fail;
    }
    vif->vif_tx(vif, pkt, fmd);
    return 0;

send_fail:
    vr_pfree(pkt, drop_reason);
    return 0;
}


int
nh_output(struct vr_packet *pkt, struct vr_nexthop *nh,
          struct vr_forwarding_md *fmd)
{
    bool need_flow_lookup = false;

    if (!pkt->vp_ttl) {
        return vr_trap(pkt, fmd->fmd_dvrf, AGENT_TRAP_ZERO_TTL, NULL);
    }

    pkt->vp_nh = nh;

    /* If nexthop does not have valid data, drop it */
    if (!(nh->nh_flags & NH_FLAG_VALID)) {
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
                     vr_pfree(pkt, VP_DROP_INVALID_NH);
                     return 0;
                 }

                 if (nh != pkt->vp_nh) {
                     return nh_output(pkt, pkt->vp_nh, fmd);
                 }
             }
        }
    }

    return nh->nh_reach_nh(pkt, nh, fmd);
}

static int
nh_encap_l2(struct vr_packet *pkt, struct vr_nexthop *nh,
            struct vr_forwarding_md *fmd)
{
    struct vr_interface *vif;
    struct vr_vrf_stats *stats;
    struct vr_forwarding_class_qos *qos;

    /* No GRO for multicast and user packets */
    if ((pkt->vp_flags & VP_FLAG_MULTICAST) ||
            (fmd->fmd_vlan != VLAN_ID_INVALID))
        pkt->vp_flags &= ~VP_FLAG_GRO;

    vif = nh->nh_dev;
    if (!vif) {
        vr_pfree(pkt, VP_DROP_INVALID_IF);
        return 0;
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
                pkt->vp_queue = qos->vfcq_queue_id + 1;
                pkt->vp_priority = qos->vfcq_dotonep_qos;
            }
        }
    }

    if (pkt->vp_flags & VP_FLAG_GRO) {
        if (vif_is_virtual(vif) && (!(vif->vif_flags &
                        VIF_FLAG_MIRROR_TX))) {
            if (vr_gro_input(pkt, nh)) {
                if (stats)
                    stats->vrf_gros++;
                return 0;
            }
        }
    }

    if (stats)
        stats->vrf_l2_encaps++;

    vif->vif_tx(vif, pkt, fmd);

    return 0;
}

static int
nh_encap_l3_validate_src(struct vr_packet *pkt, struct vr_nexthop *nh,
                         struct vr_forwarding_md *fmd, void *ret_data)
{
    if (pkt->vp_if == nh->nh_dev)
        return NH_SOURCE_VALID;

    return NH_SOURCE_INVALID;
}

static int
nh_encap_l3(struct vr_packet *pkt, struct vr_nexthop *nh,
                    struct vr_forwarding_md *fmd)
{
    unsigned short *proto_p;

    struct vr_ip *ip;
    struct vr_interface *vif;
    struct vr_vrf_stats *stats;
    struct vr_forwarding_class_qos *qos = NULL;

    stats = vr_inet_vrf_stats(fmd->fmd_dvrf, pkt->vp_cpu);

    vif = nh->nh_dev;
    if (!vif) {
        vr_pfree(pkt, VP_DROP_INVALID_IF);
        return 0;
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
        vr_pfree(pkt, VP_DROP_INVALID_PROTOCOL);
        return 0;
    }

    if (vr_pkt_is_diag(pkt)) {
        pkt->vp_flags &= ~VP_FLAG_GRO;
        if (stats)
            stats->vrf_diags++;
    } else {
        if (stats) {
            if ((pkt->vp_flags & VP_FLAG_GRO) &&
                    vif_is_virtual(vif)) {
                stats->vrf_gros++;
            } else {
                stats->vrf_encaps++;
            }
        }
    }

    if ((pkt->vp_flags & VP_FLAG_GRO) && vif_is_virtual(vif) &&
            (!(vif->vif_flags & VIF_FLAG_MIRROR_TX))) {
        if (vr_gro_input(pkt, nh))
            return 0;
    }

    if (!vif->vif_set_rewrite(vif, pkt, fmd, nh->nh_data, nh->nh_encap_len)) {
        vr_pfree(pkt, VP_DROP_REWRITE_FAIL);
        return 0;
    }

    if (nh->nh_encap_len) {
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
        return vr_trap(pkt, fmd->fmd_dvrf, AGENT_TRAP_DIAG, &vif->vif_idx);
    }

    vif->vif_tx(vif, pkt, fmd);

    return 0;
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
    struct vr_interface *vif, *old_vif;
    vif = vrouter_get_interface(nh->nh_rid, req->nhr_encap_oif_id);
    if (!vif)
        return -ENODEV;
    /*
     * We need to delete the reference to old_vif only after new vif is
     * added to NH
     */
    old_vif = nh->nh_dev;
    nh->nh_dev = vif;

    nh->nh_reach_nh = nh_l3_rcv;

    if (old_vif)
        vrouter_put_interface(old_vif);
    return 0;
}

static int
nh_vrf_translate_add(struct vr_nexthop *nh, vr_nexthop_req *req)
{
    nh->nh_reach_nh = nh_vrf_translate;
    return 0;
}

static int
nh_composite_mcast_validate(struct vr_nexthop *nh, vr_nexthop_req *req)
{
    unsigned int i;
    struct vr_nexthop *tmp_nh;

    /* Fabric and EVPN nexthop*/
    if (req->nhr_flags & (NH_FLAG_COMPOSITE_FABRIC |
                NH_FLAG_COMPOSITE_EVPN | NH_FLAG_COMPOSITE_TOR)) {
        for (i = 0; i < req->nhr_nh_list_size; i++) {
            tmp_nh = nh->nh_component_nh[i].cnh;
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

        bool l2_seen = false, l3_seen = false;
        for (i = 0; i < req->nhr_nh_list_size; i++) {
            tmp_nh = nh->nh_component_nh[i].cnh;
            if (!tmp_nh)
                continue;

            if (tmp_nh->nh_type != NH_ENCAP)
                return -1;

            if (tmp_nh->nh_flags & NH_FLAG_COMPOSITE_L2) {
                if (tmp_nh->nh_flags & NH_FLAG_MCAST)
                    return -1;
                if (l3_seen)
                    return -1;
                l2_seen = true;
            } else {
                if (l2_seen)
                    return -1;
                l3_seen = true;
            }
        }
    }

    /* L2 multicast */
    if (req->nhr_flags & NH_FLAG_COMPOSITE_L2) {

        if (!(req->nhr_flags & NH_FLAG_MCAST))
            return -1;

        for (i = 0; i < req->nhr_nh_list_size; i++) {
            tmp_nh = nh->nh_component_nh[i].cnh;

            /* NULL component NH is valid */
            if (!tmp_nh)
                continue;

            /* IT can contain only Fabric and L2ENCAP composite */
            if (tmp_nh->nh_type != NH_COMPOSITE)
                return -1;

            if (!(tmp_nh->nh_flags &
                   (NH_FLAG_COMPOSITE_FABRIC | NH_FLAG_COMPOSITE_EVPN |
                    NH_FLAG_COMPOSITE_TOR | NH_FLAG_COMPOSITE_ENCAP)))
                return -1;
        }
    }

    return 0;
}

static int
nh_composite_add(struct vr_nexthop *nh, vr_nexthop_req *req)
{
    unsigned int i, j = 0, active = 0;
    struct vr_nexthop *tmp_nh;

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
        }
    }

    if (req->nhr_nh_list_size != req->nhr_label_list_size)
        return -EINVAL;

    /* Nh list of size 0 is valid */
    if (req->nhr_nh_list_size == 0)
        return 0;

    nh->nh_component_nh = vr_zalloc(req->nhr_nh_list_size *
            sizeof(struct vr_component_nh), VR_NEXTHOP_COMPONENT_OBJECT);
    if (!nh->nh_component_nh) {
        return -ENOMEM;
    }
    for (i = 0; i < req->nhr_nh_list_size; i++) {
        nh->nh_component_nh[i].cnh = vrouter_get_nexthop(req->nhr_rid,
                                                    req->nhr_nh_list[i]);
        nh->nh_component_nh[i].cnh_label = req->nhr_label_list[i];
        if (nh->nh_component_nh[i].cnh)
            active++;

        if (req->nhr_flags & NH_FLAG_COMPOSITE_ECMP) {
            nh->nh_component_nh[i].cnh_ecmp_index = i;
        } else {
            nh->nh_component_nh[i].cnh_ecmp_index = -1;
        }
    }

    nh->nh_component_cnt = req->nhr_nh_list_size;

    if (nh_composite_mcast_validate(nh, req))
        goto error;

    /* This needs to be the last */
    if (req->nhr_flags & NH_FLAG_COMPOSITE_L2) {
        nh->nh_reach_nh = nh_composite_mcast_l2;
        nh->nh_validate_src = nh_composite_mcast_validate_src;
    } else if (req->nhr_flags & NH_FLAG_COMPOSITE_ECMP) {
        nh->nh_reach_nh = nh_composite_ecmp;
        nh->nh_validate_src = nh_composite_ecmp_validate_src;
        if (active) {
            nh->nh_component_ecmp = vr_zalloc(active *
                    sizeof(struct vr_component_nh), VR_NEXTHOP_COMPONENT_OBJECT);
            if (!nh->nh_component_ecmp) {
                goto error;
            }

            for (i = 0; i < req->nhr_nh_list_size; i++) {
                if (nh->nh_component_nh[i].cnh) {
                    memcpy(&nh->nh_component_ecmp[j++], &nh->nh_component_nh[i],
                            sizeof(struct vr_component_nh));
                    /* this happens implicitly */
                    /* nh->nh_component_ecmp[j++].cnh_ecmp_index = i */
                }
            }
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

    return 0;

error:
    if (nh->nh_component_nh) {
        for (i = 0; i < req->nhr_nh_list_size; i++) {
             tmp_nh = nh->nh_component_nh[i].cnh;
             if (tmp_nh)
                vrouter_put_nexthop(tmp_nh);
        }

        vr_free(nh->nh_component_nh, VR_NEXTHOP_COMPONENT_OBJECT);
        if (nh->nh_component_ecmp) {
            vr_free(nh->nh_component_ecmp, VR_NEXTHOP_COMPONENT_OBJECT);
            nh->nh_component_ecmp = NULL;
        }

        nh->nh_component_nh = NULL;
        nh->nh_component_cnt = 0;
    }
    return -EINVAL;
}

static int
nh_tunnel_add(struct vr_nexthop *nh, vr_nexthop_req *req)
{
    struct vr_interface *vif, *old_vif;

    if (req->nhr_family == AF_INET6) {
        if (!req->nhr_tun_sip6 || !req->nhr_tun_dip6)
            return -EINVAL;
    } else {
        if (!req->nhr_tun_sip || !req->nhr_tun_dip)
            return -EINVAL;
    }

    old_vif = nh->nh_dev;
    vif = vrouter_get_interface(nh->nh_rid, req->nhr_encap_oif_id);
    if (nh->nh_flags & NH_FLAG_TUNNEL_GRE) {
        if (!vif)
            return -ENODEV;
        nh->nh_gre_tun_sip = req->nhr_tun_sip;
        nh->nh_gre_tun_dip = req->nhr_tun_dip;
        nh->nh_gre_tun_encap_len = req->nhr_encap_size;
        nh->nh_validate_src = nh_gre_tunnel_validate_src;
        nh->nh_dev = vif;
        nh->nh_reach_nh = nh_gre_tunnel;
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
                if (!nh->nh_udp_tun6_sip)
                    return -ENOMEM;
            }
            memcpy(nh->nh_udp_tun6_sip, req->nhr_tun_sip6, VR_IP6_ADDRESS_LEN);

            if (!nh->nh_udp_tun6_dip) {
                nh->nh_udp_tun6_dip = vr_malloc(VR_IP6_ADDRESS_LEN,
                        VR_NETWORK_ADDRESS_OBJECT);
                if (!nh->nh_udp_tun6_dip)
                    return -ENOMEM;
            }
            memcpy(nh->nh_udp_tun6_dip, req->nhr_tun_dip6, VR_IP6_ADDRESS_LEN);

            nh->nh_udp_tun6_sport = req->nhr_tun_sport;
            nh->nh_udp_tun6_dport = req->nhr_tun_dport;
            nh->nh_udp_tun6_encap_len = req->nhr_encap_size;
        } else {
            return -EINVAL;
        }

        nh->nh_reach_nh = nh_udp_tunnel;
        /* VIF should be null, but lets clean if one is found */
        if (vif)
            vrouter_put_interface(vif);
    } else if (nh->nh_flags & NH_FLAG_TUNNEL_UDP_MPLS) {
        if (!vif)
            return -ENODEV;
        nh->nh_udp_tun_sip = req->nhr_tun_sip;
        nh->nh_udp_tun_dip = req->nhr_tun_dip;
        nh->nh_udp_tun_encap_len = req->nhr_encap_size;
        nh->nh_validate_src = nh_mpls_udp_tunnel_validate_src;
        nh->nh_dev = vif;
        nh->nh_reach_nh = nh_mpls_udp_tunnel;
    } else if (nh->nh_flags & NH_FLAG_TUNNEL_VXLAN) {
        if (!vif)
            return -ENODEV;
        nh->nh_udp_tun_sip = req->nhr_tun_sip;
        nh->nh_udp_tun_dip = req->nhr_tun_dip;
        nh->nh_udp_tun_encap_len = req->nhr_encap_size;
        nh->nh_dev = vif;
        nh->nh_reach_nh = nh_vxlan_tunnel;
    } else {
        /* Reference to VIf should be cleaned */
        if (vif)
            vrouter_put_interface(vif);
        return -EINVAL;
    }

    memcpy(nh->nh_data, req->nhr_encap, req->nhr_encap_size);
    if (old_vif)
        vrouter_put_interface(old_vif);

    return 0;
}

static int
nh_encap_add(struct vr_nexthop *nh, vr_nexthop_req *req)
{
    struct vr_interface *vif, *old_vif;;

    vif = vrouter_get_interface(nh->nh_rid, req->nhr_encap_oif_id);
    if (!vif)
        return -ENODEV;

    /*
     * We need to delete the reference to old_vif only after new vif is
     * added to NH
     */
    old_vif = nh->nh_dev;
    if (req->nhr_flags & NH_FLAG_ENCAP_L2) {
        if (req->nhr_encap_size < VR_ETHER_ALEN) {
            vrouter_put_interface(vif);
            return -EINVAL;
        }
        nh->nh_reach_nh = nh_encap_l2;
    } else {
        nh->nh_reach_nh = nh_encap_l3;
        nh->nh_validate_src = nh_encap_l3_validate_src;
    }

    nh->nh_dev = vif;
    nh->nh_encap_family = req->nhr_encap_family;
    nh->nh_encap_len = req->nhr_encap_size;
    if (nh->nh_encap_len && nh->nh_data)
        memcpy(nh->nh_data, req->nhr_encap, nh->nh_encap_len);


    if (old_vif)
        vrouter_put_interface(old_vif);

    return 0;
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

    return true;
}


int
vr_nexthop_add(vr_nexthop_req *req)
{
    int ret = 0, len = 0;
    struct vr_nexthop *nh;
    struct vrouter *router = vrouter_get(req->nhr_rid);
    bool invalid_to_valid = false;

    if (!vr_nexthop_valid_request(req) && (ret = -EINVAL))
        goto generate_resp;

    nh = __vrouter_get_nexthop(router, req->nhr_id);
    if (!nh) {
        ret = vr_nexthop_size(req);
        if (ret < 0)
            goto generate_resp;

        len = ret;
        nh = vr_zalloc(len, VR_NEXTHOP_OBJECT);
        if (!nh) {
            ret = -ENOMEM;
            goto generate_resp;
        }

        nh->nh_data_size = len - sizeof(struct vr_nexthop);
    } else {
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

        if (ret) {
            if (nh->nh_destructor)
                nh->nh_destructor(nh);

            goto generate_resp;
        }
    }

    /* Mark he nexthop valid after whole nexthop is cooked incase of
     * invalid to valid transition
     */
    if (invalid_to_valid)
        nh->nh_flags |= NH_FLAG_VALID;

    ret = vrouter_add_nexthop(nh);
    if (ret)
        nh->nh_destructor(nh);

generate_resp:
    ret = vr_send_response(ret);

    return ret;
}

unsigned int
vr_nexthop_req_get_size(void *req_p)
{
    vr_nexthop_req *req = (vr_nexthop_req *)req_p;

    if (req->nhr_type == NH_COMPOSITE)
        return (4 * sizeof(*req) + (req->nhr_nh_list_size * 4));
    else if ((req->nhr_type == NH_TUNNEL) &&
            (req->nhr_flags & NH_FLAG_TUNNEL_UDP) &&
            (req->nhr_family == AF_INET6)) {
        return (4 * sizeof(*req) + (VR_IP6_ADDRESS_LEN * 2 * 4));
    }

    return 4 * sizeof(*req);
}

/* we expect the caller to bzero req, before sending it here */
static int
vr_nexthop_make_req(vr_nexthop_req *req, struct vr_nexthop *nh)
{
    unsigned int i;
    unsigned char *encap = NULL;

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

        if (nh->nh_component_cnt) {
            req->nhr_nh_list =
                vr_zalloc(req->nhr_nh_list_size * sizeof(unsigned int),
                        VR_NEXTHOP_REQ_LIST_OBJECT);
            if (!req->nhr_nh_list)
                return -ENOMEM;

            req->nhr_label_list_size = req->nhr_nh_list_size;
            req->nhr_label_list =
                vr_zalloc(req->nhr_nh_list_size * sizeof(unsigned int),
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
        req->nhr_encap_family = nh->nh_encap_family;
        if (nh->nh_flags & NH_FLAG_TUNNEL_GRE) {
            req->nhr_tun_sip = nh->nh_gre_tun_sip;
            req->nhr_tun_dip = nh->nh_gre_tun_dip;
            req->nhr_encap_size = nh->nh_gre_tun_encap_len;
            if (req->nhr_encap_size)
                encap = nh->nh_data;
            if (nh->nh_dev)
                req->nhr_encap_oif_id = nh->nh_dev->vif_idx;
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
        } else if (nh->nh_flags & NH_FLAG_TUNNEL_VXLAN) {
            req->nhr_tun_sip = nh->nh_udp_tun_sip;
            req->nhr_tun_dip = nh->nh_udp_tun_dip;
            req->nhr_encap_size = nh->nh_udp_tun_encap_len;
            if (req->nhr_encap_size)
                encap = nh->nh_data;
            if (nh->nh_dev)
                req->nhr_encap_oif_id = nh->nh_dev->vif_idx;
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

generate_response:
    vr_message_response(VR_NEXTHOP_OBJECT_ID, ret < 0 ? NULL : resp, ret);
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
            if (ret || ((ret = vr_message_dump_object(dumper,
                                VR_NEXTHOP_OBJECT_ID, resp)) <= 0)) {
                vr_nexthop_req_destroy(resp);
                if (ret <= 0)
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

    case SANDESH_OP_DELETE:
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
