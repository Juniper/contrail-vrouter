/*
 * vr_nexthop.c -- data path nexthop management
 *
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#include <vr_os.h>
#include <vr_types.h>
#include <vr_packet.h>
#include <vr_nexthop.h>
#include <vr_vxlan.h>
#include "vr_message.h"
#include "vr_sandesh.h"
#include "vr_bridge.h"
#include "vr_datapath.h"
#include "vr_route.h"
#include "vr_hash.h"

extern unsigned int vr_forward(struct vrouter *, unsigned short,
        struct vr_packet *, struct vr_forwarding_md *);
extern bool vr_has_to_fragment(struct vr_interface *, struct vr_packet *,
        unsigned int);
extern struct vr_vrf_stats *(*vr_inet_vrf_stats)(unsigned short, unsigned int);
extern struct vr_nexthop * vr_inet_src_lookup(unsigned short ,
                                struct vr_ip *, struct vr_packet *);


struct vr_nexthop *ip4_default_nh;
struct vr_nexthop *ip6_default_nh;
extern struct vr_nexthop *(*vr_inet_route_lookup)(unsigned int,
                        struct vr_route_req *, struct vr_packet *);


struct vr_nexthop *
__vrouter_get_nexthop(struct vrouter *router, unsigned int index)
{
    if (!router || index >= router->vr_max_nexthops)
        return NULL;

    return router->vr_nexthops[index];
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

void
vrouter_put_nexthop(struct vr_nexthop *nh)
{
    int i;

    /* This function might get invoked with zero ref_cnt */
    if (nh->nh_users) {
        nh->nh_users--;
    }

    if (!nh->nh_users ) {

        if (!vr_not_ready)
            vr_delay_op();

        /* If composite de-ref the internal nexthops */
        if (nh->nh_type == NH_COMPOSITE) {
            for (i = 0; i < nh->nh_component_cnt; i++) {
                if (nh->nh_component_nh[i].cnh)
                    vrouter_put_nexthop(nh->nh_component_nh[i].cnh);
            }

            vr_free(nh->nh_component_nh);
        }
        if (nh->nh_dev) {
            vrouter_put_interface(nh->nh_dev);
        }
        vr_free(nh);
    }

    return;
}

static int
vrouter_add_nexthop(struct vr_nexthop *nh)
{
    struct vrouter *router = vrouter_get(nh->nh_rid);

    if (!router || nh->nh_id > router->vr_max_nexthops)
        return -EINVAL;

    /*
     * NH change just copies the field
     * over to nexthop, incase of change
     * just return
     */  
    if (router->vr_nexthops[nh->nh_id])
        return 0;
 
    nh->nh_users++;
    router->vr_nexthops[nh->nh_id] = nh;
    return 0;
}

static void
nh_del(struct vr_nexthop *nh)
{
    struct vrouter *router = vrouter_get(nh->nh_rid);
    
    if (!router || nh->nh_id > router->vr_max_nexthops)
        return; 

    if (router->vr_nexthops[nh->nh_id]) {
        router->vr_nexthops[nh->nh_id] = NULL;
    }
    vrouter_put_nexthop(nh);

    return;
}

static int
nh_resolve(unsigned short vrf, struct vr_packet *pkt,
        struct vr_nexthop *nh, struct vr_forwarding_md *fmd)
{
    struct vr_vrf_stats *stats;
    struct vr_packet *pkt_clone;

    stats = vr_inet_vrf_stats(vrf, pkt->vp_cpu);
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
            vif_xconnect(pkt->vp_if, pkt_clone);
        }
    }

    /* will trap the packet to agent to create a route */
    vr_trap(pkt, vrf, AGENT_TRAP_RESOLVE, NULL);
    return 0;
}

static int
nh_vrf_translate(unsigned short vrf, struct vr_packet *pkt,
        struct vr_nexthop *nh, struct vr_forwarding_md *fmd)
{
    if (!vr_pkt_is_l2(pkt))
        return vr_forward(nh->nh_router, nh->nh_vrf, pkt, fmd);

    return vr_bridge_input(nh->nh_router, nh->nh_vrf, pkt, fmd);
}

static int
nh_rcv(unsigned short vrf, struct vr_packet *pkt,
        struct vr_nexthop *nh, struct vr_forwarding_md *fmd)
{
    struct vr_vrf_stats *stats;

    stats = vr_inet_vrf_stats(vrf, pkt->vp_cpu);
    if (stats)
        stats->vrf_receives++;

    if (nh->nh_family == AF_INET)
        return vr_ip_rcv(nh->nh_router, pkt, fmd);
    else
        vr_pfree(pkt, VP_DROP_INVALID_PROTOCOL);

    return 0;
}


static int
nh_push_mpls_header(struct vr_packet *pkt, unsigned int label)
{
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

    *lbl = htonl((label << VR_MPLS_LABEL_SHIFT) | VR_MPLS_STACK_BIT | ttl);

    return 0;
}

/*
 * nh_udp_tunnel_helper - helper function to use for UDP tunneling. Used
 * by mirroring and MPLS over UDP. Returns true on success, false otherwise.
 */
static bool
nh_udp_tunnel_helper(struct vr_packet *pkt, unsigned short sport,
                     unsigned short dport, unsigned int sip, 
                     unsigned int dip) 
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
    ip->ip_tos = 0;
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
nh_vxlan_tunnel_helper(unsigned short vrf, struct vr_packet *pkt, 
                       struct vr_forwarding_md *fmd, unsigned int sip,
                       unsigned int dip)
{
    unsigned short udp_src_port = VR_VXLAN_UDP_SRC_PORT;
    struct vr_vxlan *vxlanh;
    struct vr_packet *tmp_pkt;

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
     * The UDP source port is a hash of the inner headers. For IPV6
     * the standard port is used till flow processing is done
     */
    if ((!fmd->fmd_udp_src_port) && (pkt->vp_type != VP_TYPE_IP6) &&
            vr_get_udp_src_port)  {
        udp_src_port = vr_get_udp_src_port(pkt, fmd, vrf);
        if (udp_src_port == 0) {
         return false;
        }
    }

    /* Add the vxlan header */
    vxlanh = (struct vr_vxlan *)pkt_push(pkt, sizeof(struct vr_vxlan));
    vxlanh->vxlan_vnid = htonl(fmd->fmd_label << VR_VXLAN_VNID_SHIFT);
    vxlanh->vxlan_flags = htonl(VR_VXLAN_IBIT);

    return nh_udp_tunnel_helper(pkt, htons(udp_src_port), 
                             htons(VR_VXLAN_UDP_DST_PORT), sip, dip);
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
nh_composite_ecmp_validate_src(unsigned short vrf, struct vr_packet *pkt,
        struct vr_nexthop *nh, struct vr_forwarding_md *fmd, void *ret_data)
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
    if (!cnh ||
            (NH_SOURCE_INVALID == cnh->nh_validate_src(vrf, pkt, cnh, fmd, NULL))) {
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
            if ((NH_SOURCE_VALID == cnh->nh_validate_src(vrf, pkt, cnh, fmd, NULL)))
                return NH_SOURCE_MISMATCH;
        }

        /* if everything else fails, source is indeed invalid */
        return NH_SOURCE_INVALID;
    }

    /* source is validated by validate_src */
    return NH_SOURCE_VALID;
}

static int
nh_composite_ecmp(unsigned short vrf, struct vr_packet *pkt,
        struct vr_nexthop *nh, struct vr_forwarding_md *fmd)
{
    int ret = 0;
    struct vr_nexthop *member_nh = NULL;
    struct vr_vrf_stats *stats;

    pkt->vp_type = VP_TYPE_IP;
    stats = vr_inet_vrf_stats(vrf, pkt->vp_cpu);
    if (stats)
        stats->vrf_ecmp_composites++;

    if (!fmd || fmd->fmd_ecmp_nh_index >= (short)nh->nh_component_cnt)
        goto drop;

    if (fmd->fmd_ecmp_nh_index >= 0)
        member_nh = nh->nh_component_nh[fmd->fmd_ecmp_nh_index].cnh;

    if (!member_nh) {
        vr_trap(pkt, vrf, AGENT_TRAP_ECMP_RESOLVE, &fmd->fmd_flow_index);
        return 0;
    }

    fmd->fmd_label = nh->nh_component_nh[fmd->fmd_ecmp_nh_index].cnh_label;
    return nh_output(vrf, pkt, member_nh, fmd);

drop:
    vr_pfree(pkt, VP_DROP_NO_FMD);
    return ret;
}


static int
nh_composite_validate_fabric_src(unsigned short vrf, struct vr_packet *pkt,
         struct vr_nexthop *nh, struct vr_forwarding_md *fmd, void *ret_flags)
{
    int j;
    struct vr_nexthop *tunnel_nh;
    unsigned int tun_dip;

    if (pkt->vp_if->vif_type != VIF_TYPE_PHYSICAL)
        return NH_SOURCE_INVALID;

    if (!fmd->fmd_outer_src_ip)
        return NH_SOURCE_INVALID;

    for(j = 0; j < nh->nh_component_cnt; j++) {
        tunnel_nh = nh->nh_component_nh[j].cnh;

        if (!tunnel_nh || !(tunnel_nh->nh_flags & NH_FLAG_VALID))
            continue;

        if (tunnel_nh->nh_type != NH_TUNNEL)
            continue;

        tun_dip = 0;
        if (tunnel_nh->nh_flags & NH_FLAG_TUNNEL_GRE)
            tun_dip = tunnel_nh->nh_gre_tun_dip;
        else if (tunnel_nh->nh_flags &
            (NH_FLAG_TUNNEL_UDP_MPLS | NH_FLAG_TUNNEL_VXLAN))
            tun_dip = tunnel_nh->nh_udp_tun_dip;

        /* If source is in districution tree, it is valid */
        if (tun_dip && fmd->fmd_outer_src_ip &&
                    fmd->fmd_outer_src_ip == tun_dip) {
            return NH_SOURCE_VALID;
        }
    }
    return NH_SOURCE_INVALID;
}

/*
 * This function validate the source  of the tunnel incase of L2
 * multicast
 */

static int
nh_composite_mcast_validate_src(unsigned short vrf, struct vr_packet *pkt,
        struct vr_nexthop *nh, struct vr_forwarding_md *fmd, void *ret_flags)
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
nh_composite_mcast_l2(unsigned short vrf, struct vr_packet *pkt,
        struct vr_nexthop *nh, struct vr_forwarding_md *fmd)
{
    int i, clone_size;
    struct vr_nexthop *dir_nh;
    unsigned short drop_reason;
    struct vr_packet *new_pkt;
    struct vr_vrf_stats *stats;
    unsigned int tun_src, evpn_src, tor_src, fabric_src, hashval, port_range;
    unsigned short pull_len, label, pkt_vrf;
    unsigned char *eth;

    stats = vr_inet_vrf_stats(vrf, pkt->vp_cpu);
    if (stats)
        stats->vrf_l2_mcast_composites++;

    drop_reason = VP_DROP_CLONED_ORIGINAL;

    if (!fmd) {
        drop_reason = VP_DROP_NO_FMD;
        goto drop;
    }


    tun_src = evpn_src = tor_src = fabric_src = 0;
    if (nh->nh_validate_src) {
        if (nh->nh_validate_src(vrf, pkt, nh, fmd, &tun_src) == NH_SOURCE_INVALID) {
            drop_reason = VP_DROP_INVALID_MCAST_SOURCE;
            goto drop;
        }
        if (tun_src & NH_FLAG_COMPOSITE_EVPN)
            evpn_src = 1;

        if (tun_src & NH_FLAG_COMPOSITE_TOR)
            tor_src = 1;

        if ((pkt->vp_if->vif_type == VIF_TYPE_PHYSICAL) &&
            (!evpn_src && !tor_src)) {
            fabric_src = 1;
        }

    }

    if (tor_src) {
        if (vr_tor_input(vrf, pkt, fmd))
            return 0;
    }

    /* 
     * The packet can come to this nexthp either from Fabric or from VM.
     * Incase of Fabric, the packet would contain the Vxlan header and
     * control information. From VM, it contains neither of them
     */

    label = fmd->fmd_label;

    if (!fmd->fmd_udp_src_port) {
        eth = NULL;
        if (vif_is_virtual(pkt->vp_if)) {
            eth = pkt_data(pkt);
        } else if (pkt->vp_if->vif_type == VIF_TYPE_PHYSICAL) {
            if (evpn_src)
                eth = pkt_data(pkt);
            else {
                eth = pkt_data_at_offset(pkt, pkt->vp_data +
                        VR_L2_MCAST_CTRL_DATA_LEN + VR_VXLAN_HDR_LEN);
            }
        }

        if (!eth) {
            drop_reason = VP_DROP_INVALID_PACKET;
            goto drop;
        }

        if (hashrnd_inited == 0) {
            get_random_bytes(&vr_hashrnd, sizeof(vr_hashrnd));
            hashrnd_inited = 1;
        }
        hashval = vr_hash(pkt_data(pkt), sizeof(struct vr_eth), vr_hashrnd);
        /* Include the VRF to calculate the hash */
        hashval = vr_hash_2words(hashval, vrf, vr_hashrnd);

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

    for (i = 0; i < nh->nh_component_cnt; i++) {

        clone_size = 0;
        dir_nh = nh->nh_component_nh[i].cnh;

        /* We need to copy back the original label from Bridge lookaup
         * as previous iteration would have manipulated that
         */
        fmd->fmd_label = label;
        pkt_vrf = vrf;

        /* If direct nexthop is not valid, dont process it */
        if ((!dir_nh) || !(dir_nh->nh_flags & NH_FLAG_VALID) ||
                                (dir_nh->nh_type != NH_COMPOSITE))
            continue;

        if (dir_nh->nh_flags & NH_FLAG_COMPOSITE_ENCAP) {

            if (!(new_pkt = nh_mcast_clone(pkt, 0))) {
                drop_reason = VP_DROP_MCAST_CLONE_FAIL;
                break;
            }

            if (fabric_src) {
                pull_len = VR_L2_MCAST_CTRL_DATA_LEN + VR_VXLAN_HDR_LEN;

                if (!pkt_pull(new_pkt, pull_len)) {
                    vr_pfree(new_pkt, VP_DROP_PULL);
                    break;
                }
            }
        } else if (dir_nh->nh_flags & NH_FLAG_COMPOSITE_FABRIC) {
            if (evpn_src)
                continue;

            /* Create head space for L2 Mcast header */
            if (!(new_pkt = nh_mcast_clone(pkt, VR_L2_MCAST_PKT_HEAD_SPACE))) {
                drop_reason = VP_DROP_MCAST_CLONE_FAIL;
                break;
            }
            pkt_vrf = dir_nh->nh_vrf;

        } else if (dir_nh->nh_flags & NH_FLAG_COMPOSITE_EVPN) {

            /* We replicate only if received from VM and Ovs TOR*/
            if (vif_is_virtual(pkt->vp_if) || tor_src) {

                /* Create head space for Vxlan header */
                clone_size = VR_L2_MCAST_PKT_HEAD_SPACE - VR_L2_MCAST_CTRL_DATA_LEN;
                if (!(new_pkt = nh_mcast_clone(pkt, clone_size))) {
                    drop_reason = VP_DROP_MCAST_CLONE_FAIL;
                    break;
                }
                pkt_vrf = dir_nh->nh_vrf;
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

            if (fabric_src) {

                pull_len = VR_L2_MCAST_CTRL_DATA_LEN + VR_VXLAN_HDR_LEN;

                if (!pkt_pull(new_pkt, pull_len)) {
                    vr_pfree(new_pkt, VP_DROP_PULL);
                    break;
                }
            }
            pkt_vrf = dir_nh->nh_vrf;

        } else {
            continue;
        }

        nh_output(pkt_vrf, new_pkt, dir_nh, fmd);
    }

    /* Original packet needs to be unconditionally dropped */
drop:
    vr_pfree(pkt, drop_reason);
    return 0;
}


static int
nh_composite_encap(unsigned short vrf, struct vr_packet *pkt,
        struct vr_nexthop *nh, struct vr_forwarding_md *fmd)
{
    int i;
    struct vr_vrf_stats *stats;
    struct vr_nexthop *dir_nh;
    unsigned short drop_reason;
    struct vr_packet *new_pkt;

    drop_reason = VP_DROP_CLONED_ORIGINAL;
    stats = vr_inet_vrf_stats(vrf, pkt->vp_cpu);
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
        nh_output(dir_nh->nh_dev->vif_vrf, new_pkt, dir_nh, fmd);
    }

    /* Original packet needs to be unconditionally dropped */
drop:
    vr_pfree(pkt, drop_reason);
    return 0;
}

static int
nh_composite_tor(unsigned short vrf, struct vr_packet *pkt,
        struct vr_nexthop *nh, struct vr_forwarding_md *fmd)
{
    int i;
    struct vr_vrf_stats *stats;
    struct vr_nexthop *dir_nh;
    unsigned short drop_reason;
    struct vr_packet *new_pkt;

    drop_reason = VP_DROP_CLONED_ORIGINAL;
    stats = vr_inet_vrf_stats(vrf, pkt->vp_cpu);
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

        fmd->fmd_label = nh->nh_component_nh[i].cnh_label;
        nh_output(dir_nh->nh_dev->vif_vrf, new_pkt, dir_nh, fmd);
    }

    /* Original packet needs to be unconditionally dropped */
drop:
    vr_pfree(pkt, drop_reason);
    return 0;
}

static int
nh_composite_evpn(unsigned short vrf, struct vr_packet *pkt,
        struct vr_nexthop *nh, struct vr_forwarding_md *fmd)
{
    int i;
    struct vr_vrf_stats *stats;
    struct vr_nexthop *dir_nh;
    unsigned short drop_reason;
    struct vr_packet *new_pkt;

    drop_reason = VP_DROP_CLONED_ORIGINAL;
    stats = vr_inet_vrf_stats(vrf, pkt->vp_cpu);
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

        fmd->fmd_label = nh->nh_component_nh[i].cnh_label;
        nh_output(dir_nh->nh_dev->vif_vrf, new_pkt, dir_nh, fmd);
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
nh_composite_fabric(unsigned short vrf, struct vr_packet *pkt,
        struct vr_nexthop *nh, struct vr_forwarding_md *fmd) 
{
    int i, fabric_src = 0;
    struct vr_vrf_stats *stats;
    struct vr_nexthop *dir_nh;
    unsigned short drop_reason;
    struct vr_packet *new_pkt;
    unsigned int dip, sip;
    int32_t label;

    drop_reason = VP_DROP_CLONED_ORIGINAL;
    stats = vr_inet_vrf_stats(vrf, pkt->vp_cpu);
    if (stats)
        stats->vrf_fabric_composites++;

    if (!fmd) {
        drop_reason = VP_DROP_NO_FMD;
        goto drop;
    }

    if (!nh->nh_validate_src) {
        drop_reason = VP_DROP_INVALID_NH;
        goto drop;
    }

    if (nh->nh_validate_src(vrf, pkt, nh, fmd, NULL) == NH_SOURCE_VALID)
        fabric_src = 1;

    /*
     * Packet can be L2 or L3 with or without control information. It is
     * always ensured before coming to this nexthop that packet headers
     * along with control inforation is in first buffer. So it can be
     * safely cow'd for the required length
     */

    label = fmd->fmd_label;
    for (i = 0; i < nh->nh_component_cnt; i++) {
        dir_nh = nh->nh_component_nh[i].cnh;

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
        if (vif_is_virtual(new_pkt->vp_if) || !fabric_src) {
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
            fmd->fmd_label = label;
            if (nh_vxlan_tunnel_helper(dir_nh->nh_dev->vif_vrf,
                                        new_pkt, fmd, sip, sip) == false) {
                vr_pfree(new_pkt, VP_DROP_PUSH);
                break;
            }

            if (vr_l2_mcast_control_data_add(new_pkt) == false) {
                vr_pfree(new_pkt, VP_DROP_PUSH);
                break;
            }
        }

        /* MPLS label for outer header encapsulation */
        fmd->fmd_label = nh->nh_component_nh[i].cnh_label;
        nh_output(dir_nh->nh_dev->vif_vrf, new_pkt, dir_nh, fmd);
    }

    /* Original packet needs to be unconditionally dropped */
drop:
    vr_pfree(pkt, drop_reason);
    return 0;
}

static int
nh_discard(unsigned short vrf, struct vr_packet *pkt,
        struct vr_nexthop *nh, struct vr_forwarding_md *fmd)
{
    struct vr_vrf_stats *stats;

    stats = vr_inet_vrf_stats(vrf, pkt->vp_cpu);
    if (stats)
        stats->vrf_discards++;

    vr_pfree(pkt, VP_DROP_DISCARD);
    return 0;
}

static int
nh_udp_tunnel(unsigned short vrf, struct vr_packet *pkt,
        struct vr_nexthop *nh, struct vr_forwarding_md *fmd)
{
    struct vr_packet *tmp;
    struct vr_ip *ip;
    struct vr_udp *udp;
    struct vr_vrf_stats *stats;

    if (!fmd)
        goto send_fail;

    if (pkt_head_space(pkt) < VR_UDP_HEAD_SPACE) {
        tmp = vr_palloc_head(pkt, VR_UDP_HEAD_SPACE);
        if (!tmp) 
            goto send_fail;

        pkt = tmp;
        if (!pkt_reserve_head_space(pkt, VR_UDP_HEAD_SPACE)) 
            goto send_fail;
    }

    if (nh_udp_tunnel_helper(pkt, nh->nh_udp_tun_sport,
                             nh->nh_udp_tun_dport, nh->nh_udp_tun_sip,
                             nh->nh_udp_tun_dip) == false) {
        goto send_fail;
    }
    pkt_set_network_header(pkt, pkt->vp_data);

    if (pkt_len(pkt) > ((1 << sizeof(ip->ip_len) * 8)))
        goto send_fail;
    /* 
     * Incase of mirroring set the inner network header to the newly added 
     * header so that this is fragmented and checksummed
     */
    pkt_set_inner_network_header(pkt, pkt->vp_data);

    /*
     * Calculate the partial checksum for udp header
     */
    ip = (struct vr_ip *)(pkt_data(pkt));
    udp = (struct vr_udp *)((char *)ip + ip->ip_hl * 4);
    udp->udp_csum = vr_ip_partial_csum(ip);

    stats = vr_inet_vrf_stats(vrf, pkt->vp_cpu);
    if (stats)
        stats->vrf_udp_tunnels++;

    vr_forward(vrouter_get(nh->nh_rid), 
               (vrf == (unsigned short)-1) ? fmd->fmd_dvrf : vrf,
               pkt, fmd);

    return 0;

send_fail:
    vr_pfree(pkt, VP_DROP_PUSH);
    return 0;
}

/*
 * nh_vxlan_tunnel - tunnel packet with VXLAN header
 */
static int
nh_vxlan_tunnel(unsigned short vrf, struct vr_packet *pkt, 
                   struct vr_nexthop *nh, struct vr_forwarding_md *fmd)
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

    stats = vr_inet_vrf_stats(vrf, pkt->vp_cpu);
    if (stats)
        stats->vrf_udp_mpls_tunnels++;

    if (vr_perfs)
        pkt->vp_flags |= VP_FLAG_GSO;

    overhead_len = VR_VXLAN_HDR_LEN;
    overhead_len += pkt_get_network_header_off(pkt) - pkt->vp_data;

    if (pkt->vp_type == VP_TYPE_IP) {
        if (vr_has_to_fragment(nh->nh_dev, pkt, overhead_len) &&
                vr_ip_dont_fragment_set(pkt)) {
            if (pkt->vp_flags & VP_FLAG_MULTICAST) {
                reason = VP_DROP_MCAST_DF_BIT;
                goto send_fail;
            }
            trap_arg.df_mtu = vif_get_mtu(nh->nh_dev) - overhead_len;
            trap_arg.df_flow_index = fmd->fmd_flow_index;
            return vr_trap(pkt, vrf, AGENT_TRAP_HANDLE_DF, (void *)&trap_arg);
        }
    }

    if (nh_vxlan_tunnel_helper(vrf, pkt, fmd, nh->nh_udp_tun_sip,
                                            nh->nh_udp_tun_dip) == false)
        goto send_fail;

    pkt_set_network_header(pkt, pkt->vp_data);

    if (pkt_head_space(pkt) < nh->nh_udp_tun_encap_len) {
        tmp_pkt = vr_pexpand_head(pkt, nh->nh_udp_tun_encap_len - pkt_head_space(pkt));
        if (!tmp_pkt) {
            goto send_fail;
        }
        pkt = tmp_pkt;
    }

    /* slap l2 header */
    vif = nh->nh_dev;
    if (!vif->vif_set_rewrite(vif, pkt, nh->nh_data, 
                                     nh->nh_udp_tun_encap_len)) {
        goto send_fail;
    }

    vif->vif_tx(vif, pkt);

    return 0;

send_fail:
    vr_pfree(pkt, reason);
    return 0;

}

static int
nh_mpls_udp_tunnel_validate_src(unsigned short vrf, struct vr_packet *pkt,
        struct vr_nexthop *nh, struct vr_forwarding_md *fmd, void *ret_data)
{
    if (fmd->fmd_outer_src_ip == nh->nh_udp_tun_dip)
        return NH_SOURCE_VALID;

    return NH_SOURCE_INVALID;
}


/*
 * nh_mpls_udp_tunnel - tunnel packet with MPLS label in UDP.
 */
static int
nh_mpls_udp_tunnel(unsigned short vrf, struct vr_packet *pkt, 
                   struct vr_nexthop *nh, struct vr_forwarding_md *fmd)
{
    unsigned char *tun_encap;
    struct vr_interface *vif;
    struct vr_vrf_stats *stats;
    unsigned int tun_sip, tun_dip, overhead_len, mudp_head_space;
    uint16_t tun_encap_len, udp_src_port = VR_MPLS_OVER_UDP_SRC_PORT;
    unsigned short reason = VP_DROP_PUSH;
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

    stats = vr_inet_vrf_stats(vrf, pkt->vp_cpu);
    if (stats)
        stats->vrf_udp_mpls_tunnels++;

    if (!fmd || fmd->fmd_label < 0)
        return vr_forward(nh->nh_router, vrf, pkt, fmd);

    if (fmd->fmd_udp_src_port)
        udp_src_port = fmd->fmd_udp_src_port;

    /*
     * The UDP source port is a hash of the inner IP src/dst address and
     * vrf. For the IPV6 standard source port is used till flow
     * procesing is done
     */
    if ((!fmd->fmd_udp_src_port) && (pkt->vp_type != VP_TYPE_IP6) &&
            vr_get_udp_src_port) {
        udp_src_port = vr_get_udp_src_port(pkt, fmd, vrf);
        if (udp_src_port == 0) {
            reason = VP_DROP_PULL;
            goto send_fail;
        }
    }

    /* Calculate the head space for mpls,udp ip and eth */
    mudp_head_space = VR_MPLS_HDR_LEN + sizeof(struct vr_ip) + sizeof(struct vr_udp);

    if (pkt->vp_type == VP_TYPE_IP) {
        overhead_len = mudp_head_space + pkt_get_network_header_off(pkt) - pkt->vp_data;
        if (vr_has_to_fragment(nh->nh_dev, pkt, overhead_len) &&
                vr_ip_dont_fragment_set(pkt)) {
            if (pkt->vp_flags & VP_FLAG_MULTICAST) {
                reason = VP_DROP_MCAST_DF_BIT;
                goto send_fail;
            }
            trap_arg.df_mtu = vif_get_mtu(nh->nh_dev) - overhead_len;
            trap_arg.df_flow_index = fmd->fmd_flow_index;
            return vr_trap(pkt, vrf, AGENT_TRAP_HANDLE_DF, (void *)&trap_arg);
        }
    }

    mudp_head_space += tun_encap_len;

    if (pkt_head_space(pkt) < mudp_head_space) {
        tmp_pkt = vr_pexpand_head(pkt, mudp_head_space - pkt_head_space(pkt));
        if (!tmp_pkt) 
            goto send_fail;

        pkt = tmp_pkt;
    }

    if (nh_push_mpls_header(pkt, fmd->fmd_label) < 0)
        goto send_fail;

    if (vr_perfs)
        pkt->vp_flags |= VP_FLAG_GSO;
   
   
    /*
     * Change the packet type
     */
    if (pkt->vp_type == VP_TYPE_IP6)
        pkt->vp_type = VP_TYPE_IP6OIP;
    else if (pkt->vp_type == VP_TYPE_IP)
        pkt->vp_type = VP_TYPE_IPOIP;

    if (nh_udp_tunnel_helper(pkt, htons(udp_src_port), 
                             htons(VR_MPLS_OVER_UDP_DST_PORT),
                             tun_sip, tun_dip) == false) {
        goto send_fail;
    }

    pkt_set_network_header(pkt, pkt->vp_data);

    /* slap l2 header */
    vif = nh->nh_dev;
    tun_encap = vif->vif_set_rewrite(vif, pkt, nh->nh_data, 
                                     tun_encap_len);
    if (!tun_encap) {
        goto send_fail;
    }

    vif->vif_tx(vif, pkt);

    return 0;

send_fail:
    vr_pfree(pkt, reason);
    return 0;

}

static int
nh_gre_tunnel_validate_src(unsigned short vrf, struct vr_packet *pkt,
        struct vr_nexthop *nh, struct vr_forwarding_md *fmd, void *ret_data)
{
    if (fmd->fmd_outer_src_ip == nh->nh_gre_tun_dip)
        return NH_SOURCE_VALID;

    return NH_SOURCE_INVALID;
}

static int
nh_gre_tunnel(unsigned short vrf, struct vr_packet *pkt,
        struct vr_nexthop *nh, struct vr_forwarding_md *fmd)
{
    unsigned int id;
    int overhead_len, gre_head_space;
    unsigned short drop_reason = VP_DROP_INVALID_NH;
    struct vr_gre *gre_hdr;
    struct vr_ip *ip;
    unsigned char *tun_encap;
    struct vr_interface *vif;
    struct vr_vrf_stats *stats;
    struct vr_packet *tmp_pkt;
    struct vr_df_trap_arg trap_arg;

    if (vr_mudp && vr_perfs) {
        return nh_mpls_udp_tunnel(vrf, pkt, nh, fmd);
    }

    stats = vr_inet_vrf_stats(vrf, pkt->vp_cpu);
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
        return vr_forward(nh->nh_router, vrf, pkt, fmd);


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


    if (pkt->vp_type == VP_TYPE_IP) {
        /* If there are any L2 headers lets add those as well. For L3
         * unicast, folloowing will add no extra overhead */
        overhead_len = gre_head_space + pkt_get_network_header_off(pkt) - pkt->vp_data;
        if (vr_has_to_fragment(nh->nh_dev, pkt, overhead_len) &&
                vr_ip_dont_fragment_set(pkt)) {
            if (pkt->vp_flags & VP_FLAG_MULTICAST) {
                drop_reason = VP_DROP_MCAST_DF_BIT;
                goto send_fail;
            }

            trap_arg.df_mtu = vif_get_mtu(nh->nh_dev) - overhead_len;
            trap_arg.df_flow_index = fmd->fmd_flow_index;
            return vr_trap(pkt, vrf, AGENT_TRAP_HANDLE_DF, (void *)&trap_arg);
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

    if (nh_push_mpls_header(pkt, fmd->fmd_label) < 0)
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
    if (pkt->vp_type == VP_TYPE_IP6)
        pkt->vp_type = VP_TYPE_IP6OIP;
    else  if (pkt->vp_type == VP_TYPE_IP)
        pkt->vp_type = VP_TYPE_IPOIP;

    ip->ip_version = 4;
    ip->ip_hl = 5;
    ip->ip_tos = 0;
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
    /* checksum will be calculated in linux_xmit_segment */

    /* slap l2 header */
    vif = nh->nh_dev;
    tun_encap = vif->vif_set_rewrite(vif, pkt, nh->nh_data,
            nh->nh_gre_tun_encap_len);
    if (!tun_encap) {
        drop_reason = VP_DROP_PUSH;
        goto send_fail;
    }
    vif->vif_tx(vif, pkt);
    return 0;

send_fail:
    vr_pfree(pkt, drop_reason);
    return 0;
}


int
nh_output(unsigned short vrf, struct vr_packet *pkt,
        struct vr_nexthop *nh, struct vr_forwarding_md *fmd)
{
    struct vr_nexthop *src_nh = NULL;
    struct vr_ip *ip;
    bool need_flow_lookup = false;

    if (!pkt->vp_ttl) {
        return vr_trap(pkt, vrf, AGENT_TRAP_ZERO_TTL, NULL);
    }

    pkt->vp_nh = nh;

    /* If nexthop does not have valid data, drop it */
    if (!(nh->nh_flags & NH_FLAG_VALID)) {
        vr_pfree(pkt, VP_DROP_INVALID_NH);
        return 0;
    }

    if (!vr_pkt_is_l2(pkt)) {
        if (pkt->vp_type == VP_TYPE_IP) {
            /*
             * If the packet has not gone through flow lookup once
             * (!VP_FLAG_FLOW_SET), we need to determine whether it has to undergo
             * flow lookup now or not. There are two cases:
             *
             * 1. when policy flag is set in the nexthop, and
             * 2. when the source is an ECMP.
             *
             * When the source is an ECMP, we would like the packet to reach the
             * same place from where it came from, and hence a flow has to be setup
             * so that DP knows where to send the packet to (from an ECMP NH).
             * Typical example for this situation is when the packet reaches the
             * target VM's server from an ECMP-ed service chain.
            */
            ip = (struct vr_ip *)pkt_network_header(pkt);
            if (!(pkt->vp_flags & VP_FLAG_FLOW_SET)) {
                if (nh->nh_flags & NH_FLAG_POLICY_ENABLED) {
                    need_flow_lookup = true;
                } else {
                    src_nh = vr_inet_src_lookup(vrf, ip, pkt);
                    if (src_nh && src_nh->nh_type == NH_COMPOSITE &&
                            src_nh->nh_flags & NH_FLAG_COMPOSITE_ECMP) {
                        need_flow_lookup = true;
                    }
                }

                if (need_flow_lookup) {
                    pkt->vp_flags |= VP_FLAG_FLOW_GET;
                    vr_flow_inet_input(nh->nh_router, vrf,
                            pkt, VR_ETH_PROTO_IP, fmd);
                    return 1;
                }
            }
        }
    }

    return nh->nh_reach_nh(vrf, pkt, nh, fmd);
}

static int
nh_encap_l2(unsigned short vrf, struct vr_packet *pkt, 
        struct vr_nexthop *nh, struct vr_forwarding_md *md)
{
    struct vr_interface *vif;
    struct vr_vrf_stats *stats;

    stats = vr_inet_vrf_stats(vrf, pkt->vp_cpu);
    if (stats)
        stats->vrf_l2_encaps++;

    /*
     * Mark the packet as L2 and make it inelgible for GRO
     */
    pkt->vp_flags &= ~VP_FLAG_GRO;

    vif = nh->nh_dev;
    vif->vif_tx(vif, pkt);

    return 0;
}

static int
nh_encap_l3_validate_src(unsigned short vrf, struct vr_packet *pkt,
        struct vr_nexthop *nh, struct vr_forwarding_md *fmd, void *ret_data)
{
    if (pkt->vp_if == nh->nh_dev)
        return NH_SOURCE_VALID;

    return NH_SOURCE_INVALID;
}

static int
nh_encap_l3_unicast(unsigned short vrf, struct vr_packet *pkt,
        struct vr_nexthop *nh, struct vr_forwarding_md *md)
{
    struct vr_interface *vif;
    struct vr_vrf_stats *stats;
    struct vr_ip *ip;
    unsigned short *proto_p;

    stats = vr_inet_vrf_stats(vrf, pkt->vp_cpu);

    vif = nh->nh_dev;
    ip = (struct vr_ip *)pkt_network_header(pkt);
    if (vr_ip_is_ip6(ip)) {
        pkt->vp_type = VP_TYPE_IP6;
    } else {
        pkt->vp_type = VP_TYPE_IP;
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

    /*
     * For packets being sent up a tap interface, retain the MPLS label
     * if we are attempting GRO. We will need the label later to figure
     * out which interface to send the packet to.
     */
    if ((pkt->vp_flags & VP_FLAG_GRO) &&
                 (vif->vif_type == VIF_TYPE_VIRTUAL)) {
        /*
         * ECMP case. When we send the packet up for GRO, the label typically
         * points to the composite nexthop. When the packet lands back in DP,
         * there is no flow information, and hence there is no way to get back
         * ECMP NH index without doing a flow lookup again. To workaround that
         * issue, overwrite the label with the component (unicast) nexthop's
         * label, which is passed in forwarding metadata. The below if comes
         * into play (as of now) only in that case.
         */
        if (md && md->fmd_label >= 0) {
            if (nh_push_mpls_header(pkt, md->fmd_label) < 0) {
                vr_pfree(pkt, VP_DROP_PUSH);
                return 0;
            }
            pkt_pull(pkt, VR_MPLS_HDR_LEN);
        }
    } else {
        if (!vif->vif_set_rewrite(vif, pkt, nh->nh_data,
                nh->nh_encap_len)) {
            vr_pfree(pkt, VP_DROP_REWRITE_FAIL);
            return 0;
        }

        if (nh->nh_encap_len) {
            proto_p = (unsigned short *)(pkt_data(pkt) +
                    nh->nh_encap_len - 2);
            if (pkt->vp_type == VP_TYPE_IP6)
                *proto_p = htons(VR_ETH_PROTO_IP6);
            else
                *proto_p = htons(VR_ETH_PROTO_IP);
        }
    }

    /*
     * Look if this is the Diag packet to trap to agent
     */
    if (vr_pkt_is_diag(pkt)) {
        pkt->vp_if = vif;
        vr_pset_data(pkt, pkt->vp_data);
        return vr_trap(pkt, vrf, AGENT_TRAP_DIAG, &vif->vif_idx);
    }

    vif->vif_tx(vif, pkt);

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
nh_rcv_add(struct vr_nexthop *nh, vr_nexthop_req *req)
{
    struct vr_interface  *vif, *old_vif;
    vif = vrouter_get_interface(nh->nh_rid, req->nhr_encap_oif_id);
    if (!vif)
        return -ENODEV;
    /* 
     *  We need to delete the reference to old_vif only after new vif is
     * added to NH
     */
    old_vif = nh->nh_dev;
    nh->nh_dev = vif;
    nh->nh_reach_nh = nh_rcv;
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

            if (tmp_nh->nh_flags & NH_FLAG_ENCAP_L2) {
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
    unsigned int i;
    struct vr_nexthop *tmp_nh;

    nh->nh_validate_src = NULL;
    /* Delete the old nexthops first */
    if (nh->nh_component_cnt && nh->nh_component_nh) {
        for (i = 0; i < nh->nh_component_cnt; i++) {
            if (nh->nh_component_nh[i].cnh)
                vrouter_put_nexthop(nh->nh_component_nh[i].cnh);
        }
        vr_free(nh->nh_component_nh);
        nh->nh_component_nh = NULL;
        nh->nh_component_cnt = 0;
    }

    if (req->nhr_nh_list_size != req->nhr_label_list_size)
        return -EINVAL;

    /* Nh list of size 0 is valid */
    if (req->nhr_nh_list_size == 0)
        return 0;

    nh->nh_component_nh = vr_zalloc(req->nhr_nh_list_size *
            sizeof(struct vr_component_nh)); 
    if (!nh->nh_component_nh) {
        return -ENOMEM;
    }
    for (i = 0; i < req->nhr_nh_list_size; i++) {
        nh->nh_component_nh[i].cnh = vrouter_get_nexthop(req->nhr_rid, 
                                                    req->nhr_nh_list[i]);
        nh->nh_component_nh[i].cnh_label = req->nhr_label_list[i];
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
    } else if (req->nhr_flags & NH_FLAG_COMPOSITE_FABRIC) {
        nh->nh_reach_nh = nh_composite_fabric;
        nh->nh_validate_src = nh_composite_validate_fabric_src;
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

        vr_free(nh->nh_component_nh);
        nh->nh_component_nh = NULL;
        nh->nh_component_cnt = 0;
    }
    return -EINVAL;
}

static int
nh_tunnel_add(struct vr_nexthop *nh, vr_nexthop_req *req)
{
    struct vr_interface *vif, *old_vif;
    if (!req->nhr_tun_sip || !req->nhr_tun_dip)
        return -EINVAL;

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
        nh->nh_udp_tun_sip = req->nhr_tun_sip;
        nh->nh_udp_tun_dip = req->nhr_tun_dip;
        nh->nh_udp_tun_sport = req->nhr_tun_sport;
        nh->nh_udp_tun_dport = req->nhr_tun_dport;
        nh->nh_udp_tun_encap_len = req->nhr_encap_size;
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
     *  We need to delete the reference to old_vif only after new vif is
     * added to NH
     */
    old_vif = nh->nh_dev;

    if (req->nhr_flags & NH_FLAG_ENCAP_L2) {
         if (req->nhr_encap_size) {
             vrouter_put_interface(vif);
             return -EINVAL;
         }
        nh->nh_dev = vif;
        nh->nh_reach_nh = nh_encap_l2;
    } else {
        nh->nh_dev = vif;
        nh->nh_encap_family = req->nhr_encap_family;
        nh->nh_encap_len = req->nhr_encap_size;
        if (nh->nh_encap_len && nh->nh_data)
            memcpy(nh->nh_data, req->nhr_encap, nh->nh_encap_len);

        nh->nh_reach_nh = nh_encap_l3_unicast;
        nh->nh_validate_src = nh_encap_l3_validate_src;
    }

    if (old_vif)
        vrouter_put_interface(old_vif);

    return 0;
}

static int
nh_discard_add(struct vr_nexthop *nh, vr_nexthop_req *req)
{
    if (nh->nh_id != NH_DISCARD_ID) {
        return -EINVAL;
    }
    nh->nh_family = req->nhr_family;
    nh->nh_type = NH_DISCARD;
    nh->nh_router = vrouter_get(0);
    nh->nh_reach_nh = nh_discard;
    ip4_default_nh = nh;
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
        nh = vr_zalloc(len);
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

        /* If valid to invalid lets propogate flags immediagtely */
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

/* we expect the caller to bzero req, before sending it here */
static int
vr_nexthop_make_req(vr_nexthop_req *req, struct vr_nexthop *nh)
{
    unsigned char *encap = NULL;
    unsigned int i;

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

    case NH_ENCAP:
        if (nh->nh_dev)
            req->nhr_encap_oif_id = nh->nh_dev->vif_idx;

        req->nhr_encap_size = nh->nh_encap_len;
        req->nhr_encap_family = nh->nh_encap_family;
        if (req->nhr_encap_size)
            encap = nh->nh_data;
        break;

    case NH_COMPOSITE:
        req->nhr_nh_list_size = nh->nh_component_cnt;
        if (nh->nh_component_cnt) {
            req->nhr_nh_list = vr_zalloc(req->nhr_nh_list_size * sizeof(unsigned int));
            if (!req->nhr_nh_list)
                return -ENOMEM;

            req->nhr_label_list_size = nh->nh_component_cnt;
            req->nhr_label_list = vr_zalloc(req->nhr_nh_list_size * sizeof(unsigned int));
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
            req->nhr_tun_sip = nh->nh_udp_tun_sip;
            req->nhr_tun_dip = nh->nh_udp_tun_dip;
            req->nhr_encap_size = nh->nh_udp_tun_encap_len;
            req->nhr_tun_sport = nh->nh_udp_tun_sport;
            req->nhr_tun_dport = nh->nh_udp_tun_dport;
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
        req->nhr_encap = vr_zalloc(req->nhr_encap_size);
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
vr_nexthop_req_get(void)
{
    return vr_zalloc(sizeof(vr_nexthop_req));
}

static void
vr_nexthop_req_destroy(vr_nexthop_req *req)
{
    if (!req)
        return;

    if (req->nhr_encap_size && req->nhr_encap) {
        vr_free(req->nhr_encap);
        req->nhr_encap_size = 0;
        req->nhr_encap = NULL;
    }

    if (req->nhr_nh_list_size && req->nhr_nh_list) {
        vr_free(req->nhr_nh_list);
        req->nhr_nh_list_size = 0;
        req->nhr_nh_list = NULL;
    }

    if (req->nhr_label_list_size && req->nhr_label_list) {
        vr_free(req->nhr_label_list);
        req->nhr_label_list = NULL;
        req->nhr_label_list_size = 0;
    }

    vr_free(req);
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
        resp = vr_nexthop_req_get();
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
        nh = router->vr_nexthops[i];
        if (nh) {
            resp = vr_nexthop_req_get();
            if (!resp && (ret = -ENOMEM))
                goto generate_response;

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
    struct vr_nexthop **vnt;

    vnt = router->vr_nexthops;
    if (!vnt)
        return;

    for (i = 0; i < router->vr_max_nexthops; i++) {
        if (vnt[i]) {
            if (soft_reset && i == NH_DISCARD_ID)
                continue;

            vnt[i]->nh_destructor(vnt[i]);
        }
    }


    if (soft_reset == false) {
        router->vr_nexthops = NULL;
        /* Make the default nh point to NULL */
        ip4_default_nh = NULL;
        vr_free(vnt);
        router->vr_max_nexthops = 0;
    }

    return;
}

static int
nh_allocate_discard(void)
{
    ip4_default_nh = vr_zalloc(sizeof(struct vr_nexthop));
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
        router->vr_max_nexthops = NH_TABLE_ENTRIES;
        table_memory = router->vr_max_nexthops * sizeof(struct vr_nexthop *);
        router->vr_nexthops = vr_zalloc(table_memory);
        if (!router->vr_nexthops)
            return vr_module_error(-ENOMEM, __FUNCTION__,
                    __LINE__, table_memory);
    }

    if (!ip4_default_nh) {
        ret = nh_allocate_discard();
        if (ret) {
            vr_module_error(ret, __FUNCTION__, __LINE__, 0);
            goto init_fail;
        }
    }

    return 0;

init_fail:
    if (router->vr_nexthops)
        vr_free(router->vr_nexthops);

    router->vr_max_nexthops = 0;
    router->vr_nexthops = NULL;

    return ret;
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
