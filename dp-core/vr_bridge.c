/*
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#include <vr_os.h>
#include <vr_packet.h>
#include "vr_interface.h"
#include "vr_message.h"
#include "vr_sandesh.h"
#include "vr_bridge.h"
#include "vr_htable.h"
#include "vr_nexthop.h"
#include "vr_datapath.h"
#include "vr_defs.h"

struct vr_bridge_entry_key {
    unsigned char be_mac[VR_ETHER_ALEN];
    unsigned short be_vrf_id;
}__attribute__((packed));

struct vr_bridge_entry;

struct vr_dummy_bridge_entry {
    vr_hentry_t be_hentry;
    struct vr_bridge_entry_key be_key;
    struct vr_nexthop *be_nh;
    uint32_t be_label;
    unsigned short be_flags;
} __attribute__((packed));

#define VR_BRIDGE_ENTRY_PACK (64 - sizeof(struct vr_dummy_bridge_entry))

struct vr_bridge_entry {
    vr_hentry_t be_hentry;
    struct vr_bridge_entry_key be_key;
    struct vr_nexthop *be_nh;
    uint32_t be_label;
    unsigned short be_flags;
    unsigned char be_pack[VR_BRIDGE_ENTRY_PACK];
} __attribute__((packed));

unsigned int vr_bridge_entries = VR_DEF_BRIDGE_ENTRIES;
unsigned int vr_bridge_oentries = 0;
static vr_htable_t vn_rtable;
char vr_bcast_mac[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

struct vr_nexthop *(*vr_bridge_lookup)(unsigned int, struct vr_route_req *);
int bridge_table_init(struct vr_rtable *, struct rtable_fspec *);
void bridge_table_deinit(struct vr_rtable *, struct rtable_fspec *, bool);
struct vr_bridge_entry *vr_find_bridge_entry(struct vr_bridge_entry_key *);
struct vr_bridge_entry *vr_find_free_bridge_entry(unsigned int, char *);
extern struct vr_vrf_stats *(*vr_inet_vrf_stats)(unsigned short, unsigned int);
extern l4_pkt_type_t vr_ip_well_known_packet(struct vr_packet *);
extern l4_pkt_type_t vr_ip6_well_known_packet(struct vr_packet *);

bool
vr_unknown_uc_flood(struct vr_interface *ingress_vif,
        struct vr_nexthop *ingress_nh)
{
    if (!ingress_vif)
        return false;

    if (vif_is_virtual(ingress_vif)) {
        return ((ingress_vif->vif_flags & VIF_FLAG_UNKNOWN_UC_FLOOD) != 0);
    } else if (vif_is_fabric(ingress_vif) && ingress_nh) {
        return ((ingress_nh->nh_flags & NH_FLAG_UNKNOWN_UC_FLOOD) != 0);
    }

    return false;
}

struct vr_bridge_entry *
vr_find_bridge_entry(struct vr_bridge_entry_key *key)
{
    if (!vn_rtable || !key)
        return NULL;

    return (struct vr_bridge_entry *)vr_htable_find_hentry(vn_rtable, key, 0);
}

struct vr_bridge_entry *
vr_find_free_bridge_entry(unsigned int vrf_id, char *mac)
{
    struct vr_bridge_entry *be;
    struct vr_bridge_entry_key key;

    if (!vn_rtable || !mac)
        return NULL;

    key.be_vrf_id = vrf_id;
    VR_MAC_COPY(key.be_mac, mac);
    be = (struct vr_bridge_entry *)vr_htable_find_free_hentry(vn_rtable,
                                                                &key, 0);
    return be;
}

static int
__bridge_table_add(struct vr_route_req *rt)
{
    struct vr_bridge_entry *be;
    struct vr_nexthop *old_nh;
    struct vr_bridge_entry_key key;

    rt->rtr_req.rtr_label_flags &= ~VR_BE_VALID_FLAG;

    VR_MAC_COPY(key.be_mac, rt->rtr_req.rtr_mac);
    key.be_vrf_id = rt->rtr_req.rtr_vrf_id;

    be = vr_find_bridge_entry(&key);

    if (!be) {
        be = vr_find_free_bridge_entry(rt->rtr_req.rtr_vrf_id,
                                        (char *)rt->rtr_req.rtr_mac);
        if (!be)
            return -ENOMEM;

        VR_MAC_COPY(be->be_key.be_mac, rt->rtr_req.rtr_mac);
        be->be_key.be_vrf_id = rt->rtr_req.rtr_vrf_id;
        be->be_flags = VR_BE_VALID_FLAG;
    }

    if (be->be_nh != rt->rtr_nh) {

        /* Un ref the old nexthop */
        old_nh = be->be_nh;
        be->be_nh = vrouter_get_nexthop(rt->rtr_req.rtr_rid,
                                        rt->rtr_req.rtr_nh_id);
        if (old_nh)
            vrouter_put_nexthop(old_nh);
    }

    if (rt->rtr_req.rtr_label_flags & VR_BE_LABEL_VALID_FLAG)
        be->be_label = rt->rtr_req.rtr_label;

    be->be_flags &= VR_BE_VALID_FLAG;
    be->be_flags |= rt->rtr_req.rtr_label_flags;

    return 0;
}

static int
bridge_table_add(struct vr_rtable * _unused, struct vr_route_req *rt)
{
    int ret;

    if (!vn_rtable)
        return -EINVAL;

    if (IS_MAC_ZERO(rt->rtr_req.rtr_mac))
        return -EINVAL;

    rt->rtr_nh = vrouter_get_nexthop(rt->rtr_req.rtr_rid,
            rt->rtr_req.rtr_nh_id);
    if (!rt->rtr_nh)
        return -ENOENT;

    if ((!(rt->rtr_req.rtr_label_flags & VR_BE_LABEL_VALID_FLAG)) &&
        (rt->rtr_nh->nh_type == NH_TUNNEL)) {
        vrouter_put_nexthop(rt->rtr_nh);
        return -EINVAL;
    }

    ret = __bridge_table_add(rt);
    vrouter_put_nexthop(rt->rtr_nh);
    return ret;
}

static void
bridge_table_entry_free(vr_htable_t table, vr_hentry_t *hentry,
        unsigned int index, void *data)
{
    struct vr_nexthop *nh;
    struct vr_bridge_entry *be = (struct vr_bridge_entry *)hentry;
    if (!be)
        return;

    /* Mark this entry as invalid */
    be->be_flags &= ~VR_BE_VALID_FLAG;

    if (be->be_nh) {
        nh = be->be_nh;
        be->be_nh = NULL;
        vrouter_put_nexthop(nh);
    }
    vr_htable_release_hentry(table, hentry);

    return;
}

static int
bridge_table_delete(struct vr_rtable * _unused, struct vr_route_req *rt)
{
    struct vr_bridge_entry_key key;
    struct vr_bridge_entry *be;

    if (!vn_rtable)
        return -EINVAL;

    VR_MAC_COPY(key.be_mac, rt->rtr_req.rtr_mac);
    key.be_vrf_id = rt->rtr_req.rtr_vrf_id;

    be = vr_find_bridge_entry(&key);
    if (!be)
        return -ENOENT;

    bridge_table_entry_free(vn_rtable, (vr_hentry_t *)be, 0, NULL);
    return 0;
}

static struct vr_nexthop *
bridge_table_lookup(unsigned int vrf_id, struct vr_route_req *rt)
{
    struct vr_bridge_entry *be;
    struct vr_bridge_entry_key key;

    rt->rtr_req.rtr_label_flags = 0;

    if (rt->rtr_req.rtr_index != VR_BE_INVALID_INDEX) {
        be = (struct vr_bridge_entry *)
             vr_htable_get_hentry_by_index(vn_rtable, rt->rtr_req.rtr_index);
        if (!be)
            return NULL;

        rt->rtr_req.rtr_label_flags = be->be_flags;
        rt->rtr_req.rtr_label = be->be_label;
        rt->rtr_nh = be->be_nh;
        if (rt->rtr_req.rtr_mac)
            VR_MAC_COPY(rt->rtr_req.rtr_mac, be->be_key.be_mac);

        return rt->rtr_nh;
    }


    rt->rtr_nh = NULL;
    rt->rtr_req.rtr_index = VR_BE_INVALID_INDEX;
    VR_MAC_COPY(key.be_mac, rt->rtr_req.rtr_mac);
    key.be_vrf_id = rt->rtr_req.rtr_vrf_id;

    be = vr_find_bridge_entry(&key);
    if (be) {
        rt->rtr_req.rtr_label_flags = be->be_flags;
        rt->rtr_req.rtr_label = be->be_label;
        rt->rtr_nh = be->be_nh;
        rt->rtr_req.rtr_index = be->be_hentry.hentry_index;
    }

    return rt->rtr_nh;
}


unsigned short
vr_bridge_route_flags(unsigned int vrf_id, unsigned char *mac)
{
    struct vr_bridge_entry *be;
    struct vr_bridge_entry_key key;

    VR_MAC_COPY(key.be_mac, mac);
    key.be_vrf_id = vrf_id;

    be = vr_find_bridge_entry(&key);
    if (be && (be->be_flags & VR_BE_VALID_FLAG))
        return be->be_flags;

    return 0;
}

unsigned int
vr_bridge_table_used_total_entries(struct vrouter *router)
{
    if (vn_rtable)
        return vr_htable_used_total_entries(vn_rtable);

    return 0;
}

unsigned int
vr_bridge_table_used_oflow_entries(struct vrouter *router)
{
    if (vn_rtable)
        return vr_htable_used_oflow_entries(vn_rtable);
    return 0;
}

static int
bridge_table_get(unsigned int vrf_id, struct vr_route_req *rt)
{
    struct vr_nexthop *nh;

    nh = bridge_table_lookup(vrf_id, rt);
    if (nh) {
        rt->rtr_req.rtr_nh_id = rt->rtr_nh->nh_id;
        return 0;
    }

    return -ENOENT;
}

static int
bridge_entry_make_req(struct vr_route_req *resp, struct vr_bridge_entry *ent)
{
    memset(resp, 0, sizeof(struct vr_route_req));
    resp->rtr_req.rtr_mac_size = VR_ETHER_ALEN;
    resp->rtr_req.rtr_mac = vr_zalloc(VR_ETHER_ALEN, VR_ROUTE_REQ_MAC_OBJECT);
    if (!resp->rtr_req.rtr_mac)
        return -ENOMEM;
    VR_MAC_COPY(resp->rtr_req.rtr_mac, ent->be_key.be_mac);
    resp->rtr_req.rtr_vrf_id = ent->be_key.be_vrf_id;
    if (ent->be_nh)
        resp->rtr_req.rtr_nh_id = ent->be_nh->nh_id;
    resp->rtr_req.rtr_family = AF_BRIDGE;
    resp->rtr_req.rtr_label = ent->be_label;
    resp->rtr_req.rtr_label_flags = ent->be_flags;
    resp->rtr_req.rtr_index = ent->be_hentry.hentry_index;

    return 0;
}

static void
bridge_entry_req_destroy(struct vr_route_req *resp)
{
    if (resp->rtr_req.rtr_mac)
        vr_free(resp->rtr_req.rtr_mac, VR_ROUTE_REQ_MAC_OBJECT);
}

static int
__bridge_table_dump(struct vr_message_dumper *dumper)
{
    struct vr_route_req *req = (struct vr_route_req *)(dumper->dump_req);
    struct vr_route_req resp;
    int ret;
    unsigned int i;
    struct vr_bridge_entry *be;

    for(i = 0; i < (vr_bridge_entries + vr_bridge_oentries); i++) {
        be = (struct vr_bridge_entry *)
                vr_htable_get_hentry_by_index(vn_rtable, i);
        if (!be)
            continue;
        if (be->be_flags & VR_BE_VALID_FLAG) {
            if (be->be_key.be_vrf_id != req->rtr_req.rtr_vrf_id)
                continue;
            if (dumper->dump_been_to_marker == 0) {
                if (VR_MAC_CMP(be->be_key.be_mac, req->rtr_req.rtr_mac)
                        && (be->be_key.be_vrf_id == req->rtr_req.rtr_vrf_id)) {
                    dumper->dump_been_to_marker = 1;
                }
            } else {
                if (!bridge_entry_make_req(&resp, be)) {
                    ret = vr_message_dump_object(dumper, VR_ROUTE_OBJECT_ID, &resp);
                    bridge_entry_req_destroy(&resp);
                    if (ret <= 0) {
                        return ret;
                    }
                }
            }
        }
    }

    return 0;
}

static int
bridge_table_dump(struct vr_rtable * __unsued, struct vr_route_req *rt)
{
    int ret = 0;
    struct vr_message_dumper *dumper;
    char *mac;

    dumper = vr_message_dump_init(&rt->rtr_req);
    if (!dumper) {
        ret = -ENOMEM;
        goto generate_response;
    }

    mac = (char *)(((vr_route_req *)(dumper->dump_req))->rtr_mac);
    if (!mac) {
        ret = -EINVAL;
        goto generate_response;
    }

    if (IS_MAC_ZERO(mac))
        dumper->dump_been_to_marker = 1;

    ret = __bridge_table_dump(dumper);

generate_response:
    vr_message_dump_exit(dumper, ret);

    return 0;
}

vr_hentry_key
bridge_entry_key(vr_htable_t table, vr_hentry_t *entry, unsigned int
        *key_len)
{
    struct vr_bridge_entry *be = CONTAINER_OF(be_hentry,
                        struct vr_bridge_entry, entry);

    if (!entry || (!(be->be_flags & VR_BE_VALID_FLAG)))
        return NULL;

    if (key_len)
        *key_len = sizeof(be->be_key);

    return &be->be_key;
}

int
bridge_table_init(struct vr_rtable *rtable, struct rtable_fspec *fs)
{

    /* If table already exists, dont create again */
    if (rtable->algo_data)
        return 0;

    if (!vr_bridge_oentries)
        vr_bridge_oentries = ((vr_bridge_entries / 5) + 1023) & ~1023;

    rtable->algo_data = vr_htable_create(vrouter_get(0), vr_bridge_entries,
                vr_bridge_oentries, sizeof(struct vr_bridge_entry),
                sizeof(struct vr_bridge_entry_key), 0, bridge_entry_key);

    if (!rtable->algo_data)
        return vr_module_error(-ENOMEM, __FUNCTION__, __LINE__,
                vr_bridge_entries);

    /* Max VRF's does not matter as Bridge table is not per VRF. But
     * still this can be maintained in table
     */
    rtable->algo_max_vrfs = fs->rtb_max_vrfs;
    rtable->algo_add = bridge_table_add;
    rtable->algo_del = bridge_table_delete;
    rtable->algo_lookup = bridge_table_lookup;
    rtable->algo_get = bridge_table_get;
    rtable->algo_dump = bridge_table_dump;

    vr_bridge_lookup = bridge_table_lookup;
    vn_rtable = rtable->algo_data;

    return 0;
}

void
bridge_table_deinit(struct vr_rtable *rtable, struct rtable_fspec *fs,
        bool soft_reset)
{
    if (!vn_rtable)
        return;

    vr_htable_trav(vn_rtable, 0, bridge_table_entry_free, NULL);

    if (!soft_reset) {
        vr_htable_delete(vn_rtable);
        rtable->algo_data = NULL;
        vn_rtable = NULL;
    }

}

unsigned int
vr_bridge_input(struct vrouter *router, struct vr_packet *pkt,
                struct vr_forwarding_md *fmd)
{
    struct vr_route_req rt;
    struct vr_forwarding_md cmd;
    struct vr_nexthop *nh = NULL;
    unsigned short pull_len, overlay_len = VROUTER_OVERLAY_LEN;
    int reason, handled;
    struct vr_vrf_stats *stats;
    l4_pkt_type_t l4_type = L4_TYPE_UNKNOWN;
    int8_t *dmac;

    dmac = (int8_t *) pkt_data(pkt);

    pull_len = 0;
    if ((pkt->vp_type == VP_TYPE_IP) || (pkt->vp_type == VP_TYPE_IP6)) {
        pull_len = pkt_get_network_header_off(pkt) - pkt_head_space(pkt);
        if (pull_len && !pkt_pull(pkt, pull_len)) {
            vr_pfree(pkt, VP_DROP_PULL);
            return 0;
        }

        if (fmd->fmd_dscp < 0) {
            if (pkt->vp_type == VP_TYPE_IP) {
                fmd->fmd_dscp =
                    vr_inet_get_tos((struct vr_ip *)pkt_network_header(pkt));
            } else if (pkt->vp_type == VP_TYPE_IP6) {
                fmd->fmd_dscp =
                    vr_inet6_get_tos((struct vr_ip6 *)pkt_network_header(pkt));
            }
        }

    } else {
        if (fmd->fmd_dotonep < 0) {
            fmd->fmd_dotonep = vr_vlan_get_tos(pkt_data(pkt));
        }
    }

    /* Do the bridge lookup for the packets not meant for "me" */
    if (!fmd->fmd_to_me) {

        /*
         * If DHCP packet coming from VM, Trap it to Agent before doing the bridge
         * lookup itself
         */
        if (vif_is_virtual(pkt->vp_if)) {
            if (pkt->vp_type == VP_TYPE_IP)
                l4_type = vr_ip_well_known_packet(pkt);
            else if (pkt->vp_type == VP_TYPE_IP6)
                l4_type = vr_ip6_well_known_packet(pkt);

            if (l4_type == L4_TYPE_DHCP_REQUEST) {
                if (pkt->vp_if->vif_flags & VIF_FLAG_DHCP_ENABLED) {
                    vr_trap(pkt, fmd->fmd_dvrf,  AGENT_TRAP_L3_PROTOCOLS, NULL);
                    return 0;
                }
            }
        }

        rt.rtr_req.rtr_label_flags = 0;
        rt.rtr_req.rtr_index = VR_BE_INVALID_INDEX;
        rt.rtr_req.rtr_mac_size = VR_ETHER_ALEN;
        rt.rtr_req.rtr_mac = dmac;
        /* If multicast L2 packet, use broadcast composite nexthop */
        if (IS_MAC_BMCAST(rt.rtr_req.rtr_mac))
            rt.rtr_req.rtr_mac = (int8_t *)vr_bcast_mac;
        rt.rtr_req.rtr_vrf_id = fmd->fmd_dvrf;

        nh = vr_bridge_lookup(fmd->fmd_dvrf, &rt);
        if (!nh || nh->nh_type == NH_DISCARD) {

            /* If Flooding of unknown unicast not allowed, drop the packet */
            if (!vr_unknown_uc_flood(pkt->vp_if, pkt->vp_nh) ||
                                 IS_MAC_BMCAST(rt.rtr_req.rtr_mac)) {
                vr_pfree(pkt, VP_DROP_L2_NO_ROUTE);
                return 0;
            }

            rt.rtr_req.rtr_mac = (int8_t *)vr_bcast_mac;
            rt.rtr_req.rtr_index = VR_BE_INVALID_INDEX;
            nh = vr_bridge_lookup(fmd->fmd_dvrf, &rt);
            if (!nh) {
                vr_pfree(pkt, VP_DROP_L2_NO_ROUTE);
                return 0;
            }
            stats = vr_inet_vrf_stats(fmd->fmd_dvrf, pkt->vp_cpu);
            if (stats)
                stats->vrf_uuc_floods++;

            /* Treat this unknown unicast packet as multicast */
            pkt->vp_flags |= VP_FLAG_MULTICAST;
        }

        if (nh->nh_type != NH_L2_RCV)
            overlay_len = VROUTER_L2_OVERLAY_LEN;
    }


    /* Adjust MSS for V4 and V6 packets */
    if ((pkt->vp_type == VP_TYPE_IP) || (pkt->vp_type == VP_TYPE_IP6)) {

        if (vif_is_virtual(pkt->vp_if) &&
                vr_from_vm_mss_adj && vr_pkt_from_vm_tcp_mss_adj) {

            if ((reason = vr_pkt_from_vm_tcp_mss_adj(pkt, overlay_len))) {
                vr_pfree(pkt, reason);
                return 0;
            }
        }

        if (fmd->fmd_to_me) {
            handled = vr_l3_input(pkt, fmd);
            if (!handled) {
                vr_pfree(pkt, VP_DROP_NOWHERE_TO_GO);
            }
            return 0;
        }
    }


    /*
     * If there is a label attached to this bridge entry add the
     * label
     */
    if (rt.rtr_req.rtr_label_flags & VR_BE_LABEL_VALID_FLAG) {
        if (!fmd) {
            vr_init_forwarding_md(&cmd);
            fmd = &cmd;
        }
        vr_forwarding_md_set_label(fmd, rt.rtr_req.rtr_label,
                VR_LABEL_TYPE_UNKNOWN);
    }

    if (pull_len && !pkt_push(pkt, pull_len)) {
        vr_pfree(pkt, VP_DROP_PUSH);
        return 0;
    }

    nh_output(pkt, nh, fmd);
    return 0;
}

