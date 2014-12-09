/*
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#include <vr_os.h>
#include <vr_packet.h>
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

struct vr_dummy_bridge_entry {
    struct vr_bridge_entry_key be_key;
    uint32_t be_label;
    struct vr_nexthop *be_nh;
    unsigned short be_flags;
} __attribute__((packed));

#define VR_BRIDGE_ENTRY_PACK (32 - sizeof(struct vr_dummy_bridge_entry))

struct vr_bridge_entry {
    struct vr_bridge_entry_key be_key;
    uint32_t be_label;
    struct vr_nexthop *be_nh;
    unsigned short be_flags;
    unsigned char be_pack[VR_BRIDGE_ENTRY_PACK];
} __attribute__((packed));

#define VR_DEF_BRIDGE_ENTRIES          (64 * 1024)
#define VR_DEF_BRIDGE_OENTRIES         (4 * 1024)

unsigned int vr_bridge_entries = VR_DEF_BRIDGE_ENTRIES;
unsigned int vr_bridge_oentries = VR_DEF_BRIDGE_OENTRIES;
static vr_htable_t vn_rtable;

extern int vr_reach_l3_hdr(struct vr_packet *, unsigned short *);

struct vr_nexthop *(*vr_bridge_lookup)(unsigned int, struct vr_route_req *, 
        struct vr_packet *);
struct vr_bridge_entry *vr_find_bridge_entry(struct vr_bridge_entry_key *);
int bridge_table_init(struct vr_rtable *, struct rtable_fspec *);
void bridge_table_deinit(struct vr_rtable *, struct rtable_fspec *, bool);
unsigned int vr_l2_input(unsigned short, struct vr_packet *,
                struct vr_forwarding_md *);
struct vr_bridge_entry *vr_find_bridge_entry(struct vr_bridge_entry_key *);
struct vr_bridge_entry *vr_find_free_bridge_entry(unsigned int, char *);

static bool
bridge_entry_valid(vr_htable_t htable, vr_hentry_t hentry, 
                                              unsigned int index)
{
    struct vr_bridge_entry *be = (struct vr_bridge_entry *)hentry;
    if (!htable || !be)
        return false;

    if (be->be_flags & VR_BE_FLAG_VALID)
        return true;

    return false;
}

struct vr_bridge_entry *
vr_find_bridge_entry(struct vr_bridge_entry_key *key) 
{
    if (!vn_rtable || !key)
        return NULL;

    return vr_find_hentry(vn_rtable, key, NULL);
}

struct vr_bridge_entry *
vr_find_free_bridge_entry(unsigned int vrf_id, char *mac)
{
    struct vr_bridge_entry_key key;

    if (!vn_rtable || !mac)
        return NULL;

    key.be_vrf_id = vrf_id;
    VR_MAC_COPY(key.be_mac, mac);
    return vr_find_free_hentry(vn_rtable, &key, NULL);
}

static int
__bridge_table_add(struct vr_route_req *rt)
{
    struct vr_bridge_entry *be;
    struct vr_nexthop *old_nh;
    struct vr_bridge_entry_key key;

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
        be->be_flags |= VR_BE_FLAG_VALID;
    }

    if (be->be_nh != rt->rtr_nh) {

        /* Un ref the old nexthop */
        old_nh = be->be_nh;
        be->be_nh = vrouter_get_nexthop(rt->rtr_req.rtr_rid,
                                        rt->rtr_req.rtr_nh_id);
        if (old_nh)
            vrouter_put_nexthop(old_nh);
    }

    if (rt->rtr_req.rtr_label_flags & VR_RT_LABEL_VALID_FLAG) {
        be->be_label = rt->rtr_req.rtr_label;
        be->be_flags |= VR_BE_FLAG_LABEL_VALID;
    }

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

    if ((!(rt->rtr_req.rtr_label_flags & VR_RT_LABEL_VALID_FLAG)) &&
        (rt->rtr_nh->nh_type == NH_TUNNEL)) {
        vrouter_put_nexthop(rt->rtr_nh);
        return -EINVAL;
    }

    ret = __bridge_table_add(rt);
    vrouter_put_nexthop(rt->rtr_nh);
    return ret;
}

static void
bridge_table_entry_free(vr_htable_t table, vr_hentry_t hentry,
        unsigned int index, void *data)
{
    struct vr_bridge_entry *be = (struct vr_bridge_entry *)hentry; 
    if (!be)
        return;

    /* Mark this entry as invalid */
    be->be_flags &= ~VR_BE_FLAG_VALID;

    if (be->be_nh)
        vrouter_put_nexthop(be->be_nh);

    memset(be, 0, sizeof(struct vr_bridge_entry));
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

    bridge_table_entry_free(vn_rtable, (vr_hentry_t )be, 0, NULL);
    return 0;
}

static struct vr_nexthop *
bridge_table_lookup(unsigned int vrf_id, struct vr_route_req *rt,
                struct vr_packet *pkt)
{
    struct vr_bridge_entry *be;
    struct vr_bridge_entry_key key;

    VR_MAC_COPY(key.be_mac, rt->rtr_req.rtr_mac);
    key.be_vrf_id = rt->rtr_req.rtr_vrf_id;

    be = vr_find_bridge_entry(&key);
    if (be) {
        if (be->be_flags & VR_BE_FLAG_LABEL_VALID)
            rt->rtr_req.rtr_label_flags = VR_RT_LABEL_VALID_FLAG;
        rt->rtr_req.rtr_label = be->be_label;
        rt->rtr_nh = be->be_nh;
        return be->be_nh;
    }

    return NULL;
}

static int
bridge_table_get(unsigned int vrf_id, struct vr_route_req *rt)
{
    struct vr_nexthop *nh;

    rt->rtr_req.rtr_nh_id = NH_DISCARD_ID;
    nh = bridge_table_lookup(vrf_id, rt, NULL);
    if (nh)
        rt->rtr_req.rtr_nh_id = nh->nh_id;
    return 0;
}

static int
bridge_entry_make_req(struct vr_route_req *resp, struct vr_bridge_entry *ent)
{
    memset(resp, 0, sizeof(struct vr_route_req));
    resp->rtr_req.rtr_mac_size = VR_ETHER_ALEN;
    resp->rtr_req.rtr_mac = vr_zalloc(VR_ETHER_ALEN);
    if (!resp->rtr_req.rtr_mac)
        return -ENOMEM;
    VR_MAC_COPY(resp->rtr_req.rtr_mac, ent->be_key.be_mac);
    resp->rtr_req.rtr_vrf_id = ent->be_key.be_vrf_id;
    if (ent->be_nh)
        resp->rtr_req.rtr_nh_id = ent->be_nh->nh_id;
    resp->rtr_req.rtr_family = AF_BRIDGE;
    resp->rtr_req.rtr_label = ent->be_label;
    if (ent->be_flags & VR_BE_FLAG_LABEL_VALID)
        resp->rtr_req.rtr_label_flags = VR_RT_LABEL_VALID_FLAG;
    return 0;
}

static void
bridge_entry_req_destroy(struct vr_route_req *resp)
{
    if (resp->rtr_req.rtr_mac)
        vr_free(resp->rtr_req.rtr_mac);
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
        be = (struct vr_bridge_entry *) vr_get_hentry_by_index(vn_rtable, i);
        if (!be) 
            continue;
        if (be->be_flags & VR_BE_FLAG_VALID) {
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
    if (IS_MAC_ZERO(mac))
        dumper->dump_been_to_marker = 1;

    ret = __bridge_table_dump(dumper);

generate_response:
    vr_message_dump_exit(dumper, ret);

    return 0;
}

int
bridge_table_init(struct vr_rtable *rtable, struct rtable_fspec *fs)
{

    /* If table already exists, dont create again */
    if (rtable->algo_data)
        return 0;

    rtable->algo_data = vr_htable_create(vr_bridge_entries,
            vr_bridge_oentries, sizeof(struct vr_bridge_entry),
            sizeof(struct vr_bridge_entry_key), bridge_entry_valid);  

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

    /* Add the shortcut to lookup routine */
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
vr_bridge_input(struct vrouter *router, unsigned short vrf,
                struct vr_packet *pkt, struct vr_forwarding_md *fmd)
{
    struct vr_route_req rt;
    struct vr_nexthop *nh;
    struct vr_forwarding_md cmd;
    char bcast_mac[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    char *mac;

    mac = (char *)pkt_data(pkt);
    rt.rtr_req.rtr_mac_size = VR_ETHER_ALEN;
    rt.rtr_req.rtr_mac =(int8_t *) mac;
    /* If multicast L2 packet, use broadcast composite nexthop */
    if (IS_MAC_BMCAST(mac))
        rt.rtr_req.rtr_mac = (int8_t *)bcast_mac;

    rt.rtr_req.rtr_vrf_id = vrf;
    nh = vr_bridge_lookup(vrf, &rt, pkt);
    if (nh) {

        /*
         * If there is a label attached to this bridge entry add the
         * label
         */
        if (rt.rtr_req.rtr_label_flags & VR_RT_LABEL_VALID_FLAG) {
            if (!fmd) {
                vr_init_forwarding_md(&cmd);
                fmd = &cmd;
            }
            fmd->fmd_label = rt.rtr_req.rtr_label;
        }
 
        return nh_output(vrf, pkt, nh, fmd);
    }

    vr_pfree(pkt, VP_DROP_INVALID_NH);
    return 0;
}

