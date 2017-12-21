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
#include "vr_hash.h"

#if defined(__linux__) && defined(__KERNEL__)
extern short vr_bridge_table_major;
#endif
unsigned char *vr_bridge_table_path;

unsigned int vr_bridge_entries = VR_DEF_BRIDGE_ENTRIES;
unsigned int vr_bridge_oentries = 0;
static vr_htable_t vn_rtable;
char vr_bcast_mac[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

int bridge_table_init(struct vr_rtable *, struct rtable_fspec *);
void bridge_table_deinit(struct vr_rtable *, struct rtable_fspec *, bool);
struct vr_bridge_entry *vr_find_bridge_entry(struct vr_bridge_entry_key *);
struct vr_bridge_entry *vr_find_free_bridge_entry(unsigned int, char *);
extern struct vr_vrf_stats *(*vr_inet_vrf_stats)(unsigned short, unsigned int);
extern l4_pkt_type_t vr_ip_well_known_packet(struct vr_packet *);
extern l4_pkt_type_t vr_ip6_well_known_packet(struct vr_packet *);

void *vr_bridge_table, *vr_bridge_otable;

void *
vr_bridge_get_va(struct vrouter *router, uint64_t offset)
{
    return vr_htable_get_address(vn_rtable, offset);
}

unsigned int
vr_bridge_table_size(struct vrouter *router)
{
    return vr_htable_size(vn_rtable);
}

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

static struct vr_bridge_entry *
bridge_add(unsigned int router_id, unsigned int vrf,
        uint8_t *mac, int nh_id)
{
    struct vr_bridge_entry *be;
    struct vr_bridge_entry_key key;
    struct vr_nexthop *old_nh;

    VR_MAC_COPY(key.be_mac, mac);
    key.be_vrf_id = vrf;
    be = vr_find_bridge_entry(&key);
    if (!be) {
        be = vr_find_free_bridge_entry(vrf, mac);
        if (!be)
            return NULL;

        VR_MAC_COPY(be->be_key.be_mac, mac);
        be->be_key.be_vrf_id = vrf;
        be->be_packets = 0;
        be->be_flags = VR_BE_VALID_FLAG;
        be->be_nh_id = -1;
    }

    /* Un ref the old nexthop */
    if (be->be_nh_id != nh_id) {
        old_nh = be->be_nh;
        be->be_nh = vrouter_get_nexthop(router_id, nh_id);
        if (be->be_nh) {
            be->be_nh_id = be->be_nh->nh_id;
        } else {
            be->be_nh_id = -1;
        }

        if (be->be_flags & VR_BE_MAC_MOVED_FLAG) {
            be->be_flags &= ~VR_BE_MAC_MOVED_FLAG;
        }

        if (old_nh)
            vrouter_put_nexthop(old_nh);
    }

    return be;
}

static int
__bridge_table_add(struct vr_route_req *rt)
{
    int ret;
    unsigned short flags, i;

    struct vr_bridge_entry *be;

    be = bridge_add(rt->rtr_req.rtr_rid, rt->rtr_req.rtr_vrf_id,
            rt->rtr_req.rtr_mac, rt->rtr_req.rtr_nh_id);
    if (!be)
        return -ENOMEM;

    rt->rtr_req.rtr_label_flags =
        VR_BRIDGE_FLAG_MASK(rt->rtr_req.rtr_label_flags);

    if (rt->rtr_req.rtr_label_flags & VR_BE_LABEL_VALID_FLAG)
        be->be_label = rt->rtr_req.rtr_label;

    /*
     * attempt the change for some number of times, if the set
     * turns out to be contested
     */
    ret = -EAGAIN;
    for (i = 0; i < 10; i++) {
        flags = be->be_flags;
        if (vr_sync_bool_compare_and_swap_16u(&be->be_flags, flags,
                VR_BE_VALID_FLAG | rt->rtr_req.rtr_label_flags)) {
            ret = 0;
            break;
        }
    }

    rt->rtr_req.rtr_index = be->be_hentry.hentry_index;

    return ret;
}

static int
bridge_table_add(struct vr_rtable * _unused, struct vr_route_req *rt)
{
    int ret;

    if (!vn_rtable)
        return -EINVAL;

    if (rt->rtr_req.rtr_mac_size != VR_ETHER_ALEN)
        return -EINVAL;

    if (IS_MAC_ZERO(rt->rtr_req.rtr_mac))
        return -EINVAL;

    rt->rtr_nh = vrouter_get_nexthop(rt->rtr_req.rtr_rid,
            rt->rtr_req.rtr_nh_id);
    if (!rt->rtr_nh)
        return -ENOENT;

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
        be->be_nh_id = -1;
        vrouter_put_nexthop(nh);
    }

    be->be_packets = 0;
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

    if (rt->rtr_req.rtr_mac_size != VR_ETHER_ALEN)
        return -EINVAL;

    VR_MAC_COPY(key.be_mac, rt->rtr_req.rtr_mac);
    key.be_vrf_id = rt->rtr_req.rtr_vrf_id;

    be = vr_find_bridge_entry(&key);
    if (!be)
        return -ENOENT;

    bridge_table_entry_free(vn_rtable, (vr_hentry_t *)be, 0, NULL);
    return 0;
}

static void
bridge_update_route_req(struct vr_bridge_entry *be, struct vr_route_req *rt)
{
    rt->rtr_req.rtr_label_flags = be->be_flags;
    rt->rtr_req.rtr_label = be->be_label;
    rt->rtr_nh = be->be_nh;
    if (rt->rtr_nh)
        rt->rtr_req.rtr_nh_id = rt->rtr_nh->nh_id;
    if (rt->rtr_req.rtr_index != VR_BE_INVALID_INDEX) {
        if (rt->rtr_req.rtr_mac) {
            VR_MAC_COPY(rt->rtr_req.rtr_mac, be->be_key.be_mac);
        }
    } else {
        rt->rtr_req.rtr_index = be->be_hentry.hentry_index;
    }

    return;
}

static struct vr_bridge_entry *
__bridge_lookup(unsigned int vrf_id, struct vr_route_req *rt)
{
    struct vr_bridge_entry *be;
    struct vr_bridge_entry_key key;

    rt->rtr_req.rtr_label_flags = 0;
    rt->rtr_nh = NULL;

    if (rt->rtr_req.rtr_index != VR_BE_INVALID_INDEX) {
        be = (struct vr_bridge_entry *)
             vr_htable_get_hentry_by_index(vn_rtable, rt->rtr_req.rtr_index);
    } else {
        VR_MAC_COPY(key.be_mac, rt->rtr_req.rtr_mac);
        key.be_vrf_id = rt->rtr_req.rtr_vrf_id;
        be = vr_find_bridge_entry(&key);
    }

    return be;
}


static struct vr_nexthop *
bridge_table_lookup(unsigned int vrf_id, struct vr_route_req *rt)
{
    struct vr_bridge_entry *be;

    be = __bridge_lookup(vrf_id, rt);
    if (be)
        bridge_update_route_req(be, rt);

    return rt->rtr_nh;
}

struct vr_nexthop *
vr_bridge_lookup(unsigned int vrf_id, struct vr_route_req *rt)
{
    if (!vn_rtable)
        return NULL;

    return bridge_table_lookup(vrf_id, rt);
}

static struct vr_bridge_entry *
bridge_lookup(uint8_t *mac, struct vr_forwarding_md *fmd)
{
    struct vr_route_req rt;
    struct vr_bridge_entry *be;

    rt.rtr_req.rtr_label_flags = 0;
    rt.rtr_req.rtr_index = VR_BE_INVALID_INDEX;
    rt.rtr_req.rtr_mac_size = VR_ETHER_ALEN;
    rt.rtr_req.rtr_mac = mac;
    /* If multicast L2 packet, use broadcast composite nexthop */
    if (IS_MAC_BMCAST(rt.rtr_req.rtr_mac))
        rt.rtr_req.rtr_mac = (int8_t *)vr_bcast_mac;
    rt.rtr_req.rtr_vrf_id = fmd->fmd_dvrf;
    be = __bridge_lookup(rt.rtr_req.rtr_vrf_id, &rt);

    if (be && fmd) {
        if (be->be_flags & VR_BE_LABEL_VALID_FLAG)
            vr_fmd_set_label(fmd, be->be_label, VR_LABEL_TYPE_UNKNOWN);
        if (be->be_flags & VR_BE_L2_CONTROL_DATA_FLAG)
            vr_fmd_update_l2_control_data(fmd, true);
    }

    return be;
}

struct vr_nexthop *
__vrouter_bridge_lookup(unsigned int vrf_id, unsigned char *mac)
{
    struct vr_route_req rt;

    if (!mac)
        return NULL;

    rt.rtr_req.rtr_label_flags = 0;
    rt.rtr_req.rtr_index = VR_BE_INVALID_INDEX;
    rt.rtr_req.rtr_mac_size = VR_ETHER_ALEN;
    rt.rtr_req.rtr_mac = mac;
    /* If multicast L2 packet, use broadcast composite nexthop */
    if (IS_MAC_BMCAST(rt.rtr_req.rtr_mac))
        rt.rtr_req.rtr_mac = (int8_t *)vr_bcast_mac;
   rt.rtr_req.rtr_vrf_id = vrf_id;

    return vr_bridge_lookup(vrf_id,  &rt);
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

int
vr_bridge_set_route_flags(struct vr_bridge_entry *be, unsigned short flags)
{
    unsigned short be_flags, be_flags_old;

    if (be) {
        be_flags = be_flags_old = be->be_flags;
        if (be_flags & VR_BE_VALID_FLAG) {
            if ((be_flags & flags) == flags)
                return -EEXIST;

            flags = VR_BRIDGE_FLAG_MASK(flags);
            be_flags = vr_sync_val_compare_and_swap_16u(&be->be_flags, be_flags,
                    flags | be_flags);

            if ((be_flags & flags) == flags)
                return -EEXIST;

            if (be_flags == be_flags_old)
                return 0;
        }
    }

    return -EINVAL;
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
    if (nh)
        return 0;

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

    if (rt->rtr_req.rtr_mac_size != VR_ETHER_ALEN)
        return -EINVAL;

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

static void
vr_bridge_table_data_destroy(vr_bridge_table_data *data)
{
    if (data) {
        if (data->btable_file_path) {
            vr_free(data->btable_file_path, VR_BRIDGE_TABLE_DATA_OBJECT);
            data->btable_file_path = NULL;
        }
        vr_free(data, VR_BRIDGE_TABLE_DATA_OBJECT);
    }

    return;
}

static vr_bridge_table_data *
vr_bridge_table_data_get(void)
{
    vr_bridge_table_data *data = vr_zalloc(sizeof(vr_bridge_table_data),
                VR_BRIDGE_TABLE_DATA_OBJECT);
    if (!data)
        return NULL;

    if (vr_bridge_table_path) {
        data->btable_file_path = vr_zalloc(VR_UNIX_PATH_MAX,
                VR_BRIDGE_TABLE_DATA_OBJECT);
        if (!data->btable_file_path) {
            goto exit_func;
        }
    }

    return data;

exit_func:
    vr_bridge_table_data_destroy(data);
    return NULL;
}


void
vr_bridge_table_data_process(void *s_req)
{
    int ret = 0;
    struct vrouter *router;
    vr_bridge_table_data *resp = NULL, *req = (vr_bridge_table_data *)s_req;

    router = vrouter_get(req->btable_rid);
    if (!router) {
        ret = -EINVAL;
        goto generate_response;
    }

    resp = vr_bridge_table_data_get();
    if (!resp) {
        ret = -ENOMEM;
        goto generate_response;
    }

    resp->btable_op = req->btable_op;
    switch (req->btable_op) {
    case SANDESH_OP_GET:
        resp->btable_size = vr_bridge_table_size(router);
#if defined(__linux__) && defined(__KERNEL__)
        resp->btable_dev = vr_bridge_table_major;
#endif
        if (vr_bridge_table_path) {
            strncpy(resp->btable_file_path, vr_bridge_table_path,
                    VR_UNIX_PATH_MAX - 1);
        }
        break;

    default:
        ret = -EINVAL;
        break;
    }

generate_response:
    vr_message_response(VR_BRIDGE_TABLE_DATA_OBJECT_ID, resp, ret, false);
    if (resp) {
        vr_bridge_table_data_destroy(resp);
        resp = NULL;
    }

    return;
}

int
bridge_table_init(struct vr_rtable *rtable, struct rtable_fspec *fs)
{

    /* If table already exists, dont create again */
    if (rtable->algo_data)
        return 0;

    if (!vr_bridge_oentries)
        vr_bridge_oentries = ((vr_bridge_entries / 5) + 1023) & ~1023;

    if (!vr_bridge_table && vr_huge_page_mem_get) {
        vr_bridge_table = vr_huge_page_mem_get(VR_BRIDGE_TABLE_SIZE +
                VR_BRIDGE_OFLOW_TABLE_SIZE);
        if (vr_bridge_table)
            vr_bridge_otable = (unsigned char *)vr_bridge_table + VR_BRIDGE_TABLE_SIZE;
    }

    rtable->algo_data = vr_htable_attach(vrouter_get(0), vr_bridge_entries,
                vr_bridge_table, vr_bridge_oentries, vr_bridge_otable,
                sizeof(struct vr_bridge_entry),
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

    vn_rtable = rtable->algo_data;

    return 0;
}

void
bridge_table_deinit(struct vr_rtable *rtable, struct rtable_fspec *fs,
        bool soft_reset)
{
    if (!vn_rtable)
        return;

    vr_htable_reset(vn_rtable, bridge_table_entry_free, NULL);

    if (!soft_reset) {
        vr_htable_delete(vn_rtable);
        rtable->algo_data = NULL;
        vn_rtable = NULL;
    }

}

static void
bridge_table_unlock(struct vr_interface *vif, uint8_t *mac, int cpu)
{
    uint8_t *bridge_table_lock = vif->vif_bridge_table_lock;

    if (cpu < 0 || !bridge_table_lock)
        return;

    bridge_table_lock[cpu] = 0;

    return;
}

static int
bridge_table_lock(struct vr_interface *vif, uint8_t *mac)
{
    uint8_t lock = 1, *bridge_table_lock = vif->vif_bridge_table_lock;
    uint32_t hash;
    uint64_t t1s, t1ns, t2s, t2ns, diff;

    if (!bridge_table_lock)
        return -EINVAL;

    hash = vr_hash(mac, VR_ETHER_ALEN, 0);
    hash %= vr_num_cpus;

    vr_get_mono_time(&t1s, &t1ns);
    while (lock) {
        lock = vr_sync_lock_test_and_set_8u(&bridge_table_lock[hash], lock);
        if (lock) {
            vr_get_mono_time(&t2s, &t2ns);
            if (t2ns >= t1ns) {
                diff = t2ns - t1ns;
            } else {
                diff = 999999999 - t1ns + t2ns;
            }

            if (diff >= 50000) {
                return -EINVAL;
            }
        }
    }

    return hash;
}

mac_learn_t
vr_bridge_learn(struct vrouter *router, struct vr_packet *pkt,
        struct vr_eth *eth, struct vr_forwarding_md *fmd)
{
    int lock, valid_src;
    unsigned int trap_reason;
    bool trap = false, root = false;
    mac_learn_t ml_res = MAC_EXISTS;
    struct vr_packet *pkt_c;
    struct vr_nexthop *nh = NULL;
    struct vr_bridge_entry *be;

    if (!eth)
        return MAC_LEARN_FAILURE;

    if (IS_MAC_BMCAST(eth->eth_smac))
        return MAC_LEARN_FAILURE;

    vr_fmd_update_etree(fmd, true);
    if (vif_is_virtual(pkt->vp_if)) {
        if (pkt->vp_if->vif_flags & VIF_FLAG_ETREE_ROOT)
            root = true;
        vr_fmd_update_etree_root(fmd, root);
    }

    be = bridge_lookup(eth->eth_smac, fmd);
    if (be) {
        nh = be->be_nh;
    }

    if (!nh) {
        be = bridge_lookup((uint8_t *)vr_bcast_mac, fmd);
        if (be) {
            nh = be->be_nh;
        }

        if (!nh)
            return MAC_LEARN_FAILURE;

        lock = bridge_table_lock(pkt->vp_if, eth->eth_smac);
        if (lock < 0)
            return MAC_LEARN_FAILURE;

        be = bridge_add(0, fmd->fmd_dvrf, eth->eth_smac, nh->nh_id);
        if (be)
            be->be_flags |= VR_BE_MAC_NEW_FLAG;
        bridge_table_unlock(pkt->vp_if, eth->eth_smac, lock);
        if (!be)
            return MAC_LEARN_FAILURE;

        trap_reason = AGENT_TRAP_MAC_LEARN;
        trap = true;
        ml_res = MAC_LEARNT;
    } else {
        if (!(be->be_flags & VR_BE_MAC_MOVED_FLAG) && (nh->nh_validate_src)) {
            valid_src = nh->nh_validate_src(pkt, nh, fmd, NULL);
            if (valid_src != NH_SOURCE_VALID) {
                if (!vr_bridge_set_route_flags(be, VR_BE_MAC_MOVED_FLAG)) {
                    /* trap the packet for mac move */
                    trap_reason = AGENT_TRAP_MAC_MOVE;
                    trap = true;
                }
            }
        }
        if (be->be_flags & VR_BE_MAC_MOVED_FLAG)
            ml_res = MAC_MOVED;
    }

    vr_sync_fetch_and_add_64u(&be->be_packets, 1);

    if (trap) {
        pkt_c = pkt_cow(pkt, 0);
        if (!pkt_c) {
            pkt_c = pkt;
            ml_res = MAC_TRAPPED;
        }

        vr_trap(pkt_c, fmd->fmd_dvrf,
                trap_reason, (void *)&be->be_hentry.hentry_index);
    }


    return ml_res;
}

unsigned int
vr_bridge_input(struct vrouter *router, struct vr_packet *pkt,
                struct vr_forwarding_md *fmd)
{
    int reason, handled;
    l4_pkt_type_t l4_type = L4_TYPE_UNKNOWN;
    unsigned short pull_len, overlay_len = VROUTER_OVERLAY_LEN;
    int8_t *dmac;
    mac_learn_t ml_res;
    struct vr_bridge_entry *be;
    struct vr_nexthop *nh = NULL;
    struct vr_vrf_stats *stats;

    if ((pkt->vp_type == VP_TYPE_IP) || (pkt->vp_type == VP_TYPE_IP6)) {
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

    if (!fmd->fmd_to_me) {
        if ((pkt->vp_if->vif_flags & VIF_FLAG_MAC_LEARN) ||
                (pkt->vp_nh && (pkt->vp_nh->nh_flags & NH_FLAG_MAC_LEARN))) {
            ml_res = vr_bridge_learn(router, pkt,
                    (struct vr_eth *)pkt_data(pkt), fmd);
            if (ml_res == MAC_TRAPPED)
                return 0;
        }
    }

    dmac = (int8_t *) pkt_data(pkt);
    pull_len = 0;
    if ((pkt->vp_type == VP_TYPE_IP) || (pkt->vp_type == VP_TYPE_IP6) ||
            (pkt->vp_type == VP_TYPE_ARP)) {
        pull_len = pkt_get_network_header_off(pkt) - pkt_head_space(pkt);
        if (pull_len && !pkt_pull(pkt, pull_len)) {
            vr_pfree(pkt, VP_DROP_PULL);
            return 0;
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

            /*
             * Handle the unicast ARP, coming from VM, not
             * destined to us. Broadcast ARP requests would be handled
             * in L2 multicast nexthop. Multicast ARP on fabric
             * interface also would be handled in L2 multicast nexthop.
             * Unicast ARP packets on fabric interface would be handled
             * in plug routines of interface.
             */
            if ((!IS_MAC_BMCAST(dmac)) ||
                    (pkt->vp_if->vif_flags & VIF_FLAG_MAC_PROXY)) {
                handled = 0;
                if (pkt->vp_type == VP_TYPE_ARP) {
                    handled = vr_arp_input(pkt, fmd, dmac);
                } else if (l4_type == L4_TYPE_NEIGHBOUR_SOLICITATION) {
                    handled = vr_neighbor_input(pkt, fmd, dmac);
                }

                if (handled)
                    return 0;
            }
        }

        if (IS_MAC_BMCAST(dmac) && (pkt->vp_if->vif_mcast_vrf != 65535))
            fmd->fmd_dvrf = pkt->vp_if->vif_mcast_vrf;

        be = bridge_lookup(dmac, fmd);
        if (be)
            nh = be->be_nh;

        if (!nh || nh->nh_type == NH_DISCARD) {

            /* If Flooding of unknown unicast not allowed, drop the packet */
            if (!vr_unknown_uc_flood(pkt->vp_if, pkt->vp_nh) ||
                                 IS_MAC_BMCAST(dmac)) {
                vr_pfree(pkt, VP_DROP_L2_NO_ROUTE);
                return 0;
            }

            be = bridge_lookup(vr_bcast_mac, fmd);
            if (!be || !(nh = be->be_nh)) {
                vr_pfree(pkt, VP_DROP_L2_NO_ROUTE);
                return 0;
            }
            stats = vr_inet_vrf_stats(fmd->fmd_dvrf, pkt->vp_cpu);
            if (stats)
                stats->vrf_uuc_floods++;

            /* Treat this unknown unicast packet as multicast */
            pkt->vp_flags |= VP_FLAG_MULTICAST;
        }

        if (be)
            vr_sync_fetch_and_add_64u(&be->be_packets, 1);

        if (nh->nh_type != NH_L2_RCV)
            overlay_len = VROUTER_L2_OVERLAY_LEN;

        /*
         * If the tunnel is a PBB tunnel, we need to accomodate for Itag
         * and an extra ethernet (for Bmac) + Vlan header
         */
        if (nh->nh_flags & NH_FLAG_TUNNEL_PBB) {
            overlay_len += VR_ETHER_HLEN + sizeof(struct vr_vlan_hdr) +
                            sizeof(struct vr_pbb_itag);
        }
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

    if (pull_len && !pkt_push(pkt, pull_len)) {
        vr_pfree(pkt, VP_DROP_PUSH);
        return 0;
    }

    nh_output(pkt, nh, fmd);
    return 0;
}
