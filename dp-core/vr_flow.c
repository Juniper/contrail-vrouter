/*
 * vr_flow.c -- flow handling
 *
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#include <vr_os.h>
#include <vr_types.h>
#include <vrouter.h>
#include <vr_packet.h>
#include <vr_htable.h>
#include <vr_flow.h>
#include <vr_mirror.h>
#include "vr_interface.h"
#include "vr_sandesh.h"
#include "vr_message.h"
#include "vr_btable.h"
#include "vr_fragment.h"
#include "vr_datapath.h"
#include "vr_hash.h"
#include "vr_ip_mtrie.h"
#include "vr_bridge.h"

#include "vr_offloads.h"

#define VR_NUM_FLOW_TABLES          1

#define VR_NUM_OFLOW_TABLES         1

#define VR_DEF_MAX_FLOW_TABLE_HOLD_COUNT 8192

unsigned int vr_flow_entries = VR_DEF_FLOW_ENTRIES;
unsigned int vr_oflow_entries = 0;

/*
 * host can provide its own memory . Point in case is the DPDK. In DPDK,
 * we allocate the table from hugepages and just ask the flow module to
 * use those tables
 */
void *vr_flow_table;
void *vr_oflow_table;
/*
 * The flow table memory can also be a file that could be mapped. The path
 * is set by somebody and passed to agent for it to map
 */
unsigned char *vr_flow_path;
unsigned int vr_flow_hold_limit = VR_DEF_MAX_FLOW_TABLE_HOLD_COUNT;

#if defined(__linux__) && defined(__KERNEL__)
extern short vr_flow_major;
#endif

uint32_t vr_hashrnd = 0;
int hashrnd_inited = 0;

static void vr_flush_entry(struct vrouter *, struct vr_flow_entry *,
        struct vr_flow_md *, struct vr_forwarding_md *);
static void __vr_flow_flush_hold_queue(struct vrouter *, struct vr_flow_entry *,
        struct vr_forwarding_md *, struct vr_flow_queue *);
static void vr_flow_set_forwarding_md(struct vrouter *, struct vr_flow_entry *,
        unsigned int, struct vr_forwarding_md *);
static int
__vr_flow_schedule_transition(struct vrouter *, struct vr_flow_entry *,
        unsigned int, unsigned short);
static bool vr_flow_is_fat_flow(struct vrouter *, struct vr_packet *,
        struct vr_flow_entry *);

struct vr_flow_entry *vr_find_flow(struct vrouter *, struct vr_flow *,
        uint8_t, unsigned int *);
unsigned int vr_trap_flow(struct vrouter *, struct vr_flow_entry *,
        struct vr_packet *, unsigned int, struct vr_flow_stats *,
        struct vr_packet_node *);

void get_random_bytes(void *buf, int nbytes);

#if defined(__FreeBSD__) || defined(_WIN32)
uint32_t
jhash(void *key, uint32_t length, uint32_t initval)
{
  uint32_t ret = 0;
  int i;
  unsigned char *data = (unsigned char *)key;

  for (i = 0; i < length; i ++)
    ret += data[i];

  return ret;
}
#endif


bool
vr_valid_link_local_port(struct vrouter *router, int family,
                         int proto, int port)
{
    unsigned char data;
    unsigned int tmp;

    if (!router->vr_link_local_ports)
        return false;

    if ((family != AF_INET) ||
        ((proto != VR_IP_PROTO_TCP) && (proto != VR_IP_PROTO_UDP) &&
         (proto != VR_IP_PROTO_ICMP)))
        return false;

    if ((port < VR_DYNAMIC_PORT_START) || (port > VR_DYNAMIC_PORT_END))
        return false;

    tmp = port - VR_DYNAMIC_PORT_START;
    if (proto == VR_IP_PROTO_UDP)
        tmp += (router->vr_link_local_ports_size * 8 / VR_LL_RP_MAX);
    if (proto == VR_IP_PROTO_ICMP)
        tmp += (router->vr_link_local_ports_size * 8 * VR_LL_RP_ICMP_INDEX /
                                                       VR_LL_RP_MAX);

    data = router->vr_link_local_ports[(tmp / 8)];
    if (data & (1 << (tmp % 8)))
        return true;

    return false;
}

static void
vr_clear_link_local_port(struct vrouter *router, int family,
                       int proto, int port)
{
    unsigned char *data;
    unsigned int tmp;

    if (!router->vr_link_local_ports)
        return;

    if ((family != AF_INET) ||
        ((proto != VR_IP_PROTO_TCP) && (proto != VR_IP_PROTO_UDP) &&
         (proto != VR_IP_PROTO_ICMP)))
        return;

    if ((port < VR_DYNAMIC_PORT_START) || (port > VR_DYNAMIC_PORT_END))
        return;

    tmp = port - VR_DYNAMIC_PORT_START;
    if (proto == VR_IP_PROTO_UDP)
        tmp += (router->vr_link_local_ports_size * 8 / VR_LL_RP_MAX);
    if (proto == VR_IP_PROTO_ICMP)
        tmp += ((router->vr_link_local_ports_size * 8 * VR_LL_RP_ICMP_INDEX)/
                                                        VR_LL_RP_MAX);

    data = &router->vr_link_local_ports[(tmp / 8)];
    *data &= (~(1 << (tmp % 8)));

    return;
}

static void
vr_set_link_local_port(struct vrouter *router, int family,
                       int proto, int port)
{
    unsigned char *data;
    unsigned int tmp;

    if (!router->vr_link_local_ports)
        return;

    if ((family != AF_INET) ||
        ((proto != VR_IP_PROTO_TCP) && (proto != VR_IP_PROTO_UDP) &&
         (proto != VR_IP_PROTO_ICMP)))
        return;

    if ((port < VR_DYNAMIC_PORT_START) || (port > VR_DYNAMIC_PORT_END))
        return;

    tmp = port - VR_DYNAMIC_PORT_START;
    if (proto == VR_IP_PROTO_UDP)
        tmp += (router->vr_link_local_ports_size * 8 / VR_LL_RP_MAX);
    if (proto == VR_IP_PROTO_ICMP)
        tmp += ((router->vr_link_local_ports_size * 8 * VR_LL_RP_ICMP_INDEX)/
                                                        VR_LL_RP_MAX);

    data = &router->vr_link_local_ports[tmp / 8];
    *data |= (1 << (tmp % 8));

    return;
}

static void
vr_flow_reset_mirror(struct vrouter *router, struct vr_flow_entry *fe,
                                                            unsigned int index)
{
    if (fe->fe_flags & VR_FLOW_FLAG_MIRROR) {
        fe->fe_mirror_id = VR_MAX_MIRROR_INDICES;
        fe->fe_sec_mirror_id = VR_MAX_MIRROR_INDICES;
        if (fe->fe_mme) {
            vr_mirror_meta_entry_del(router, fe->fe_mme);
            fe->fe_mme = NULL;
            vr_offload_flow_meta_data_set(index, 0, 0, 0);
        }
    }
    fe->fe_flags &= ~VR_FLOW_FLAG_MIRROR;
    fe->fe_mirror_id = VR_MAX_MIRROR_INDICES;
    fe->fe_sec_mirror_id = VR_MAX_MIRROR_INDICES;

    return;
}

static void
vr_init_flow_entry(struct vr_flow_entry *fe)
{
    fe->fe_rflow = -1;
    fe->fe_mirror_id = VR_MAX_MIRROR_INDICES;
    fe->fe_sec_mirror_id = VR_MAX_MIRROR_INDICES;
    fe->fe_ecmp_nh_index = -1;

    return;
}


static void
__vr_flow_reset_entry(struct vrouter *router, struct vr_flow_entry *fe)
{
    if (fe->fe_hold_list) {
        vr_printf("vrouter: Potential memory leak @ %s:%d\n",
                __FILE__, __LINE__);
    }
    fe->fe_hold_list = NULL;
    fe->fe_key.flow_key_len = 0;

    (void)vr_offload_flow_del(fe);

    vr_flow_reset_mirror(router, fe, fe->fe_hentry.hentry_index);
    fe->fe_ecmp_nh_index = -1;
    fe->fe_src_nh_index = NH_DISCARD_ID;
    fe->fe_rflow = -1;
    fe->fe_action = VR_FLOW_ACTION_DROP;
    fe->fe_udp_src_port = 0;
    fe->fe_tcp_flags = 0;
    fe->fe_flags &=
        (VR_FLOW_FLAG_ACTIVE | VR_FLOW_FLAG_EVICTED |
         VR_FLOW_FLAG_NEW_FLOW | VR_FLOW_FLAG_DELETE_MARKED);
    fe->fe_ttl = 0;
    fe->fe_src_info = 0;

    return;
}

static void
vr_flow_reset_entry(struct vrouter *router, struct vr_flow_entry *fe)
{
    __vr_flow_reset_entry(router, fe);
    memset(&fe->fe_stats, 0, sizeof(fe->fe_stats));
    fe->fe_type = VP_TYPE_NULL;
    fe->fe_flags = 0;

    vr_htable_release_hentry(router->vr_flow_table, &fe->fe_hentry);
    return;
}

static void
vr_flow_reset_active_entry(struct vrouter *router, struct vr_flow_entry *fe)
{
    __vr_flow_reset_entry(router, fe);
    vr_htable_release_hentry(router->vr_flow_table, &fe->fe_hentry);
    return;
}


static vr_hentry_key
vr_flow_get_key(vr_htable_t flow_table, vr_hentry_t *entry,
        unsigned int *key_len)
{
    struct vr_flow_entry *fe = CONTAINER_OF(fe_hentry,
                             struct vr_flow_entry, entry);

    if ((fe->fe_flags & VR_FLOW_FLAG_DELETE_MARKED) ||
                    !(fe->fe_flags & VR_FLOW_FLAG_ACTIVE))
        return NULL;

    if (key_len)
        *key_len = fe->fe_key.flow_key_len;

    return &fe->fe_key;
}

uint32_t
vr_flow_get_rflow_src_info(struct vrouter *router,
        struct vr_flow_entry *fe)
{
    struct vr_flow_entry *rfe;

    if ((!fe) || !(fe->fe_flags & VR_RFLOW_VALID))
        return (unsigned int)-1;

    rfe = vr_flow_get_entry(router, fe->fe_rflow);
    if (!rfe)
        return (unsigned int)-1;

    return rfe->fe_src_info;
}

static inline bool
vr_flow_set_active(struct vr_flow_entry *fe)
{
    return vr_sync_bool_compare_and_swap_16u(&fe->fe_flags,
            fe->fe_flags & ~VR_FLOW_FLAG_ACTIVE,
            VR_FLOW_FLAG_ACTIVE | VR_FLOW_FLAG_NEW_FLOW);
}

unsigned int
vr_flow_table_size(struct vrouter *router)
{
    return vr_htable_size(router->vr_flow_table);
}

unsigned int
vr_flow_table_used_oflow_entries(struct vrouter *router)
{
    return vr_htable_used_oflow_entries(router->vr_flow_table);
}

unsigned int
vr_flow_table_used_total_entries(struct vrouter *router)
{
    return vr_htable_used_total_entries(router->vr_flow_table);
}
/*
 * this is used by the mmap code. mmap sees the whole flow table
 * (including the overflow table) as one large table. so, given
 * an offset into that large memory, we should return the correct
 * virtual address
 */
void *
vr_flow_get_va(struct vrouter *router, uint64_t offset)
{
    return vr_htable_get_address(router->vr_flow_table, offset);
}

struct vr_flow_entry *
vr_flow_get_entry(struct vrouter *router, int index)
{
    if (index < 0)
        return NULL;

    return (struct vr_flow_entry *)
            vr_htable_get_hentry_by_index(router->vr_flow_table, index);
}

static inline void
vr_flow_stop_modify(struct vrouter *router, struct vr_flow_entry *fe)
{
    if (!fe)
        return;

    (void)vr_sync_and_and_fetch_16u(&fe->fe_flags, ~VR_FLOW_FLAG_MODIFIED);
    return;
}

static inline bool
vr_flow_start_modify(struct vrouter *router, struct vr_flow_entry *fe)
{
    unsigned short flags;

    flags = fe->fe_flags;
    if (!(flags & (VR_FLOW_FLAG_MODIFIED | VR_FLOW_FLAG_EVICTED |
                    VR_FLOW_FLAG_NEW_FLOW))) {
        if (vr_sync_bool_compare_and_swap_16u(&fe->fe_flags, flags,
                    flags | VR_FLOW_FLAG_MODIFIED)) {
            return true;
        }
    }

    return false;
}


/* Non-static due to RCU callback pointer comparison in vRouter/DPDK */
void
vr_flow_flush_hold_queue(struct vrouter *router, struct vr_flow_entry *fe,
        struct vr_flow_queue *vfq)
{
    struct vr_forwarding_md fmd;

    if (vfq) {
        vr_init_forwarding_md(&fmd);
        vr_flow_set_forwarding_md(router, fe, vfq->vfq_index, &fmd);
        __vr_flow_flush_hold_queue(router, fe, &fmd, vfq);
    }

    return;
}

static void
vr_flow_evict_flow(struct vrouter *router, struct vr_flow_entry *fe)
{
    unsigned short flags;

    if (!fe)
        return;

    if ((fe->fe_flags & VR_FLOW_FLAG_ACTIVE) &&
            (fe->fe_flags & VR_FLOW_FLAG_EVICT_CANDIDATE)) {
        flags = fe->fe_flags | VR_FLOW_FLAG_ACTIVE |
            VR_FLOW_FLAG_EVICT_CANDIDATE;
        if (vr_sync_bool_compare_and_swap_16u(&fe->fe_flags, flags,
                (flags ^ VR_FLOW_FLAG_EVICT_CANDIDATE) |
                VR_FLOW_FLAG_EVICTED)) {
            vr_flow_stop_modify(router, fe);
            vr_flow_reset_active_entry(router, fe);
        }
    }

    return;
}

void
vr_flow_defer_cb(struct vrouter *router, void *arg)
{
    struct vr_defer_data *defer;
    struct vr_flow_entry *fe, *rfe;
    struct vr_flow_queue *vfq;
    struct vr_flow_defer_data *vfdd;

    defer = (struct vr_defer_data *)arg;
    if (!defer)
        return;

    vfdd = (struct vr_flow_defer_data *)defer->vdd_data;
    if (!vfdd)
        return;
    fe = vfdd->vfdd_fe;

    vfq = (struct vr_flow_queue *)vfdd->vfdd_flow_queue;
    if (vfq) {
        vr_flow_flush_hold_queue(router, fe, vfq);
        vr_free(vfq, VR_FLOW_QUEUE_OBJECT);
        vfdd->vfdd_flow_queue = NULL;
    }

    if (vfdd->vfdd_delete) {
        vr_flow_reset_entry(router, fe);
    } else {
        rfe = vr_flow_get_entry(router, fe->fe_rflow);
        vr_flow_evict_flow(router, fe);
        if (rfe)
            vr_flow_evict_flow(router, rfe);
    }

    vr_free(vfdd, VR_FLOW_DEFER_DATA_OBJECT);

    return;
}

static void
vr_flow_reset_evict(struct vrouter *router, struct vr_flow_entry *fe)
{
    unsigned short flags;

    if (!fe)
        return;

    flags = fe->fe_flags;
    if (flags & VR_FLOW_FLAG_EVICT_CANDIDATE) {
        (void)vr_sync_bool_compare_and_swap_16u(&fe->fe_flags, flags,
                (flags ^ VR_FLOW_FLAG_EVICT_CANDIDATE));
    }

    vr_flow_stop_modify(router, fe);

    return;
}

static void
vr_flow_defer(struct vr_flow_md *flmd, struct vr_flow_entry *fe)
{
    struct vr_flow_entry *rfe;
    struct vr_defer_data *vdd = flmd->flmd_defer_data;
    struct vr_flow_defer_data *vfdd;

    if (!vdd || !vdd->vdd_data) {
        if (flmd->flmd_flags & VR_FLOW_FLAG_EVICT_CANDIDATE) {
            if (fe->fe_rflow) {
                rfe = vr_flow_get_entry(flmd->flmd_router, fe->fe_rflow);
                vr_flow_reset_evict(flmd->flmd_router, rfe);
            }
            vr_flow_reset_evict(flmd->flmd_router, fe);
        }

        if (!(flmd->flmd_flags & VR_FLOW_FLAG_ACTIVE)) {
            vr_flow_reset_entry(flmd->flmd_router, fe);
        }

        return;
    }

    vfdd = (struct vr_flow_defer_data *)vdd->vdd_data;
    vfdd->vfdd_fe = fe;

    vr_defer(flmd->flmd_router, vr_flow_defer_cb, (void *)vdd);
    flmd->flmd_defer_data = NULL;

    return;
}

static struct vr_flow_entry *
vr_flow_table_get_free_entry(struct vrouter *router, struct vr_flow *key,
        unsigned int *free_index)
{
    unsigned short flags;
    struct vr_flow_entry *fe;

    fe = (struct vr_flow_entry *)
         vr_htable_find_free_hentry(router->vr_flow_table, key,
                 key->flow_key_len);
    if (fe) {
        flags = fe->fe_flags;
        if (!(flags & VR_FLOW_FLAG_ACTIVE)) {
            if (vr_flow_set_active(fe)) {
                vr_init_flow_entry(fe);
            }
        } else if (flags & VR_FLOW_FLAG_EVICTED) {
            fe->fe_flags = ((flags & ~VR_FLOW_FLAG_EVICTED) |
                     VR_FLOW_FLAG_NEW_FLOW);
        }

        fe->fe_gen_id = (fe->fe_gen_id + 1) %
            (1 << (8 * sizeof(fe->fe_gen_id)));
        *free_index = fe->fe_hentry.hentry_index;
    }

    return fe;
}


static struct vr_flow_entry *
vr_flow_get_free_entry(struct vrouter *router, struct vr_flow *key, uint8_t type,
        bool need_hold, unsigned int *fe_index)
{
    struct vr_flow_entry *fe = NULL;

    fe = vr_flow_table_get_free_entry(router, key, fe_index);
    if (fe) {
        if (need_hold) {
            fe->fe_hold_list = vr_zalloc(sizeof(struct vr_flow_queue),
                    VR_FLOW_QUEUE_OBJECT);
            if (!fe->fe_hold_list) {
                vr_flow_reset_entry(router, fe);
                fe = NULL;
            } else {
                fe->fe_hold_list->vfq_index = *fe_index;
            }
        }

        fe->fe_type = type;
        memcpy(&fe->fe_key, key, key->flow_key_len);
        fe->fe_key.flow_key_len = key->flow_key_len;
    }

    return fe;
}


struct vr_flow_entry *
vr_find_flow(struct vrouter *router, struct vr_flow *key,
        uint8_t type, unsigned int *fe_index)
{
    struct vr_flow_entry *fe;

    fe = (struct vr_flow_entry *)vr_htable_find_hentry(router->vr_flow_table,
                                                    key, key->flow_key_len);
    if (fe) {
        if (fe_index)
            *fe_index = fe->fe_hentry.hentry_index;
    }

    return fe;
}


void
vr_flow_fill_pnode(struct vr_packet_node *pnode, struct vr_packet *pkt,
        struct vr_forwarding_md *fmd)
{
    struct vr_ip *ip = (struct vr_ip *)pkt_inner_network_header(pkt);

    /*
     * we cannot cache nexthop here. to cache, we need to hold reference
     * to the nexthop. to hold a reference, we will have to hold a lock,
     * which we cannot. the only known case of misbehavior if we do not
     * cache is ECMP. when the packet comes from the fabric, the nexthop
     * actually points to a local composite, whereas a route lookup actually
     * returns a different nexthop, in which case the ecmp index will return
     * a bad nexthop. to avoid that, we will cache the label, and reuse it
     */
    pkt->vp_nh = NULL;

    pnode->pl_flags = 0;
    pnode->pl_vif_idx = pkt->vp_if->vif_idx;

    if (fmd) {
        pnode->pl_outer_src_ip = fmd->fmd_outer_src_ip;
        pnode->pl_label = fmd->fmd_label;
        if (vr_fmd_label_is_vxlan_id(fmd))
            pnode->pl_flags |= PN_FLAG_LABEL_IS_VXLAN_ID;
        if (fmd->fmd_to_me)
            pnode->pl_flags |= PN_FLAG_TO_ME;
    }

    if (ip) {
        if (vr_ip_is_ip4(ip)) {
            /*
             * Source IP & Dest IP can change while the packet is in the queue
             * (NAT). For e.g.: when the cloned head of a fragment is enqueued
             * to the assembler and subsequently dequeued by the assembler, the
             * original packet might have undergone a NAT, resulting in wrong
             * hash and thus a wrong search for other fragments of the packet.
             * Hence, store them here for others interested in the original IPs
             */
            pnode->pl_inner_src_ip = ip->ip_saddr;
            pnode->pl_inner_dst_ip = ip->ip_daddr;
            if (vr_ip_fragment_head(ip))
                pnode->pl_flags |= PN_FLAG_FRAGMENT_HEAD;
        } else if (vr_ip_is_ip6(ip)) {
            if (vr_ip6_fragment_head((struct vr_ip6 *)ip))
                pnode->pl_flags |= PN_FLAG_FRAGMENT_HEAD;
        }
    }

    pnode->pl_dscp = fmd->fmd_dscp;
    pnode->pl_dotonep = fmd->fmd_dotonep;
    pnode->pl_vrf = fmd->fmd_dvrf;
    pnode->pl_vlan = fmd->fmd_vlan;
    pnode->pl_mirror_vlan = fmd->fmd_mirror_data;

    vr_sync_synchronize();
    pnode->pl_packet = pkt;

    return;
}

static int
vr_enqueue_flow(struct vrouter *router, struct vr_flow_entry *fe,
        struct vr_packet *pkt, unsigned int index,
        struct vr_flow_stats *stats, struct vr_forwarding_md *fmd)
{
    int ret = 0;
    unsigned int i;
    unsigned short drop_reason = 0;
    struct vr_flow_queue *vfq = fe->fe_hold_list;
    struct vr_packet_node *pnode;

    if (!vfq) {
        drop_reason = VP_DROP_FLOW_UNUSABLE;
        goto drop;
    }

    i = vr_sync_fetch_and_add_32u(&vfq->vfq_entries, 1);
    if (i >= VR_MAX_FLOW_QUEUE_ENTRIES) {
        drop_reason = VP_DROP_FLOW_QUEUE_LIMIT_EXCEEDED;
        goto drop;
    }

    pnode = &vfq->vfq_pnodes[i];
    vr_flow_fill_pnode(pnode, pkt, fmd);
    if (!i)
        ret = vr_trap_flow(router, fe, pkt, index, stats, pnode);

    return ret;
drop:
    vr_pfree(pkt, drop_reason);
    return 0;
}

static flow_result_t
vr_flow_nat(struct vr_flow_entry *fe,
        struct vr_packet *pkt, struct vr_forwarding_md *fmd)
{
    if (pkt->vp_type == VP_TYPE_IP)
        return vr_inet_flow_nat(fe, pkt, fmd);

    vr_pfree(pkt, VP_DROP_FLOW_ACTION_INVALID);
    return FLOW_CONSUMED;
}

static void
vr_flow_set_forwarding_md(struct vrouter *router, struct vr_flow_entry *fe,
        unsigned int index, struct vr_forwarding_md *md)
{
    struct vr_flow_entry *rfe;

    md->fmd_flow_index = index;
    md->fmd_ecmp_nh_index = fe->fe_ecmp_nh_index;
    md->fmd_udp_src_port = fe->fe_udp_src_port;
    if (fe->fe_flags & VR_RFLOW_VALID) {
        rfe = vr_flow_get_entry(router, fe->fe_rflow);
        if (rfe)
            md->fmd_ecmp_src_nh_index = rfe->fe_ecmp_nh_index;
    }

    return;
}

static bool
__vr_flow_mark_evict(struct vrouter *router, struct vr_flow_entry *fe)
{
    unsigned short flags;

    flags = fe->fe_flags;
    if (flags & VR_FLOW_FLAG_ACTIVE) {
        flags = vr_sync_fetch_and_or_16u(&fe->fe_flags,
                VR_FLOW_FLAG_EVICT_CANDIDATE);
        if (!(flags & VR_FLOW_FLAG_EVICT_CANDIDATE)) {
            return true;
        }
    }

    return false;
}

static void
vr_flow_mark_evict(struct vrouter *router, struct vr_flow_entry *fe,
        unsigned int index)
{
    bool evict_forward_flow = true;

    struct vr_flow_entry *rfe = NULL;

    /* start modifying the entry */
    if (!vr_flow_start_modify(router, fe)) {
        return;
    }

    if (fe->fe_rflow >= 0) {
        rfe = vr_flow_get_entry(router, fe->fe_rflow);
        if (rfe) {
            evict_forward_flow = false;
            if (rfe->fe_tcp_flags & VR_FLOW_TCP_DEAD) {
                if (!vr_flow_start_modify(router, rfe)) {
                    /* no modification. hence...*/
                    rfe = NULL;
                } else {
                    /* we do not want hold flows to be evicted, just yet */
                    if (((rfe->fe_rflow == index) || (rfe->fe_rflow < 0)) &&
                            (rfe->fe_action != VR_FLOW_ACTION_HOLD)) {
                        evict_forward_flow = __vr_flow_mark_evict(router, rfe);
                    }
                }
            } else {
                /* no modification. hence...*/
                rfe = NULL;
            }
        }
    }

    /*
     * presence of rfe means that we might need to reset the evict bit
     * or at the minimum reset the modified bit under failure conditions
     */
    if (evict_forward_flow) {
        if (__vr_flow_mark_evict(router, fe)) {
            if (!__vr_flow_schedule_transition(router, fe,
                        index, fe->fe_flags)) {
                return;
            } else {
                goto reset_evict;
            }
        }
    }

    /* stop modifying the forward and the reverse */
    if (rfe)
        vr_flow_stop_modify(router, rfe);
    vr_flow_stop_modify(router, fe);

    return;

reset_evict:
    if (rfe)
        vr_flow_reset_evict(router, rfe);
    vr_flow_reset_evict(router, fe);

    return;
}

int16_t
vr_flow_get_qos(struct vrouter *router, struct vr_packet *pkt,
        struct vr_forwarding_md *fmd)
{
    struct vr_flow_entry *fe;

    if (fmd->fmd_flow_index >= 0) {
        fe = vr_flow_get_entry(router, fmd->fmd_flow_index);
        if (fe)
            return fe->fe_qos_id;
    }

    return -1;
}

static int
vr_rflow_update_ecmp_index(struct vrouter *router, struct vr_flow_entry *fe,
                    unsigned int new_ecmp_index, struct vr_forwarding_md *fmd)
{
    struct vr_flow_entry *rfe;

    if (new_ecmp_index == -1)
        return -1;

    rfe = vr_flow_get_entry(router, fe->fe_rflow);
    if ((!rfe) || (rfe->fe_flags & VR_FLOW_FLAG_DELETE_MARKED))
        return -1;

    rfe->fe_ecmp_nh_index = new_ecmp_index;

    fmd->fmd_ecmp_src_nh_index = new_ecmp_index;

    return 0;
}


int
vr_flow_update_ecmp_index(struct vrouter *router, struct vr_flow_entry *fe,
                       unsigned int new_ecmp_index, struct vr_forwarding_md *fmd)
{

    if (new_ecmp_index == -1)
        return -1;

    if ((!fe) || (fe->fe_flags & VR_FLOW_FLAG_DELETE_MARKED))
        return -1;

    /* If RPF verification is manipulating this flow, let it succeed */
    (void)vr_sync_bool_compare_and_swap_8s(&fe->fe_ecmp_nh_index,
                                fmd->fmd_ecmp_nh_index, new_ecmp_index);

    fmd->fmd_ecmp_nh_index = fe->fe_ecmp_nh_index;

    return 0;
}

static flow_result_t
vr_flow_action(struct vrouter *router, struct vr_flow_entry *fe,
        unsigned int index, struct vr_packet *pkt,
        struct vr_forwarding_md *fmd)
{
    int valid_src, modified_index = -1;
    unsigned int ip_inc_diff_cksum = 0;
    struct vr_ip *ip;
    flow_result_t result = FLOW_CONSUMED;

    struct vr_forwarding_md mirror_fmd;
    struct vr_nexthop *src_nh;

    fmd->fmd_dvrf = fe->fe_vrf;
    /*
     * for now, we will not use dvrf if VRFT is set, because the RPF
     * check needs to happen in the source vrf
     */
    src_nh = __vrouter_get_nexthop(router, fe->fe_src_nh_index);
    if (!src_nh) {
        vr_pfree(pkt, VP_DROP_INVALID_NH);
        goto res;
    }

    if (src_nh->nh_validate_src) {
        valid_src = src_nh->nh_validate_src(pkt, src_nh, fmd, &modified_index);
        if (valid_src == NH_SOURCE_INVALID) {
            vr_pfree(pkt, VP_DROP_INVALID_SOURCE);
            goto res;
        }

        if (valid_src == NH_SOURCE_MISMATCH) {
            valid_src = vr_rflow_update_ecmp_index(router, fe,
                                            modified_index, fmd);
            if (valid_src == -1) {
                vr_pfree(pkt, VP_DROP_INVALID_SOURCE);
                goto res;
            }
        }
    }


    if (fe->fe_flags & VR_FLOW_FLAG_VRFT) {
        if (fmd->fmd_dvrf != fe->fe_dvrf) {
            fmd->fmd_dvrf = fe->fe_dvrf;
            fmd->fmd_to_me = 1;
        }
    }

    if (fe->fe_flags & VR_FLOW_FLAG_MIRROR) {
        if (fe->fe_mirror_id < VR_MAX_MIRROR_INDICES) {
            mirror_fmd = *fmd;
            mirror_fmd.fmd_ecmp_nh_index = -1;
            vr_mirror(router, fe->fe_mirror_id, pkt, &mirror_fmd,
                    MIRROR_TYPE_ACL);
            fmd->fmd_mirror_data = mirror_fmd.fmd_mirror_data;
        }

        if (fe->fe_sec_mirror_id < VR_MAX_MIRROR_INDICES) {
            mirror_fmd = *fmd;
            mirror_fmd.fmd_ecmp_nh_index = -1;
            vr_mirror(router, fe->fe_sec_mirror_id, pkt, &mirror_fmd,
                    MIRROR_TYPE_ACL);
            fmd->fmd_mirror_data = mirror_fmd.fmd_mirror_data;
        }
    }

    switch (fe->fe_action) {
    case VR_FLOW_ACTION_DROP:
        vr_pfree(pkt, VP_DROP_FLOW_ACTION_DROP);
        result = FLOW_CONSUMED;
        break;

    case VR_FLOW_ACTION_FORWARD:
        result = FLOW_FORWARD;
        break;

    case VR_FLOW_ACTION_NAT:
        result = vr_flow_nat(fe, pkt, fmd);
        break;

    default:
        vr_pfree(pkt, VP_DROP_FLOW_ACTION_INVALID);
        result = FLOW_CONSUMED;
        break;
    }

    if (result == FLOW_FORWARD) {
        if (pkt->vp_type == VP_TYPE_IP) {
            ip = (struct vr_ip *)pkt_network_header(pkt);
            if (ip) {
                if (fe->fe_ttl && (fe->fe_ttl != ip->ip_ttl)) {
                    vr_incremental_diff(ip->ip_ttl, fe->fe_ttl, &ip_inc_diff_cksum);
                    ip->ip_ttl = fe->fe_ttl;

                    if (ip_inc_diff_cksum)
                        vr_ip_incremental_csum(ip, ip_inc_diff_cksum);
                }
            }
        }
    }

res:
    if (fe->fe_tcp_flags & VR_FLOW_TCP_DEAD)
        vr_flow_mark_evict(router, fe, index);

    return result;
}


unsigned int
vr_trap_flow(struct vrouter *router, struct vr_flow_entry *fe,
        struct vr_packet *pkt, unsigned int index,
        struct vr_flow_stats *stats, struct vr_packet_node *pnode)
{
    unsigned int trap_reason;

    struct vr_packet *npkt;
    struct vr_flow_trap_arg ta;

    npkt = vr_pclone(pkt);
    if (!npkt) {
        /* Lets manipulate the stats */
        pkt_drop_stats(pkt->vp_if, VP_DROP_TRAP_ORIGINAL, pkt->vp_cpu);
        if (pnode)
            pnode->pl_packet = NULL;
        npkt = pkt;
    }

    vr_preset(npkt);

    switch (fe->fe_flags & VR_FLOW_FLAG_TRAP_MASK) {
    default:
        /*
         * agent needs a method to identify new flows from existing flows.
         * existing flows can be reused (evicted) or the action of such flows
         * can become hold. If existing flows are reused and packet is trapped,
         * agent will not re-evaluate the flow. Hence, agent has to be told
         * that this is a new flow, which we indicate by the trap reason.
         */
        if (fe->fe_flags & VR_FLOW_FLAG_NEW_FLOW) {
            trap_reason = AGENT_TRAP_FLOW_MISS;
            fe->fe_flags ^= VR_FLOW_FLAG_NEW_FLOW;
        } else {
            trap_reason = AGENT_TRAP_FLOW_ACTION_HOLD;
        }

        ta.vfta_index = index;
        if ((fe->fe_type == VP_TYPE_IP) || (fe->fe_type == VP_TYPE_IP6))
            ta.vfta_nh_index = fe->fe_key.flow_nh_id;
        if (stats) {
            ta.vfta_stats = *stats;
        } else {
            ta.vfta_stats = fe->fe_stats;
        }

        ta.vfta_gen_id = fe->fe_gen_id;

        break;
    }

    return vr_trap(npkt, fe->fe_vrf, trap_reason, &ta);
}

static flow_result_t
vr_do_flow_action(struct vrouter *router, struct vr_flow_entry *fe,
        unsigned int index, struct vr_packet *pkt,
        struct vr_forwarding_md *fmd)
{
    uint32_t new_stats;
    struct vr_flow_stats stats, *stats_p = NULL;

    if (fe->fe_flags & VR_FLOW_FLAG_NEW_FLOW) {
        memcpy(&stats, &fe->fe_stats, sizeof(fe->fe_stats));
        memset(&fe->fe_stats, 0, sizeof(fe->fe_stats));
        stats_p = &stats;
    }

    new_stats = vr_sync_add_and_fetch_32u(&fe->fe_stats.flow_bytes, pkt_len(pkt));
    if (new_stats < pkt_len(pkt))
        fe->fe_stats.flow_bytes_oflow++;

    new_stats = vr_sync_add_and_fetch_32u(&fe->fe_stats.flow_packets, 1);
    if (!new_stats)
        fe->fe_stats.flow_packets_oflow++;

    if (fe->fe_action == VR_FLOW_ACTION_HOLD) {
        vr_enqueue_flow(router, fe, pkt, index, stats_p, fmd);
        return FLOW_HELD;
    }

    return vr_flow_action(router, fe, index, pkt, fmd);
}

static unsigned int
vr_flow_table_hold_count(struct vrouter *router)
{
    unsigned int i, num_cpus;
    uint64_t hcount = 0, act_count;
    struct vr_flow_table_info *infop = router->vr_flow_table_info;

    num_cpus = vr_num_cpus;
    for (i = 0; i < num_cpus; i++)
        hcount += infop->vfti_hold_count[i];

    act_count = infop->vfti_action_count;
    if (hcount >= act_count)
        return hcount - act_count;

    return 0;
}

static void
vr_flow_burst_timeout(void *arg)
{
    int tokens;
    struct vrouter *router = (struct vrouter *)arg;
    struct vr_flow_table_info *infop = router->vr_flow_table_info;

    tokens = infop->vfti_burst_tokens - infop->vfti_burst_used;
    if (tokens > 0) {

        tokens  = infop->vfti_burst_tokens_configured - tokens;
        if (tokens <= 0) {
            infop->vfti_timer->vt_stop_timer = 1;
            return;
        }

        if (tokens > infop->vfti_burst_step_configured)
            tokens = infop->vfti_burst_step_configured;
    } else {
        tokens = infop->vfti_burst_step_configured;
    }

    infop->vfti_burst_tokens += tokens;

    return;
}

static void
vr_flow_start_burst_processing(struct vrouter *router)
{
    struct vr_timer *vtimer;
    struct vr_flow_table_info *infop = router->vr_flow_table_info;

    if (!infop->vfti_burst_tokens_configured ||
            !infop->vfti_burst_interval_configured ||
            !infop->vfti_burst_step_configured) {
        return;
    }

    if (!infop->vfti_timer) {
        vtimer = vr_zalloc(sizeof(*vtimer), VR_TIMER_OBJECT);
        if (!vtimer) {
            vr_module_error(-ENOMEM, __FUNCTION__, __LINE__, sizeof(*vtimer));
            return;
        }

        vtimer->vt_timer = vr_flow_burst_timeout;
        vtimer->vt_vr_arg = router;
        vtimer->vt_msecs = infop->vfti_burst_interval_configured;

        if (vr_create_timer(vtimer)) {
            vr_free(vtimer, VR_TIMER_OBJECT);
            return;
        }

        infop->vfti_timer = vtimer;
    } else {
        if (!infop->vfti_timer->vt_stop_timer)
            return;

        if (vr_sync_bool_compare_and_swap_32u(
                 &infop->vfti_timer->vt_stop_timer, 1, 0)) {
            infop->vfti_timer->vt_msecs = infop->vfti_burst_interval_configured;
            vr_restart_timer(infop->vfti_timer);
        }
    }

    return;
}

static void
vr_flow_entry_set_hold(struct vrouter *router, struct vr_flow_entry
        *flow_e, bool burst)
{
    unsigned int cpu;
    uint64_t act_count;
    struct vr_flow_table_info *infop = router->vr_flow_table_info;

    cpu = vr_get_cpu();
    if (cpu >= vr_num_cpus) {
        vr_printf("vrouter: Set HOLD failed (cpu %u num_cpus %u)\n",
                cpu, vr_num_cpus);
        return;
    }

    flow_e->fe_action = VR_FLOW_ACTION_HOLD;

    if (infop->vfti_hold_count[cpu] + 1 < infop->vfti_hold_count[cpu]) {
        (void)vr_sync_add_and_fetch_32u(&infop->vfti_oflows, 1);
        act_count = infop->vfti_action_count;
        if (act_count > infop->vfti_hold_count[cpu]) {
           (void)vr_sync_sub_and_fetch_64u(&infop->vfti_action_count,
                    infop->vfti_hold_count[cpu]);
            infop->vfti_hold_count[cpu] = 0;
        } else {
            infop->vfti_hold_count[cpu] -= act_count;
            (void)vr_sync_sub_and_fetch_64u(&infop->vfti_action_count,
                    act_count);
        }
    }

    infop->vfti_hold_count[cpu]++;

    if (burst == true) {
        (void)vr_sync_add_and_fetch_64u(&infop->vfti_burst_used, 1);
        vr_flow_start_burst_processing(router);
    }

    return;
}

static void
vr_flow_init_close(struct vrouter *router, struct vr_flow_entry *flow_e,
        struct vr_packet *pkt, struct vr_forwarding_md *fmd)
{
    struct vr_flow_entry *rfe;

    (void)vr_sync_fetch_and_or_16u(&flow_e->fe_tcp_flags, VR_FLOW_TCP_DEAD);
    rfe = vr_flow_get_entry(router, flow_e->fe_rflow);
    if (rfe) {
        (void)vr_sync_fetch_and_or_16u(&rfe->fe_tcp_flags, VR_FLOW_TCP_DEAD);
    }

    return;
}

static void
vr_flow_tcp_rflow_set(struct vrouter *router, struct vr_flow_entry *fe,
        struct vr_flow_entry *rfe)
{
    uint16_t flags = 0;

    if (!fe || !rfe)
        return;

    if (rfe->fe_tcp_flags & VR_FLOW_TCP_SYN) {
        flags |= VR_FLOW_TCP_SYN_R;
    }

    if (rfe->fe_tcp_flags & VR_FLOW_TCP_RST) {
        flags |= VR_FLOW_TCP_RST;
    }

    if (rfe->fe_tcp_flags & VR_FLOW_TCP_DEAD) {
        flags |= VR_FLOW_TCP_DEAD;
    }

    if (rfe->fe_tcp_flags & VR_FLOW_TCP_FIN) {
        flags |= VR_FLOW_TCP_FIN_R;
    }

    if (rfe->fe_tcp_flags & VR_FLOW_TCP_ESTABLISHED) {
        flags |= (VR_FLOW_TCP_ESTABLISHED | VR_FLOW_TCP_ESTABLISHED_R);
    }

    (void)vr_sync_fetch_and_or_16u(&fe->fe_tcp_flags, flags);
    return;
}

static void
vr_flow_tcp_digest(struct vrouter *router, struct vr_flow_entry *flow_e,
        struct vr_packet *pkt, struct vr_forwarding_md *fmd)
{
    uint8_t proto = 0, hlen = 0;
    uint16_t tcp_offset_flags;
    unsigned int length = 0;

    struct vr_ip *iph;
    struct vr_ip6 *ip6h;
    struct vr_tcp *tcph;
    struct vr_ip6_frag *v6_frag;
    struct vr_flow_entry *rflow_e = NULL;

    if (pkt->vp_type == VP_TYPE_IP) {
        iph = (struct vr_ip *)pkt_network_header(pkt);
        if (!vr_ip_transport_header_valid(iph))
            return;
        proto = iph->ip_proto;

        length = ntohs(iph->ip_len) - (iph->ip_hl * 4);
        hlen = iph->ip_hl * 4;
    } else if (pkt->vp_type == VP_TYPE_IP6) {
        ip6h = (struct vr_ip6 *)pkt_network_header(pkt);
        if (!vr_ip6_transport_header_valid(ip6h))
            return;
        proto = ip6h->ip6_nxt;
        length = ntohs(ip6h->ip6_plen);
        hlen = sizeof(struct vr_ip6);
        if (proto == VR_IP6_PROTO_FRAG) {
            v6_frag = (struct vr_ip6_frag *)(ip6h + 1);
            proto = v6_frag->ip6_frag_nxt;
            length -= sizeof(struct vr_ip6_frag);
            hlen += sizeof(struct vr_ip6_frag);
        }
    }

    if (proto != VR_IP_PROTO_TCP)
        return;

    tcph = (struct vr_tcp *)(pkt_network_header(pkt) + hlen);

    if (tcph) {
        if (vr_flow_is_fat_flow(router, pkt, flow_e))
            return;

        /*
         * there are some optimizations here that makes the code slightly
         * not so frugal. For e.g.: the *_R flags are used to make sure that
         * for a packet that contains ACK, we will not need to fetch the
         * reverse flow if we are not interested, thus saving some execution
         * time.
         */
        tcp_offset_flags = ntohs(tcph->tcp_offset_r_flags);
        /* if we get a reset, session has to be closed */
        if (tcp_offset_flags & VR_TCP_FLAG_RST) {
            (void)vr_sync_fetch_and_or_16u(&flow_e->fe_tcp_flags,
                    VR_FLOW_TCP_RST);
            if (flow_e->fe_flags & VR_RFLOW_VALID) {
                rflow_e = vr_flow_get_entry(router, flow_e->fe_rflow);
                if (rflow_e) {
                    (void)vr_sync_fetch_and_or_16u(&rflow_e->fe_tcp_flags,
                            VR_FLOW_TCP_RST);
                }
            }
            vr_flow_init_close(router, flow_e, pkt, fmd);
            return;
        } else if (tcp_offset_flags & VR_TCP_FLAG_SYN) {
            /* if only a SYN... */
            flow_e->fe_tcp_seq = ntohl(tcph->tcp_seq);
            (void)vr_sync_fetch_and_or_16u(&flow_e->fe_tcp_flags, VR_FLOW_TCP_SYN);
            if (flow_e->fe_flags & VR_RFLOW_VALID) {
                rflow_e = vr_flow_get_entry(router, flow_e->fe_rflow);
                if (rflow_e) {
                    (void)vr_sync_fetch_and_or_16u(&rflow_e->fe_tcp_flags,
                            VR_FLOW_TCP_SYN_R);
                    if ((flow_e->fe_tcp_flags & VR_FLOW_TCP_SYN_R) &&
                            (tcp_offset_flags & VR_TCP_FLAG_ACK)) {
                        if (ntohl(tcph->tcp_ack) == (rflow_e->fe_tcp_seq + 1)) {
                            (void)vr_sync_fetch_and_or_16u(&rflow_e->fe_tcp_flags,
                                    VR_FLOW_TCP_ESTABLISHED);
                            (void)vr_sync_fetch_and_or_16u(&flow_e->fe_tcp_flags,
                                     VR_FLOW_TCP_ESTABLISHED_R);
                        }
                    }
                }
            }
        } else if (tcp_offset_flags & VR_TCP_FLAG_FIN) {
            /*
             * when a FIN is received, update the sequence of the FIN and set
             * the flow FIN flag. It is possible that the FIN packet came with
             * some data, in which case the sequence number of the FIN is one
             * more than the last data byte in the sequence
             */
            length -= (((tcp_offset_flags) >> 12) * 4);
            flow_e->fe_tcp_seq = ntohl(tcph->tcp_seq) + length;
            (void)vr_sync_fetch_and_or_16u(&flow_e->fe_tcp_flags, VR_FLOW_TCP_FIN);
            /*
             * when an ack for a FIN is sent, we need to take some actions
             * on the reverse flow (since FIN came in the reverse flow). to
             * avoid looking up the reverse flow for all acks, we mark the
             * reverse flow's reverse flow with a flag (FIN_R). we will
             * lookup the reverse flow only if this flag is set and the
             * tcp header has an ack bit set
             */
            if (flow_e->fe_flags & VR_RFLOW_VALID) {
                rflow_e = vr_flow_get_entry(router, flow_e->fe_rflow);
                if (rflow_e) {
                    (void)vr_sync_fetch_and_or_16u(&rflow_e->fe_tcp_flags,
                            VR_FLOW_TCP_FIN_R);
                }
            }
        }

        /*
         * if FIN_R is set in the flow and if the ACK bit is set in the
         * tcp header, then we need to mark the reverse flow as dead.
         *
         * OR
         *
         * if the SYN_R is set and ESTABLISHED_R is not set and if this
         * is an ack packet, if this ack completes the connection, we
         * need to set ESTABLISHED
         */
        if (((flow_e->fe_tcp_flags & VR_FLOW_TCP_FIN_R) ||
                (!(flow_e->fe_tcp_flags & VR_FLOW_TCP_ESTABLISHED_R) &&
                 (flow_e->fe_tcp_flags & VR_FLOW_TCP_SYN_R))) &&
                (tcp_offset_flags & VR_TCP_FLAG_ACK)) {
            if (flow_e->fe_flags & VR_RFLOW_VALID) {
                if (!rflow_e) {
                    rflow_e = vr_flow_get_entry(router, flow_e->fe_rflow);
                }

                if (rflow_e) {
                    if ((ntohl(tcph->tcp_ack) == (rflow_e->fe_tcp_seq + 1)) &&
                            (flow_e->fe_tcp_flags & VR_FLOW_TCP_FIN_R)) {
                        (void)vr_sync_fetch_and_or_16u(&rflow_e->fe_tcp_flags,
                                VR_FLOW_TCP_HALF_CLOSE);
                        /*
                         * both the forward and the reverse flows are
                         * now dead
                         */
                        if (flow_e->fe_tcp_flags & VR_FLOW_TCP_HALF_CLOSE) {
                            vr_flow_init_close(router, flow_e, pkt, fmd);
                        }
                    } else if (ntohl(tcph->tcp_ack) != rflow_e->fe_tcp_seq) {
                        if (!(flow_e->fe_tcp_flags &
                                    VR_FLOW_TCP_ESTABLISHED_R)) {
                            (void)vr_sync_fetch_and_or_16u(&rflow_e->fe_tcp_flags,
                                    VR_FLOW_TCP_ESTABLISHED);
                            (void)vr_sync_fetch_and_or_16u(&flow_e->fe_tcp_flags,
                                     VR_FLOW_TCP_ESTABLISHED_R);
                        }
                    }
                }
            }
        }
    }

    return;
}

static inline bool
vr_flow_vif_allow_new_flow(struct vrouter *router, struct vr_packet *pkt,
                           unsigned short *drop_reason)
{
    struct vr_interface *vif_l = NULL;
    struct vr_nexthop *nh = NULL;

    if (vif_is_virtual(pkt->vp_if)) {
        vif_l = pkt->vp_if;
    } else if (vif_is_fabric(pkt->vp_if)) {
        nh = pkt->vp_nh;
        if ((nh != NULL) && (nh->nh_flags & NH_FLAG_VALID)) {
            vif_l = nh->nh_dev;
        }
    }

    if (vif_l && vif_drop_new_flows(vif_l)) {
        *drop_reason = VP_DROP_NEW_FLOWS;
        return false;
    }

    return true;
}

void
vr_flow_get_burst_params(struct vrouter *router, int *burst_tokens,
        int *burst_interval, int *burst_step)
{
    struct vr_flow_table_info *infop;

    if (!router || !router->vr_flow_table_info)
        return;

    infop = router->vr_flow_table_info;

    if (burst_tokens)
        *burst_tokens = infop->vfti_burst_tokens_configured;
    if (burst_interval)
        *burst_interval = infop->vfti_burst_interval_configured;
    if (burst_step)
        *burst_step = infop->vfti_burst_step_configured;

    return;
}

void
vr_flow_set_burst_params(struct vrouter *router, int burst_tokens,
                                int burst_interval, int burst_step)
{
    struct vr_flow_table_info *infop;

    if (!router || !router->vr_flow_table_info)
        return;

    infop = router->vr_flow_table_info;

    if (burst_tokens != -1)
        infop->vfti_burst_tokens_configured = burst_tokens;

    if (burst_interval != -1)
        infop->vfti_burst_interval_configured = burst_interval;

    if (burst_step != -1)
        infop->vfti_burst_step_configured = burst_step;


    vr_flow_start_burst_processing(router);
    return;
}

static inline unsigned int
vr_flow_burst_count(struct vrouter *router)
{
    struct vr_flow_table_info *infop = router->vr_flow_table_info;

    return infop->vfti_burst_tokens;
}

static inline bool
vr_flow_allow_new_flow(struct vrouter *router, struct vr_packet *pkt,
                       unsigned short *drop_reason, bool *burst)
{
    unsigned int hold_count;
    struct vr_flow_table_info *infop = router->vr_flow_table_info;


    *drop_reason = VP_DROP_FLOW_UNUSABLE;
    if (burst)
        *burst = false;

    if (pkt->vp_type == VP_TYPE_IP) {
        if (!vr_inet_flow_allow_new_flow(router, pkt)) {
            *drop_reason = VP_DROP_FLOW_UNUSABLE;
            return false;
        }
    }

    if (vr_flow_hold_limit) {
        hold_count = vr_flow_table_hold_count(router);
        if (hold_count > vr_flow_hold_limit) {
            if (infop->vfti_burst_used >= vr_flow_burst_count(router)) {
                *drop_reason = VP_DROP_FLOW_UNUSABLE;
                return false;
            }
            if (burst) {
                *burst = true;
            }
        }
    }

    return vr_flow_vif_allow_new_flow(router, pkt, drop_reason);
}

flow_result_t
vr_flow_lookup(struct vrouter *router, struct vr_flow *key,
               struct vr_packet *pkt, struct vr_forwarding_md *fmd)
{
    unsigned int fe_index;
    struct vr_flow_entry *flow_e;
    unsigned short drop_reason = 0;
    bool burst = false;

    pkt->vp_flags |= VP_FLAG_FLOW_SET;

    if (!fmd->fmd_fe) {
        flow_e = vr_find_flow(router, key, pkt->vp_type,  &fe_index);
        if (!flow_e) {
            if (pkt->vp_nh &&
                (pkt->vp_nh->nh_flags &
                 (NH_FLAG_RELAXED_POLICY | NH_FLAG_FLOW_LOOKUP)))
                return FLOW_FORWARD;

            if (!vr_flow_allow_new_flow(router, pkt, &drop_reason, &burst)) {
                vr_pfree(pkt, drop_reason);
                return FLOW_CONSUMED;
            }

            flow_e = vr_flow_get_free_entry(router, key, pkt->vp_type,
                    true, &fe_index);
            if (!flow_e) {
                vr_pfree(pkt, VP_DROP_FLOW_TABLE_FULL);
                return FLOW_CONSUMED;
            }

            flow_e->fe_vrf = fmd->fmd_dvrf;
            /* mark as hold */
            vr_flow_entry_set_hold(router, flow_e, burst);
        }
    } else {
        flow_e = fmd->fmd_fe;
        fe_index = fmd->fmd_flow_index;
    }

    if (flow_e->fe_flags & VR_FLOW_FLAG_EVICT_CANDIDATE)
        return FLOW_EVICT_DROP;

    /*
     * Store the source of the packet which gets used incase of Ecmp
     * Source
     */
    if (vif_is_fabric(pkt->vp_if))
        flow_e->fe_src_info = fmd->fmd_outer_src_ip;
    else if (vif_is_virtual(pkt->vp_if))
        flow_e->fe_src_info = pkt->vp_if->vif_idx;

    vr_flow_set_forwarding_md(router, flow_e, fe_index, fmd);
    vr_flow_tcp_digest(router, flow_e, pkt, fmd);

    return vr_do_flow_action(router, flow_e, fe_index, pkt, fmd);
}

static bool
__vr_flow_forward(flow_result_t result, struct vr_packet *pkt,
        struct vr_forwarding_md *fmd)
{
    bool forward = false;

    switch (result) {
    case FLOW_FORWARD:
        forward = true;
        break;

    case FLOW_TRAP:
        vr_trap(pkt, fmd->fmd_dvrf, AGENT_TRAP_L3_PROTOCOLS, NULL);
        break;

    case FLOW_EVICT_DROP:
        vr_pfree(pkt, VP_DROP_FLOW_EVICT);
        break;

    case FLOW_HELD:
    case FLOW_CONSUMED:
        break;

    case FLOW_DROP:
    default:
        vr_pfree(pkt, VP_DROP_FLOW_UNUSABLE);
        break;
    }

    return forward;
}

static bool
vr_flow_is_fat_flow(struct vrouter *router, struct vr_packet *pkt,
        struct vr_flow_entry *fe)
{
    if (pkt->vp_type == VP_TYPE_IP) {
        return vr_inet_flow_is_fat_flow(router, pkt, fe);
    } else if (pkt->vp_type == VP_TYPE_IP6) {
        return vr_inet6_flow_is_fat_flow(router, pkt, fe);
    }

    return false;
}

uint16_t
vr_flow_fat_flow_lookup(struct vrouter *router, struct vr_packet *pkt,
        struct vr_ip *ip, struct vr_ip6 *ip6,
        uint16_t l4_proto, uint16_t sport, uint16_t dport)
{
    uint8_t fat_flow_mask, tmp_mask = 0;
    struct vr_nexthop *nh;
    struct vr_interface *vif_l = NULL;

    if (vif_is_virtual(pkt->vp_if)) {
        vif_l = pkt->vp_if;
    } else if (vif_is_fabric(pkt->vp_if)) {
        if ((nh = pkt->vp_nh) && (nh->nh_flags & NH_FLAG_VALID)) {
            vif_l = nh->nh_dev;
        }
    }

    if (!vif_l)
        return VR_FAT_FLOW_NO_MASK;

    fat_flow_mask = vif_fat_flow_lookup(vif_l, ip, ip6, l4_proto, sport, dport);
    if (pkt->vp_if != vif_l) {

        if (fat_flow_mask & VR_FAT_FLOW_SRC_IP_MASK)
            tmp_mask |= VR_FAT_FLOW_DST_IP_MASK;

        if (fat_flow_mask & VR_FAT_FLOW_DST_IP_MASK)
            tmp_mask |= VR_FAT_FLOW_SRC_IP_MASK;

        fat_flow_mask &= ~(VR_FAT_FLOW_DST_IP_MASK |
                VR_FAT_FLOW_SRC_IP_MASK);


        fat_flow_mask |= tmp_mask;

    }

    return fat_flow_mask;
}

static flow_result_t
vr_do_flow_lookup(struct vrouter *router, struct vr_packet *pkt,
                struct vr_forwarding_md *fmd)
{
    flow_result_t result = FLOW_FORWARD;

    /* Flow processing is only for untagged unicast IP packets */
    if (pkt->vp_type == VP_TYPE_IP)
        result = vr_inet_flow_lookup(router, pkt, fmd);
    else if (pkt->vp_type == VP_TYPE_IP6)
        result = vr_inet6_flow_lookup(router, pkt, fmd);

    return result;
}

bool
vr_flow_forward(struct vrouter *router, struct vr_packet *pkt,
                struct vr_forwarding_md *fmd)
{
    flow_result_t result = FLOW_FORWARD;

    if ((!(pkt->vp_flags & VP_FLAG_MULTICAST))
        && ((fmd->fmd_vlan == VLAN_ID_INVALID) || vif_is_service(pkt->vp_if)))
        result = vr_do_flow_lookup(router, pkt, fmd);

    return __vr_flow_forward(result, pkt, fmd);
}

int
vr_flow_flush_pnode(struct vrouter *router, struct vr_packet_node *pnode,
        struct vr_flow_entry *fe, struct vr_forwarding_md *fmd)
{
    bool forward;

    struct vr_interface *vif;
    struct vr_packet *pkt;
    flow_result_t result;

    fmd->fmd_outer_src_ip = pnode->pl_outer_src_ip;
    if (pnode->pl_flags & PN_FLAG_LABEL_IS_VXLAN_ID) {
        vr_fmd_set_label(fmd, pnode->pl_label,
                VR_LABEL_TYPE_VXLAN_ID);
    } else {
        vr_fmd_set_label(fmd, pnode->pl_label,
                VR_LABEL_TYPE_MPLS);
    }

    if (pnode->pl_flags & PN_FLAG_TO_ME)
        fmd->fmd_to_me = 1;

    pkt = pnode->pl_packet;
    if (!pkt)
        return -EINVAL;

    fmd->fmd_dscp = pnode->pl_dscp;
    fmd->fmd_dotonep = pnode->pl_dotonep;
    fmd->fmd_vlan = pnode->pl_vlan;
    fmd->fmd_mirror_data = pnode->pl_mirror_vlan;

    pnode->pl_packet = NULL;
    /*
     * this is only a security check and not a catch all check. one note
     * of caution. please do not access pkt->vp_if till the if block is
     * succesfully bypassed
     */
    vif = __vrouter_get_interface(router, pnode->pl_vif_idx);
    if (!vif || (pkt->vp_if != vif)) {
        pkt->vp_if = NULL;
        vr_pfree(pkt, VP_DROP_INVALID_IF);
        return -ENODEV;
    }

    if (!pkt->vp_nh) {
        if (vif_is_fabric(pkt->vp_if) && fmd &&
                (fmd->fmd_label >= 0)) {
            if (!vr_fmd_label_is_vxlan_id(fmd)) {
                pkt->vp_nh = __vrouter_get_label(router, fmd->fmd_label);
            }  else {
                pkt->vp_nh = __vrouter_bridge_lookup(fmd->fmd_dvrf,
                                                        pkt_data(pkt));
            }
        }
    }

    if (fe) {
        result = vr_flow_action(router, fe, fmd->fmd_flow_index, pkt, fmd);
        forward = __vr_flow_forward(result, pkt, fmd);
    } else {
        forward = vr_flow_forward(router, pkt, fmd);
    }

    if (forward)
        vr_reinject_packet(pkt, fmd);

    return 0;
}

static void
__vr_flow_flush_hold_queue(struct vrouter *router, struct vr_flow_entry *fe,
        struct vr_forwarding_md *fmd, struct vr_flow_queue *vfq)
{
    unsigned int i;
    struct vr_packet_node *pnode;

    for (i = 0; i < VR_MAX_FLOW_QUEUE_ENTRIES; i++) {
        pnode = &vfq->vfq_pnodes[i];
        vr_flow_flush_pnode(router, pnode, fe, fmd);
    }

    return;
}

static void
vr_flush_entry(struct vrouter *router, struct vr_flow_entry *fe,
        struct vr_flow_md *flmd, struct vr_forwarding_md *fmd)
{
    bool swapped;

    struct vr_flow_queue *vfq;
    struct vr_defer_data *vdd = flmd->flmd_defer_data;
    struct vr_flow_defer_data *vfdd;

    vfq = fe->fe_hold_list;
    if (vfq) {
        if (fe->fe_action == VR_FLOW_ACTION_HOLD)
            return;

        swapped = vr_sync_bool_compare_and_swap_p(&fe->fe_hold_list, vfq, NULL);
        if (swapped) {
            __vr_flow_flush_hold_queue(router, fe, fmd, vfq);
            if (!vdd || !vdd->vdd_data)
                goto free_flush_queue;

            vfdd = (struct vr_flow_defer_data *)vdd->vdd_data;
            vfdd->vfdd_flow_queue = vfq;
        }
    }

    return;

free_flush_queue:
    if (vfq)
        vr_free(vfq, VR_FLOW_QUEUE_OBJECT);
    return;
}

static void
__vr_flow_work(struct vrouter *router, struct vr_flow_entry *fe,
        struct vr_flow_md *flmd)
{
    struct vr_forwarding_md fmd;

    vr_init_forwarding_md(&fmd);
    vr_flow_set_forwarding_md(router, fe, flmd->flmd_index, &fmd);
    vr_flush_entry(router, fe, flmd, &fmd);

    vr_flow_defer(flmd, fe);
    return;
}


static void
vr_flow_work(void *arg)
{
    struct vrouter *router;
    struct vr_flow_entry *fe;
    struct vr_flow_md *flmd =
                (struct vr_flow_md *)arg;

    router = flmd->flmd_router;
    if (!router)
        goto exit_flush;

    fe = vr_flow_get_entry(router, flmd->flmd_index);
    if (!fe)
        goto exit_flush;

    __vr_flow_work(router, fe, flmd);

exit_flush:
    if (flmd->flmd_defer_data) {
        if (flmd->flmd_defer_data->vdd_data) {
            vr_free(flmd->flmd_defer_data->vdd_data,
                    VR_FLOW_DEFER_DATA_OBJECT);
        }
        vr_put_defer_data(flmd->flmd_defer_data);
        flmd->flmd_defer_data = NULL;
    }

    vr_free(flmd, VR_FLOW_METADATA_OBJECT);

    return;
}

static void
vr_flow_set_mirror(struct vrouter *router, vr_flow_req *req,
        struct vr_flow_entry *fe)
{
    struct vr_mirror_entry *mirror = NULL, *sec_mirror = NULL;

    if (!(req->fr_flags & VR_FLOW_FLAG_MIRROR) &&
            (fe->fe_flags & VR_FLOW_FLAG_MIRROR)) {
        vr_flow_reset_mirror(router, fe, req->fr_index);
        return;
    }

    if (!(req->fr_flags & VR_FLOW_FLAG_MIRROR))
        return;

    if (fe->fe_mirror_id != req->fr_mir_id) {
        if (fe->fe_mirror_id < router->vr_max_mirror_indices) {
            fe->fe_mirror_id = router->vr_max_mirror_indices;
        }

        if ((unsigned int)req->fr_mir_id < router->vr_max_mirror_indices) {
            mirror = vrouter_get_mirror(req->fr_rid, req->fr_mir_id);
            if (mirror)
                fe->fe_mirror_id = req->fr_mir_id;

            /* when we reached this point, we had already done all the
             * sanity checks we could do. failing here will add only
             * complexity to code here. so !mirror case, we will not
             * handle
             */
        }
    }

    if (fe->fe_sec_mirror_id != req->fr_sec_mir_id) {
        if (fe->fe_sec_mirror_id < router->vr_max_mirror_indices) {
            fe->fe_sec_mirror_id = router->vr_max_mirror_indices;
        }

        if ((unsigned int)req->fr_sec_mir_id < router->vr_max_mirror_indices) {
            sec_mirror = vrouter_get_mirror(req->fr_rid, req->fr_sec_mir_id);
            if (sec_mirror)
                fe->fe_sec_mirror_id = req->fr_sec_mir_id;
        }
    }

    if (req->fr_pcap_meta_data_size && req->fr_pcap_meta_data) {
        if (fe->fe_mme) {
            vr_mirror_meta_entry_del(router, fe->fe_mme);
            fe->fe_mme = NULL;
        }

        fe->fe_mme = vr_mirror_meta_entry_set(router, req->fr_index,
                req->fr_mir_sip, req->fr_mir_sport,
                req->fr_pcap_meta_data, req->fr_pcap_meta_data_size,
                req->fr_mir_vrf);

        if (fe->fe_mme) {
            vr_offload_flow_meta_data_set(req->fr_index,
                                          req->fr_pcap_meta_data_size,
                                          req->fr_pcap_meta_data,
                                          req->fr_mir_vrf);
        }
    }

    return;
}

void
vr_fill_flow_common(struct vr_flow *flowp, unsigned short nh_id,
        uint8_t proto, uint16_t sport, uint16_t dport, uint8_t family,
        uint8_t valid_fkey_params)
{
    flowp->flow_nh_id = nh_id;
    flowp->flow_family = family;
    if (family == AF_INET)
        flowp->flow_key_len = VR_FLOW_IPV4_HASH_SIZE;
    else
        flowp->flow_key_len = VR_FLOW_IPV6_HASH_SIZE;
    flowp->flow_unused = 0;

    if (valid_fkey_params & VR_FLOW_KEY_PROTO)
        flowp->flow_proto = proto;

    if (valid_fkey_params & VR_FLOW_KEY_SRC_PORT)
        flowp->flow_sport = sport;

    if (valid_fkey_params & VR_FLOW_KEY_DST_PORT)
        flowp->flow_dport = dport;

    return;
}

static struct vr_flow_entry *
vr_add_flow(unsigned int rid, struct vr_flow *key, uint8_t type,
        bool need_hold_queue, unsigned int *fe_index,
        uint8_t *fe_gen_id)
{
    struct vr_flow_entry *flow_e;
    struct vrouter *router = vrouter_get(rid);

    flow_e = vr_find_flow(router, key, type, fe_index);
    if (flow_e) {
        *fe_gen_id = flow_e->fe_gen_id;
        /* a race between agent and dp. allow agent to handle this error */
        return NULL;
    } else {
        flow_e = vr_flow_get_free_entry(router, key, type,
                need_hold_queue, fe_index);
    }

    return flow_e;
}

static struct vr_flow_entry *
vr_add_flow_req(vr_flow_req *req, unsigned int *fe_index, uint8_t *fe_gen_id)
{
    uint8_t type;
    bool need_hold_queue = false;

    struct vr_flow key;
    struct vr_flow_entry *fe;

    switch (req->fr_family) {
    case  AF_INET6:
        type = VP_TYPE_IP6;
        vr_inet6_fill_flow_from_req(&key, req);
        break;

    case  AF_INET:
        type = VP_TYPE_IP;
        vr_inet_fill_flow(&key, req->fr_flow_nh_id,
            (uint32_t)req->fr_flow_sip_l, (uint32_t)req->fr_flow_dip_l,
            req->fr_flow_proto, req->fr_flow_sport, req->fr_flow_dport,
            VR_FLOW_KEY_ALL);
        break;

    default:
        return NULL;
    }

    if (req->fr_action == VR_FLOW_ACTION_HOLD)
        need_hold_queue = true;

    fe = vr_add_flow(req->fr_rid, &key, type, need_hold_queue, fe_index,
                     fe_gen_id);
    if (fe)
        req->fr_index = *fe_index;

    return fe;
}

/*
 * can be called with 'fe' as null (specifically when flow is added from
 * agent), in which case we should be checking only the request
 */
static int
vr_flow_set_req_is_invalid(struct vrouter *router, vr_flow_req *req,
        struct vr_flow_entry *fe)
{
    int error = 0, key_type;
    struct vr_flow_entry *rfe;
    struct vr_flow key;
    uint64_t *ip;

    if (fe) {

        /* If Delete marked, dont allow any other change */
        if (fe->fe_flags & VR_FLOW_FLAG_DELETE_MARKED)
            return -EINVAL;

        if ((fe->fe_type == VP_TYPE_IP) || (fe->fe_type == VP_TYPE_IP6)) {
            if ((uint8_t)req->fr_gen_id != fe->fe_gen_id) {
                error = -EBADF;
                goto invalid_req;
            }

            /*
             * when gen id is same flow keys should not mis-match
             * send EFAULT if such incident happens
             */
            if((unsigned short)req->fr_flow_sport != fe->fe_key.flow_sport ||
                    (unsigned short)req->fr_flow_dport != fe->fe_key.flow_dport||
                    (unsigned short)req->fr_flow_nh_id != fe->fe_key.flow_nh_id ||
                    (unsigned char)req->fr_flow_proto != fe->fe_key.flow_proto) {
                error = -EFAULT;
                goto invalid_req;
            }

            if (fe->fe_type == VP_TYPE_IP) {
                if ((fe->fe_key.flow4_sip != (uint32_t)req->fr_flow_sip_l) ||
                        (fe->fe_key.flow4_dip != (uint32_t)req->fr_flow_dip_l)) {
                    error = -EFAULT;
                    goto invalid_req;
                }
            } else {
                ip = (uint64_t *)fe->fe_key.flow6_sip;
                if ((*ip != req->fr_flow_sip_u) ||
                        (*(ip+1) != req->fr_flow_sip_l) ||
                        (*(ip+2) != req->fr_flow_dip_u) ||
                        (*(ip+3) != req->fr_flow_dip_l)) {
                    error = -EFAULT;
                    goto invalid_req;
                }
            }
        }
    } else {
        /*
         * flow set request received with an index which is
         * not active anymore, return ENOENT error
         */
        if ((req->fr_flags & VR_FLOW_FLAG_ACTIVE) && !(req->fr_index < 0)) {
            error = -ENOENT;
            goto invalid_req;
        }
    }

    if (req->fr_flags & VR_FLOW_FLAG_VRFT) {
        if ((unsigned short)req->fr_flow_dvrf >= router->vr_max_vrfs) {
            error = -EINVAL;
            goto invalid_req;
        }
    }

    if (req->fr_flags & VR_FLOW_FLAG_MIRROR) {
        if (((unsigned int)req->fr_mir_id >= router->vr_max_mirror_indices) &&
                (unsigned int)req->fr_sec_mir_id >= router->vr_max_mirror_indices) {
            error = -EINVAL;
            goto invalid_req;
        }
    }

    if (req->fr_flags & VR_RFLOW_VALID) {
        if (req->fr_rindex != -1) {
            rfe = vr_flow_get_entry(router, req->fr_rindex);
        } else {
            if (req->fr_family == AF_INET) {
                vr_inet_fill_flow(&key, req->fr_rflow_nh_id,
                  (uint32_t)req->fr_rflow_sip_l, (uint32_t)req->fr_rflow_dip_l,
                  req->fr_flow_proto, req->fr_rflow_sport,
                  req->fr_rflow_dport, VR_FLOW_KEY_ALL);

                key_type = VP_TYPE_IP;
            } else {
                vr_inet6_fill_rflow_from_req(&key, req);
                key_type = VP_TYPE_IP6;
            }

            rfe = vr_find_flow(router, &key, key_type,  &req->fr_rindex);
        }

        if (!rfe) {
            error = -EINVAL;
            goto invalid_req;
        }
    }

    return 0;

invalid_req:
    return error;
}

static int
__vr_flow_schedule_transition(struct vrouter *router, struct vr_flow_entry *fe,
        unsigned int index, unsigned short flags)
{
    struct vr_flow_md *flmd;
    struct vr_defer_data *defer = NULL;

    flmd = (struct vr_flow_md *)vr_malloc(sizeof(*flmd),
            VR_FLOW_METADATA_OBJECT);
    if (!flmd)
        return -ENOMEM;

    flmd->flmd_router = router;
    flmd->flmd_index = index;
    flmd->flmd_flags = flags;
    if (fe->fe_hold_list || (flags & VR_FLOW_FLAG_EVICT_CANDIDATE)) {
        defer = vr_get_defer_data(sizeof(*defer));
        if (defer) {
            defer->vdd_data = (void *)vr_zalloc(sizeof(struct vr_flow_defer_data),
                    VR_FLOW_DEFER_DATA_OBJECT);
            if (!(flmd->flmd_flags & VR_FLOW_FLAG_ACTIVE)) {
                ((struct vr_flow_defer_data *)defer->vdd_data)->vfdd_delete =
                    true;
            }
        }
    }
    flmd->flmd_defer_data = defer;

    return vr_schedule_work(vr_get_cpu(), vr_flow_work, (void *)flmd);
}

static int
vr_flow_schedule_transition(struct vrouter *router, vr_flow_req *req,
        struct vr_flow_entry *fe)
{
    return __vr_flow_schedule_transition(router, fe, req->fr_index, req->fr_flags);
}

static int
vr_flow_delete(struct vrouter *router, vr_flow_req *req,
        struct vr_flow_entry *fe)
{
    int port = 0;
    /* Delete Mark it */
    fe->fe_flags |= VR_FLOW_FLAG_DELETE_MARKED;


    if (fe->fe_flags & VR_FLOW_FLAG_LINK_LOCAL) {
        if (fe->fe_key.flow_proto == VR_IP_PROTO_ICMP) {
            /*
             * ICMP id passed as source port would be
             * used for relaxed policy flow lookup
             */
            port = ntohs(fe->fe_key.flow_sport);
        } else {
            port = ntohs(fe->fe_key.flow_dport);
        }
        vr_clear_link_local_port(router, AF_INET, fe->fe_key.flow_proto, port);
    }

    fe->fe_action = VR_FLOW_ACTION_DROP;
    vr_flow_reset_mirror(router, fe, req->fr_index);

    return vr_flow_schedule_transition(router, req, fe);
}

static void
vr_flow_udp_src_port (struct vrouter *router, struct vr_flow_entry *fe)
{
    uint32_t hash_key[10], hashval, port_range, hash_len;
    uint16_t port;

    if (fe->fe_udp_src_port)
        return;

    if (hashrnd_inited == 0) {
        get_random_bytes(&vr_hashrnd, sizeof(vr_hashrnd));
        hashrnd_inited = 1;
    }

    hash_key[0] = fe->fe_vrf;
    hash_key[1] = (fe->fe_key.flow_sport << 16) | fe->fe_key.flow_dport;
    memcpy(&hash_key[2], fe->fe_key.flow_ip, 2 * VR_IP_ADDR_SIZE(fe->fe_type));
    hash_len = VR_FLOW_HASH_SIZE(fe->fe_type);

    hashval = jhash(hash_key, hash_len, vr_hashrnd);
    port_range = VR_MUDP_PORT_RANGE_END - VR_MUDP_PORT_RANGE_START;
    port = (uint16_t ) (((uint64_t ) hashval * port_range) >> 32);

    if (port > port_range) {
        /*
         * Shouldn't happen...
         */
        port = 0;
    }
    fe->fe_udp_src_port = port + VR_MUDP_PORT_RANGE_START;
}

static void
vr_flow_update_link_local_port(struct vrouter *router, vr_flow_req *req,
        struct vr_flow_entry *fe)
{
    bool set_port = false;
    int port = 0;

    if (!req || !fe)
        return;

    if (fe->fe_type != VP_TYPE_IP)
        return;

    if (fe->fe_key.flow_proto == VR_IP_PROTO_ICMP) {
        /*
         * ICMP id passed as source port would be
         * used for relaxed policy flow lookup
         */
        port = ntohs(fe->fe_key.flow_sport);
    } else {
        port = ntohs(fe->fe_key.flow_dport);
    }

    if (req->fr_flags & VR_FLOW_FLAG_LINK_LOCAL) {
        if (!(fe->fe_flags & VR_FLOW_FLAG_LINK_LOCAL))
            set_port = true;
    } else if (fe->fe_flags & VR_FLOW_FLAG_LINK_LOCAL) {
        vr_clear_link_local_port(router, AF_INET, fe->fe_key.flow_proto,
                                                  port);
    }

    if (req->fr_flags & VR_FLOW_BGP_SERVICE) {
        if (!(fe->fe_flags & VR_FLOW_BGP_SERVICE))
            set_port = true;
    }

    if (set_port) {
        vr_set_link_local_port(router, AF_INET, fe->fe_key.flow_proto, port);
    }

    return;
}

/* command from agent */
static int
vr_flow_set(struct vrouter *router, vr_flow_req *req,
            vr_flow_response *flow_resp)
{
    int ret;
    unsigned int fe_index = (unsigned int)-1;
    uint8_t fe_gen_id = 0;
    bool new_flow = false, modified = false;

    struct vr_flow_entry *fe = NULL, *rfe = NULL;
    struct vr_flow_table_info *infop = router->vr_flow_table_info;

    router = vrouter_get(req->fr_rid);
    if (!router)
        return -EINVAL;

    flow_resp->fresp_index = req->fr_index;

    fe = vr_flow_get_entry(router, req->fr_index);
    if (fe) {
        if (!(modified = vr_flow_start_modify(router, fe)))
            return -EBUSY;
        fe_index = (unsigned int)(req->fr_index);
    }

    if ((ret = vr_flow_set_req_is_invalid(router, req, fe)))
        goto exit_set;

    if (fe) {
        if ((fe->fe_action == VR_FLOW_ACTION_HOLD) &&
            ((req->fr_action != fe->fe_action) ||
             !(req->fr_flags & VR_FLOW_FLAG_ACTIVE))) {
            vr_sync_fetch_and_add_64u(&infop->vfti_action_count, 1);
        } else {
            infop->vfti_changed++;
        }

    }
    /*
     * for delete, absence of the requested flow entry is caustic. so
     * handle that case first
     */
    if (!(req->fr_flags & VR_FLOW_FLAG_ACTIVE)) {
        if (!fe)
            return -ENOENT;

        infop->vfti_deleted++;
        flow_resp->fresp_flags |= VR_FLOW_RESP_FLAG_DELETED;
        return vr_flow_delete(router, req, fe);
    }


    /*
     * for non-delete cases, absence of flow entry means addition of a
     * new flow entry with the key specified in the request
     */
    if (!fe) {
        fe = vr_add_flow_req(req, &fe_index, &fe_gen_id);
        if (!fe) {
            if (fe_index != (unsigned int)-1) {
                /*
                 * add flow req failed to allocate an entry due to race
                 * between agent and datapath, where flow entry at fe_index
                 * was already created due to packet trap, return EEXIST
                 * error and allow agent to wait and handle flow add due to
                 * packet trap
                 */
                flow_resp->fresp_index = fe_index;
                flow_resp->fresp_gen_id = fe_gen_id;
                return -EEXIST;
            }
            return -ENOSPC;
        }

        new_flow = true;
        infop->vfti_added++;
    } else {
        if ((req->fr_action == VR_FLOW_ACTION_HOLD) &&
                (fe->fe_action != req->fr_action)) {
            if (!fe->fe_hold_list) {
                fe->fe_hold_list = vr_zalloc(sizeof(struct vr_flow_queue),
                        VR_FLOW_QUEUE_OBJECT);
                if (!fe->fe_hold_list) {
                    ret = -ENOMEM;
                    goto exit_set;
                }
            }
        }
    }

    flow_resp->fresp_gen_id = fe->fe_gen_id;
    flow_resp->fresp_index = fe->fe_hentry.hentry_index;

    vr_flow_set_mirror(router, req, fe);

    if (req->fr_flags & VR_RFLOW_VALID) {
        fe->fe_rflow = req->fr_rindex;
    } else {
        if (fe->fe_rflow >= 0)
            fe->fe_rflow = -1;
    }

    fe->fe_vrf = req->fr_flow_vrf;
    if (req->fr_flags & VR_FLOW_FLAG_VRFT)
        fe->fe_dvrf = req->fr_flow_dvrf;

    vr_flow_update_link_local_port(router, req, fe);

    if (fe->fe_ecmp_nh_index == -1)
        (void)vr_sync_bool_compare_and_swap_8s(&fe->fe_ecmp_nh_index, -1,
                req->fr_ecmp_nh_index);

    fe->fe_src_nh_index = req->fr_src_nh_index;
    fe->fe_qos_id = req->fr_qos_id;

    if ((req->fr_action == VR_FLOW_ACTION_HOLD) &&
            (fe->fe_action != VR_FLOW_ACTION_HOLD)) {
        vr_flow_entry_set_hold(router, fe, false);
    } else {
        fe->fe_action = req->fr_action;
    }

    fe->fe_ttl = req->fr_ttl;

    if (fe->fe_action == VR_FLOW_ACTION_DROP)
        fe->fe_drop_reason = (uint8_t)req->fr_drop_reason;

    fe->fe_flags = VR_FLOW_FLAG_DP_BITS(fe) |
        VR_FLOW_FLAG_MASK(req->fr_flags);
    if (new_flow) {

        flow_resp->fresp_bytes = fe->fe_stats.flow_bytes;
        flow_resp->fresp_packets = fe->fe_stats.flow_packets;
        flow_resp->fresp_stats_oflow = (fe->fe_stats.flow_bytes_oflow |
                                    (fe->fe_stats.flow_packets_oflow << 16));

        if (fe->fe_flags & VR_FLOW_FLAG_NEW_FLOW) {
            if (fe->fe_stats.flow_packets || fe->fe_stats.flow_packets_oflow)
                memset(&fe->fe_stats, 0, sizeof(fe->fe_stats));
        }

        if (fe->fe_flags & VR_RFLOW_VALID) {
            rfe = vr_flow_get_entry(router, fe->fe_rflow);
            if (rfe) {
                vr_flow_tcp_rflow_set(router, fe, rfe);
            }
        }

    }

    vr_flow_udp_src_port(router, fe);

    if (fe->fe_flags & VR_FLOW_FLAG_NEW_FLOW)
        fe->fe_flags &= ~VR_FLOW_FLAG_NEW_FLOW;



    ret = vr_flow_schedule_transition(router, req, fe);

    /*
     * offload, no need to differentiate between add and modify. Pass the
     * reverse flow as well if present.
     */
    if (!ret) {
        vr_offload_flow_set(fe, fe_index, rfe);
    }

exit_set:
    if (modified && fe) {
        vr_flow_stop_modify(router, fe);
    }

    return ret;
}

static void
vr_flow_table_data_destroy(vr_flow_table_data *ftable)
{
    if (!ftable)
        return;

    if (ftable->ftable_file_path) {
        vr_free(ftable->ftable_file_path, VR_FLOW_REQ_PATH_OBJECT);
        ftable->ftable_file_path = NULL;
    }

    if (ftable->ftable_hold_stat && ftable->ftable_hold_stat_size) {
        vr_free(ftable->ftable_hold_stat, VR_FLOW_HOLD_STAT_OBJECT);
        ftable->ftable_hold_stat = NULL;
        ftable->ftable_hold_stat_size = 0;
    }

    vr_free(ftable, VR_FLOW_TABLE_DATA_OBJECT);

    return;
}

vr_flow_table_data *
vr_flow_table_data_get(vr_flow_table_data *ref)
{
    unsigned int hold_stat_size;
    unsigned int num_cpus = vr_num_cpus;
    vr_flow_table_data *ftable = vr_zalloc(sizeof(*ref),
            VR_FLOW_TABLE_DATA_OBJECT);

    if (!ftable)
        return NULL;

    if (vr_flow_path) {
        ftable->ftable_file_path = vr_zalloc(VR_UNIX_PATH_MAX,
                VR_FLOW_REQ_PATH_OBJECT);
        if (!ftable->ftable_file_path) {
            vr_free(ftable, VR_FLOW_TABLE_DATA_OBJECT);
            return NULL;
        }
    }

    if (num_cpus > VR_FLOW_MAX_CPUS)
        num_cpus = VR_FLOW_MAX_CPUS;

    hold_stat_size = num_cpus * sizeof(uint32_t);
    ftable->ftable_hold_stat = vr_zalloc(hold_stat_size, VR_FLOW_HOLD_STAT_OBJECT);
    if (!ftable->ftable_hold_stat) {
        if (ftable->ftable_file_path) {
            vr_free(ftable->ftable_file_path, VR_FLOW_REQ_PATH_OBJECT);
            ftable->ftable_file_path = NULL;
        }

        vr_free(ftable, VR_FLOW_TABLE_DATA_OBJECT);
        return NULL;
    }
    ftable->ftable_hold_stat_size = num_cpus;

    return ftable;
}

/*
 * sandesh handler for vr_flow_table_data
 */
void
vr_flow_table_data_process(void *s_req)
{
    int i, ret = 0;
    uint64_t hold_count = 0;
    struct vrouter *router;
    struct vr_flow_table_info *infop;
    vr_flow_table_data *resp, *ftable = (vr_flow_table_data *)s_req;

    router = vrouter_get(ftable->ftable_rid);
    resp = vr_flow_table_data_get(ftable);
    if (!resp) {
        ret = -ENOMEM;
        goto send_response;
    }

    infop = router->vr_flow_table_info;
    resp->ftable_op = ftable->ftable_op;
    resp->ftable_size = vr_flow_table_size(router);
#if defined(__linux__) && defined(__KERNEL__)
    resp->ftable_dev = vr_flow_major;
#endif
    if (vr_flow_path)
        strncpy(resp->ftable_file_path, vr_flow_path, VR_UNIX_PATH_MAX - 1);

    if (!infop)
        goto send_response;

    resp->ftable_used_entries = vr_flow_table_used_total_entries(router);
    resp->ftable_deleted = infop->vfti_deleted;
    resp->ftable_changed = infop->vfti_changed;
    resp->ftable_processed = infop->vfti_action_count;
    resp->ftable_hold_oflows = infop->vfti_oflows;
    resp->ftable_added = infop->vfti_added;
    resp->ftable_cpus = vr_num_cpus;
    /* we only have space for 64 stats block max when encoding */
    for (i = 0; ((i < vr_num_cpus) && (i < VR_FLOW_MAX_CPUS)); i++) {
        resp->ftable_hold_stat[i] = infop->vfti_hold_count[i];
        hold_count += resp->ftable_hold_stat[i];
    }

    resp->ftable_created = hold_count;
    resp->ftable_oflow_entries = vr_flow_table_used_oflow_entries(router);
    resp->ftable_burst_free_tokens = infop->vfti_burst_tokens - infop->vfti_burst_used;
    resp->ftable_hold_entries = vr_flow_table_hold_count(router);

send_response:
    vr_message_response(VR_FLOW_TABLE_DATA_OBJECT_ID, resp, ret, false);
    if (resp)
        vr_flow_table_data_destroy(resp);

    return;
}

/*
 * sandesh handler for vr_flow_req
 */
void
vr_flow_req_process(void *s_req)
{
    int ret = 0;
    struct vrouter *router;
    vr_flow_req *req = (vr_flow_req *)s_req;
    vr_flow_response flow_resp;

    router = vrouter_get(req->fr_rid);
    switch (req->fr_op) {
    case FLOW_OP_FLOW_SET:

        flow_resp.fresp_rid = 0;
        flow_resp.fresp_op = req->fr_op;

        ret = vr_flow_set(router, req, &flow_resp);
        break;

    default:
        ret = -EINVAL;
    }

    vr_message_response(VR_FLOW_RESPONSE_OBJECT_ID, &flow_resp, ret, false);

    return;
}

void
vr_flow_response_process(void *s_req)
{
    return;
}

static void
vr_flow_table_info_destroy(struct vrouter *router)
{
    if (!router->vr_flow_table_info)
        return;

    vr_free(router->vr_flow_table_info, VR_FLOW_TABLE_INFO_OBJECT);
    router->vr_flow_table_info = NULL;
    router->vr_flow_table_info_size = 0;

    return;
}

static void
vr_flow_table_info_reset(struct vrouter *router)
{
    if (!router->vr_flow_table_info)
        return;

    if (router->vr_flow_table_info->vfti_timer) {
        vr_delete_timer(router->vr_flow_table_info->vfti_timer);
        vr_free(router->vr_flow_table_info->vfti_timer, VR_TIMER_OBJECT);
        router->vr_flow_table_info->vfti_timer = NULL;
    }

    memset(router->vr_flow_table_info, 0, router->vr_flow_table_info_size);

    return;
}

static int
vr_flow_table_info_init(struct vrouter *router)
{
    unsigned int size;
    struct vr_flow_table_info *infop;

    if (router->vr_flow_table_info)
        return 0;

    size = sizeof(struct vr_flow_table_info) + sizeof(uint32_t) * vr_num_cpus;
    infop = (struct vr_flow_table_info *)vr_zalloc(size,
            VR_FLOW_TABLE_INFO_OBJECT);
    if (!infop)
        return vr_module_error(-ENOMEM, __FUNCTION__, __LINE__, size);

    router->vr_flow_table_info = infop;
    router->vr_flow_table_info_size = size;

    return 0;
}

static void
vr_flow_table_destroy(struct vrouter *router)
{
    if (router->vr_flow_table) {
        vr_htable_delete(router->vr_flow_table);
        router->vr_flow_table = NULL;
    }

    vr_flow_table_info_destroy(router);

    return;
}

static void
vr_flow_invalidate_entry(vr_htable_t htable, vr_hentry_t *ent,
                                unsigned int index, void *data)
{
    struct vr_flow_entry *fe;
    struct vr_forwarding_md fmd;
    struct vr_flow_md flmd;
    struct vrouter *router = (struct vrouter *)data;

    if (!ent || !data)
        return;

    fe = CONTAINER_OF(fe_hentry, struct vr_flow_entry, ent);
    if (!(fe->fe_flags & VR_FLOW_FLAG_ACTIVE))
        return;

    flmd.flmd_defer_data = NULL;
    flmd.flmd_index = index;
    flmd.flmd_flags = fe->fe_flags;

    vr_init_forwarding_md(&fmd);

    fe->fe_action = VR_FLOW_ACTION_DROP;
    vr_flush_entry(router, fe, &flmd, &fmd);
    vr_flow_reset_entry(router, fe);
}

static void
vr_flow_table_reset(struct vrouter *router)
{
    vr_htable_reset(router->vr_flow_table,
            vr_flow_invalidate_entry, router);
    vr_flow_table_info_reset(router);

    return;
}

void
vr_compute_size_oflow_table(void)
{
    /*
    * Overflow entries is 20% of the main flow table
    * adjusted to next 1k
    */
    if (!vr_oflow_entries) {
        vr_oflow_entries = ((vr_flow_entries / 5) + 1023) & ~1023;
    }
}

static int
vr_flow_table_init(struct vrouter *router)
{
    if (!router->vr_flow_table) {

        vr_compute_size_oflow_table();

        if (!vr_flow_table && vr_huge_page_mem_get) {

            vr_flow_table = vr_huge_page_mem_get(VR_FLOW_TABLE_SIZE +
                    VR_OFLOW_TABLE_SIZE);
            if (vr_flow_table)
                vr_oflow_table = (char*)vr_flow_table + VR_FLOW_TABLE_SIZE;
        }

        router->vr_flow_table = vr_htable_attach(router, vr_flow_entries,
                vr_flow_table, vr_oflow_entries, vr_oflow_table,
                sizeof(struct vr_flow_entry), 0, 0, vr_flow_get_key);

        if (!router->vr_flow_table) {
            return vr_module_error(-ENOMEM, __FUNCTION__,
                    __LINE__, vr_flow_entries + vr_oflow_entries);
        }
    }

    return vr_flow_table_info_init(router);
}

static void
vr_link_local_ports_reset(struct vrouter *router)
{
    if (router->vr_link_local_ports) {
        memset(router->vr_link_local_ports,
               0, router->vr_link_local_ports_size);
    }

    return;
}

static void
vr_link_local_ports_exit(struct vrouter *router)
{
    if (router->vr_link_local_ports) {
        vr_free(router->vr_link_local_ports, VR_FLOW_LINK_LOCAL_OBJECT);
        router->vr_link_local_ports = NULL;
        router->vr_link_local_ports_size = 0;
    }

    return;
}

static int
vr_link_local_ports_init(struct vrouter *router)
{
    unsigned int port_range, bytes;

    if (router->vr_link_local_ports)
        return 0;

    /*  ICMP, Udp and TCP inclusive of low and high limits*/
    port_range = VR_LL_RP_MAX *
                     ((VR_DYNAMIC_PORT_END - VR_DYNAMIC_PORT_START) + 1);
    /* Make it 16 bit boundary */
    bytes = (port_range + 15) & ~15;
    /* Bits to Bytes */
    bytes /= 8;

    router->vr_link_local_ports = vr_zalloc(bytes, VR_FLOW_LINK_LOCAL_OBJECT);
    if (!router->vr_link_local_ports)
        return -1;
    router->vr_link_local_ports_size = bytes;

    return 0;
}

/* flow module exit and init */
void
vr_flow_exit(struct vrouter *router, bool soft_reset)
{
    vr_flow_table_reset(router);
    vr_link_local_ports_reset(router);
    if (!soft_reset) {
        vr_flow_table_destroy(router);
        vr_fragment_table_exit(router);
        vr_link_local_ports_exit(router);
    }

    return;
}

int
vr_flow_mem(struct vrouter *router)
{
    int ret;

    if ((ret = vr_fragment_table_init(router)) < 0)
        return ret;

    if ((ret = vr_flow_table_init(router)))
        return ret;

    if ((ret = vr_link_local_ports_init(router)))
        return ret;

    return 0;
}

int
vr_flow_init(struct vrouter *router)
{
    return 0;
}
