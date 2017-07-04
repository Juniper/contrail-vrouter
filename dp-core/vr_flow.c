/*
 * vr_flow.c -- flow handling
 *
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#include <vr_os.h>
#include <vr_types.h>
#include <vrouter.h>
#include <vr_packet.h>
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

#define VR_NUM_FLOW_TABLES          1
#define VR_DEF_FLOW_ENTRIES         (512 * 1024)

#define VR_NUM_OFLOW_TABLES         1
#define VR_DEF_OFLOW_ENTRIES        (8 * 1024)

#define VR_FLOW_ENTRIES_PER_BUCKET  4U

#define VR_MAX_FLOW_TABLE_HOLD_COUNT \
                                    4096

unsigned int vr_flow_entries = VR_DEF_FLOW_ENTRIES;
unsigned int vr_oflow_entries = VR_DEF_OFLOW_ENTRIES;

/*
 * host can provide its own btables. Point in case is the DPDK. In DPDK,
 * we allocate the table from hugepages and just ask the flow module to
 * use those tables
 */
struct vr_btable *vr_flow_table;
struct vr_btable *vr_oflow_table;
/*
 * The flow table memory can also be a file that could be mapped. The path
 * is set by somebody and passed to agent for it to map
 */
unsigned char *vr_flow_path;
unsigned int vr_flow_hold_limit = 1;

#if defined(__linux__) && defined(__KERNEL__)
extern unsigned short vr_flow_major;
#endif

uint32_t vr_hashrnd = 0;
int hashrnd_inited = 0;

static void vr_flush_entry(struct vrouter *, struct vr_flow_entry *,
        struct vr_flow_md *, struct vr_forwarding_md *);
static void vr_flush_flow_queue(struct vrouter *, struct vr_flow_entry *,
        struct vr_forwarding_md *, struct vr_flow_queue *);

struct vr_flow_entry *vr_find_flow(struct vrouter *, struct vr_flow *,
        uint8_t, unsigned int *);
unsigned int vr_trap_flow(struct vrouter *, struct vr_flow_entry *,
        struct vr_packet *, unsigned int);

void get_random_bytes(void *buf, int nbytes);

#ifdef __FreeBSD__
uint32_t
jhash(void *key, uint32_t length, uint32_t initval);
#endif

#ifdef __FreeBSD__
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
        ((proto != VR_IP_PROTO_TCP) && (proto != VR_IP_PROTO_UDP)))
        return false;

    if ((port < VR_DYNAMIC_PORT_START) || (port > VR_DYNAMIC_PORT_END))
        return false;

    tmp = port - VR_DYNAMIC_PORT_START;
    if (proto == VR_IP_PROTO_UDP)
        tmp += (router->vr_link_local_ports_size * 8 / 2);

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
        ((proto != VR_IP_PROTO_TCP) && (proto != VR_IP_PROTO_UDP)))
        return;

    if ((port < VR_DYNAMIC_PORT_START) || (port > VR_DYNAMIC_PORT_END))
        return;

    tmp = port - VR_DYNAMIC_PORT_START;
    if (proto == VR_IP_PROTO_UDP)
        tmp += (router->vr_link_local_ports_size * 8 / 2);

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
        ((proto != VR_IP_PROTO_TCP) && (proto != VR_IP_PROTO_UDP)))
        return;

    if ((port < VR_DYNAMIC_PORT_START) || (port > VR_DYNAMIC_PORT_END))
        return;

    tmp = port - VR_DYNAMIC_PORT_START;
    if (proto == VR_IP_PROTO_UDP)
        tmp += (router->vr_link_local_ports_size * 8 / 2);

    data = &router->vr_link_local_ports[tmp / 8];
    *data |= (1 << (tmp % 8));

    return;
}

static void
vr_flow_reset_mirror(struct vrouter *router, struct vr_flow_entry *fe,
                                                            unsigned int index)
{
    if (fe->fe_flags & VR_FLOW_FLAG_MIRROR) {
        vrouter_put_mirror(router, fe->fe_mirror_id);
        fe->fe_mirror_id = VR_MAX_MIRROR_INDICES;
        vrouter_put_mirror(router, fe->fe_sec_mirror_id);
        fe->fe_sec_mirror_id = VR_MAX_MIRROR_INDICES;
        vr_mirror_meta_entry_del(router, index);
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
vr_reset_flow_entry(struct vrouter *router, struct vr_flow_entry *fe,
        unsigned int index)
{
    memset(&fe->fe_stats, 0, sizeof(fe->fe_stats));

    if (fe->fe_hold_list) {
        vr_printf("vrouter: Potential memory leak @ %s:%d\n",
                __FILE__, __LINE__);
    }
    fe->fe_hold_list = NULL;

    fe->fe_key.key_len = 0;
    fe->fe_type = VP_TYPE_NULL;
    memset(&fe->fe_key, 0, sizeof(fe->fe_key));

    vr_flow_reset_mirror(router, fe, index);
    fe->fe_ecmp_nh_index = -1;
    fe->fe_src_nh_index = NH_DISCARD_ID;
    fe->fe_rflow = -1;
    fe->fe_action = VR_FLOW_ACTION_DROP;
    fe->fe_flags = 0;
    fe->fe_udp_src_port = 0;

    return;
}


static inline bool
vr_set_flow_active(struct vr_flow_entry *fe)
{
    return __sync_bool_compare_and_swap(&fe->fe_flags,
            fe->fe_flags & ~VR_FLOW_FLAG_ACTIVE, VR_FLOW_FLAG_ACTIVE);
}

static inline struct vr_flow_entry *
vr_flow_table_entry_get(struct vrouter *router, unsigned int i)
{
    return (struct vr_flow_entry *)vr_btable_get(router->vr_flow_table, i);
}

static inline struct vr_flow_entry *
vr_oflow_table_entry_get(struct vrouter *router, unsigned int i)
{
    return (struct vr_flow_entry *)vr_btable_get(router->vr_oflow_table, i);
}

unsigned int
vr_flow_table_size(struct vrouter *router)
{
    return vr_btable_size(router->vr_flow_table);
}

unsigned int
vr_oflow_table_size(struct vrouter *router)
{
    return vr_btable_size(router->vr_oflow_table);
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
    struct vr_btable *table = router->vr_flow_table;
    unsigned int size = vr_flow_table_size(router);

    if (offset >= vr_flow_table_size(router)) {
        table = router->vr_oflow_table;
        offset -= size;
    }

    return vr_btable_get_address(table, offset);
}

struct vr_flow_entry *
vr_get_flow_entry(struct vrouter *router, int index)
{
    struct vr_btable *table;

    if (index < 0)
        return NULL;

    if ((unsigned int)index < vr_flow_entries)
        table = router->vr_flow_table;
    else {
        table = router->vr_oflow_table;
        index -= vr_flow_entries;
        if ((unsigned int)index >= vr_oflow_entries)
            return NULL;
    }

    return (struct vr_flow_entry *)vr_btable_get(table, index);
}

static void
vr_flow_queue_free(struct vrouter *router, void *arg)
{
    struct vr_forwarding_md fmd;
    struct vr_defer_data *defer;
    struct vr_flow_entry *fe;
    struct vr_flow_queue *vfq;

    defer = (struct vr_defer_data *)arg;
    if (!defer)
        return;

    vr_init_forwarding_md(&fmd);

    vfq = (struct vr_flow_queue *)defer->vdd_data;
    fe = vr_get_flow_entry(router, vfq->vfq_index);
    vr_flush_flow_queue(router, fe, &fmd, vfq);
    vr_free(vfq);
    return;
}

static void
vr_flow_queue_free_defer(struct vr_flow_md *flmd, struct vr_flow_queue *vfq)
{
    struct vr_defer_data *vdd = flmd->flmd_defer_data;

    if (!vdd) {
        vr_free(vfq);
        return;
    }

    vdd->vdd_data = (void *)vfq;
    vr_defer(flmd->flmd_router, vr_flow_queue_free, (void *)vdd);
    flmd->flmd_defer_data = NULL;

    return;
}

static struct vr_flow_entry *
vr_find_free_entry(struct vrouter *router, struct vr_flow *key, uint8_t type,
        bool need_hold, unsigned int *fe_index)
{
    unsigned int i, index, hash, free_index = 0;
    struct vr_flow_entry *tmp_fe, *fe = NULL;

    hash = vr_hash(key, key->key_len, 0);

    index = (hash % vr_flow_entries) & ~(VR_FLOW_ENTRIES_PER_BUCKET - 1);
    for (i = 0; i < VR_FLOW_ENTRIES_PER_BUCKET; i++) {
        tmp_fe = vr_flow_table_entry_get(router, index);
        if (tmp_fe && !(tmp_fe->fe_flags & VR_FLOW_FLAG_ACTIVE)) {
            if (vr_set_flow_active(tmp_fe)) {
                vr_init_flow_entry(tmp_fe);
                fe = tmp_fe;
                break;
            }
        }
        index++;
    }

    if (!fe) {
        index = hash % vr_oflow_entries;
        for (i = 0; i < vr_oflow_entries; i++) {
            tmp_fe = vr_oflow_table_entry_get(router, index);
            if (tmp_fe && !(tmp_fe->fe_flags & VR_FLOW_FLAG_ACTIVE)) {
                if (vr_set_flow_active(tmp_fe)) {
                    vr_init_flow_entry(tmp_fe);
                    fe = tmp_fe;
                    break;
                }
            }
            index = (index + 1) % vr_oflow_entries;
        }

        if (fe)
            free_index += vr_flow_entries;
    }

    if (fe) {
        free_index += index;
        if (need_hold) {
            fe->fe_hold_list = vr_zalloc(sizeof(struct vr_flow_queue));
            if (!fe->fe_hold_list) {
                vr_reset_flow_entry(router, fe, free_index);
                fe = NULL;
            } else {
                fe->fe_hold_list->vfq_index = free_index;
            }
        }

        if (fe) {
            fe->fe_type = type;
            fe->fe_key.key_len = key->key_len;
            memcpy(&fe->fe_key, key, key->key_len);
            *fe_index = free_index;
        }
    }

    return fe;
}

static inline struct vr_flow_entry *
vr_flow_table_lookup(struct vr_flow *key, uint16_t type,
        struct vr_btable *table, unsigned int table_size,
        unsigned int bucket_size, unsigned int hash, unsigned int *fe_index)
{
    unsigned int i;
    struct vr_flow_entry *flow_e;

    hash %= table_size;

    if (!bucket_size) {
        bucket_size = table_size;
    } else {
        hash &= ~(bucket_size - 1);
    }

    for (i = 0; i < bucket_size; i++) {
        flow_e = (struct vr_flow_entry *)vr_btable_get(table,
                (hash + i) % table_size);
        if (flow_e && (!(flow_e->fe_flags & VR_FLOW_FLAG_DELETE_MARKED)) &&
                (flow_e->fe_flags & VR_FLOW_FLAG_ACTIVE) &&
                (flow_e->fe_type == type)) {
            if (!memcmp(&flow_e->fe_key, key, key->key_len)) {
                *fe_index = (hash + i) % table_size;
                return flow_e;
            }
        }
    }

    return NULL;
}


struct vr_flow_entry *
vr_find_flow(struct vrouter *router, struct vr_flow *key,
        uint8_t type, unsigned int *fe_index)
{
    unsigned int hash;
    struct vr_flow_entry *flow_e;

    hash = vr_hash(key, key->key_len, 0);

    /* first look in the regular flow table */
    flow_e = vr_flow_table_lookup(key, type, router->vr_flow_table,
            vr_flow_entries, VR_FLOW_ENTRIES_PER_BUCKET, hash, fe_index);
    /* if not in the regular flow table, lookup in the overflow flow table */
    if (!flow_e) {
        flow_e = vr_flow_table_lookup(key, type, router->vr_oflow_table,
                vr_oflow_entries, 0, hash, fe_index);
        *fe_index += vr_flow_entries;
    }

    return flow_e;
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
        if (vr_forwarding_md_label_is_vxlan_id(fmd))
            pnode->pl_flags |= PN_FLAG_LABEL_IS_VXLAN_ID;
        if (fmd->fmd_to_me)
            pnode->pl_flags |= PN_FLAG_TO_ME;
    }

    if (ip && vr_ip_is_ip4(ip)) {
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
    }

    pnode->pl_vrf = fmd->fmd_dvrf;
    pnode->pl_vlan = fmd->fmd_vlan;

    __sync_synchronize();
    pnode->pl_packet = pkt;

    return;
}

static int
vr_enqueue_flow(struct vrouter *router, struct vr_flow_entry *fe,
        struct vr_packet *pkt, unsigned int index,
        struct vr_forwarding_md *fmd)
{
    unsigned int i;
    unsigned short drop_reason = 0;
    struct vr_flow_queue *vfq = fe->fe_hold_list;
    struct vr_packet_node *pnode;

    if (!vfq) {
        drop_reason = VP_DROP_FLOW_UNUSABLE;
        goto drop;
    }

    i = __sync_fetch_and_add(&vfq->vfq_entries, 1);
    if (i >= VR_MAX_FLOW_QUEUE_ENTRIES) {
        drop_reason = VP_DROP_FLOW_QUEUE_LIMIT_EXCEEDED;
        goto drop;
    }

    pnode = &vfq->vfq_pnodes[i];
    vr_flow_fill_pnode(pnode, pkt, fmd);
    if (!i)
        vr_trap_flow(router, fe, pkt, index);

    return 0;
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
        rfe = vr_get_flow_entry(router, fe->fe_rflow);
        if (rfe)
            md->fmd_ecmp_src_nh_index = rfe->fe_ecmp_nh_index;
    }

    return;
}

static int
vr_rflow_update_ecmp_index(struct vrouter *router, struct vr_flow_entry *fe,
        unsigned int new_ecmp_index, struct vr_forwarding_md *fmd)
{
    struct vr_flow_entry *rfe;

    if (new_ecmp_index == -1)
        return -1;

    rfe = vr_get_flow_entry(router, fe->fe_rflow);
    if ((!rfe) || (rfe->fe_flags & VR_FLOW_FLAG_DELETE_MARKED))
        return -1;

    rfe->fe_ecmp_nh_index = new_ecmp_index;

    fmd->fmd_ecmp_src_nh_index = new_ecmp_index;

    return 0;
}

int
vr_flow_update_ecmp_index(struct vrouter *router,
            unsigned int new_ecmp_index, struct vr_forwarding_md *fmd)
{
    struct vr_flow_entry *fe;

    if (new_ecmp_index == -1)
        return -1;

    fe = vr_get_flow_entry(router, fmd->fmd_flow_index);
    if ((!fe) || (fe->fe_flags & VR_FLOW_FLAG_DELETE_MARKED))
        return -1;

    /* If RPF verification is manipulating this flow, let it succeed */
    (void)__sync_bool_compare_and_swap(&fe->fe_ecmp_nh_index,
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

    flow_result_t result;

    struct vr_forwarding_md mirror_fmd;
    struct vr_nexthop *src_nh;

    fmd->fmd_dvrf = fe->fe_vrf;
    /*
     * for now, we will not use dvrf if VRFT is set, because the RPF
     * check needs to happen in the source vrf
     */

    vr_flow_set_forwarding_md(router, fe, index, fmd);
    src_nh = __vrouter_get_nexthop(router, fe->fe_src_nh_index);
    if (!src_nh) {
        vr_pfree(pkt, VP_DROP_INVALID_NH);
        return FLOW_CONSUMED;
    }

    if (src_nh->nh_validate_src) {
        valid_src = src_nh->nh_validate_src(pkt, src_nh, fmd, &modified_index);
        if (valid_src == NH_SOURCE_INVALID) {
            vr_pfree(pkt, VP_DROP_INVALID_SOURCE);
            return FLOW_CONSUMED;
        }

        if (valid_src == NH_SOURCE_MISMATCH) {
            valid_src = vr_rflow_update_ecmp_index(router, fe,
                                                    modified_index, fmd);
            if (valid_src == -1) {
                vr_pfree(pkt, VP_DROP_INVALID_SOURCE);
                return FLOW_CONSUMED;
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
            vr_mirror(router, fe->fe_mirror_id, pkt, &mirror_fmd);
        }
        if (fe->fe_sec_mirror_id < VR_MAX_MIRROR_INDICES) {
            mirror_fmd = *fmd;
            mirror_fmd.fmd_ecmp_nh_index = -1;
            vr_mirror(router, fe->fe_sec_mirror_id, pkt, &mirror_fmd);
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

    return result;
}


unsigned int
vr_trap_flow(struct vrouter *router, struct vr_flow_entry *fe,
        struct vr_packet *pkt, unsigned int index)
{
    unsigned int trap_reason;
    struct vr_packet *npkt;
    struct vr_flow_trap_arg ta;

    npkt = vr_pclone(pkt);
    if (!npkt)
        return -ENOMEM;

    vr_preset(npkt);

    switch (fe->fe_flags & VR_FLOW_FLAG_TRAP_MASK) {
    default:
        trap_reason = AGENT_TRAP_FLOW_MISS;
        ta.vfta_index = index;
        if (fe->fe_type == VP_TYPE_IP)
            ta.vfta_nh_index = fe->fe_key.flow4_nh_id;
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

    new_stats = __sync_add_and_fetch(&fe->fe_stats.flow_bytes, pkt_len(pkt));
    if (new_stats < pkt_len(pkt))
        fe->fe_stats.flow_bytes_oflow++;

    new_stats = __sync_add_and_fetch(&fe->fe_stats.flow_packets, 1);
    if (!new_stats)
        fe->fe_stats.flow_packets_oflow++;

    if (fe->fe_action == VR_FLOW_ACTION_HOLD) {
        vr_enqueue_flow(router, fe, pkt, index, fmd);
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
vr_flow_entry_set_hold(struct vrouter *router, struct vr_flow_entry *flow_e)
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
        (void)__sync_add_and_fetch(&infop->vfti_oflows, 1);
        act_count = infop->vfti_action_count;
        if (act_count > infop->vfti_hold_count[cpu]) {
           (void)__sync_sub_and_fetch(&infop->vfti_action_count,
                    infop->vfti_hold_count[cpu]);
            infop->vfti_hold_count[cpu] = 0;
        } else {
            infop->vfti_hold_count[cpu] -= act_count;
            (void)__sync_sub_and_fetch(&infop->vfti_action_count,
                    act_count);
        }
    }

    infop->vfti_hold_count[cpu]++;

    return;
}

flow_result_t
vr_flow_lookup(struct vrouter *router, struct vr_flow *key,
               struct vr_packet *pkt, struct vr_forwarding_md *fmd)
{
    unsigned int fe_index;
    struct vr_flow_entry *flow_e;

    pkt->vp_flags |= VP_FLAG_FLOW_SET;

    flow_e = vr_find_flow(router, key, pkt->vp_type,  &fe_index);
    if (!flow_e) {
        if (pkt->vp_nh &&
            (pkt->vp_nh->nh_flags & NH_FLAG_RELAXED_POLICY))
            return FLOW_FORWARD;

        if ((vr_flow_hold_limit) &&
                (vr_flow_table_hold_count(router) >
                 VR_MAX_FLOW_TABLE_HOLD_COUNT)) {
            vr_pfree(pkt, VP_DROP_FLOW_UNUSABLE);
            return FLOW_CONSUMED;
        }

        flow_e = vr_find_free_entry(router, key, pkt->vp_type,
                true, &fe_index);
        if (!flow_e) {
            vr_pfree(pkt, VP_DROP_FLOW_TABLE_FULL);
            return FLOW_CONSUMED;
        }

        flow_e->fe_vrf = fmd->fmd_dvrf;
        /* mark as hold */
        vr_flow_entry_set_hold(router, flow_e);
    }

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

bool
vr_flow_forward(struct vrouter *router, struct vr_packet *pkt,
                struct vr_forwarding_md *fmd)
{
    flow_result_t result;

    /* Flow processig is only for untagged unicast IP packets */
    if ((pkt->vp_type == VP_TYPE_IP) && (!(pkt->vp_flags & VP_FLAG_MULTICAST))
        && ((fmd->fmd_vlan == VLAN_ID_INVALID) || vif_is_service(pkt->vp_if)))
        result = vr_inet_flow_lookup(router, pkt, fmd);
    else
        result = FLOW_FORWARD;

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
        vr_forwarding_md_set_label(fmd, pnode->pl_label,
                VR_LABEL_TYPE_VXLAN_ID);
    } else {
        vr_forwarding_md_set_label(fmd, pnode->pl_label,
                VR_LABEL_TYPE_MPLS);
    }

    if (pnode->pl_flags & PN_FLAG_TO_ME)
        fmd->fmd_to_me = 1;

    pkt = pnode->pl_packet;
    if (!pkt)
        return -EINVAL;

    pnode->pl_packet = NULL;
    /*
     * this is only a security check and not a catch all check. one note
     * of caution. please do not access pkt->vp_if till the if block is
     * succesfully bypassed
     */
    vif = __vrouter_get_interface(router, pnode->pl_vif_idx);
    if (!vif || (pkt->vp_if != vif)) {
        vr_pfree(pkt, VP_DROP_INVALID_IF);
        return -ENODEV;
    }

    if (!pkt->vp_nh) {
        if (vif_is_fabric(pkt->vp_if) && fmd &&
                (fmd->fmd_label >= 0)) {
            if (!vr_forwarding_md_label_is_vxlan_id(fmd))
                pkt->vp_nh = __vrouter_get_label(router, fmd->fmd_label);
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
vr_flush_flow_queue(struct vrouter *router, struct vr_flow_entry *fe,
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
    struct vr_flow_queue *vfq;

    if (fe->fe_action == VR_FLOW_ACTION_HOLD)
        return;

    vfq = fe->fe_hold_list;
    if (!vfq)
        return;
    fe->fe_hold_list = NULL;

    vr_flush_flow_queue(router, fe, fmd, vfq);
    vr_flow_queue_free_defer(flmd, vfq);

    return;
}

static void
vr_flow_flush(void *arg)
{
    struct vrouter *router;
    struct vr_flow_entry *fe;
    struct vr_forwarding_md fmd;
    struct vr_flow_md *flmd =
                (struct vr_flow_md *)arg;

    router = flmd->flmd_router;
    if (!router)
        goto exit_flush;

    fe = vr_get_flow_entry(router, flmd->flmd_index);
    if (!fe)
        goto exit_flush;

    vr_init_forwarding_md(&fmd);
    vr_flow_set_forwarding_md(router, fe, flmd->flmd_index, &fmd);

    vr_flush_entry(router, fe, flmd, &fmd);

    if (!(flmd->flmd_flags & VR_FLOW_FLAG_ACTIVE)) {
        vr_reset_flow_entry(router, fe, flmd->flmd_index);
    }

exit_flush:
    if (flmd->flmd_defer_data) {
        vr_put_defer_data(flmd->flmd_defer_data);
        flmd->flmd_defer_data = NULL;
    }

    vr_free(flmd);

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
            vrouter_put_mirror(router, fe->fe_mirror_id);
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
            vrouter_put_mirror(router, fe->fe_sec_mirror_id);
            fe->fe_sec_mirror_id = router->vr_max_mirror_indices;
        }

        if ((unsigned int)req->fr_sec_mir_id < router->vr_max_mirror_indices) {
            sec_mirror = vrouter_get_mirror(req->fr_rid, req->fr_sec_mir_id);
            if (sec_mirror)
                fe->fe_sec_mirror_id = req->fr_sec_mir_id;
        }
    }

    if (req->fr_pcap_meta_data_size && req->fr_pcap_meta_data)
        vr_mirror_meta_entry_set(router, req->fr_index,
                req->fr_mir_sip, req->fr_mir_sport,
                req->fr_pcap_meta_data, req->fr_pcap_meta_data_size,
                req->fr_mir_vrf);

    return;
}

static struct vr_flow_entry *
vr_add_flow(unsigned int rid, struct vr_flow *key, uint8_t type,
        bool need_hold_queue, unsigned int *fe_index)
{
    struct vr_flow_entry *flow_e;
    struct vrouter *router = vrouter_get(rid);

    flow_e = vr_find_flow(router, key, type, fe_index);
    if (flow_e) {
        /* a race between agent and dp. allow agent to handle this error */
        return NULL;
    } else {
        flow_e = vr_find_free_entry(router, key, type,
                need_hold_queue, fe_index);
    }

    return flow_e;
}

static struct vr_flow_entry *
vr_add_flow_req(vr_flow_req *req, unsigned int *fe_index)
{
    uint8_t type;
    bool need_hold_queue = false;

    struct vr_flow key;
    struct vr_flow_entry *fe;

    vr_inet_fill_flow(&key, req->fr_flow_nh_id, req->fr_flow_sip,
            req->fr_flow_dip, req->fr_flow_proto,
            req->fr_flow_sport, req->fr_flow_dport);
    type = VP_TYPE_IP;

    if (req->fr_action == VR_FLOW_ACTION_HOLD)
        need_hold_queue = true;

    fe = vr_add_flow(req->fr_rid, &key, type, need_hold_queue, fe_index);
    if (fe)
        req->fr_index = *fe_index;

    return fe;
}

/*
 * can be called with 'fe' as null (specifically when flow is added from
 * agent), in which case we should be checking only the request
 */
static int
vr_flow_req_is_invalid(struct vrouter *router, vr_flow_req *req,
        struct vr_flow_entry *fe)
{
    struct vr_flow_entry *rfe;

    if (fe) {

        /* If Delete marked, dont allow any other change */
        if (fe->fe_flags & VR_FLOW_FLAG_DELETE_MARKED)
            return -EINVAL;

        if (fe->fe_type == VP_TYPE_IP) {
            if ((unsigned int)req->fr_flow_sip != fe->fe_key.flow4_sip ||
                    (unsigned int)req->fr_flow_dip != fe->fe_key.flow4_dip ||
                    (unsigned short)req->fr_flow_sport != fe->fe_key.flow4_sport ||
                    (unsigned short)req->fr_flow_dport != fe->fe_key.flow4_dport||
                    (unsigned short)req->fr_flow_nh_id != fe->fe_key.flow4_nh_id ||
                    (unsigned char)req->fr_flow_proto != fe->fe_key.flow4_proto) {
                return -EBADF;
            }
        }
    }

    if (req->fr_flags & VR_FLOW_FLAG_VRFT) {
        if ((unsigned short)req->fr_flow_dvrf >= router->vr_max_vrfs)
            return -EINVAL;
    }

    if (req->fr_flags & VR_FLOW_FLAG_MIRROR) {
        if (((unsigned int)req->fr_mir_id >= router->vr_max_mirror_indices) &&
                (unsigned int)req->fr_sec_mir_id >= router->vr_max_mirror_indices)
            return -EINVAL;
    }

    if (req->fr_flags & VR_RFLOW_VALID) {
        rfe = vr_get_flow_entry(router, req->fr_rindex);
        if (!rfe)
            return -EINVAL;
    }

    return 0;
}

static int
vr_flow_schedule_transition(struct vrouter *router, vr_flow_req *req,
        struct vr_flow_entry *fe)
{
    struct vr_flow_md *flmd;
    struct vr_defer_data *defer = NULL;

    flmd = (struct vr_flow_md *)vr_malloc(sizeof(*flmd));
    if (!flmd)
        return -ENOMEM;

    flmd->flmd_router = router;
    flmd->flmd_index = req->fr_index;
    flmd->flmd_flags = req->fr_flags;
    if (fe->fe_hold_list) {
        defer = vr_get_defer_data(sizeof(*defer));
        if (!defer) {
            vr_free(flmd);
            return -ENOMEM;
        }
    }
    flmd->flmd_defer_data = defer;

    vr_schedule_work(vr_get_cpu(), vr_flow_flush, (void *)flmd);
    return 0;
}

static int
vr_flow_delete(struct vrouter *router, vr_flow_req *req,
        struct vr_flow_entry *fe)
{

    /* Delete Mark */
    fe->fe_flags |= VR_FLOW_FLAG_DELETE_MARKED;

    if (fe->fe_flags & VR_FLOW_FLAG_LINK_LOCAL)
        vr_clear_link_local_port(router, AF_INET, fe->fe_key.flow4_proto,
                                   ntohs(fe->fe_key.flow4_dport));

    fe->fe_action = VR_FLOW_ACTION_DROP;
    vr_flow_reset_mirror(router, fe, req->fr_index);

    return vr_flow_schedule_transition(router, req, fe);
}

static void
vr_flow_udp_src_port (struct vrouter *router, struct vr_flow_entry *fe)
{
    uint32_t hash_key[5], hashval, port_range;
    uint16_t port;

    if (fe->fe_udp_src_port)
        return;

    if (hashrnd_inited == 0) {
        get_random_bytes(&vr_hashrnd, sizeof(vr_hashrnd));
        hashrnd_inited = 1;
    }

    hash_key[0] = fe->fe_key.flow4_sip;
    hash_key[1] = fe->fe_key.flow4_dip;
    hash_key[2] = fe->fe_vrf;
    hash_key[3] = fe->fe_key.flow4_sport;
    hash_key[4] = fe->fe_key.flow4_dport;

    hashval = jhash(hash_key, 20, vr_hashrnd);
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


/* command from agent */
static int
vr_flow_set(struct vrouter *router, vr_flow_req *req)
{
    int ret;
    unsigned int fe_index = (unsigned int)-1;

    struct vr_flow_entry *fe = NULL;
    struct vr_flow_table_info *infop = router->vr_flow_table_info;

    router = vrouter_get(req->fr_rid);
    if (!router)
        return -EINVAL;

    fe = vr_get_flow_entry(router, req->fr_index);

    if ((ret = vr_flow_req_is_invalid(router, req, fe)))
        return ret;

    if (fe && (fe->fe_action == VR_FLOW_ACTION_HOLD) &&
            ((req->fr_action != fe->fe_action) ||
             !(req->fr_flags & VR_FLOW_FLAG_ACTIVE)))
        __sync_fetch_and_add(&infop->vfti_action_count, 1);
    /*
     * for delete, absence of the requested flow entry is caustic. so
     * handle that case first
     */
    if (!(req->fr_flags & VR_FLOW_FLAG_ACTIVE)) {
        if (!fe)
            return -EINVAL;
        return vr_flow_delete(router, req, fe);
    }


    /*
     * for non-delete cases, absence of flow entry means addition of a
     * new flow entry with the key specified in the request
     */
    if (!fe) {
        fe = vr_add_flow_req(req, &fe_index);
        if (!fe) {
            if (fe_index != (unsigned int)-1) {
                /*
                 * add flow req failed to allocate an entry due to race
                 * between agent and datapath, where flow entry at fe_index
                 * was already created due to packet trap, return EEXIST
                 * error and allow agent to wait and handle flow add due to
                 * packet trap
                 */
                return -EEXIST;
            }
            return -ENOSPC;
        }

        infop->vfti_added++;
    } else {
        if ((req->fr_action == VR_FLOW_ACTION_HOLD) &&
                (fe->fe_action != req->fr_action)) {
            if (!fe->fe_hold_list) {
                fe->fe_hold_list = vr_zalloc(sizeof(struct vr_flow_queue));
                if (!fe->fe_hold_list)
                    return -ENOMEM;
            }
        }
    }

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

    if (fe->fe_type == VP_TYPE_IP) {
        if (req->fr_flags & VR_FLOW_FLAG_LINK_LOCAL) {
            if (!(fe->fe_flags & VR_FLOW_FLAG_LINK_LOCAL))
                vr_set_link_local_port(router, AF_INET,
                        fe->fe_key.flow4_proto,
                        ntohs(fe->fe_key.flow4_dport));
        } else {
            if (fe->fe_flags & VR_FLOW_FLAG_LINK_LOCAL)
                vr_clear_link_local_port(router, AF_INET,
                        fe->fe_key.flow4_proto,
                        ntohs(fe->fe_key.flow4_dport));
        }
    }

    /*
     * Accept the Ecmp nexthop index from Agent only when setting the
     * flow for the first time
     */
    if (fe->fe_ecmp_nh_index == -1)
        (void)__sync_bool_compare_and_swap(&fe->fe_ecmp_nh_index, -1,
                req->fr_ecmp_nh_index);

    fe->fe_src_nh_index = req->fr_src_nh_index;

    if ((req->fr_action == VR_FLOW_ACTION_HOLD) &&
            (fe->fe_action != VR_FLOW_ACTION_HOLD)) {
        vr_flow_entry_set_hold(router, fe);
    } else {
        fe->fe_action = req->fr_action;
    }

    if (fe->fe_action == VR_FLOW_ACTION_DROP)
        fe->fe_drop_reason = (uint8_t)req->fr_drop_reason;

    fe->fe_flags = req->fr_flags; 
    vr_flow_udp_src_port(router, fe);

    return vr_flow_schedule_transition(router, req, fe);
}

static void
vr_flow_req_destroy(vr_flow_req *req)
{
    if (!req)
        return;

    if (req->fr_file_path) {
        vr_free(req->fr_file_path);
        req->fr_file_path = NULL;
    }

    if (req->fr_hold_stat && req->fr_hold_stat_size) {
        vr_free(req->fr_hold_stat);
        req->fr_hold_stat = NULL;
        req->fr_hold_stat_size = 0;
    }

    vr_free(req);

    return;
}

vr_flow_req *
vr_flow_req_get(vr_flow_req *ref_req)
{
    unsigned int hold_stat_size;
    unsigned int num_cpus = vr_num_cpus;
    vr_flow_req *req = vr_zalloc(sizeof(*req));

    if (!req)
        return NULL;

    if (ref_req) {
        memcpy(req, ref_req, sizeof(*ref_req));
        /* not intended */
        req->fr_pcap_meta_data = NULL;
        req->fr_pcap_meta_data_size = 0;
    }

    if (vr_flow_path) {
        req->fr_file_path = vr_zalloc(VR_UNIX_PATH_MAX);
        if (!req->fr_file_path) {
            vr_free(req);
            return NULL;
        }
    }

    if (num_cpus > VR_FLOW_MAX_CPUS)
        num_cpus = VR_FLOW_MAX_CPUS;

    hold_stat_size = num_cpus * sizeof(uint32_t);
    req->fr_hold_stat = vr_zalloc(hold_stat_size);
    if (!req->fr_hold_stat) {
        if (vr_flow_path && req->fr_file_path) {
            vr_free(req->fr_file_path);
            req->fr_file_path = NULL;
        }

        vr_free(req);
        return NULL;
    }
    req->fr_hold_stat_size = num_cpus;

    return req;
}

/*
 * sandesh handler for vr_flow_req
 */
void
vr_flow_req_process(void *s_req)
{
    int ret = 0;
    unsigned int i, object = VR_FLOW_OBJECT_ID;
    bool need_destroy = false;
    uint64_t hold_count = 0;

    struct vrouter *router;
    vr_flow_req *req = (vr_flow_req *)s_req;
    vr_flow_req *resp = NULL;

    router = vrouter_get(req->fr_rid);
    switch (req->fr_op) {
    case FLOW_OP_FLOW_TABLE_GET:
        resp = vr_flow_req_get(req);
        if (!resp) {
            ret = -ENOMEM;
            goto send_response;
        }

        need_destroy = true;
        resp->fr_op = req->fr_op;
        resp->fr_ftable_size = vr_flow_table_size(router) +
            vr_oflow_table_size(router);
#if defined(__linux__) && defined(__KERNEL__)
        resp->fr_ftable_dev = vr_flow_major;
#endif
        if (vr_flow_path) {
            strncpy(resp->fr_file_path, vr_flow_path, VR_UNIX_PATH_MAX - 1);
        }

        resp->fr_processed = router->vr_flow_table_info->vfti_action_count;
        resp->fr_hold_oflows = router->vr_flow_table_info->vfti_oflows;
        resp->fr_added = router->vr_flow_table_info->vfti_added;
        resp->fr_cpus = vr_num_cpus;
        /* we only have space for 64 stats block max when encoding */
        for (i = 0; ((i < vr_num_cpus) && (i < VR_FLOW_MAX_CPUS)); i++) {
            resp->fr_hold_stat[i] =
                router->vr_flow_table_info->vfti_hold_count[i];
            hold_count += resp->fr_hold_stat[i];
        }

        resp->fr_created = hold_count;

        object = VR_FLOW_INFO_OBJECT_ID;
        break;

    case FLOW_OP_FLOW_SET:
        ret = vr_flow_set(router, req);
        resp = req;
        break;

    default:
        ret = -EINVAL;
    }

send_response:
    vr_message_response(object, resp, ret);
    if (need_destroy) {
        vr_flow_req_destroy(resp);
    }

    return;
}

static void
vr_flow_table_info_destroy(struct vrouter *router)
{
    if (!router->vr_flow_table_info)
        return;

    vr_free(router->vr_flow_table_info);
    router->vr_flow_table_info = NULL;
    router->vr_flow_table_info_size = 0;

    return;
}

static void
vr_flow_table_info_reset(struct vrouter *router)
{
    if (!router->vr_flow_table_info)
        return;

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
    infop = (struct vr_flow_table_info *)vr_zalloc(size);
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
        vr_btable_free(router->vr_flow_table);
        router->vr_flow_table = NULL;
    }

    if (router->vr_oflow_table) {
        vr_btable_free(router->vr_oflow_table);
        router->vr_oflow_table = NULL;
    }

    vr_flow_table_info_destroy(router);

    return;
}

static void
vr_flow_table_reset(struct vrouter *router)
{
    unsigned int start, end, i;
    struct vr_flow_entry *fe;
    struct vr_forwarding_md fmd;
    struct vr_flow_md flmd;

    start = end = 0;
    if (router->vr_flow_table)
        end = vr_btable_entries(router->vr_flow_table);

    if (router->vr_oflow_table) {
        if (!end)
            start = vr_flow_entries;
        end += vr_btable_entries(router->vr_oflow_table);
    }

    if (end) {
        flmd.flmd_defer_data = NULL;
        vr_init_forwarding_md(&fmd);
        for (i = start; i < end; i++) {
            fe = vr_get_flow_entry(router, i);
            if (fe) {
                flmd.flmd_index = i;
                flmd.flmd_flags = fe->fe_flags;
                fe->fe_action = VR_FLOW_ACTION_DROP;
                vr_flush_entry(router, fe, &flmd, &fmd);
                vr_reset_flow_entry(router, fe, i);
            }
        }
    }

    vr_flow_table_info_reset(router);

    return;
}


static int
vr_flow_table_init(struct vrouter *router)
{
    if (!router->vr_flow_table) {
        if (vr_flow_entries % VR_FLOW_ENTRIES_PER_BUCKET)
            return vr_module_error(-EINVAL, __FUNCTION__,
                    __LINE__, vr_flow_entries);

        if (vr_flow_table) {
            router->vr_flow_table = vr_flow_table;
        } else {
            router->vr_flow_table = vr_btable_alloc(vr_flow_entries,
                    sizeof(struct vr_flow_entry));
        }

        if (!router->vr_flow_table) {
            return vr_module_error(-ENOMEM, __FUNCTION__,
                    __LINE__, vr_flow_entries);
        }
    }

    if (!router->vr_oflow_table) {
        if (vr_oflow_table) {
            router->vr_oflow_table = vr_oflow_table;
        } else {
            router->vr_oflow_table = vr_btable_alloc(vr_oflow_entries,
                    sizeof(struct vr_flow_entry));
        }

        if (!router->vr_oflow_table) {
            return vr_module_error(-ENOMEM, __FUNCTION__,
                    __LINE__, vr_oflow_entries);
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
        vr_free(router->vr_link_local_ports);
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

    /*  Udp and TCP inclusive of low and high limits*/
    port_range = 2 * ((VR_DYNAMIC_PORT_END - VR_DYNAMIC_PORT_START) + 1);
    /* Make it 16 bit boundary */
    bytes = (port_range + 15) & ~15;
    /* Bits to Bytes */
    bytes /= 8;

    router->vr_link_local_ports = vr_zalloc(bytes);
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
vr_flow_init(struct vrouter *router)
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
