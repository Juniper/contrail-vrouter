/*
 * vr_flow.c -- flow handling
 *
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#include <vr_os.h>
#include <vr_types.h>
#include <vr_packet.h>
#include <vr_mirror.h>
#include "vr_sandesh.h"
#include "vr_message.h"
#include "vr_mcast.h"
#include "vr_btable.h"
#include "vr_fragment.h"
#include "vr_datapath.h"
#include "vr_hash.h"
#include "vr_ip_mtrie.h"

#define VR_NUM_FLOW_TABLES          1
#define VR_DEF_FLOW_ENTRIES         (512 * 1024)
#define VR_FLOW_TABLE_SIZE          (vr_flow_entries * \
        sizeof(struct vr_flow_entry))

#define VR_NUM_OFLOW_TABLES         1
#define VR_DEF_OFLOW_ENTRIES        (8 * 1024)
#define VR_OFLOW_TABLE_SIZE         (vr_oflow_entries *\
        sizeof(struct vr_flow_entry))

#define VR_FLOW_ENTRIES_PER_BUCKET  4U

#define VR_MAX_FLOW_QUEUE_ENTRIES   3U

#define VR_MAX_FLOW_TABLE_HOLD_COUNT \
                                    4096

unsigned int vr_flow_entries = VR_DEF_FLOW_ENTRIES;
unsigned int vr_oflow_entries = VR_DEF_OFLOW_ENTRIES;

#if defined(__linux__) && defined(__KERNEL__)
extern unsigned short vr_flow_major;
#endif

uint32_t vr_hashrnd = 0;
int hashrnd_inited = 0;


extern int vr_ip_input(struct vrouter *, unsigned short,
        struct vr_packet *, struct vr_forwarding_md *);
extern void vr_ip_update_csum(struct vr_packet *, unsigned int,
        unsigned int);
extern uint16_t vr_icmp6_checksum(void * buffer, int bytes);

static void vr_flush_entry(struct vrouter *, struct vr_flow_entry *,
        struct vr_flow_md *, struct vr_forwarding_md *);
struct vr_flow_entry *vr_find_flow(struct vrouter *, struct vr_flow_key *,
        unsigned int *);
unsigned int vr_trap_flow(struct vrouter *, struct vr_flow_entry *,
        struct vr_packet *, unsigned int);

void get_random_bytes(void *buf, int nbytes);

#ifdef __FreeBSD__
uint32_t
jhash(void *key, uint32_t length, uint32_t interval);
#endif

#ifdef __FreeBSD__
uint32_t
jhash(void *key, uint32_t length, uint32_t interval)
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

    data = router->vr_link_local_ports[(tmp /8)];
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

    data = &router->vr_link_local_ports[(tmp /8)];
    *data &= (~(1 << (tmp % 8)));
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

    data = &router->vr_link_local_ports[tmp /8];
    *data |= (1 << (tmp % 8));
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
    memset(&fe->fe_hold_list, 0, sizeof(fe->fe_hold_list));;
    memset(&fe->fe_key, 0, sizeof(fe->fe_key));

    vr_flow_reset_mirror(router, fe, index);
    fe->fe_ecmp_nh_index = -1;
    fe->fe_src_nh_index = NH_DISCARD_ID;
    fe->fe_rflow = -1;
    fe->fe_action = VR_FLOW_ACTION_DROP;
    fe->fe_flags = 0;

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

static inline void
vr_get_flow_key(struct vr_flow_key *key, uint16_t vlan, struct vr_packet *pkt,
        unsigned int sip, unsigned int dip, unsigned char proto,
        unsigned short sport, unsigned short dport)
{
    unsigned short nh_id;

    /* copy both source and destinations */
    key->key_src_ip = sip;
    key->key_dest_ip = dip;
    key->key_proto = proto;
    key->key_zero = 0;

    if (vif_is_fabric(pkt->vp_if) && pkt->vp_nh) {
        nh_id = pkt->vp_nh->nh_id;
    } else if (vif_is_service(pkt->vp_if)) {
        nh_id = vif_vrf_table_get_nh(pkt->vp_if, vlan);
    } else {
        nh_id = pkt->vp_if->vif_nh_id;
    }

    key->key_nh_id = nh_id;

    switch (proto) {
    case VR_IP_PROTO_TCP:
    case VR_IP_PROTO_UDP:
    case VR_IP_PROTO_ICMP:
    case VR_IP_PROTO_ICMP6:
        key->key_src_port = sport;
        key->key_dst_port = dport;
        break;

    default:
        key->key_src_port = key->key_dst_port = 0;
        break;
    }

    return;
}

static struct vr_flow_entry *
vr_find_free_entry(struct vrouter *router, struct vr_flow_key *key,
        unsigned int *fe_index)
{
    unsigned int i, index, hash;
    struct vr_flow_entry *tmp_fe, *fe = NULL;

    *fe_index = 0;

    hash = vr_hash(key, sizeof(*key), 0);

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
            *fe_index += vr_flow_entries;
    }

    if (fe) {
        *fe_index += index;
        memcpy(&fe->fe_key, key, sizeof(*key));
    }

    return fe;
}

static inline struct vr_flow_entry *
vr_flow_table_lookup(struct vr_flow_key *key, struct vr_btable *table,
                unsigned int table_size, unsigned int bucket_size,
                unsigned int hash, unsigned int *fe_index)
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
        if (flow_e && flow_e->fe_flags & VR_FLOW_FLAG_ACTIVE) {
            if (!memcmp(&flow_e->fe_key, key, sizeof(*key))) {
                *fe_index = (hash + i) % table_size;
                return flow_e;
            }
        }
    }

    return NULL;
}


struct vr_flow_entry *
vr_find_flow(struct vrouter *router, struct vr_flow_key *key,
        unsigned int *fe_index)
{
    unsigned int hash;
    struct vr_flow_entry *flow_e;

    hash = vr_hash(key, sizeof(*key), 0);

    /* first look in the regular flow table */
    flow_e = vr_flow_table_lookup(key, router->vr_flow_table, vr_flow_entries,
                    VR_FLOW_ENTRIES_PER_BUCKET, hash, fe_index);
    /* if not in the regular flow table, lookup in the overflow flow table */
    if (!flow_e) {
        flow_e = vr_flow_table_lookup(key, router->vr_oflow_table, vr_oflow_entries,
                        0, hash, fe_index);
        *fe_index += vr_flow_entries;
    }

    return flow_e;
}

static inline bool
vr_flow_queue_is_empty(struct vrouter *router, struct vr_flow_entry *fe)
{
    if (fe->fe_hold_list.node_p)
        return false;
    return true;
}


static int
vr_enqueue_flow(struct vr_flow_entry *fe, struct vr_packet *pkt,
        unsigned short proto, struct vr_forwarding_md *fmd)
{
    unsigned int i = 0;
    unsigned short drop_reason = 0;
    struct vr_list_node **head = &fe->fe_hold_list.node_p;
    struct vr_packet_node *pnode;

    while (*head && ++i) {
        head = &(*head)->node_n;
    }

    if (i >= VR_MAX_FLOW_QUEUE_ENTRIES) {
        drop_reason = VP_DROP_FLOW_QUEUE_LIMIT_EXCEEDED;
        goto drop;
    }

    pnode = (struct vr_packet_node *)vr_zalloc(sizeof(struct vr_packet_node));
    if (!pnode) {
        drop_reason = VP_DROP_FLOW_NO_MEMORY;
        goto drop;
    }

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

    pnode->pl_packet = pkt;
    pnode->pl_proto = proto;
    pnode->pl_vif_idx = pkt->vp_if->vif_idx;
    if (fmd) {
        pnode->pl_outer_src_ip = fmd->fmd_outer_src_ip;
        pnode->pl_label = fmd->fmd_label;
    }

    *head = &pnode->pl_node;

    return 0;

drop:
    vr_pfree(pkt, drop_reason);
    return 0;
}

int
vr_flow_forward(unsigned short vrf, struct vr_packet *pkt,
        unsigned short proto, struct vr_forwarding_md *fmd)
{
    struct vr_interface *vif = pkt->vp_if;
    struct vrouter *router = vif->vif_router;

    if ((proto != VR_ETH_PROTO_IP) && (proto != VR_ETH_PROTO_IP6)) {
        vr_pfree(pkt, VP_DROP_FLOW_INVALID_PROTOCOL);
        return 0;
    }

    if (pkt->vp_nh)
        return nh_output(vrf, pkt, pkt->vp_nh, fmd);

    pkt_set_data(pkt, pkt->vp_network_h);
    return vr_ip_input(router, vrf, pkt, fmd);
}

static int
vr_flow_nat(unsigned short vrf, struct vr_flow_entry *fe, struct vr_packet *pkt,
        unsigned short proto, struct vr_forwarding_md *fmd)
{
    unsigned int ip_inc, inc = 0; 
    unsigned short *t_sport, *t_dport;
    struct vrouter *router = pkt->vp_if->vif_router;
    struct vr_flow_entry *rfe;
    struct vr_ip *ip, *icmp_pl_ip;
    struct vr_icmp *icmph;
    bool hdr_update = false;

    if (fe->fe_rflow < 0)
        goto drop;

    ip = (struct vr_ip *)pkt_data(pkt);

    if (vr_ip_is_ip6(ip)) {
        /* No NAT support for IPv6 yet */
        vr_pfree(pkt, VP_DROP_FLOW_ACTION_INVALID);
        return 0;
    }

    rfe = vr_get_flow_entry(router, fe->fe_rflow);
    if (!rfe)
        goto drop;

    if (ip->ip_proto == VR_IP_PROTO_ICMP) {
        icmph = (struct vr_icmp *)((unsigned char *)ip + (ip->ip_hl * 4));
        if (vr_icmp_error(icmph)) {
            icmp_pl_ip = (struct vr_ip *)(icmph + 1);
            if (fe->fe_flags & VR_FLOW_FLAG_SNAT) {
                icmp_pl_ip->ip_daddr = rfe->fe_key.key_dest_ip;
                hdr_update = true;
            }

            if (fe->fe_flags & VR_FLOW_FLAG_DNAT) {
                icmp_pl_ip->ip_saddr = rfe->fe_key.key_src_ip;
                hdr_update = true;
            }

            if (hdr_update)
                icmp_pl_ip->ip_csum = vr_ip_csum(icmp_pl_ip);

            t_sport = (unsigned short *)((unsigned char *)icmp_pl_ip +
                    (icmp_pl_ip->ip_hl * 4));
            t_dport = t_sport + 1;

            if (fe->fe_flags & VR_FLOW_FLAG_SPAT)
                *t_dport = rfe->fe_key.key_dst_port;

            if (fe->fe_flags & VR_FLOW_FLAG_DPAT)
                *t_sport = rfe->fe_key.key_src_port;
        }
    }


    if ((fe->fe_flags & VR_FLOW_FLAG_SNAT) &&
            (ip->ip_saddr == fe->fe_key.key_src_ip)) {
        vr_incremental_diff(ip->ip_saddr, rfe->fe_key.key_dest_ip, &inc);
        ip->ip_saddr = rfe->fe_key.key_dest_ip;
    }

    if (fe->fe_flags & VR_FLOW_FLAG_DNAT) {
        vr_incremental_diff(ip->ip_daddr, rfe->fe_key.key_src_ip, &inc);
        ip->ip_daddr = rfe->fe_key.key_src_ip;
    }

    ip_inc = inc;

    if (vr_ip_transport_header_valid(ip)) {
        t_sport = (unsigned short *)((unsigned char *)ip +
                (ip->ip_hl * 4));
        t_dport = t_sport + 1;

        if (fe->fe_flags & VR_FLOW_FLAG_SPAT) {
            vr_incremental_diff(*t_sport, rfe->fe_key.key_dst_port, &inc);
            *t_sport = rfe->fe_key.key_dst_port;
        }

        if (fe->fe_flags & VR_FLOW_FLAG_DPAT) {
            vr_incremental_diff(*t_dport, rfe->fe_key.key_src_port, &inc);
            *t_dport = rfe->fe_key.key_src_port;
        }
    }

#ifdef VROUTER_CONFIG_DIAG
    if (ip->ip_csum != VR_DIAG_IP_CSUM)
        vr_ip_update_csum(pkt, ip_inc, inc);
#else
    vr_ip_update_csum(pkt, ip_inc, inc);
#endif


    /*
     * If VRF is translated lets chose a new nexthop
     */
    if ((fe->fe_flags & VR_FLOW_FLAG_VRFT) &&
            pkt->vp_nh && pkt->vp_nh->nh_vrf != vrf)
        pkt->vp_nh = NULL;

    return vr_flow_forward(vrf, pkt, proto, fmd);

drop:
    vr_pfree(pkt, VP_DROP_FLOW_NAT_NO_RFLOW);
    return 0;
}

static void
vr_flow_set_forwarding_md(struct vrouter *router, struct vr_flow_entry *fe,
        unsigned int index, struct vr_forwarding_md *md)
{
    struct vr_flow_entry *rfe;

    md->fmd_flow_index = index;
    md->fmd_ecmp_nh_index = fe->fe_ecmp_nh_index;
    if (fe->fe_flags & VR_RFLOW_VALID) {
        rfe = vr_get_flow_entry(router, fe->fe_rflow);
        if (rfe)
            md->fmd_ecmp_src_nh_index = rfe->fe_ecmp_nh_index;
    }

    return;
}

static int
vr_flow_action(struct vrouter *router, struct vr_flow_entry *fe, 
        unsigned int index, struct vr_packet *pkt,
        unsigned short proto, struct vr_forwarding_md *fmd)
{
    int ret = 0, valid_src;
    unsigned short vrf;
    struct vr_forwarding_md mirror_fmd;
    struct vr_nexthop *src_nh;
    struct vr_packet *pkt_clone;

    vrf = fe->fe_vrf;
    /*
     * for now, we will not use dvrf if VRFT is set, because the RPF
     * check needs to happen in the source vrf
     */

    vr_flow_set_forwarding_md(router, fe, index, fmd);
    src_nh = __vrouter_get_nexthop(router, fe->fe_src_nh_index);
    if (!src_nh) {
        vr_pfree(pkt, VP_DROP_INVALID_NH);
        return 0;
    }

    if (src_nh->nh_validate_src) {
        valid_src = src_nh->nh_validate_src(vrf, pkt, src_nh, fmd, NULL);
        if (valid_src == NH_SOURCE_INVALID) {
            vr_pfree(pkt, VP_DROP_INVALID_SOURCE);
            return 0;
        }

        if (valid_src == NH_SOURCE_MISMATCH) {
            pkt_clone = vr_pclone(pkt);
            if (pkt_clone) {
                vr_preset(pkt_clone);
                if (vr_pcow(pkt_clone, sizeof(struct vr_eth) +
                            sizeof(struct agent_hdr))) {
                    vr_pfree(pkt_clone, VP_DROP_PCOW_FAIL);
                } else {
                    vr_trap(pkt_clone, vrf,
                            AGENT_TRAP_ECMP_RESOLVE, &fmd->fmd_flow_index);
                }
            }
        }
    }


    if (fe->fe_flags & VR_FLOW_FLAG_VRFT)
        vrf = fe->fe_dvrf;

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
        break;

    case VR_FLOW_ACTION_FORWARD:
        ret = vr_flow_forward(vrf, pkt, proto, fmd);
        break;

    case VR_FLOW_ACTION_NAT:
        ret = vr_flow_nat(vrf, fe, pkt, proto, fmd);
        break;

    default:
        vr_pfree(pkt, VP_DROP_FLOW_ACTION_INVALID);
        break;
    }

    return ret;
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
        ta.vfta_nh_index = fe->fe_key.key_nh_id;
        break;
    }


    return vr_trap(npkt, fe->fe_vrf, trap_reason, &ta);
}

static int
vr_do_flow_action(struct vrouter *router, struct vr_flow_entry *fe,
        unsigned int index, struct vr_packet *pkt,
        unsigned short proto, struct vr_forwarding_md *fmd)
{
    uint32_t new_stats;

    new_stats = __sync_add_and_fetch(&fe->fe_stats.flow_bytes, pkt_len(pkt));
    if (new_stats < pkt_len(pkt))
        fe->fe_stats.flow_bytes_oflow++;

    new_stats = __sync_add_and_fetch(&fe->fe_stats.flow_packets, 1);
    if (!new_stats) 
        fe->fe_stats.flow_packets_oflow++;

    if (fe->fe_action == VR_FLOW_ACTION_HOLD) {
        if (vr_flow_queue_is_empty(router, fe)) {
            vr_trap_flow(router, fe, pkt, index);
            return vr_enqueue_flow(fe, pkt, proto, fmd);
        } else {
            vr_pfree(pkt, VP_DROP_FLOW_UNUSABLE);
            return 0;
        }
    }

    return vr_flow_action(router, fe, index, pkt, proto, fmd);
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
    flow_e->fe_action = VR_FLOW_ACTION_HOLD;

    if (infop->vfti_hold_count[cpu] + 1 < infop->vfti_hold_count[cpu]) {
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

static int
vr_flow_lookup(struct vrouter *router, unsigned short vrf,
        struct vr_flow_key *key, struct vr_packet *pkt, unsigned short proto,
        struct vr_forwarding_md *fmd)
{
    unsigned int fe_index;
    struct vr_flow_entry *flow_e;

    pkt->vp_flags |= VP_FLAG_FLOW_SET;

    flow_e = vr_find_flow(router, key, &fe_index);
    if (!flow_e) {
        if (pkt->vp_nh &&
            (pkt->vp_nh->nh_flags & NH_FLAG_RELAXED_POLICY))
            return vr_flow_forward(vrf, pkt, proto, fmd);

        if (vr_flow_table_hold_count(router) > VR_MAX_FLOW_TABLE_HOLD_COUNT) {
            vr_pfree(pkt, VP_DROP_FLOW_UNUSABLE);
            return 0;
        }

        flow_e = vr_find_free_entry(router, key, &fe_index);
        if (!flow_e) {
            vr_pfree(pkt, VP_DROP_FLOW_TABLE_FULL);
            return 0;
        }

        flow_e->fe_vrf = vrf;
        /* mark as hold */
        vr_flow_entry_set_hold(router, flow_e);
        vr_do_flow_action(router, flow_e, fe_index, pkt, proto, fmd);
        return 0;
    } 
    

    return vr_do_flow_action(router, flow_e, fe_index, pkt, proto, fmd);
}


/*
 * This inline function decides whether to trap the packet, or bypass 
 * flow table or not. 
 */
inline unsigned int
vr_flow_parse(struct vrouter *router, struct vr_flow_key *key,
        struct vr_packet *pkt, unsigned int *trap_res)
{
   unsigned int proto_port;
   /* without any data, the result has to be BYPASS, right? */
   unsigned int res = VR_FLOW_BYPASS;

    /* 
     * if the packet has already done one round of flow lookup, there
     * is no point in doing it again, eh?
     */
    if (pkt->vp_flags & VP_FLAG_FLOW_SET)
        return res;

    /*
     * if the interface is policy enabled, or if somebody else (eg:nexthop)
     * has requested for a policy lookup, packet has to go through a lookup
     */
    if ((pkt->vp_if->vif_flags & VIF_FLAG_POLICY_ENABLED) ||
            (pkt->vp_flags & VP_FLAG_FLOW_GET))
        res = VR_FLOW_LOOKUP;

    /*
     * ..., but then there are some exceptions, as checked below.
     * please note that these conditions also need to work when policy is
     * really not enabled
     */
    if (key) {
        if (IS_BMCAST_IP(key->key_dest_ip)) {
           /* no flow lookup for multicast or broadcast ip */
           res = VR_FLOW_BYPASS;
           pkt->vp_flags |= VP_FLAG_MULTICAST | VP_FLAG_FLOW_SET;

           /*
            * dhcp packet handling:
            *
            * for now we handle dhcp requests from only VMs and that too only
            * for VMs that are not in the fabric VRF. dhcp refresh packets will
            * anyway hit the route entry and get trapped from there.
            */
            if (vif_is_virtual(pkt->vp_if) && vif_dhcp_enabled(pkt->vp_if)) {
                proto_port = (key->key_proto << VR_FLOW_PROTO_SHIFT) |
                    key->key_src_port;
                if (proto_port == VR_UDP_DHCP_CPORT) {
                    res = VR_FLOW_TRAP;
                    pkt->vp_flags |= VP_FLAG_FLOW_SET;
                    if (trap_res)
                        *trap_res = AGENT_TRAP_L3_PROTOCOLS;
                }
            }
        }
    }

    return res;
}

extern struct vr_nexthop *(*vr_inet_route_lookup)(unsigned int,
                struct vr_route_req *, struct vr_packet *);
unsigned int
vr_flow_inet6_input(struct vrouter *router, unsigned short vrf,
        struct vr_packet *pkt, unsigned short proto,
        struct vr_forwarding_md *fmd)
{
    struct vr_ip6 *ip6;
    struct vr_eth *eth;
    unsigned int trap_res  = 0;
    unsigned short *t_hdr, sport, dport, eth_off;
    struct vr_icmp *icmph;
    unsigned char *icmp_opt_ptr;
    int proxy = 0;
    struct vr_route_req rt;
    struct vr_nexthop *nh;
    struct vr_interface *vif = pkt->vp_if;
    uint32_t rt_prefix[4];
   
    pkt->vp_type = VP_TYPE_IP6;
    ip6 = (struct vr_ip6 *)pkt_network_header(pkt); 
    /* TODO: Handle options headers */
    t_hdr = (unsigned short *)((char *)ip6 + sizeof(struct vr_ip6));
    switch (ip6->ip6_nxt) {
    case VR_IP_PROTO_ICMP6: 
        /* First word on ICMP and ICMPv6 are same */
        icmph = (struct vr_icmp *)t_hdr;
        switch (icmph->icmp_type) {
        case VR_ICMP6_TYPE_ECHO_REQ: 
        case VR_ICMP6_TYPE_ECHO_REPLY: 
            /* ICMPv6 Echo format is same as ICMP */
            sport = icmph->icmp_eid;
            dport = VR_ICMP6_TYPE_ECHO_REPLY;
            break;
        case VR_ICMP6_TYPE_NEIGH_SOL: //Neighbor Solicit, respond with VRRP MAC

            /* For L2-only networks, bridge the packets */
            if (vif_is_virtual(vif) && !(vif->vif_flags & VIF_FLAG_L3_ENABLED)) {
                return 0;
            }

            rt.rtr_req.rtr_vrf_id = vrf;
            rt.rtr_req.rtr_family = AF_INET6;
            rt.rtr_req.rtr_prefix = (uint8_t*)&rt_prefix;
            memcpy(rt.rtr_req.rtr_prefix, &icmph->icmp_data, 16);
            rt.rtr_req.rtr_prefix_size = 16;
            rt.rtr_req.rtr_prefix_len = IP6_PREFIX_LEN;
            rt.rtr_req.rtr_nh_id = 0;
            rt.rtr_req.rtr_label_flags = 0;
            rt.rtr_req.rtr_src_size = rt.rtr_req.rtr_marker_size = 0;
        
            nh = vr_inet_route_lookup(vrf, &rt, NULL);
            if (!nh || nh->nh_type == NH_DISCARD) {
                vr_pfree(pkt, VP_DROP_ARP_NOT_ME);
                return 1;
            }
        
            if (rt.rtr_req.rtr_label_flags & VR_RT_HOSTED_FLAG) {
                proxy = 1;
            }

            /*
             * If an L3VPN route is learnt, we need to proxy
             */
            if (nh->nh_type == NH_TUNNEL) {
                proxy = 1;
            }

            /*
             * If not l3 vpn route, we default to flooding
             */
            if ((nh->nh_type == NH_COMPOSITE) &&
                ((nh->nh_flags & NH_FLAG_COMPOSITE_EVPN) || 
                  (nh->nh_flags & NH_FLAG_COMPOSITE_L2))) {
                nh_output(vrf, pkt, nh, fmd);
                return 1;
            } else if (!proxy) {
                vr_pfree(pkt, VP_DROP_ARP_NOT_ME);
                return 1;
            }

            /* 
             * Update IPv6 header  
             * Copy the IP6 src to IP6 dst 
             * Copy the target IP n ICMPv6 header as src IP of packet
             * Do IP lookup to confirm if we can respond with Neighbor advertisement
             */
             memcpy(ip6->ip6_dst, ip6->ip6_src, 16);
             memcpy(ip6->ip6_src, &icmph->icmp_data, 16);
             ip6->ip6_src[15] = 0xFF; // Mimic a different src IP

             /* Update ICMP header and options */
             icmph->icmp_type = VR_ICMP6_TYPE_NEIGH_AD; 
             icmp_opt_ptr = ((char*)&icmph->icmp_data[0]) + 16;
             *icmp_opt_ptr = 0x02; //Target-link-layer-address
             memcpy(icmp_opt_ptr+2, vif->vif_mac, VR_ETHER_ALEN);
             
             /*
              * Update icmp6 checksum
              * ICMPv6 option size is 24 bytes (IPv6 + MAC + 2 bytes)
              */
             icmph->icmp_csum = 
                       ~(vr_icmp6_checksum(ip6, sizeof(struct vr_ip6) + 
                                                sizeof(struct vr_icmp) + 24));
             
             /* Update Ethernet headr */
             eth = (struct vr_eth*) ((char*)ip6 - sizeof(struct vr_eth));
             memcpy(eth->eth_dmac, eth->eth_smac, VR_ETHER_ALEN);
             memcpy(eth->eth_smac, vif->vif_mac, VR_ETHER_ALEN);

             eth_off = pkt_get_network_header_off(pkt) - sizeof(struct vr_eth);

             pkt_set_data(pkt,eth_off);

             /* Respond back directly*/
             vif->vif_tx(vif, pkt);
             
             return 1;
        case VR_ICMP6_TYPE_ROUTER_SOL: //Router solicit, trap to agent
             return vr_trap(pkt, vrf, AGENT_TRAP_L3_PROTOCOLS, NULL);
        default:
            sport = 0;
            dport = icmph->icmp_type;
        }
        break;
    case VR_IP_PROTO_UDP:
        sport = *t_hdr;
        dport = *(t_hdr + 1);
        
        if (vif_is_virtual(pkt->vp_if)) {
            if ((sport == VR_DHCP6_SPORT) && (dport == VR_DHCP6_DPORT)) {
                trap_res = AGENT_TRAP_L3_PROTOCOLS;
                return vr_trap(pkt, vrf, trap_res, NULL);
            }
        }
        break;
    case VR_IP_PROTO_TCP:
        sport = *t_hdr;
        dport = *(t_hdr + 1);
    default:
        break;
    }

    return vr_flow_forward(vrf, pkt, proto, fmd);
}

unsigned int
vr_flow_inet_input(struct vrouter *router, unsigned short vrf,
        struct vr_packet *pkt, unsigned short proto,
        struct vr_forwarding_md *fmd)
{
    struct vr_flow_key key, *key_p = &key;
    struct vr_ip *ip, *icmp_pl_ip = NULL;
    struct vr_fragment *frag;
    unsigned int flow_parse_res;
    unsigned int trap_res  = 0;
    unsigned int sip, dip;
    unsigned short *t_hdr, sport, dport;
    unsigned char ip_proto;
    struct vr_icmp *icmph;

    /*
     * interface is in a mode where it wants all packets to be received
     * without doing lookups to figure out whether packets were destined
     * to me or not
     */
    if (pkt->vp_flags & VP_FLAG_TO_ME)
        return vr_ip_rcv(router, pkt, fmd);

    ip = (struct vr_ip *)pkt_network_header(pkt);
    ip_proto = ip->ip_proto;

    /* if the packet is not a fragment, we easily know the sport, and dport */
    if (vr_ip_transport_header_valid(ip)) {
        t_hdr = (unsigned short *)((char *)ip + (ip->ip_hl * 4));
        if (ip_proto == VR_IP_PROTO_ICMP) {
            icmph = (struct vr_icmp *)t_hdr;
            if (vr_icmp_error(icmph)) {
                icmp_pl_ip = (struct vr_ip *)(icmph + 1);
                ip_proto = icmp_pl_ip->ip_proto;
                t_hdr = (unsigned short *)((char *)icmp_pl_ip +
                        (icmp_pl_ip->ip_hl * 4));
                if (ip_proto == VR_IP_PROTO_ICMP)
                    icmph = (struct vr_icmp *)t_hdr;
            }
        }

        if (ip_proto == VR_IP_PROTO_ICMP) {
            if (icmph->icmp_type == VR_ICMP_TYPE_ECHO ||
                    icmph->icmp_type == VR_ICMP_TYPE_ECHO_REPLY) {
                sport = icmph->icmp_eid;
                dport = VR_ICMP_TYPE_ECHO_REPLY;
            } else {
                sport = 0;
                dport = icmph->icmp_type;
            }
        } else {
            if (icmp_pl_ip) {
                sport = *(t_hdr + 1);
                dport = *t_hdr;
            } else {
                sport = *t_hdr;
                dport = *(t_hdr + 1);
            }
        }
    } else {
        /* ...else, we need to get it from somewhere */
        flow_parse_res = vr_flow_parse(router, NULL, pkt, &trap_res);
        /* ...and it really matters only if we need to do a flow lookup */
        if (flow_parse_res == VR_FLOW_LOOKUP) {
            frag = vr_fragment_get(router, vrf, ip);
            if (!frag) {
                vr_pfree(pkt, VP_DROP_FRAGMENTS);
                return 0;
            }
            sport = frag->f_sport;
            dport = frag->f_dport;
            if (vr_ip_fragment_tail(ip))
                vr_fragment_del(frag);
        } else {
            /* 
             * since there is no other way of deriving a key, set the
             * key_p to NULL, indicating to code below that there is
             * indeed no need for flow lookup
             */
            key_p = NULL;
        }
    }

    if (key_p) {
        /* we have everything to make a key */

        if (icmp_pl_ip) {
            sip = icmp_pl_ip->ip_daddr;
            dip = icmp_pl_ip->ip_saddr;
        } else {
            sip = ip->ip_saddr;
            dip = ip->ip_daddr;
        }

        vr_get_flow_key(key_p, fmd->fmd_vlan, pkt,
                sip, dip, ip_proto, sport, dport);

        flow_parse_res = vr_flow_parse(router, key_p, pkt, &trap_res);
        if (flow_parse_res == VR_FLOW_LOOKUP && vr_ip_fragment_head(ip))
            vr_fragment_add(router, vrf, ip, key_p->key_src_port,
                    key_p->key_dst_port);

        if (flow_parse_res == VR_FLOW_BYPASS) {
            return vr_flow_forward(vrf, pkt, proto, fmd);
        } else if (flow_parse_res == VR_FLOW_TRAP) {
            return vr_trap(pkt, vrf, trap_res, NULL);
        }

        return vr_flow_lookup(router, vrf, key_p, pkt, proto, fmd);
    }

    /* 
     * ...come here, when there is not enough information to do a
     * flow lookup
     */
    return vr_flow_forward(vrf, pkt, proto, fmd);
}

static void
vr_flush_entry(struct vrouter *router, struct vr_flow_entry *fe,
        struct vr_flow_md *flmd, struct vr_forwarding_md *fmd)
{
    struct vr_list_node *head;
    struct vr_packet_node *pnode;
    struct vr_packet *pkt;
    struct vr_interface *vif;

    head = fe->fe_hold_list.node_p;
    fe->fe_hold_list.node_p = NULL;

    while (head) {
        pnode = (struct vr_packet_node *)head;
        if (fmd) {
            fmd->fmd_outer_src_ip = pnode->pl_outer_src_ip;
            fmd->fmd_label = pnode->pl_label;
        }

        pkt = pnode->pl_packet;
        /* 
         * this is only a security check and not a catch all check. one note
         * of caution. please do not access pkt->vp_if till the if block is
         * succesfully bypassed
         */
        vif = __vrouter_get_interface(router, pnode->pl_vif_idx);
        if (!vif || (pkt->vp_if != vif)) {
            vr_pfree(pkt, VP_DROP_INVALID_IF);
            goto loop_continue;
        }

        if (!pkt->vp_nh) {
            if (vif_is_fabric(pkt->vp_if) && fmd &&
                    (fmd->fmd_label >= 0)) {
                pkt->vp_nh = __vrouter_get_label(router, fmd->fmd_label);
            }
        }

        vr_flow_action(router, fe, flmd->flmd_index, pkt,
                pnode->pl_proto, fmd);

loop_continue:
        head = pnode->pl_node.node_n;
        vr_free(pnode);
    }

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
        return;

    fe = vr_get_flow_entry(router, flmd->flmd_index);
    if (!fe)
        return;

    vr_init_forwarding_md(&fmd);
    vr_flow_set_forwarding_md(router, fe, flmd->flmd_index, &fmd);

    vr_flush_entry(router, fe, flmd, &fmd);

    if (!(flmd->flmd_flags & VR_FLOW_FLAG_ACTIVE)) {
        vr_reset_flow_entry(router, fe, flmd->flmd_index);
    } 

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
vr_add_flow(unsigned int rid, struct vr_flow_key *key,
        unsigned int *fe_index)
{
    struct vr_flow_entry *flow_e;
    struct vrouter *router = vrouter_get(rid);

    flow_e = vr_find_flow(router, key, fe_index);
    if (!flow_e)
        flow_e = vr_find_free_entry(router, key, fe_index);

    return flow_e;
}

static struct vr_flow_entry *
vr_add_flow_req(vr_flow_req *req, unsigned int *fe_index)
{
    struct vr_flow_key key;
    struct vr_flow_entry *fe;

    key.key_src_port = req->fr_flow_sport;
    key.key_dst_port = req->fr_flow_dport;
    key.key_src_ip = req->fr_flow_sip;
    key.key_dest_ip = req->fr_flow_dip;
    key.key_nh_id = req->fr_flow_nh_id;
    key.key_proto = req->fr_flow_proto;
    key.key_zero = 0;

    fe = vr_add_flow(req->fr_rid, &key, fe_index);
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
        if ((unsigned int)req->fr_flow_sip != fe->fe_key.key_src_ip ||
                (unsigned int)req->fr_flow_dip != fe->fe_key.key_dest_ip ||
                (unsigned short)req->fr_flow_sport != fe->fe_key.key_src_port ||
                (unsigned short)req->fr_flow_dport != fe->fe_key.key_dst_port||
                (unsigned short)req->fr_flow_nh_id != fe->fe_key.key_nh_id ||
                (unsigned char)req->fr_flow_proto != fe->fe_key.key_proto) {
            return -EBADF;
        }
    }

    if (req->fr_flags & VR_FLOW_FLAG_VRFT) {
        if ((unsigned short)req->fr_flow_dvrf >= VR_MAX_VRFS)
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

    /* 
     * for delete, we need not validate nh_index from incoming request
     */
    if (req->fr_flags & VR_FLOW_FLAG_ACTIVE) {
        if (!__vrouter_get_nexthop(router, req->fr_src_nh_index))
            return -EINVAL;
    }

    return 0;
}

static int
vr_flow_schedule_transition(struct vrouter *router, vr_flow_req *req,
        struct vr_flow_entry *fe)
{
    struct vr_flow_md *flmd = NULL;

    flmd = (struct vr_flow_md *)vr_malloc(sizeof(*flmd));
    if (!flmd)
        return -ENOMEM;

    flmd->flmd_router = router;
    flmd->flmd_index = req->fr_index;
    flmd->flmd_action = req->fr_action;
    flmd->flmd_flags = req->fr_flags;

    vr_schedule_work(vr_get_cpu(), vr_flow_flush, (void *)flmd);
    return 0;
}

static int
vr_flow_delete(struct vrouter *router, vr_flow_req *req,
        struct vr_flow_entry *fe)
{
    if (fe->fe_flags & VR_FLOW_FLAG_LINK_LOCAL)
        vr_clear_link_local_port(router, AF_INET, fe->fe_key.key_proto,
                                   ntohs(fe->fe_key.key_dst_port));

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

    hash_key[0] = fe->fe_key.key_src_ip;
    hash_key[1] = fe->fe_key.key_dest_ip;
    hash_key[2] = fe->fe_vrf;
    hash_key[3] = fe->fe_key.key_src_port;
    hash_key[4] = fe->fe_key.key_dst_port;

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
    unsigned int fe_index;
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
        if (!fe)
            return -ENOSPC;
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

    if (req->fr_flags & VR_FLOW_FLAG_LINK_LOCAL) {
        if (!(fe->fe_flags & VR_FLOW_FLAG_LINK_LOCAL))
            vr_set_link_local_port(router, AF_INET, fe->fe_key.key_proto,
                                   ntohs(fe->fe_key.key_dst_port));
    } else {
        if (fe->fe_flags & VR_FLOW_FLAG_LINK_LOCAL)
            vr_clear_link_local_port(router, AF_INET, fe->fe_key.key_proto,
                                   ntohs(fe->fe_key.key_dst_port));
    }

    fe->fe_ecmp_nh_index = req->fr_ecmp_nh_index;
    fe->fe_src_nh_index = req->fr_src_nh_index;
    fe->fe_action = req->fr_action;
    if (fe->fe_action == VR_FLOW_ACTION_DROP)
        fe->fe_drop_reason = (uint8_t)req->fr_drop_reason;
    fe->fe_flags = req->fr_flags; 
    vr_flow_udp_src_port(router, fe);

    return vr_flow_schedule_transition(router, req, fe);
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

    router = vrouter_get(req->fr_rid);
    switch (req->fr_op) {
    case FLOW_OP_FLOW_TABLE_GET:
        req->fr_ftable_size = vr_flow_table_size(router) +
            vr_oflow_table_size(router);
#if defined(__linux__) && defined(__KERNEL__)
        req->fr_ftable_dev = vr_flow_major;
#endif
        break;

    case FLOW_OP_FLOW_SET:
        ret = vr_flow_set(router, req);
        break;

    default:
        ret = -EINVAL;
    }

    vr_message_response(VR_FLOW_OBJECT_ID, req, ret);
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
        vr_init_forwarding_md(&fmd);
        flmd.flmd_action = VR_FLOW_ACTION_DROP;
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

        router->vr_flow_table = vr_btable_alloc(vr_flow_entries,
                sizeof(struct vr_flow_entry));
        if (!router->vr_flow_table) {
            return vr_module_error(-ENOMEM, __FUNCTION__,
                    __LINE__, vr_flow_entries);
        }
    }

    if (!router->vr_oflow_table) {
        router->vr_oflow_table = vr_btable_alloc(vr_oflow_entries,
                sizeof(struct vr_flow_entry));
        if (!router->vr_oflow_table) {
            return vr_module_error(-ENOMEM, __FUNCTION__,
                    __LINE__, vr_oflow_entries);
        }
    }

    return vr_flow_table_info_init(router);
}
void
vr_link_local_ports_reset(struct vrouter *router)
{
    if (router->vr_link_local_ports) {
        memset(router->vr_link_local_ports,
               0, router->vr_link_local_ports_size);
    }
}



void
vr_link_local_ports_exit(struct vrouter *router)
{
    if (router->vr_link_local_ports) {
        vr_free(router->vr_link_local_ports);
        router->vr_link_local_ports = NULL;
        router->vr_link_local_ports_size = 0;
    }
}

int
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

    if ((ret = vr_fragment_table_init(router) < 0))
        return ret;

    if ((ret = vr_flow_table_init(router)))
        return ret;

    if ((ret = vr_link_local_ports_init(router)))
        return ret;

    return 0;
}
