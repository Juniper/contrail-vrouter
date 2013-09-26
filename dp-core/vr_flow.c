/*
 * vr_flow.c -- flow handling
 *
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#include <vr_os.h>
#include "vr_sandesh.h"
#include "vr_message.h"
#include "vr_mcast.h"
#include "vr_btable.h"

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

unsigned int vr_flow_entries = VR_DEF_FLOW_ENTRIES;
unsigned int vr_oflow_entries = VR_DEF_OFLOW_ENTRIES;

#ifdef __KERNEL__
extern unsigned short vr_flow_major;
#endif

extern int vr_ip_input(struct vrouter *, unsigned short,
        struct vr_packet *, struct vr_forwarding_md *);
extern void vr_ip_update_csum(struct vr_packet *, unsigned int,
        unsigned int);

static void vr_flush_entry(struct vrouter *, struct vr_flow_entry *,
        unsigned int, struct vr_forwarding_md *, unsigned short );

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
    if (fe->fe_flags & VR_FLOW_FLAG_MIRROR) {
        vrouter_put_mirror(router, fe->fe_mirror_id);
        fe->fe_mirror_id = VR_MAX_MIRROR_INDICES;
        vrouter_put_mirror(router, fe->fe_sec_mirror_id);
        fe->fe_sec_mirror_id = VR_MAX_MIRROR_INDICES;
        vr_mirror_meta_entry_del(router, index);
    }

    fe->fe_ecmp_nh_index = -1;
    fe->fe_rflow = -1;
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

static struct vr_flow_entry *
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
vr_get_flow_key(struct vr_flow_key *key, unsigned short vrf,
                struct vr_ip *ip)
{
    unsigned short *t_hdr;
    struct vr_icmp *icmph;

    /* copy both source and destinations */
    memcpy(&key->key_src_ip, &ip->ip_saddr, 2 * sizeof(ip->ip_saddr));
    key->key_proto = ip->ip_proto;
    key->key_zero = 0;
    key->key_vrf_id = vrf;

    /* extract port information */
    t_hdr = (unsigned short *)((char *)ip + (ip->ip_hl * 4));

    switch (ip->ip_proto) {
    case VR_IP_PROTO_TCP:
    case VR_IP_PROTO_UDP:
        key->key_src_port = *(t_hdr);
        key->key_dst_port = *(t_hdr + 1);
        break;

    case VR_IP_PROTO_ICMP:
        icmph = (struct vr_icmp *)t_hdr;
        if (icmph->icmp_type == VR_ICMP_TYPE_ECHO ||
                icmph->icmp_type == VR_ICMP_TYPE_ECHO_REPLY) {
            key->key_src_port = icmph->icmp_eid;
            key->key_dst_port = VR_ICMP_TYPE_ECHO_REPLY;
        } else {
            key->key_src_port = 0;
            key->key_dst_port = icmph->icmp_type;
        }

        break;

    default:
        key->key_src_port = key->key_dst_port = 0;
        break;
    }

    return;
}

static struct vr_flow_entry *
vr_find_free_entry(struct vrouter *router, unsigned int hash,
        unsigned int *fe_index)
{
    unsigned int i, index;
    struct vr_flow_entry *fe;

    *fe_index = 0;
    index = (hash % vr_flow_entries) & ~(VR_FLOW_ENTRIES_PER_BUCKET - 1);
    for (i = 0; i < VR_FLOW_ENTRIES_PER_BUCKET; i++) {
        fe = vr_flow_table_entry_get(router, (index + i));
        if (fe && !(fe->fe_flags & VR_FLOW_FLAG_ACTIVE)) {
            if (vr_set_flow_active(fe)) {
                vr_init_flow_entry(fe);
                *fe_index += index + i;
                return fe;
            }
        }
    }
        
    *fe_index = vr_flow_entries;
    index = hash % vr_oflow_entries;
    for (i = 0; i < vr_oflow_entries; i++) {
        fe = vr_oflow_table_entry_get(router, ((index + i) %
                vr_oflow_entries));
        if (fe && !(fe->fe_flags & VR_FLOW_FLAG_ACTIVE)) {
            if (vr_set_flow_active(fe)) {
                vr_init_flow_entry(fe);
                *fe_index += ((index + i) % vr_oflow_entries);
                return fe;
            }
        }
    }

    return NULL;
}

static int
vr_find_duplicate(struct vrouter *router, struct vr_flow_entry *flow_e,
        unsigned int *fe_index)
{
    unsigned int hash, hash_tmp, i;
    struct vr_flow_entry *flow_d;

    hash = hash_tmp = vr_hash(&flow_e->fe_key, sizeof(flow_e->fe_key), 0);

    hash_tmp %= vr_flow_entries;
    hash_tmp &= ~(VR_FLOW_ENTRIES_PER_BUCKET - 1);
    for (i = 0; i < VR_FLOW_ENTRIES_PER_BUCKET; i++) {
        flow_d = vr_flow_table_entry_get(router, hash_tmp + i);
        if (!(flow_d->fe_flags & VR_FLOW_FLAG_ACTIVE))
            continue;

        if ((flow_d == flow_e) ||
                memcmp(&flow_d->fe_key, &flow_e->fe_key,
                    sizeof(flow_d->fe_key)))
            continue;

        return hash_tmp + i;
    }

    hash_tmp = hash % vr_oflow_entries;
    for (i = 0; i < vr_oflow_entries; i++) {
        flow_d = vr_oflow_table_entry_get(router,
                (hash_tmp + i) % vr_oflow_entries);
        if (!(flow_d->fe_flags & VR_FLOW_FLAG_ACTIVE))
            continue;

        if ((flow_d == flow_e) ||
                memcmp(&flow_d->fe_key, &flow_e->fe_key,
                    sizeof(flow_d->fe_key)))
            continue;

        return (hash_tmp + i) % vr_oflow_entries;
    }

    return -1;
}

static inline struct vr_flow_entry *
vr_find_flow(struct vr_flow_key *key, struct vr_btable *table,
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

static int
vr_enqueue_flow(struct vr_flow_entry *fe, struct vr_packet *pkt,
        unsigned short proto)
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

    pkt->vp_nh = NULL;

    pnode->pl_packet = pkt;
    pnode->pl_proto = proto;
    *head = &pnode->pl_node;

    return 0;

drop:
    vr_pfree(pkt, drop_reason);
    return 0;
}

static int
vr_flow_forward(unsigned short vrf, struct vr_packet *pkt,
        unsigned short proto, struct vr_forwarding_md *fmd)
{
    struct vr_interface *vif = pkt->vp_if;
    struct vrouter *router = vif->vif_router;

    if (proto != VR_ETH_PROTO_IP) {
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
    struct vr_ip *ip;

    if (fe->fe_rflow < 0)
        goto drop;

    rfe = vr_get_flow_entry(router, fe->fe_rflow);
    if (!rfe)
        goto drop;

    ip = (struct vr_ip *)pkt_data(pkt);

    if (fe->fe_flags & VR_FLOW_FLAG_SNAT) {
        vr_incremental_diff(ip->ip_saddr, rfe->fe_key.key_dest_ip, &inc);
        ip->ip_saddr = rfe->fe_key.key_dest_ip;
    }

    if (fe->fe_flags & VR_FLOW_FLAG_DNAT) {
        vr_incremental_diff(ip->ip_daddr, rfe->fe_key.key_src_ip, &inc);
        ip->ip_daddr = rfe->fe_key.key_src_ip;
    }

    ip_inc = inc;
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

    if (ip->ip_csum != VR_DIAG_IP_CSUM)
        vr_ip_update_csum(pkt, ip_inc, inc);

    return vr_flow_forward(vrf, pkt, proto, fmd);

drop:
    vr_pfree(pkt, VP_DROP_FLOW_NAT_NO_RFLOW);
    return 0;
}

static void
vr_flow_set_forwarding_md(struct vr_flow_entry *fe, unsigned int index, 
        struct vr_forwarding_md *md)
{
    md->fmd_flow_index = index;
    md->fmd_ecmp_nh_index = fe->fe_ecmp_nh_index;
    return;
}

static int
vr_flow_action(struct vrouter *router, struct vr_flow_entry *fe, 
        unsigned int index, struct vr_packet *pkt,
        unsigned short proto, struct vr_forwarding_md *fmd)
{
    int ret = 0;
    unsigned short vrf;
    struct vr_forwarding_md mirror_fmd;

    vrf = fe->fe_key.key_vrf_id;
    if (fe->fe_flags & VR_FLOW_FLAG_VRFT)
        vrf = fe->fe_dvrf;

    vr_flow_set_forwarding_md(fe, index, fmd);

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
vr_trap_flow(struct vrouter *router, unsigned short vrf,
        struct vr_packet *pkt, unsigned int index)
{
    /* ...and clone the packet */
    pkt = vr_pclone(pkt);
    /* first reset the packet to original */
    vr_preset(pkt);

    return vr_trap(pkt, vrf, AGENT_TRAP_FLOW_MISS, &index);
}

static int
vr_do_flow_action(struct vrouter *router, struct vr_flow_entry *fe,
        unsigned int index, struct vr_packet *pkt,
        unsigned short proto, struct vr_forwarding_md *fmd)
{
    fe->fe_stats.flow_bytes += pkt_len(pkt);
    fe->fe_stats.flow_packets++;

    if (fe->fe_flags & VR_FLOW_FLAG_UNUSABLE) {
        vr_pfree(pkt, VP_DROP_FLOW_UNUSABLE);
        return 0;
    }

    if (fe->fe_action == VR_FLOW_ACTION_HOLD)
        return vr_enqueue_flow(fe, pkt, proto);

    return vr_flow_action(router, fe, index, pkt, proto, fmd);
}

static int
vr_flow_lookup(struct vrouter *router, struct vr_flow_key *key,
        struct vr_packet *pkt, unsigned short proto,
        struct vr_forwarding_md *fmd)
{
    unsigned int hash, fe_index;
    struct vr_flow_entry *flow_e;

    pkt->vp_flags |= VP_FLAG_FLOW_SET;

    hash = vr_hash(key, sizeof(*key), 0);

    /* first look in the regular flow table */
    flow_e = vr_find_flow(key, router->vr_flow_table, vr_flow_entries,
                    VR_FLOW_ENTRIES_PER_BUCKET, hash, &fe_index);
    /* if not in the regular flow table, lookup in the overflow flow table */
    if (!flow_e) {
        flow_e = vr_find_flow(key, router->vr_oflow_table, vr_oflow_entries,
                        0, hash, &fe_index);
        fe_index += vr_flow_entries;
    }

    if (!flow_e) {
        flow_e = vr_find_free_entry(router, hash, &fe_index);
        if (!flow_e) {
            vr_pfree(pkt, VP_DROP_FLOW_TABLE_FULL);
            return 0;
        }

        /* mark as hold */
        flow_e->fe_action = VR_FLOW_ACTION_HOLD;
        memcpy(&flow_e->fe_key, key, sizeof(*key));
        vr_do_flow_action(router, flow_e, fe_index, pkt, proto, fmd);
        vr_trap_flow(router, key->key_vrf_id, pkt, fe_index);
        return 0;
    } 
    

    return vr_do_flow_action(router, flow_e, fe_index, pkt, proto, fmd);
}

/*
 * This inline function decides whether to trap the packet, or bypass 
 * flow table or not. 
 * Return value:
 * 1  - Bypass the flow
 * 2  - Trap the flow
 * 3  - Continue flow table
 */
inline unsigned int
vr_flow_parse(struct vrouter *router, struct vr_flow_key *key,
        struct vr_packet *pkt, unsigned int *trap_res)
{
   unsigned int proto_port;
   unsigned int res;

    /* this has to be the first check, please,,, */
    if (pkt->vp_flags & VP_FLAG_FLOW_SET)
        return VR_FLOW_BYPASS;


    res = VR_FLOW_LOOKUP;
    if (key) {

        proto_port = (key->key_proto << VR_FLOW_PROTO_SHIFT) | 
                                                key->key_dst_port;

        if (IS_BMCAST_IP(key->key_dest_ip)) {
           /* If multicast or broadcast ip, 
            * mark it for further processing 
            */
           res = VR_FLOW_BYPASS;
           pkt->vp_flags |= VP_FLAG_MULTICAST;
        }

        if (proto_port == VR_UDP_DHCP_SPORT || 
                proto_port == VR_UDP_DHCP_CPORT) { 
            res = VR_FLOW_TRAP;
        }
    }

    if (res == VR_FLOW_LOOKUP)
        if (pkt->vp_if->vif_flags & VIF_FLAG_POLICY_ENABLED ||
            pkt->vp_flags & VP_FLAG_FLOW_GET)
            return VR_FLOW_LOOKUP;

    if (res != VR_FLOW_LOOKUP)
        pkt->vp_flags |= VP_FLAG_FLOW_SET;
    else 
        res = VR_FLOW_BYPASS;

    if (trap_res) 
        *trap_res = AGENT_TRAP_L3_PROTOCOLS;
    return res;
}

unsigned int
vr_flow_inet_input(struct vrouter *router, unsigned short vrf,
        struct vr_packet *pkt, unsigned short proto,
        struct vr_forwarding_md *fmd)
{
    struct vr_flow_key key;
    struct vr_ip *ip;
    unsigned int flow_parse_res;
    unsigned int trap_res  = 0;

    /*
     * interface is in a mode where it wants all packets to be received
     * without doing lookups to figure out whether packets were destined
     * to me or not
     */
    if (pkt->vp_flags & VP_FLAG_TO_ME)
        return vr_ip_rcv(router, pkt, fmd);

    ip = (struct vr_ip *)pkt_network_header(pkt);
    if (vr_ip_transport_header_valid(ip)) {
        vr_get_flow_key(&key, vrf, ip);
        flow_parse_res = vr_flow_parse(router, &key, pkt, &trap_res);
    } else {
        pkt->vp_flags |= VP_FLAG_FLOW_SET;
        flow_parse_res = VR_FLOW_BYPASS;
    }

    if (flow_parse_res == VR_FLOW_BYPASS) {
    	return vr_flow_forward(vrf, pkt, proto, fmd);
    } else if (flow_parse_res == VR_FLOW_TRAP) {
        return vr_trap(pkt, vrf, trap_res, NULL);
    }

    return vr_flow_lookup(router, &key, pkt, proto, fmd);
}

static void
vr_flush_entry(struct vrouter *router, struct vr_flow_entry *fe,
        unsigned int index, struct vr_forwarding_md *fmd, 
        unsigned short fe_action)
{
    struct vr_list_node **head;
    struct vr_packet_node *pnode;

    if (fe->fe_flags & VR_FLOW_FLAG_FLUSH) {
        fe->fe_flags &= ~VR_FLOW_FLAG_FLUSH;
        fe->fe_action = fe_action;
    }

    head = &fe->fe_hold_list.node_p;
    while (*head) {
        pnode = (struct vr_packet_node *)*head;
        vr_flow_action(router, fe, index, pnode->pl_packet,
                pnode->pl_proto, fmd);
        *head = pnode->pl_node.node_n;
        vr_free(pnode);
    }

    if (fe->fe_flags & VR_FLOW_FLAG_UNUSABLE) {
        vr_reset_flow_entry(router, fe, index);
    } 
    
    return;
}

static void
vr_flow_flush(struct vrouter *router, void *arg)
{
    struct vr_flow_entry *fe;
    struct vr_forwarding_md fmd;
    struct vr_flow_defer_data *defer_data = 
                (struct vr_flow_defer_data *)arg;

    if (!router)
        return;

    fe = vr_get_flow_entry(router, defer_data->def_index);
    if (!fe)
        return;

    vr_init_forwarding_md(&fmd);
    vr_flow_set_forwarding_md(fe, defer_data->def_index, &fmd);

    vr_flush_entry(router, fe, defer_data->def_index, &fmd, defer_data->def_action);
    return;
}

static int
vr_get_reverse_flow(vr_flow_req *req)
{
    struct vr_flow_key key;
    struct vr_flow_entry *flow_e;
    struct vrouter *router = vrouter_get(req->fr_rid);
    unsigned int hash, fe_index;
    int fe_dup;

    if (req->fr_rindex >= 0)
        return req->fr_rindex;

    key.key_src_port = req->fr_rflow_sport;
    key.key_dst_port = req->fr_rflow_dport;
    key.key_src_ip = req->fr_rflow_sip;
    key.key_dest_ip = req->fr_rflow_dip;
    key.key_vrf_id = req->fr_rflow_vrf;
    key.key_proto = req->fr_rflow_proto;
    key.key_zero = 0;

    hash = vr_hash(&key, sizeof(key), 0);

    /* first look in the regular flow table */
    flow_e = vr_find_flow(&key, router->vr_flow_table, vr_flow_entries,
                    VR_FLOW_ENTRIES_PER_BUCKET, hash, &fe_index);
    /* if not in the regular flow table, lookup in the overflow flow table */
    if (!flow_e) {
        flow_e = vr_find_flow(&key, router->vr_oflow_table, vr_oflow_entries,
                        0, hash, &fe_index);
        fe_index += vr_flow_entries;
    }

    if (!flow_e) {
        flow_e = vr_find_free_entry(router, hash, &fe_index);
        if (!flow_e)
            return -1;

        memcpy(&flow_e->fe_key, &key, sizeof(key));

        flow_e->fe_rflow = req->fr_rindex;
        flow_e->fe_flags = req->fr_flags | VR_FLOW_FLAG_UNUSABLE;

        vr_delay_op();

        fe_dup = vr_find_duplicate(router, flow_e, &fe_index);
        if (fe_dup < 0) {
            req->fr_rindex = fe_index;
            flow_e->fe_rflow = req->fr_index;
            flow_e->fe_action = VR_FLOW_ACTION_HOLD;
            flow_e->fe_flags &= ~VR_FLOW_FLAG_UNUSABLE;
        } else {
            vr_reset_flow_entry(router, flow_e, fe_index);
            req->fr_rindex = fe_dup;
            flow_e = vr_get_flow_entry(router, fe_dup);
            flow_e->fe_rflow = req->fr_index;
        }
    } else {
        req->fr_rindex = fe_index;
    }


    return req->fr_rindex;
}

/* command from agent */
static int
vr_flow_set(struct vrouter *router, vr_flow_req *req)
{
    int rf_id, flow_delete = 0, ret;
    unsigned short flags, action, rflags;
    struct vr_flow_entry *fe = NULL, *rfe = NULL;
    struct vr_mirror_entry *mirror = NULL, *sec_mirror = NULL;
    struct vr_flow_defer_data *defer_data = NULL;
    struct vr_flow_defer_data *rev_defer_data = NULL;
    unsigned short orig_action;

    router = vrouter_get(req->fr_rid);
    if (!router)
        return -EINVAL;

    fe = vr_get_flow_entry(router, req->fr_index);
    if (!fe)
        return -EINVAL;


    flags = req->fr_flags;
    orig_action = req->fr_action;
    action = VR_FLOW_ACTION_DROP;

    defer_data = vr_get_defer_data(sizeof(*defer_data));
    if (!defer_data)
        return -ENOMEM;

    /* In both delete and active cases, we need to drain the hold queue */
    if (!(flags & VR_FLOW_FLAG_ACTIVE)) {
        flow_delete = 1; 
        flags |= VR_FLOW_FLAG_UNUSABLE | VR_FLOW_FLAG_ACTIVE;
        if (fe->fe_rflow >= 0) {
            rev_defer_data = vr_get_defer_data(sizeof(*rev_defer_data));
            if (!rev_defer_data) {
                ret = -ENOMEM;
                goto flow_set_fail;
            }
        }
    } else {
        flags |= VR_FLOW_FLAG_FLUSH;
        if ((orig_action & VR_FLOW_ACTION_NAT) || (flags & VR_RFLOW_VALID)) {
            rev_defer_data = vr_get_defer_data(sizeof(*rev_defer_data));
            if (!rev_defer_data) {
                ret = -ENOMEM;
                goto flow_set_fail;
            }
        }
    }



    if ((unsigned int)req->fr_flow_sip != fe->fe_key.key_src_ip ||
        (unsigned int)req->fr_flow_dip != fe->fe_key.key_dest_ip ||
        (unsigned short)req->fr_flow_sport != fe->fe_key.key_src_port ||
        (unsigned short)req->fr_flow_dport != fe->fe_key.key_dst_port||
        (unsigned short)req->fr_flow_vrf != fe->fe_key.key_vrf_id ||
        (unsigned char)req->fr_flow_proto != fe->fe_key.key_proto) {
        ret = -EBADF;
        goto flow_set_fail;
    }

    if (flags & VR_FLOW_FLAG_VRFT) {
        if ((unsigned short)req->fr_flow_dvrf >= VR_MAX_VRFS ||
                (unsigned short)req->fr_rflow_dvrf >= VR_MAX_VRFS) {
            ret = -EINVAL;
            goto flow_set_fail;
        }
    }

    if (!flow_delete && (flags & VR_FLOW_FLAG_MIRROR)) {
        if ((fe->fe_mirror_id != req->fr_mir_id) &&
                (unsigned int)req->fr_mir_id < VR_MAX_MIRROR_INDICES) {
            mirror = vrouter_get_mirror(req->fr_rid, req->fr_mir_id);
            if (!mirror) {
                ret = -EINVAL;
                goto flow_set_fail;
            }
        }

        if ((fe->fe_sec_mirror_id != req->fr_sec_mir_id) &&
                (unsigned int)req->fr_sec_mir_id < VR_MAX_MIRROR_INDICES) {
            sec_mirror = vrouter_get_mirror(req->fr_rid, req->fr_sec_mir_id);
            if (!sec_mirror) {
                if (mirror) {
                    vrouter_put_mirror(router, req->fr_mir_id);
                }
                ret = -EINVAL;
                goto flow_set_fail;
            }
        }

        if (req->fr_pcap_meta_data_size && req->fr_pcap_meta_data)
            vr_mirror_meta_entry_set(router, req->fr_index,
                                     req->fr_mir_sip, req->fr_mir_sport,
                                     req->fr_pcap_meta_data, req->fr_pcap_meta_data_size,
                                     req->fr_mir_vrf);
    }

    /* only needed for agent test framework */
    if (!(fe->fe_flags & VR_FLOW_FLAG_ACTIVE) &&
            (flags & VR_FLOW_FLAG_ACTIVE)) {
        /* it is useful to log the event */
        vr_printf("AGENT request to create flow at %d\n", req->fr_index);
        vr_reset_flow_entry(router, fe, req->fr_index);
    }

    if (!flow_delete && ((orig_action & VR_FLOW_ACTION_NAT) || (flags &
                    VR_RFLOW_VALID))) {
        if ((unsigned short)req->fr_rflow_vrf >= VR_MAX_VRFS) {
            ret = -EINVAL;
            goto flow_set_fail;
        }

        if (fe->fe_rflow < 0) {
            rf_id = vr_get_reverse_flow(req);
            if (rf_id < 0) {
                ret = -ENOSPC;
                goto flow_set_fail;
            }
            fe->fe_rflow = rf_id;
        }
    }

    if (flags & VR_FLOW_FLAG_VRFT) 
        fe->fe_dvrf = req->fr_flow_dvrf;

    if (flags & VR_FLOW_FLAG_MIRROR) {
        fe->fe_mirror_id = req->fr_mir_id;
        fe->fe_sec_mirror_id = req->fr_sec_mir_id;
    }

    /* when mirror flag is reset... */
    if ((fe->fe_flags & VR_FLOW_FLAG_MIRROR) &&
            !(flags & VR_FLOW_FLAG_MIRROR)) {
        fe->fe_flags &= ~VR_FLOW_FLAG_MIRROR;
        vrouter_put_mirror(router, fe->fe_mirror_id);
        fe->fe_mirror_id = VR_MAX_MIRROR_INDICES;
        vrouter_put_mirror(router, fe->fe_sec_mirror_id);
        fe->fe_sec_mirror_id = VR_MAX_MIRROR_INDICES;
        vr_mirror_meta_entry_del(router, req->fr_index);
    }

    fe->fe_ecmp_nh_index = req->fr_ecmp_nh_index;
    fe->fe_flags = flags;
    fe->fe_action = action;

    if (fe->fe_rflow >= 0) {
        rfe = vr_get_flow_entry(router, fe->fe_rflow);
        rflags = flags & ~VR_FLOW_FLAG_NAT_MASK;
        if (orig_action == VR_FLOW_ACTION_NAT) {
            if (flags & VR_FLOW_FLAG_SNAT)
                rflags |= VR_FLOW_FLAG_DNAT;

            if (flags & VR_FLOW_FLAG_DNAT)
                rflags |= VR_FLOW_FLAG_SNAT;

            if (flags & VR_FLOW_FLAG_SPAT)
                rflags |= VR_FLOW_FLAG_DPAT;

            if (flags & VR_FLOW_FLAG_DPAT)
                rflags |= VR_FLOW_FLAG_SPAT;
        }

        if (flags & VR_FLOW_FLAG_VRFT) 
            rfe->fe_dvrf = req->fr_rflow_dvrf;

        rfe->fe_ecmp_nh_index = req->fr_rflow_ecmp_nh_index;
        rfe->fe_action = action;
        /* do not change the mirror flags for the reverse entry */
        if (rflags & VR_FLOW_FLAG_MIRROR) {
            rfe->fe_mirror_id = req->fr_mir_id;
            rfe->fe_sec_mirror_id = req->fr_sec_mir_id;
            if (req->fr_pcap_meta_data_size && req->fr_pcap_meta_data)
                vr_mirror_meta_entry_set(router, fe->fe_rflow,
                                         req->fr_mir_sip, req->fr_mir_sport,
                                         req->fr_rflow_pcap_meta_data, 
                                         req->fr_rflow_pcap_meta_data_size,
                                         req->fr_rflow_mir_vrf);
        } 
        rfe->fe_flags = rflags;
    }

    if (rfe && rfe->fe_flags & (VR_FLOW_FLAG_FLUSH |
                VR_FLOW_FLAG_UNUSABLE)) {
        rev_defer_data->def_index = fe->fe_rflow;
        rev_defer_data->def_action = orig_action;
        vr_defer(router, vr_flow_flush, rev_defer_data);
    }

    if (fe->fe_flags & (VR_FLOW_FLAG_FLUSH | 
                 VR_FLOW_FLAG_UNUSABLE)) {
        defer_data->def_index = req->fr_index;
        defer_data->def_action = orig_action;
        vr_defer(router, vr_flow_flush, defer_data);
    }

    return 0;

flow_set_fail:
    if (mirror)
        vrouter_put_mirror(router, req->fr_mir_id);
    if (sec_mirror)
        vrouter_put_mirror(router, req->fr_sec_mir_id);

    if (defer_data)
        vr_put_defer_data(defer_data);

    if (rev_defer_data)
        vr_put_defer_data(rev_defer_data);

    return ret;
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
#ifdef __KERNEL__
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

    return;
}

/* flow module exit and init */
void
vr_flow_exit(struct vrouter *router, bool soft_reset)
{
    unsigned int i;
    struct vr_flow_entry *fe;
    struct vr_forwarding_md fmd;

    vr_init_forwarding_md(&fmd);

    for (i = 0; i < vr_flow_entries + vr_oflow_entries; i++) {
        fe = vr_get_flow_entry(router, i);
        if (fe) {
            fe->fe_action = VR_FLOW_ACTION_DROP;
            vr_flush_entry(router, fe, i, &fmd, VR_FLOW_ACTION_DROP);
            vr_reset_flow_entry(router, fe, i);
        }
    }

    if (!soft_reset)
        vr_flow_table_destroy(router);

    return;
}

int
vr_flow_init(struct vrouter *router)
{
    int ret;

    if (!router->vr_flow_table) {
        if (vr_flow_entries % VR_FLOW_ENTRIES_PER_BUCKET)
            return vr_module_error(-EINVAL, __FUNCTION__,
                    __LINE__, vr_flow_entries);

        router->vr_flow_table = vr_btable_alloc(vr_flow_entries,
                sizeof(struct vr_flow_entry));
        if (!router->vr_flow_table && (ret = -ENOMEM)) {
            vr_module_error(ret, __FUNCTION__, __LINE__, VR_DEF_FLOW_ENTRIES);
            goto exit_init;
        }
    }

    if (!router->vr_oflow_table) {
        router->vr_oflow_table = vr_btable_alloc(vr_oflow_entries,
                sizeof(struct vr_flow_entry));
        if (!router->vr_oflow_table && (ret = -ENOMEM)) {
            vr_module_error(ret, __FUNCTION__, __LINE__, VR_DEF_OFLOW_ENTRIES);
            goto exit_init;
        }
    }

    return 0;

exit_init:
    return ret;
}
