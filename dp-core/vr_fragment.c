/*
 * vr_fragment.c -- basic fragment handling code
 *
 * Copyright (c) 2013, Juniper Networks Private Limited
 * All rights reserved
 */
#include <vr_os.h>
#include <vr_packet.h>
#include "vr_interface.h"
#include "vr_btable.h"
#include "vr_fragment.h"
#include "vr_hash.h"

#define FRAG_TABLE_ENTRIES  1024
#define FRAG_TABLE_BUCKETS  4
#define FRAG_OTABLE_ENTRIES 512

static inline void
fragment_key(struct vr_fragment_key *key, unsigned short vrf,
        struct vr_ip *iph)
{
    key->fk_sip = iph->ip_saddr;
    key->fk_dip = iph->ip_daddr;
    key->fk_id = iph->ip_id;
    key->fk_vrf = vrf;

    return;
}

static inline void
fragment_entry_set(struct vr_fragment *fe, unsigned short vrf, struct vr_ip *iph,
        unsigned short sport, unsigned short dport)
{
    unsigned int sec, nsec;

    fe->f_sip = iph->ip_saddr;
    fe->f_dip = iph->ip_daddr;
    fe->f_id = iph->ip_id;
    fe->f_vrf = vrf;
    fe->f_sport = sport;
    fe->f_dport = dport;
    vr_get_mono_time(&sec, &nsec);
    fe->f_time = sec;
    fe->f_expected = 0;
    fe->f_received = 0;

    return;
}

static inline struct vr_fragment *
fragment_oentry_get(struct vrouter *router, unsigned int index)
{
    return (struct vr_fragment *)vr_btable_get(router->vr_fragment_otable, index);
}

static inline struct vr_fragment *
fragment_entry_get(struct vrouter *router, unsigned int index)
{
    return (struct vr_fragment *)vr_btable_get(router->vr_fragment_table, index);
}

static inline bool
fragment_entry_alloc(struct vr_fragment *fe)
{
    return __sync_bool_compare_and_swap(&fe->f_dip, 0, 1);
}

static void
vr_fragment_queue_element_free(struct vr_fragment_queue_element *vfqe)
{
    if (vfqe->fqe_pnode.pl_packet) {
        vr_pfree(vfqe->fqe_pnode.pl_packet, VP_DROP_CLONED_ORIGINAL);
    }

    vr_free(vfqe);
    return;
}

static void
fragment_free_frag(struct vr_fragment *frag)
{
    struct vr_fragment_queue_element *fqe;

    while ((fqe = frag->f_qe)) {
        frag->f_qe = fqe->fqe_next;
        vr_fragment_queue_element_free(fqe);
    }

    vr_free(frag);
    return;
}

static void
fragment_unlink_frag(struct vr_fragment **prev, struct vr_fragment *frag)
{
    *prev = frag->f_next;
    return;
}

unsigned int
vr_assembler_table_scan(struct vr_fragment **head)
{
    unsigned int scanned = 0;
    unsigned int sec, nsec, dest;
    struct vr_fragment *frag = *head, *next, **prev;

    prev = head;
    while (frag) {
        next = frag->f_next;

        vr_get_mono_time(&sec, &nsec);
        dest = frag->f_time + VR_ASSEMBLER_TIMEOUT_TIME;
        if (dest < frag->f_time) {
            if ((sec < frag->f_time) && (dest < sec)) {
                fragment_unlink_frag(prev, frag);
                fragment_free_frag(frag);
            } else {
                prev = &frag->f_next;
            }
        } else {
            if ((sec > dest) || (sec < frag->f_time)) {
                fragment_unlink_frag(prev, frag);
                fragment_free_frag(frag);
            } else {
                prev = &frag->f_next;
            }
        }
        scanned++;
        frag = next;
    }

    return scanned;
}

int
vr_fragment_assembler(struct vr_fragment **head_p,
        struct vr_fragment_queue_element *vfqe)
{
    int ret;
    unsigned int sec, nsec;
    bool found = false, forward = false;

    struct vrouter *router;
    struct vr_ip *ip;
    struct vr_flow flow;
    struct vr_packet *pkt;
    struct vr_packet_node *pnode;
    struct vr_fragment *frag, **prev = NULL;
    struct vr_fragment_queue_element *fqe;
    struct vr_fragment_key vfk;
    struct vr_interface *vif;
    struct vr_forwarding_md fmd;


    router = vfqe->fqe_router;
    pkt = vfqe->fqe_pnode.pl_packet;
    ip = (struct vr_ip *)pkt_network_header(pkt);
    fragment_key(&vfk, vfqe->fqe_pnode.pl_vrf, ip);

    frag = *head_p;
    prev = head_p;
    while (frag) {
        if (!memcmp(&frag->f_key, &vfk, sizeof(vfk))) {
            found = true;
            break;
        }

        prev = &frag->f_next;
        frag = frag->f_next;
    }

    if (!found) {
        if (vfqe->fqe_action == VR_ASSEMBLER_ACTION_DATA) {
            vr_fragment_queue_element_free(vfqe);
            return 0;
        }

        frag = vr_zalloc(sizeof(*frag));
        if (!frag)
            return -ENOMEM;
        memcpy(&frag->f_key, &vfk, sizeof(vfk));
        frag->f_port_info_valid = false;
    }

    if (vr_ip_fragment_tail(ip)) {
        frag->f_expected = ((ntohs(ip->ip_frag_off) && 0x1FFF) * 8) +
            ntohs(ip->ip_len) - (ip->ip_hl * 4) ;
    }
    frag->f_received += (ntohs(ip->ip_len) - (ip->ip_hl * 4));

    vr_get_mono_time(&sec, &nsec);
    frag->f_time = sec;
    if (!found) {
        prev = head_p;
        frag->f_next = *head_p;
        *head_p = frag;
    }

    if (vr_ip_transport_header_valid(ip)) {
        ret = vr_inet_form_flow(router, vfqe->fqe_pnode.pl_vrf,
                vfqe->fqe_pnode.pl_packet, vfqe->fqe_pnode.pl_vlan, &flow);

        if (ret) {
            fragment_free_frag(frag);
            return 0;
        }

        frag->f_sport = flow.flow4_sport;
        frag->f_dport = flow.flow4_dport;
        frag->f_port_info_valid = true;

    }

    if (vfqe->fqe_action == VR_ASSEMBLER_ACTION_ENQUEUE) {
        vfqe->fqe_next = NULL;
        fqe = frag->f_qe;
        if (!fqe) {
            frag->f_qe = vfqe;
        } else {
            while (fqe) {
                if (fqe->fqe_next) {
                    fqe = fqe->fqe_next;
                } else {
                    break;
                }
            }

            fqe->fqe_next = vfqe;
        }
    } else if (vfqe->fqe_action == VR_ASSEMBLER_ACTION_DATA) {
        vr_fragment_queue_element_free(vfqe);
    }


    if (frag->f_port_info_valid) {
        while ((fqe = frag->f_qe)) {
            pnode = &fqe->fqe_pnode;
            pkt = pnode->pl_packet;
            if (pkt) {
                memset(&fmd, 0, sizeof(fmd));
                fmd.fmd_outer_src_ip = pnode->pl_outer_src_ip;
                fmd.fmd_label = pnode->pl_label;
                if (pnode->pl_flags & PN_FLAG_TO_ME)
                    fmd.fmd_to_me = 1;
                fmd.fmd_dvrf = pnode->pl_vrf;
                fmd.fmd_vlan = pnode->pl_vlan;

                vif = __vrouter_get_interface(router, pnode->pl_vif_idx);
                if (!vif || (pkt->vp_if != vif)) {
                    vr_pfree(pkt, VP_DROP_INVALID_IF);
                    continue;
                }

                if (!pkt->vp_nh) {
                    if (vif_is_fabric(pkt->vp_if) && (fmd.fmd_label >= 0)) {
                        if (!(pnode->pl_flags & PN_FLAG_LABEL_IS_VNID))
                            pkt->vp_nh = __vrouter_get_label(router, fmd.fmd_label);
                    }
                }

                forward = vr_flow_forward(router, pkt, &fmd);
                if (forward)
                    vr_reinject_packet(pkt, &fmd);
                fqe->fqe_pnode.pl_packet = NULL;
            }
            frag->f_qe = fqe->fqe_next;
            vr_fragment_queue_element_free(fqe);
        }

        if (frag->f_received == frag->f_expected) {
            fragment_unlink_frag(prev, frag);
            fragment_free_frag(frag);
        }

    }

    return 0;
}

uint32_t
vr_fragment_get_hash(unsigned int vrf, struct vr_packet *pkt)
{
    struct vr_ip *ip;
    struct vr_fragment_key vfk;

    ip = (struct vr_ip *)pkt_network_header(pkt);
    fragment_key(&vfk, vrf, ip);

    return vr_hash(&vfk, sizeof(vfk), 0);
}

int
vr_fragment_enqueue(struct vrouter *router,
        struct vr_fragment_queue_element **tailp, unsigned int action,
        struct vr_packet *pkt, struct vr_forwarding_md *fmd)
{
    bool swapped = false;
    unsigned int i;

    struct vr_packet_node *pnode;
    struct vr_fragment_queue_element *fq = NULL, *tail;

    fq = vr_malloc(sizeof(*fq));
    if (!fq) {
        goto fail;
    }
    fq->fqe_router = router;
    fq->fqe_action = action;
    fq->fqe_next = NULL;

    pkt->vp_flags &= ~VP_FLAG_FLOW_SET;

    pnode = &fq->fqe_pnode;
    if (pkt->vp_nh &&
            (pkt->vp_nh->nh_type == NH_VRF_TRANSLATE) &&
            (pkt->vp_nh->nh_flags & NH_FLAG_VNID))
        pnode->pl_flags |= PN_FLAG_LABEL_IS_VNID;

    pkt->vp_nh = NULL;
    pnode->pl_vif_idx = pkt->vp_if->vif_idx;
    pnode->pl_outer_src_ip = fmd->fmd_outer_src_ip;
    pnode->pl_label = fmd->fmd_label;
    if (fmd->fmd_to_me)
        pnode->pl_flags |= PN_FLAG_TO_ME;
    pnode->pl_vrf = fmd->fmd_dvrf;
    pnode->pl_vlan = fmd->fmd_vlan;
    pnode->pl_packet = pkt;

    /*
     * we are actually competing with an existing assembler work that must
     * be in the process of dequeueing the list from the per-cpu queue.
     * we try thrice to enqueue our element. It is unlikely that it will
     * fail more than once
     */
    for (i = 0; i < VR_FRAG_ENQUEUE_ATTEMPTS; i++) {
        tail = *tailp;
        fq->fqe_next = tail;
        swapped = __sync_bool_compare_and_swap(tailp, tail, fq);
        if (swapped) {
            break;
        } else if (i == (VR_FRAG_ENQUEUE_ATTEMPTS - 1)) {
            goto fail;
        }
    }

    return 0;

fail:
    if (fq)
        vr_free(fq);

    vr_pfree(pkt, VP_DROP_FRAGMENTS);
    return -1;
}


void
vr_fragment_del(struct vr_fragment *fe)
{
    fe->f_dip = 0;
}

int
vr_fragment_add(struct vrouter *router, unsigned short vrf, struct vr_ip *iph,
        unsigned short sport, unsigned short dport)
{
    unsigned int hash, index, i;
    struct vr_fragment_key key;
    struct vr_fragment *fe;

    fragment_key(&key, vrf, iph);
    hash = vr_hash(&key, sizeof(key), 0);
    index = (hash % FRAG_TABLE_ENTRIES) * FRAG_TABLE_BUCKETS;
    for (i = 0; i < FRAG_TABLE_BUCKETS; i++) {
        fe = fragment_entry_get(router, index + i);
        if (fe && !fe->f_dip && fragment_entry_alloc(fe)) {
            fragment_entry_set(fe, vrf, iph, sport, dport);
            break;
        } else {
            fe = NULL;
            continue;
        }
    }

    if (!fe) {
        index = (hash % FRAG_OTABLE_ENTRIES);
        for (i = 0; i < FRAG_OTABLE_ENTRIES; i++) {
            fe = fragment_oentry_get(router, (index + i) % FRAG_OTABLE_ENTRIES);
            if (fe && !fe->f_dip && fragment_entry_alloc(fe)) {
                fragment_entry_set(fe, vrf, iph, sport, dport);
                break;
            } else {
                fe = NULL;
                continue;
            }
        }
    }

    if (!fe)
        return -ENOMEM;

    fe->f_received += (ntohs(iph->ip_len) - (iph->ip_hl * 4));

    return 0;
}

struct vr_fragment *
vr_fragment_get(struct vrouter *router, unsigned short vrf, struct vr_ip *iph)
{
    unsigned int hash, index, i;
    struct vr_fragment_key key;
    struct vr_fragment *fe;
    unsigned int sec, nsec;

    fragment_key(&key, vrf, iph);
    hash = vr_hash(&key, sizeof(key), 0);
    index = (hash % FRAG_TABLE_ENTRIES) * FRAG_TABLE_BUCKETS;
    for (i = 0; i < FRAG_TABLE_BUCKETS; i++) {
        fe = fragment_entry_get(router, index + i);
        if (fe && !memcmp((const void *)&key, (const void *)&(fe->f_key),
                    sizeof(key)))
            break;
    }

    if (i == FRAG_TABLE_BUCKETS) {
        index = (hash % FRAG_OTABLE_ENTRIES);
        for (i = 0; i < FRAG_OTABLE_ENTRIES; i++) {
            fe = fragment_oentry_get(router, (index + i) % FRAG_OTABLE_ENTRIES);
            if (fe && !memcmp((const void *)&key, (const void *)&(fe->f_key),
                        sizeof(key)))
                break;
        }

        if (i == FRAG_OTABLE_ENTRIES)
            fe = NULL;
    }

    if (fe) {
        vr_get_mono_time(&sec, &nsec);
        fe->f_time = sec;
    }

    return fe;
}

#define ENTRIES_PER_SCAN    64

struct scanner_params {
    struct vrouter *sp_router;
    struct vr_btable *sp_fragment_table;
    unsigned int sp_num_entries;
    int sp_last_scanned_entry;
};

static void
fragment_reap(struct vr_btable *table, int start,
        unsigned int num_entries)
{
    unsigned int i;
    struct vr_fragment *fe;
    unsigned int sec, nsec;

    vr_get_mono_time(&sec, &nsec);

    for (i = 0; i < ENTRIES_PER_SCAN; i++) {
        fe = vr_btable_get(table, (start + i) % num_entries);
        if (fe && fe->f_dip) {
            if (sec > fe->f_time + 1)
                vr_fragment_del(fe);
        }
    }


    return;
}

static void
fragment_table_scanner(void *arg)
{
    struct scanner_params *sp = (struct scanner_params *)arg;

    fragment_reap(sp->sp_fragment_table, sp->sp_last_scanned_entry + 1,
            sp->sp_num_entries);

    sp->sp_last_scanned_entry += ENTRIES_PER_SCAN;
    sp->sp_last_scanned_entry %= sp->sp_num_entries;

    return;
}

static struct vr_timer *
fragment_table_scanner_init(struct vrouter *router, struct vr_btable *table)
{
    unsigned int num_entries;
    struct vr_timer *vtimer;
    struct scanner_params *scanner;

    if (!table)
        return NULL;

    num_entries = vr_btable_entries(table);

    scanner = vr_zalloc(sizeof(*scanner));
    if (!scanner) {
        vr_module_error(-ENOMEM, __FUNCTION__, __LINE__, num_entries);
        return NULL;
    }

    scanner->sp_router = router;
    scanner->sp_fragment_table = table;
    scanner->sp_num_entries = num_entries;
    scanner->sp_last_scanned_entry = -1;

    vtimer = vr_malloc(sizeof(*vtimer));
    if (!vtimer) {
        vr_module_error(-ENOMEM, __FUNCTION__, __LINE__, num_entries);
        goto fail_init;
    }

    vtimer->vt_timer = fragment_table_scanner;
    vtimer->vt_vr_arg = scanner;
    vtimer->vt_msecs = 1000;

    if (vr_create_timer(vtimer)) {
        vr_module_error(-ENOMEM, __FUNCTION__, __LINE__, num_entries);
        goto fail_init;
    }

    return vtimer;

fail_init:
    if (scanner)
        vr_free(scanner);

    return NULL;
}

static void
vr_fragment_table_scanner_exit(struct vrouter *router)
{
    if (router->vr_fragment_table_scanner) {
        vr_delete_timer(router->vr_fragment_table_scanner);
        vr_free(router->vr_fragment_table_scanner->vt_vr_arg);
        vr_free(router->vr_fragment_table_scanner);
        router->vr_fragment_table_scanner = NULL;
    }

    if (router->vr_fragment_otable_scanner) {
        vr_delete_timer(router->vr_fragment_otable_scanner);
        vr_free(router->vr_fragment_otable_scanner->vt_vr_arg);
        vr_free(router->vr_fragment_otable_scanner);
        router->vr_fragment_otable_scanner = NULL;
    }

    return;
}

void
vr_fragment_table_exit(struct vrouter *router)
{
    vr_fragment_table_scanner_exit(router);

    if (router->vr_fragment_table)
        vr_btable_free(router->vr_fragment_table);
    if (router->vr_fragment_otable)
        vr_btable_free(router->vr_fragment_otable);

    return;
}

static int
vr_fragment_table_scanner_init(struct vrouter *router)
{
    if (!router->vr_fragment_table_scanner) {
        router->vr_fragment_table_scanner =
            fragment_table_scanner_init(router, router->vr_fragment_table);
        if (!router->vr_fragment_table_scanner)
            return -ENOMEM;
    }

    if (!router->vr_fragment_otable_scanner) {
        router->vr_fragment_otable_scanner =
            fragment_table_scanner_init(router, router->vr_fragment_otable);
        if (!router->vr_fragment_otable_scanner)
            return -ENOMEM;
    }

    return 0;
}

int
vr_fragment_table_init(struct vrouter *router)
{
    int num_entries, ret;

    if (!router->vr_fragment_table) {
        num_entries = FRAG_TABLE_ENTRIES * FRAG_TABLE_BUCKETS;
        router->vr_fragment_table = vr_btable_alloc(num_entries,
                sizeof(struct vr_fragment));
        if (!router->vr_fragment_table)
            return vr_module_error(-ENOMEM, __FUNCTION__,
                    __LINE__, num_entries);
    }

    if (!router->vr_fragment_otable) {
        num_entries = FRAG_OTABLE_ENTRIES;
        router->vr_fragment_otable = vr_btable_alloc(num_entries,
                sizeof(struct vr_fragment));
        if (!router->vr_fragment_otable)
            return vr_module_error(-ENOMEM, __FUNCTION__,
                    __LINE__, num_entries);
    }

    if ((ret = vr_fragment_table_scanner_init(router)))
        return ret;

    return 0;
}

