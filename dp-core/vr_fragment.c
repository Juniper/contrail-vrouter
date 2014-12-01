/*
 * vr_fragment.c -- basic fragment handling code
 *
 * Copyright (c) 2013, Juniper Networks Private Limited
 * All rights reserved
 */
#include <vr_os.h>
#include <vr_packet.h>
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
        if (fe && !fe->f_dip  && fragment_entry_alloc(fe)) {
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

    return fe;;
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

