/*
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#include <vr_os.h>
#include <vrouter.h>
#include <vr_htable.h>
#include <vr_btable.h>
#include <vr_hash.h>

#define VR_HENTRIES_PER_BUCKET 4
struct vr_htable {
    unsigned int hentries;
    unsigned int oentries;
    unsigned int entry_size;
    unsigned int key_size;
    struct vr_btable *htable;
    struct vr_btable *otable;
    is_hentry_valid is_valid_entry;
};

void
vr_htable_trav(vr_htable_t htable, unsigned int marker, htable_trav_cb cb,
                                                                void *data)
{
    struct vr_htable *table = (struct vr_htable *)htable;
    vr_hentry_t ent;
    unsigned int i;

    if (!table || !cb)
        return;

    if (marker < table->hentries) {
        for (i = marker; i < table->hentries; i++) {
            ent = vr_btable_get(table->htable, i);
            if(ent && table->is_valid_entry(htable, ent, i) == true)
                cb(htable, ent, i, data);
        }
    }

    marker -= table->hentries;
    if (marker < table->oentries) {
        for (i = marker; i < table->oentries; i++) {
            ent = vr_btable_get(table->htable, i);
            if(ent && table->is_valid_entry(htable, ent,
                        (i + table->hentries)) == true)
                cb(htable, ent, (i + table->hentries), data);
        }
    }
}

vr_hentry_t
vr_find_free_hentry(vr_htable_t htable, void *key, unsigned int *index)
{
    struct vr_htable *table = (struct vr_htable *)htable;
    unsigned int hash, tmp_hash, i, ind;
    vr_hentry_t ent;

    if (!table || !key)
        return NULL;

    hash = vr_hash(key, table->key_size, 0);
    tmp_hash = hash % table->hentries;
    tmp_hash &= ~(VR_HENTRIES_PER_BUCKET - 1);
    for(i = 0; i < VR_HENTRIES_PER_BUCKET; i++) {
        ind = tmp_hash + i;
        ent = vr_btable_get(table->htable, ind);
        if (table->is_valid_entry(htable, ent, ind) == false) {
            if (index)
                *index = ind;
            return ent;
        }
    }

    tmp_hash = hash % table->oentries;
    for(i = 0; i < table->oentries; i++) {
        ent = vr_btable_get(table->otable, ((tmp_hash + i) % table->oentries));
        ind = table->hentries + ((tmp_hash + i) % table->oentries);
        if (table->is_valid_entry(htable, ent, ind) == false) {
            if (index)
                *index = ind;
            return ent;
        }
    }

    return NULL;
}

vr_hentry_t
vr_get_hentry_by_index(vr_htable_t htable, unsigned int index)
{
    struct vr_htable *table = (struct vr_htable *)htable;

    if (!table)
        return NULL;

    if (index < table->hentries)
        return vr_btable_get(table->htable, index);

    if (index < (table->oentries + table->hentries))
        return vr_btable_get(table->otable, (index - table->hentries));

    return NULL;
}

int
vr_find_duplicate_hentry_index(vr_htable_t htable, vr_hentry_t hentry)
{
    unsigned int hash, tmp_hash, ind, i;
    vr_hentry_t ent;
    struct vr_htable *table = (struct vr_htable *)htable;

    if (!table || !hentry)
        return -1;

    hash = vr_hash(hentry, table->key_size, 0);

    /* Look into the hash table from hash, VR_HENTRIES_PER_BUCKET */
    tmp_hash = hash % table->hentries;
    tmp_hash &= ~(VR_HENTRIES_PER_BUCKET - 1);
    for(i = 0; i < VR_HENTRIES_PER_BUCKET; i++) {
        ind = tmp_hash + i;
        ent = vr_btable_get(table->htable, ind);
        if (table->is_valid_entry(htable, ent, ind) == false)
            continue;
        if ((ent == hentry) || (memcmp(ent, hentry, table->key_size) != 0))
            continue;
        return ind;
    }

    /* Look into the complete over flow table starting from hash*/
    tmp_hash = hash % table->oentries;
    for(i = 0; i < table->oentries; i++) {
        ind = table->hentries + ((tmp_hash + i) % table->oentries);
        ent = vr_btable_get(table->otable, ((tmp_hash + i) % table->oentries));
        if (table->is_valid_entry(htable, ent, ind) == false)
            continue;
        if ((ent == hentry) || (memcmp(ent, hentry, table->key_size) != 0))
            continue;

        return ind;
    }

    /* No duplicate entry is found */
    return -1;
}

vr_hentry_t
vr_find_hentry(vr_htable_t htable, void *key, unsigned int *index)
{
    unsigned int hash, tmp_hash, ind, i;
    vr_hentry_t ent;
    struct vr_htable *table = (struct vr_htable *)htable;

    if (!table || !key)
        return NULL;

    hash = vr_hash(key, table->key_size, 0);

    /* Look into the hash table from hash, VR_HENTRIES_PER_BUCKET */
    tmp_hash = hash % table->hentries;
    tmp_hash &= ~(VR_HENTRIES_PER_BUCKET - 1);
    for(i = 0; i < VR_HENTRIES_PER_BUCKET; i++) {
        ind = tmp_hash + i;
        ent = vr_btable_get(table->htable, ind);
        if (table->is_valid_entry(htable, ent, ind) == false)
            continue;
        if (memcmp(ent, key, table->key_size) == 0) {
            if (index)
                *index = ind;
            return ent;
        }
    }

    /* Look into the complete over flow table starting from hash*/
    tmp_hash = hash % table->oentries;
    for(i = 0; i < table->oentries; i++) {
        ind = table->hentries + ((tmp_hash + i) % table->oentries);
        ent = vr_btable_get(table->otable, ((tmp_hash + i) % table->oentries));
        if (table->is_valid_entry(htable, ent, ind) == false)
            continue;
        if (memcmp(ent, key, table->key_size) == 0) {
            if (index)
                *index = ind;
            return ent;
        }
    }

    /* Entry not found */
    return NULL;
}

void
vr_htable_delete(vr_htable_t htable)
{
    struct vr_htable *table = (struct vr_htable *)htable;

    if (!table)
        return;

    if (table->htable)
        vr_btable_free(table->htable);

    if (table->otable)
        vr_btable_free(table->otable);

    vr_free(table);
}

vr_htable_t
vr_htable_create(unsigned int entries, unsigned int oentries,
        unsigned int entry_size, unsigned int key_size,
        is_hentry_valid is_valid_entry)
{
    struct vr_htable *table;

    if (!is_valid_entry || !key_size || !entry_size || !entries ||
            !oentries)
        return NULL;

    if (entries % VR_HENTRIES_PER_BUCKET) {
        vr_module_error(-EINVAL, __FUNCTION__, __LINE__, entries);
        return NULL;
    }

    table = vr_zalloc(sizeof(struct vr_htable));
    if (!table) {
        vr_module_error(-ENOMEM, __FUNCTION__, __LINE__,
                                       sizeof(struct vr_htable));
        return NULL;
    }

    table->htable = vr_btable_alloc(entries, entry_size);
    if (!table->htable) {
        vr_module_error(-ENOMEM, __FUNCTION__, __LINE__, entries);
        return NULL;
    }

    table->otable = vr_btable_alloc(oentries, entry_size);
    if (!table->otable) {
        vr_module_error(-ENOMEM, __FUNCTION__, __LINE__, oentries);
        return NULL;
    }

    table->hentries = entries;
    table->oentries = oentries;
    table->entry_size = entry_size;
    /* Key is assumed to be at the start of the entry of size key_size */
    table->key_size = key_size;
    table->is_valid_entry = is_valid_entry;
    return (vr_htable_t)table;
}
