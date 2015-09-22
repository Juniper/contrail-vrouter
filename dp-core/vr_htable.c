/*
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#include <vr_os.h>
#include <vrouter.h>
#include <vr_htable.h>
#include <vr_btable.h>
#include <vr_hash.h>
#include <vr_bitmap.h>

#define VR_HENTRIES_PER_BUCKET 4
struct vr_htable {
    unsigned int hentries;
    unsigned int oentries;
    unsigned int entry_size;
    unsigned int key_size;
    struct vr_btable *htable;
    struct vr_btable *otable;
    is_hentry_valid is_valid_entry;
    get_hentry_key get_key;
    vr_bmap_t free_oentries;
};

void
vr_htable_trav(vr_htable_t htable, unsigned int marker, htable_trav_cb cb,
                                                                void *data)
{
    struct vr_htable *table = (struct vr_htable *)htable;
    vr_hentry_t *ent;
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

void
vr_release_hentry(vr_htable_t htable, vr_hentry_t *entry)
{
    struct vr_htable *table = (struct vr_htable *)htable;

    if (entry->hentry_index < table->hentries)
        return;

    entry->hentry_prev->hentry_next = entry->hentry_next;
    if (entry->hentry_next)
        entry->hentry_next->hentry_prev = entry->hentry_prev;

    entry->hentry_bucket_index = (unsigned int) -1;
    entry->hentry_next = NULL;
    entry->hentry_prev = NULL;

    vr_bitmap_clear_bit(table->free_oentries, entry->hentry_index -
            table->hentries);

    return;
}

vr_hentry_t *
vr_find_free_hentry(vr_htable_t htable, void *key)
{
    unsigned int hash, tmp_hash, i;
    struct vr_htable *table = (struct vr_htable *)htable;
    vr_hentry_t *ent, *o_ent;
    int ind;

    if (!table || !key)
        return NULL;

    hash = vr_hash(key, table->key_size, 0);
    tmp_hash = hash % table->hentries;
    tmp_hash &= ~(VR_HENTRIES_PER_BUCKET - 1);
    for(i = 0; i < VR_HENTRIES_PER_BUCKET; i++) {
        ind = tmp_hash + i;
        ent = vr_btable_get(table->htable, ind);
        if (table->is_valid_entry(htable, ent, ind) == false) {
            ent->hentry_index = ind;
            ent->hentry_bucket_index = (unsigned int) -1;
            return ent;
        }
    }

    ent->hentry_index = ind;
    ent->hentry_prev = NULL;

    if (table->oentries) {
        ind = vr_bitmap_get_first_free_bit(table->free_oentries);
        if (ind == -1)
            return NULL;

        vr_bitmap_set_bit(table->free_oentries, ind);

        o_ent = vr_btable_get(table->otable, ind);
        o_ent->hentry_bucket_index = ent->hentry_index;
        o_ent->hentry_index = ind + table->hentries;

        /* Link the overflow entry at the start */
        o_ent->hentry_next = ent->hentry_next;
        if (o_ent->hentry_next)
            o_ent->hentry_next->hentry_prev = o_ent;
        ent->hentry_next = o_ent;
        o_ent->hentry_prev = ent;
        return o_ent;
    }

    return NULL;
}

vr_hentry_t *
vr_get_hentry_by_index(vr_htable_t htable, unsigned int index)
{
    struct vr_htable *table = (struct vr_htable *)htable;

    if (!table)
        return NULL;

    if (index < table->hentries)
        return vr_btable_get(table->htable, index);

    if (index < table->oentries)
        return vr_btable_get(table->otable, (index - table->hentries));

    return NULL;
}

int
vr_find_duplicate_hentry_index(vr_htable_t htable, vr_hentry_t *hentry)
{
    unsigned int hash, tmp_hash, ind, i;
    vr_hentry_t *ent;
    vr_hentry_key hkey;
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

        if (ent == hentry)
            continue;

        hkey = table->get_key(htable, ent);
        if (!hkey)
            continue;

        if (memcmp(hkey, hentry, table->key_size) != 0)
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

        if (ent == hentry)
            continue;

        hkey = table->get_key(htable, ent);
        if (!hkey)
            continue;

        if (memcmp(hkey, hentry, table->key_size) != 0)
            continue;

        return ind;
    }

    /* No duplicate entry is found */
    return -1;
}

vr_hentry_t *
vr_find_hentry(vr_htable_t htable, void *key)
{
    unsigned int hash, tmp_hash, ind, i;
    vr_hentry_t *ent, *o_ent;
    vr_hentry_key ent_key;
    struct vr_htable *table = (struct vr_htable *)htable;

    if (!table || !key)
        return NULL;

    hash = vr_hash(key, table->key_size, 0);

    /* Look into the hash table from hash, VR_HENTRIES_PER_BUCKET */
    tmp_hash = hash % table->hentries;
    tmp_hash &= ~(VR_HENTRIES_PER_BUCKET - 1);
    for (i = 0; i < VR_HENTRIES_PER_BUCKET; i++) {
        ind = tmp_hash + i;
        ent = vr_btable_get(table->htable, ind);
        if (table->is_valid_entry(htable, ent, ind) == false)
            continue;

        ent_key = table->get_key(htable, ent);
        if (!ent_key)
            continue;

        if (memcmp(ent_key, key, table->key_size) == 0)
            return ent;
    }

    for(o_ent = ent->hentry_next; o_ent; o_ent = o_ent->hentry_next) {
        if (table->is_valid_entry(htable, o_ent, o_ent->hentry_index) == false)
            continue;

        ent_key = table->get_key(htable, o_ent);
        if (!ent_key)
            continue;

        if (memcmp(ent_key, key, table->key_size) == 0)
            return o_ent;
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

    if (table->free_oentries)
        vr_bitmap_delete(table->free_oentries);

    vr_free(table, VR_HTABLE_OBJECT);

    return;
}

vr_htable_t
vr_htable_create(unsigned int entries, unsigned int oentries,
        unsigned int entry_size, unsigned int key_size,
        is_hentry_valid is_valid_entry, get_hentry_key get_entry_key)
{
    struct vr_htable *table;

    if (!is_valid_entry || !key_size || !entry_size || !entries ||
            !oentries || !get_entry_key)
        return NULL;
    /* Ceil to near upper number, which is dividable by VR_HTABLE_OBJECT. */
    entries = ((entries + VR_HENTRIES_PER_BUCKET -1) / VR_HENTRIES_PER_BUCKET)
               * VR_HENTRIES_PER_BUCKET;

    table = vr_zalloc(sizeof(struct vr_htable), VR_HTABLE_OBJECT);
    if (!table) {
        vr_module_error(-ENOMEM, __FUNCTION__, __LINE__,
                                       sizeof(struct vr_htable));
        goto exit;
    }

    table->htable = vr_btable_alloc(entries, entry_size);
    if (!table->htable) {
        vr_module_error(-ENOMEM, __FUNCTION__, __LINE__, entries);
        goto exit;
    }


    if (oentries) {
        table->otable = vr_btable_alloc(oentries, entry_size);
        if (!table->otable) {
            vr_module_error(-ENOMEM, __FUNCTION__, __LINE__, oentries);
            goto exit;
        }

        table->free_oentries = vr_bitmap_create(oentries);
        if (!table->free_oentries) {
            vr_module_error(-ENOMEM, __FUNCTION__, __LINE__, oentries);
            goto exit;
        }
    }

    table->hentries = entries;
    table->oentries = oentries;
    table->entry_size = entry_size;
    /* Key is assumed to be at the start of the entry of size key_size */
    table->key_size = key_size;
    table->is_valid_entry = is_valid_entry;
    table->get_key = get_entry_key;
    return (vr_htable_t)table;

exit:
    vr_htable_delete((vr_htable_t)table);
    return NULL;
}
