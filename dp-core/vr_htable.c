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
    unsigned int ht_hentries;
    unsigned int ht_oentries;
    unsigned int ht_entry_size;
    unsigned int ht_key_size;
    unsigned int ht_bucket_size;
    struct vr_btable *ht_htable;
    struct vr_btable *ht_otable;
    get_hentry_key ht_get_key;
    vr_bmap_t ht_free_oentries;
};

struct vr_hentry_delete_data {
    vr_htable_t hd_htable;
    unsigned int hd_index;
    unsigned int hd_shcedule_count;
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

    if (marker < table->ht_hentries) {
        for (i = marker; i < table->ht_hentries; i++) {
            ent = vr_btable_get(table->ht_htable, i);
            if(ent && (ent->hentry_index != VR_INVALID_HENTRY_INDEX))
                cb(htable, ent, i, data);
        }
    }


    marker -= table->ht_hentries;
    if (marker < table->ht_oentries) {
        for (i = marker; i < table->ht_oentries; i++) {
            ent = vr_btable_get(table->ht_htable, i);
            if(ent && (ent->hentry_index != VR_INVALID_HENTRY_INDEX))
                cb(htable, ent, (i + table->ht_hentries), data);
        }
    }

    return;
}

vr_hentry_t *
vr_get_hentry_by_index(vr_htable_t htable, unsigned int index)
{
    struct vr_htable *table = (struct vr_htable *)htable;

    if (!table)
        return NULL;

    if (index < table->ht_hentries)
        return vr_btable_get(table->ht_htable, index);

    if (index < (table->ht_oentries + table->ht_hentries))
        return vr_btable_get(table->ht_otable, (index - table->ht_hentries));

    return NULL;
}


static int
__vr_release_hentry(vr_htable_t htable, vr_hentry_t *entry)
{
    unsigned int index = entry->hentry_index;
    vr_hentry_t *prev, *head_ent;
    struct vr_htable *table = (struct vr_htable *)htable;

    if (index == VR_INVALID_HENTRY_INDEX)
        return 0;

    entry->hentry_index = VR_INVALID_HENTRY_INDEX;

    if (index >= table->ht_hentries) {

        head_ent = vr_get_hentry_by_index(htable, entry->hentry_bucket_index);

        prev = head_ent;
        while(prev) {
           if (prev->hentry_next == entry)
              break;
           prev = prev->hentry_next;
        }

        /*
         * Remove ourselves from list, if previous entry is not under
         * deletion
         */
        if (((prev == head_ent) ||
                        (prev->hentry_index != VR_INVALID_HENTRY_INDEX))) {
            if (__sync_bool_compare_and_swap(&prev->hentry_next, entry,
                                                    entry->hentry_next)) {
                entry->hentry_next = NULL;
                entry->hentry_next_index = VR_INVALID_HENTRY_INDEX;
                entry->hentry_bucket_index = VR_INVALID_HENTRY_INDEX;

                if (prev->hentry_next)
                    prev->hentry_next_index = prev->hentry_next->hentry_index;
                else
                    prev->hentry_next_index = VR_INVALID_HENTRY_INDEX;

                vr_bitmap_clear_bit(table->ht_free_oentries, index - table->ht_hentries);
                return 0;
            }
        }

        entry->hentry_index = index;
        return -1;
    }

    return 0;
}

static void
vr_hentry_defer_delete(void *arg)
{
    struct vr_hentry_delete_data *delete_data;
    vr_hentry_t *entry;

    delete_data = (struct vr_hentry_delete_data *)arg;
    delete_data->hd_shcedule_count++;

    entry = vr_get_hentry_by_index(delete_data->hd_htable,
                                        delete_data->hd_index);

    if (entry && __vr_release_hentry(delete_data->hd_htable, entry)) {
        delete_data->hd_shcedule_count++;
        vr_schedule_work(vr_get_cpu(), vr_hentry_defer_delete, arg);
        return;
    }

    vr_printf("Hentry %d deleted after %d attempts\n",
            delete_data->hd_index, delete_data->hd_shcedule_count);
    vr_free(arg);

    return;
}

void
vr_release_hentry(vr_htable_t htable, vr_hentry_t *entry)
{
    unsigned int index = entry->hentry_index;
    struct vr_hentry_delete_data *delete_data;

retry:
    if (__vr_release_hentry(htable, entry)) {

        /*
         * We did not succeed in deleting either because previous entry
         * is also in the process of deletion or something is
         * getting inserted after previous. In both the cases, defer
         * this deletion. As bit map is not cleared, this entry is
         * always seen as a used entry, till it is really deleted. Get
         * back the index to entry, so that nodes after this see this as
         * valid entry and continue with their deltion
         */
        delete_data = (struct vr_hentry_delete_data *)
                                vr_zalloc(sizeof(*delete_data));
        if (!delete_data) {
            /* Just retry? Attempt to yield cpu before retry? */
            goto retry;
        }

        delete_data->hd_htable = htable;
        delete_data->hd_index = index;
        vr_schedule_work(vr_get_cpu(), vr_hentry_defer_delete,
                                                (void *)delete_data);
    }

    return;
}

vr_hentry_t *
vr_find_free_hentry(vr_htable_t htable, void *key, unsigned int key_size)
{
    unsigned int hash, tmp_hash, i;
    struct vr_htable *table = (struct vr_htable *)htable;
    vr_hentry_t *ent, *o_ent;
    int ind, bucket_index;

    if (!table || !key)
        return NULL;

    if (!key_size) {
        key_size = table->ht_key_size;
        if (!key_size)
            return NULL;
    }

    hash = vr_hash(key, key_size, 0);
    tmp_hash = hash % table->ht_hentries;
    tmp_hash &= ~(table->ht_bucket_size - 1);

    ind = 0;
    ent = NULL;
    for(i = 0; i < table->ht_bucket_size; i++) {
        ind = tmp_hash + i;
        ent = vr_btable_get(table->ht_htable, ind);
        if (ent->hentry_index == VR_INVALID_HENTRY_INDEX) {
            if (__sync_bool_compare_and_swap(&ent->hentry_index,
                        VR_INVALID_HENTRY_INDEX, ind)) {
                return ent;
            }
        }
    }

    bucket_index = ind;

    if (table->ht_oentries) {
        ind = vr_bitmap_set_first_free_bit(table->ht_free_oentries);
        if (ind == -1)
            return NULL;

        o_ent = vr_btable_get(table->ht_otable, ind);
        o_ent->hentry_bucket_index = bucket_index;
        o_ent->hentry_index = ind + table->ht_hentries;
        o_ent->hentry_next_index = VR_INVALID_HENTRY_INDEX;

        /* Link the overflow entry at the start */
        while(1) {

            o_ent->hentry_next = ent->hentry_next;

            /* Update the next entry's index in o_ent */
            if (o_ent->hentry_next)
                o_ent->hentry_next_index = o_ent->hentry_next->hentry_index;

            if (__sync_bool_compare_and_swap(&ent->hentry_next,
                                                o_ent->hentry_next, o_ent)) {

                /*
                 * ent->hentry_next need not be o_ent for the below
                 * statement, if some new entry is inserted after 'ent'.
                 * So updating hentry_next_index by taking hentry_next
                 * pointer should still do the right thing
                 */
                ent->hentry_next_index = ent->hentry_next->hentry_index;
                return o_ent;
            }
        }
    }

    return NULL;
}

int
vr_find_duplicate_hentry_index(vr_htable_t htable, vr_hentry_t *hentry)
{
    unsigned int hash, tmp_hash, ind, i, key_len, ent_key_len;
    vr_hentry_t *ent;
    vr_hentry_key hkey;
    struct vr_htable *table = (struct vr_htable *)htable;

    if (!table || !hentry)
        return -1;

    hkey = table->ht_get_key(htable, hentry, &key_len);
    if (!key_len) {
        key_len = table->ht_key_size;
        if (!key_len)
            return -1;
    }

    hash = vr_hash(hentry, key_len, 0);

    /* Look into the hash table from hash */
    tmp_hash = hash % table->ht_hentries;
    tmp_hash &= ~(table->ht_bucket_size - 1);
    for(i = 0; i < table->ht_bucket_size; i++) {
        ind = tmp_hash + i;
        ent = vr_btable_get(table->ht_htable, ind);

        if (ent->hentry_index == VR_INVALID_HENTRY_INDEX)
            continue;

        if (ent == hentry)
            continue;

        hkey = table->ht_get_key(htable, ent, &ent_key_len);
        if (!hkey || (ent_key_len != key_len))
            continue;

        if (memcmp(hkey, hentry, key_len) != 0)
            continue;
        return ind;
    }

    /* Look into the complete over flow table starting from hash*/
    tmp_hash = hash % table->ht_oentries;
    for(i = 0; i < table->ht_oentries; i++) {
        ind = table->ht_hentries + ((tmp_hash + i) % table->ht_oentries);
        ent = vr_btable_get(table->ht_otable, ((tmp_hash + i) % table->ht_oentries));

        if (ent->hentry_index == VR_INVALID_HENTRY_INDEX)
            continue;

        if (ent == hentry)
            continue;

        hkey = table->ht_get_key(htable, ent, &ent_key_len);
        if (!hkey || (ent_key_len != key_len))
            continue;

        if (memcmp(hkey, hentry, table->ht_key_size) != 0)
            continue;

        return ind;
    }

    /* No duplicate entry is found */
    return -1;
}

vr_hentry_t *
vr_find_hentry(vr_htable_t htable, void *key, unsigned int key_len)
{
    unsigned int hash, tmp_hash, ind, i, ent_key_len;
    vr_hentry_t *ent, *o_ent;
    vr_hentry_key ent_key;
    struct vr_htable *table = (struct vr_htable *)htable;

    if (!table || !key)
        return NULL;

    if (!key_len) {
        key_len = table->ht_key_size;
        if (!key_len)
            return NULL;
    }

    ent = NULL;

    hash = vr_hash(key, key_len, 0);

    /* Look into the hash table from hash*/
    tmp_hash = hash % table->ht_hentries;
    tmp_hash &= ~(table->ht_bucket_size - 1);
    for (i = 0; i < table->ht_bucket_size; i++) {
        ind = tmp_hash + i;
        ent = vr_btable_get(table->ht_htable, ind);
        if (ent->hentry_index == VR_INVALID_HENTRY_INDEX)
            continue;

        ent_key = table->ht_get_key(htable, ent, &ent_key_len);
        if (!ent_key || (key_len != ent_key_len))
            continue;

        if (memcmp(ent_key, key, key_len) == 0)
            return ent;
    }

    for(o_ent = ent->hentry_next; o_ent; o_ent = o_ent->hentry_next) {

        ent_key = table->ht_get_key(htable, o_ent, &ent_key_len);
        if (!ent_key || (key_len != ent_key_len))
            continue;

        if (memcmp(ent_key, key, key_len) == 0)
            return o_ent;
    }

    /* Entry not found */
    return NULL;
}

unsigned int
vr_htable_size(vr_htable_t htable)
{
    struct vr_htable *table = (struct vr_htable *)htable;
    unsigned int size = 0;

    if (table) {
        if (table->ht_htable)
            size = vr_btable_size(table->ht_htable);
        if (table->ht_otable)
            size += vr_btable_size(table->ht_otable);
    }

    return size;
}

void *
vr_htable_get_address(vr_htable_t htable, uint64_t offset)
{
    struct vr_htable *table = (struct vr_htable *)htable;
    unsigned int size = vr_btable_size(table->ht_htable);
    struct vr_btable *btable;

    btable = table->ht_htable;
    if (offset >= size) {
        offset -= size;
        btable = table->ht_otable;
    }

    return vr_btable_get_address(btable, offset);
}

void
vr_htable_delete(vr_htable_t htable)
{
    struct vr_htable *table = (struct vr_htable *)htable;

    if (!table)
        return;

    if (table->ht_htable)
        vr_btable_free(table->ht_htable);

    if (table->ht_otable)
        vr_btable_free(table->ht_otable);

    if (table->ht_free_oentries)
        vr_bitmap_delete(table->ht_free_oentries);

    vr_free(table);

    return;
}

vr_htable_t
vr_htable_create(unsigned int entries, unsigned int oentries,
        unsigned int entry_size, unsigned int key_size,
        unsigned int bucket_size, get_hentry_key get_entry_key)
{
    int i;
    struct vr_htable *table;
    vr_hentry_t *ent;

    if (!entry_size || !entries || !get_entry_key)
        return NULL;

    if (!bucket_size)
        bucket_size = VR_HENTRIES_PER_BUCKET;

    if (entries % bucket_size) {
        vr_module_error(-EINVAL, __FUNCTION__, __LINE__, entries);
        return NULL;
    }

    table = vr_zalloc(sizeof(struct vr_htable));
    if (!table) {
        vr_module_error(-ENOMEM, __FUNCTION__, __LINE__,
                                       sizeof(struct vr_htable));
        goto exit;
    }

    table->ht_htable = vr_btable_alloc(entries, entry_size);
    if (!table->ht_htable) {
        vr_module_error(-ENOMEM, __FUNCTION__, __LINE__, entries);
        goto exit;
    }


    if (oentries) {
        table->ht_otable = vr_btable_alloc(oentries, entry_size);
        if (!table->ht_otable) {
            vr_module_error(-ENOMEM, __FUNCTION__, __LINE__, oentries);
            goto exit;
        }

        table->ht_free_oentries = vr_bitmap_create(oentries);
        if (!table->ht_free_oentries) {
            vr_module_error(-ENOMEM, __FUNCTION__, __LINE__, oentries);
            goto exit;
        }
    }

    for(i = 0; i < entries; i++) {
        ent = vr_btable_get(table->ht_htable, i);
        ent->hentry_index = VR_INVALID_HENTRY_INDEX;
        ent->hentry_next_index = VR_INVALID_HENTRY_INDEX;
        ent->hentry_bucket_index = VR_INVALID_HENTRY_INDEX;
    }

    for(i = 0; i < oentries; i++) {
        ent = vr_btable_get(table->ht_otable, i);
        ent->hentry_index = VR_INVALID_HENTRY_INDEX;
        ent->hentry_next_index = VR_INVALID_HENTRY_INDEX;
        ent->hentry_bucket_index = VR_INVALID_HENTRY_INDEX;
    }

    table->ht_hentries = entries;
    table->ht_oentries = oentries;
    table->ht_entry_size = entry_size;
    table->ht_key_size = key_size;
    table->ht_get_key = get_entry_key;
    table->ht_bucket_size = bucket_size;

    return (vr_htable_t)table;

exit:
    vr_htable_delete((vr_htable_t)table);

    return NULL;
}
