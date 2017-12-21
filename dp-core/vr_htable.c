/*
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#include <vr_os.h>
#include <vrouter.h>
#include <vr_htable.h>
#include <vr_btable.h>
#include <vr_hash.h>
#include <vrouter.h>

#define VR_HENTRIES_PER_BUCKET 4

#define VR_HENTRY_FLAG_VALID             0x1
#define VR_HENTRY_FLAG_DELETE_MARKED     0x2
#define VR_HENTRY_FLAG_DELETE_PROCESSED  0x4
#define VR_HENTRY_FLAG_UNDER_DELETION    (VR_HENTRY_FLAG_DELETE_MARKED | \
                                            VR_HENTRY_FLAG_DELETE_PROCESSED)
#define VR_HENTRY_FLAG_IN_FREE_LIST      0x8


struct vr_htable {
    struct vrouter *ht_router;
    unsigned int ht_hentries;
    unsigned int ht_oentries;
    unsigned int ht_entry_size;
    unsigned int ht_key_size;
    unsigned int ht_bucket_size;
    struct vr_btable *ht_htable;
    struct vr_btable *ht_otable;
    struct vr_btable *ht_dtable;
    get_hentry_key ht_get_key;
    vr_hentry_t *ht_free_oentry_head;
    unsigned int ht_used_oentries;
    unsigned int ht_used_entries;
};

struct vr_hentry_delete_data {
    struct vr_htable *hd_table;
    unsigned int hd_index;
    unsigned short hd_count;
    unsigned short hd_scheduled;
};

int
vr_htable_trav_range(vr_htable_t htable, unsigned int start,
        unsigned int range, htable_trav_cb cb, void *data)
{
    unsigned int i, hindex;
    vr_hentry_t *ent;
    struct vr_htable *table = (struct vr_htable *)htable;

    if (!table || !cb)
        return -EINVAL;

    for (i = start; i < start + range; i++) {
        hindex = i % (table->ht_oentries + table->ht_hentries);
        ent = vr_htable_get_hentry_by_index(htable, hindex);
        cb(htable, ent, hindex, data);
    }

    return i;
}

void
vr_htable_trav(vr_htable_t htable, unsigned int marker,
        htable_trav_cb cb, void *data)
{
    unsigned int range;
    struct vr_htable *table = (struct vr_htable *)htable;

    range = (table->ht_hentries + table->ht_oentries - marker);
    vr_htable_trav_range(htable, marker, range, cb, data);

    return;
}

static vr_hentry_t *
vr_htable_get_free_oentry(struct vr_htable *table)
{
    vr_hentry_t *ent;

    if (!table)
        return NULL;

    do {

        /*
         * Get the head of the free list. And move the head to next free
         * entry. This can become NULL while the loop is in progress
         */
        ent = table->ht_free_oentry_head;
        if (!ent)
            return NULL;

        if (vr_sync_bool_compare_and_swap_p(&table->ht_free_oentry_head,
                    ent, ent->hentry_next)) {
            ent->hentry_next = NULL;
            (void)vr_sync_add_and_fetch_32u(&table->ht_used_oentries, 1);
            ent->hentry_flags &= ~VR_HENTRY_FLAG_IN_FREE_LIST;
            return ent;
        }

    } while (1);

    return NULL;
}

static void
vr_htable_put_free_oentry(struct vr_htable *table, vr_hentry_t *ent)
{

    vr_hentry_t *tmp;

    if (!table || !ent || ent->hentry_index < table->ht_hentries)
        return;

    if (ent->hentry_flags & VR_HENTRY_FLAG_IN_FREE_LIST)
        return;

    ent->hentry_flags |= VR_HENTRY_FLAG_IN_FREE_LIST;

    tmp = NULL;
    do {

        /*
         * Insert this new entry as head.
         */
        tmp = table->ht_free_oentry_head;
        ent->hentry_next = tmp;

        if (vr_sync_bool_compare_and_swap_p(&table->ht_free_oentry_head,
                                                            tmp, ent)) {
            (void)vr_sync_sub_and_fetch_32u(&table->ht_used_oentries, 1);
            return;
        }

    } while (1);

    return;
}


/*
 * Returns the hash entry given an index. Does not validate whether the
 * entry is Valid or not
 */
vr_hentry_t *
__vr_htable_get_hentry_by_index(vr_htable_t htable, unsigned int index)
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

/*
 * Returns the hash entry, given an index, only if Valid
 */
vr_hentry_t *
vr_htable_get_hentry_by_index(vr_htable_t htable, unsigned int index)
{
    vr_hentry_t *ent;

    ent = __vr_htable_get_hentry_by_index(htable, index);
    if (ent && (ent->hentry_flags & VR_HENTRY_FLAG_VALID))
        return ent;

    return NULL;
}

static void
vr_htable_oentry_invalidate(struct vr_htable *table, vr_hentry_t *ent)
{
    if (!table || !ent || (ent->hentry_index < table->ht_hentries))
        return;

    /* Clear all the flags except free list */
    ent->hentry_flags &= VR_HENTRY_FLAG_IN_FREE_LIST;
    ent->hentry_bucket_index = VR_INVALID_HENTRY_INDEX;
    ent->hentry_next_index = VR_INVALID_HENTRY_INDEX;
    ent->hentry_next = NULL;

    vr_htable_put_free_oentry(table, ent);
}

static void
vr_htable_hentry_defer_delete(struct vrouter *router, void *arg)
{
    vr_hentry_t *ent;
    struct vr_hentry_delete_data *defer_data;
    struct vr_htable *table;

    defer_data = (struct vr_hentry_delete_data *)arg;
    table = (struct vr_htable *)(defer_data->hd_table);

    ent = __vr_htable_get_hentry_by_index((vr_htable_t)table,
                                        defer_data->hd_index);
    vr_htable_oentry_invalidate(table, ent);

    return;
}

void
vr_htable_hentry_scheduled_delete(void *arg)
{
    unsigned int count;
    struct vr_hentry_delete_data *delete_data, *defer_data;
    vr_hentry_t *head_ent, *ent, *prev, *next;
    struct vr_htable *table;


    delete_data = (struct vr_hentry_delete_data *)arg;
    table = delete_data->hd_table;

    head_ent = __vr_htable_get_hentry_by_index((vr_htable_t)(table),
                                                delete_data->hd_index);

    if (!head_ent)
        return;

    (void)vr_sync_bool_compare_and_swap_16u(&delete_data->hd_scheduled, 1, 0);

    /*
     * We attempt to delete only those many entries that have been
     * delete marked. If some new entries are delete marked while
     * processing these, they will get scheduled in new work item
     */
    count = delete_data->hd_count;
    (void)vr_sync_sub_and_fetch_16u(&delete_data->hd_count, count);

    prev = head_ent;
    ent = head_ent->hentry_next;

    while (count && ent) {

        /*
         * Process only if delete marked. If already processed,
         * delete marking is changed to delete processed
         */
        if (ent->hentry_flags & VR_HENTRY_FLAG_DELETE_MARKED) {

            /*
             * As the insertion happens only at head entry, it has
             * to be verified if something is inserted while delete
             * attemped. If inserted, traversal needs to restart, to
             * get hold of the new previous
             */
            if (prev == head_ent) {
                if (!vr_sync_bool_compare_and_swap_p(&prev->hentry_next,
                                                      ent, ent->hentry_next)) {
                    prev = head_ent;
                    ent = head_ent->hentry_next;
                    continue;
                }
            } else {
                prev->hentry_next = ent->hentry_next;
            }

            count--;

            /* update next index for the previous */
            if (ent->hentry_next)
                prev->hentry_next_index = ent->hentry_next->hentry_index;
            else
                prev->hentry_next_index = VR_INVALID_HENTRY_INDEX;

            ent->hentry_flags &= ~VR_HENTRY_FLAG_DELETE_MARKED;
            ent->hentry_flags |= VR_HENTRY_FLAG_DELETE_PROCESSED;
        }

        next = ent->hentry_next;

        /*
         * A separate check for VR_HENTRY_FLAG_DELETE_PROCESSED flag to
         * defer the entry if we ever failed to allocate memeory while
         * deferring it
         */
        if (ent->hentry_flags & VR_HENTRY_FLAG_DELETE_PROCESSED) {

            /*
             * Defer the entry to reset the values. If alloc of
             * defer data fails, this entry will be in delete state
             * for ever
             */
            if (!vr_not_ready) {
                defer_data = vr_get_defer_data(sizeof(*defer_data));
                if (defer_data) {
                    defer_data->hd_table = delete_data->hd_table;
                    defer_data->hd_index = ent->hentry_index;
                    vr_defer(delete_data->hd_table->ht_router,
                         vr_htable_hentry_defer_delete, (void *)defer_data);
                }
            } else {
                vr_htable_oentry_invalidate(table, ent);
                ent = next;
                continue;
            }
        }

        /* Previous should not be under deletion */
        if (!(ent->hentry_flags & VR_HENTRY_FLAG_UNDER_DELETION))
            prev = ent;

        ent = next;
    }

    return;
}

void
vr_htable_reset(vr_htable_t htable, htable_trav_cb cb, void *data)
{
    unsigned int i;
    vr_hentry_t *ent, *next;
    struct vr_htable *table = (struct vr_htable *)htable;

    if (!table || !cb)
        return;

    for (i = 0; i < table->ht_hentries + table->ht_oentries; i++) {
        ent = __vr_htable_get_hentry_by_index(htable, i);

        cb(htable, ent, i, data);

        if (ent->hentry_flags & VR_HENTRY_FLAG_VALID) {
            ent->hentry_flags &= ~VR_HENTRY_FLAG_VALID;
            (void)vr_sync_sub_and_fetch_32u(&table->ht_used_entries, 1);
        }


        if ((i < table->ht_hentries) && ent->hentry_next) {
            next = ent->hentry_next;
            ent->hentry_next = NULL;
            ent->hentry_next_index = VR_INVALID_HENTRY_INDEX;
            ent = next;

            while (ent) {
                next = ent->hentry_next;

                if (ent->hentry_flags & VR_HENTRY_FLAG_VALID) {
                    ent->hentry_flags &= ~VR_HENTRY_FLAG_VALID;
                    (void)vr_sync_sub_and_fetch_32u(&table->ht_used_entries, 1);
                }

                vr_htable_oentry_invalidate(table, ent);

                ent = next;
            }
        }
    }

    return;
}


void
vr_htable_release_hentry(vr_htable_t htable, vr_hentry_t *ent)
{
    unsigned int cpu_num, delete_index;
    struct vr_hentry_delete_data *delete_data;
    vr_hentry_t *head_ent;
    struct vr_htable *table = (struct vr_htable *)htable;

    if (!(ent->hentry_flags & VR_HENTRY_FLAG_VALID))
        return;

    (void)vr_sync_sub_and_fetch_32u(&table->ht_used_entries, 1);

    /* Mark it as Invalid */
    ent->hentry_flags &= ~VR_HENTRY_FLAG_VALID;

    if (ent->hentry_index < table->ht_hentries)
        return;

    if (vr_not_ready)
        return;

    ent->hentry_flags |= VR_HENTRY_FLAG_DELETE_MARKED;

    head_ent = __vr_htable_get_hentry_by_index(htable, ent->hentry_bucket_index);
    delete_index = head_ent->hentry_index / table->ht_bucket_size;
    delete_data = vr_btable_get(table->ht_dtable, delete_index);

    (void)vr_sync_add_and_fetch_16u(&delete_data->hd_count, 1);

    /* Schedule the deltion only if it is not already scheduled */
    if (vr_sync_bool_compare_and_swap_16u(&delete_data->hd_scheduled, 0, 1)) {

        delete_data->hd_table = (struct vr_htable *)htable;
        delete_data->hd_index = head_ent->hentry_index;

        /* Schedule the deletion on a cpu based on bucket index */
        cpu_num = head_ent->hentry_index % vr_num_cpus;
        if (vr_schedule_work(cpu_num, vr_htable_hentry_scheduled_delete,
                                                (void *)delete_data)) {
            /*
             * We can only write back the status as not scheduled. There
             * might be some entries that get marked as Deleted, but
             * would not be pushed to free list as work queue is not
             * scheduled. These marked entries would be deleted only if
             * this hash bucket is revisisted
             */
            (void)vr_sync_bool_compare_and_swap_16u(&delete_data->hd_scheduled,1, 0);
        }
    }

    return;
}

vr_hentry_t *
vr_htable_find_free_hentry(vr_htable_t htable, void *key, unsigned int key_size)
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
    for (i = 0; i < table->ht_bucket_size; i++) {
        ind = tmp_hash + i;
        ent = vr_btable_get(table->ht_htable, ind);
        if (!(ent->hentry_flags & VR_HENTRY_FLAG_VALID)) {
            if (vr_sync_bool_compare_and_swap_8u(&ent->hentry_flags,
                        (ent->hentry_flags & ~VR_HENTRY_FLAG_VALID),
                        VR_HENTRY_FLAG_VALID)) {
                ent->hentry_bucket_index = VR_INVALID_HENTRY_INDEX;
                (void)vr_sync_add_and_fetch_32u(&table->ht_used_entries, 1);
                return ent;
            }
        }
    }

    bucket_index = ind;

    if (table->ht_oentries) {

        o_ent = vr_htable_get_free_oentry(table);
        if (!o_ent) {
            return NULL;
        }

        o_ent->hentry_bucket_index = bucket_index;
        o_ent->hentry_next_index = VR_INVALID_HENTRY_INDEX;
        o_ent->hentry_flags = VR_HENTRY_FLAG_VALID;

        /* Link the overflow entry at the start */
        do {
            o_ent->hentry_next = ent->hentry_next;

            /* Update the next entry's index in o_ent */
            if (o_ent->hentry_next)
                o_ent->hentry_next_index = o_ent->hentry_next->hentry_index;

            if (vr_sync_bool_compare_and_swap_p(&ent->hentry_next,
                                                o_ent->hentry_next, o_ent)) {

                /*
                 * ent->hentry_next need not be o_ent for the below
                 * statement, if some new entry is inserted after 'ent'.
                 * So updating hentry_next_index by taking hentry_next
                 * pointer should still do the right thing
                 */
                ent->hentry_next_index = ent->hentry_next->hentry_index;
                (void)vr_sync_add_and_fetch_32u(&table->ht_used_entries, 1);
                return o_ent;
            }
        } while (1);
    }

    return NULL;
}

int
vr_htable_find_duplicate_hentry_index(vr_htable_t htable, vr_hentry_t *hentry)
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

    hash = vr_hash(hkey, key_len, 0);

    /* Look into the hash table from hash */
    tmp_hash = hash % table->ht_hentries;
    tmp_hash &= ~(table->ht_bucket_size - 1);
    for (i = 0; i < table->ht_bucket_size; i++) {
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
    for (i = 0; i < table->ht_oentries; i++) {
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
vr_htable_find_hentry(vr_htable_t htable, void *key, unsigned int key_len)
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
        if (!(ent->hentry_flags & VR_HENTRY_FLAG_VALID))
            continue;

        ent_key = table->ht_get_key(htable, ent, &ent_key_len);
        if (!ent_key || (key_len != ent_key_len))
            continue;

        if (memcmp(ent_key, key, key_len) == 0)
            return ent;
    }

    for (o_ent = ent->hentry_next; o_ent; o_ent = o_ent->hentry_next) {

        /* Though in the list, can be under the deletion */
        if (!(o_ent->hentry_flags & VR_HENTRY_FLAG_VALID))
            continue;

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
vr_htable_used_oflow_entries(vr_htable_t htable)
{
    struct vr_htable *table = (struct vr_htable *)htable;

    if (table)
        return table->ht_used_oentries;

    return 0;
}

unsigned int
vr_htable_used_total_entries(vr_htable_t htable)
{
    struct vr_htable *table = (struct vr_htable *)htable;

    if (table)
        return table->ht_used_entries;

    return 0;
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

vr_htable_t
__vr_htable_create(struct vrouter *router, unsigned int entries,
        void *htable, unsigned int oentries, void *otable,
        unsigned int entry_size, unsigned int key_size,
        unsigned int bucket_size, get_hentry_key get_entry_key)
{
    int i;
    struct vr_htable *table;
    vr_hentry_t *ent, *prev;
    struct iovec iov;

    if (!entry_size || !entries || !get_entry_key)
        return NULL;

    if (!bucket_size)
        bucket_size = VR_HENTRIES_PER_BUCKET;

    /* Ceil to near upper number, which is dividable by bucket_size */
    entries = ((entries + bucket_size -1) / bucket_size) * bucket_size;

    table = vr_zalloc(sizeof(struct vr_htable), VR_HTABLE_OBJECT);
    if (!table) {
        vr_module_error(-ENOMEM, __FUNCTION__, __LINE__,
                                       sizeof(struct vr_htable));
        goto exit;
    }

    if (!htable) {
        table->ht_htable = vr_btable_alloc(entries, entry_size);
    } else {
        iov.iov_base = htable;
        iov.iov_len = entry_size * entries;
        table->ht_htable = vr_btable_attach(&iov, 1, entry_size);
    }

    if (!table->ht_htable) {
        vr_module_error(-ENOMEM, __FUNCTION__, __LINE__, entries);
        goto exit;
    }

    if (oentries) {

        if (!otable) {
            table->ht_otable = vr_btable_alloc(oentries, entry_size);
        } else {
            iov.iov_base = otable;
            iov.iov_len = entry_size * oentries;
            table->ht_otable = vr_btable_attach(&iov, 1, entry_size);
        }

        if (!table->ht_otable) {
            vr_module_error(-ENOMEM, __FUNCTION__, __LINE__, oentries);
            goto exit;
        }

        /*
         * If there is an over flow table, create the delete data for
         * main flow table
         */
        i = entries / bucket_size;
        table->ht_dtable = vr_btable_alloc(i,
                sizeof(struct vr_hentry_delete_data));
        if (!table->ht_dtable) {
            vr_module_error(-ENOMEM, __FUNCTION__, __LINE__, i);
            goto exit;
        }
    }

    for (i = 0; i < entries; i++) {
        ent = vr_btable_get(table->ht_htable, i);
        ent->hentry_index = i;
        ent->hentry_next_index = VR_INVALID_HENTRY_INDEX;
    }


    prev = NULL;
    for (i = 0; i < oentries; i++) {
        ent = vr_btable_get(table->ht_otable, i);
        ent->hentry_index = entries + i;
        ent->hentry_next_index = VR_INVALID_HENTRY_INDEX;
        if (i == 0)
            table->ht_free_oentry_head = ent;
        else
            prev->hentry_next = ent;

        ent->hentry_flags |= VR_HENTRY_FLAG_IN_FREE_LIST;
        prev = ent;
    }

    table->ht_hentries = entries;
    table->ht_oentries = oentries;
    table->ht_entry_size = entry_size;
    table->ht_key_size = key_size;
    table->ht_get_key = get_entry_key;
    table->ht_bucket_size = bucket_size;
    table->ht_router = router;
    table->ht_used_oentries = 0;

    return (vr_htable_t)table;

exit:
    vr_htable_delete((vr_htable_t)table);

    return NULL;
}

vr_htable_t
vr_htable_attach(struct vrouter *router, unsigned int entries,
        void *htable, unsigned int oentries, void *otable,
        unsigned int entry_size, unsigned int key_size,
        unsigned int bucket_size, get_hentry_key get_entry_key)
{
    if (!entries || (otable && !oentries)) {
        return NULL;
    }

    return __vr_htable_create(router, entries, htable, oentries, otable,
            entry_size, key_size, bucket_size, get_entry_key);
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

    if (table->ht_dtable)
        vr_btable_free(table->ht_dtable);

    vr_free(table, VR_HTABLE_OBJECT);

    return;
}

vr_htable_t
vr_htable_create(struct vrouter *router, unsigned int entries,
        unsigned int oentries, unsigned int entry_size, unsigned int key_size,
        unsigned int bucket_size, get_hentry_key get_entry_key)
{
    return __vr_htable_create(router, entries, NULL, oentries, NULL,
            entry_size, key_size, bucket_size, get_entry_key);
}
