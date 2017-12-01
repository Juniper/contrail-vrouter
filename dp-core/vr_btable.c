/*
 * vr_btable.c -- Big tables. With (kernel)malloc, there is a limitation of
 * how much contiguous memory we will get (4M). So, for allocations more than
 * 4M, we need a way to manage the requests, and that's where big tables come
 * in. Basically, a two level table.
 *
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#include <vr_os.h>
#include <vrouter.h>
#include "vr_btable.h"

/*
 * The aim of btable is to workaround kernel's limitation of 4M allocation
 * size by allocating multiple chunks of 4M for a huge allocation.
 *
 * In the linux world, while vmalloc can provide a huge chunk of memory,
 * kmalloc is preferred to vmalloc for the following reasons
 *
 * - lesser TLB misses
 * - vmalloc is restricted in 32 bit systems
 * - potential pagefaults
 *
 * Also, in 2.6, there are problems with mmap-ing k(mz)alloced memory (for
 * flow table). So, a page based allocation is what btable will follow.
 *
 * The basic oprations supported are alloc, free, and get. get is defined in
 * the header file as an inline function for performance reasons.
 */

/*
 * the discontiguous chunks of memory are seen as partitions, and hence the
 * nomenclature
 */
struct vr_btable_partition *
vr_btable_get_partition(struct vr_btable *table, unsigned int partition)
{
    if (partition >= table->vb_partitions)
        return NULL;

    return &table->vb_table_info[partition];
}

/*
 * given an offset into the total memory managed by the btable (i.e memory
 * across all partitions), return the corresponding virtual address
 */
void *
vr_btable_get_address(struct vr_btable *table, unsigned int offset)
{
    unsigned int i;
    struct vr_btable_partition *partition;

    for (i = 0; i < table->vb_partitions; i++) {
        partition = vr_btable_get_partition(table, i);
        if (!partition)
            break;

        if (offset >= partition->vb_offset &&
                offset < partition->vb_offset + partition->vb_mem_size)
            return (char *)table->vb_mem[i] + (offset - partition->vb_offset);
    }

    return NULL;
}

void
vr_btable_free(struct vr_btable *table)
{
    unsigned int i;

    if (!table)
        return;

    if (!(table->vb_flags & VB_FLAG_MEMORY_ATTACHED) &&
            (table->vb_mem)) {
        for (i = 0; i < table->vb_partitions; i++) {
            if (table->vb_mem[i]) {
#ifdef _WIN32
                vr_free(table->vb_mem[i], VR_BTABLE_OBJECT);
#else
                vr_page_free(table->vb_mem[i],
                        table->vb_table_info[i].vb_mem_size);
#endif
            }
        }
    }

    vr_free(table, VR_BTABLE_OBJECT);

    return;
}

struct vr_btable *
vr_btable_alloc(unsigned int num_entries, unsigned int entry_size)
{
    unsigned int i = 0, num_parts, remainder;
    unsigned int total_parts, alloc_size;
    uint64_t total_mem;
    struct vr_btable *table;
    unsigned int offset = 0;

    total_mem = num_entries * entry_size;

    num_parts = total_mem / VR_SINGLE_ALLOC_LIMIT;
    remainder = total_mem % VR_SINGLE_ALLOC_LIMIT;

    total_parts = num_parts;
    /*
     * anything left over that is not a multiple of VR_SINGLE_ALLOC_LIMIT
     * gets accomodated in the remainder, and hence an extra partition has
     * to be given
     */
    if (remainder)
        total_parts++;

    if (num_parts) {
        /*
         * the entry size has to be a factor of VR_SINGLE_ALLOC limit.
         * otherwise, we might access memory beyond the allocated chunk
         * while accessing the last entry
         */
        if (VR_SINGLE_ALLOC_LIMIT % entry_size)
            return NULL;
    }

    if (!total_parts)
        return NULL;

    alloc_size = sizeof(*table) + (total_parts * (sizeof(void *))) +
        (total_parts * sizeof(struct vr_btable_partition));

    table = vr_zalloc(alloc_size, VR_BTABLE_OBJECT);
    if (!table)
        return NULL;

    table->vb_alloc_limit = VR_SINGLE_ALLOC_LIMIT;
    table->vb_mem = (void **)(table + 1);
    table->vb_table_info =
        (struct vr_btable_partition *)((unsigned char *)table->vb_mem +
                (total_parts * sizeof(void *)));

    if (num_parts) {
        for (i = 0; i < num_parts; i++) {
#ifdef _WIN32
            table->vb_mem[i] = vr_zalloc(VR_SINGLE_ALLOC_LIMIT, VR_BTABLE_OBJECT);
#else
            table->vb_mem[i] = vr_page_alloc(VR_SINGLE_ALLOC_LIMIT);
#endif
            if (!table->vb_mem[i])
                goto exit_alloc;
            table->vb_table_info[i].vb_mem_size = VR_SINGLE_ALLOC_LIMIT;
            table->vb_table_info[i].vb_offset = offset;
            offset += table->vb_table_info[i].vb_mem_size;
            table->vb_partitions++;
        }
    }

    if (remainder) {
#ifdef _WIN32
        table->vb_mem[i] = vr_zalloc(remainder, VR_BTABLE_OBJECT);
#else
        table->vb_mem[i] = vr_page_alloc(remainder);
#endif
        if (!table->vb_mem[i])
            goto exit_alloc;
        table->vb_table_info[i].vb_mem_size = remainder;
        table->vb_table_info[i].vb_offset = offset;
        table->vb_partitions++;
    }

    table->vb_entries = num_entries;
    table->vb_esize = entry_size;

    return table;

exit_alloc:
    vr_btable_free(table);
    return NULL;
}

struct vr_btable *
vr_btable_attach(struct iovec *iov, unsigned int iov_len,
        unsigned short esize)
{
    unsigned int i, alloc_size;
    unsigned int offset = 0, total_size = 0;
    struct vr_btable *table;

    if (!iov || !iov_len)
        return NULL;

    if (iov[0].iov_len % esize)
        return NULL;

    alloc_size = sizeof(struct vr_btable);
    alloc_size += (sizeof(void *) * iov_len);
    alloc_size += (sizeof(struct vr_btable_partition) * iov_len);


    table = (struct vr_btable *)vr_zalloc(alloc_size, VR_BTABLE_OBJECT);
    if (!table)
        return NULL;

    table->vb_esize = esize;
    table->vb_partitions = iov_len;
    table->vb_alloc_limit = iov->iov_len;
    table->vb_mem = (void **)(table + 1);
    table->vb_table_info =
        (struct vr_btable_partition *)((unsigned char *)table->vb_mem +
                (iov_len * sizeof(void *)));

    for (i = 0; i < iov_len; i++) {
        table->vb_mem[i] = iov[i].iov_base;
        if ((iov[i].iov_len != table->vb_alloc_limit) &&
                (i != (iov_len - 1)))
            goto error;

        table->vb_table_info[i].vb_mem_size = iov[i].iov_len;
        table->vb_table_info[i].vb_offset = offset;

        offset += iov[i].iov_len;
        total_size += iov[i].iov_len;
    }

    if (total_size % esize)
        goto error;

    table->vb_entries = (total_size / esize);
    table->vb_flags |= VB_FLAG_MEMORY_ATTACHED;

    return table;

error:
    vr_btable_free(table);
    return NULL;
}

