/*
 * vr_btable.h -- 
 *
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#ifndef __VR_BTABLE_H__
#define __VR_BTABLE_H__

#ifdef __DPDK__

struct vr_btable {
	unsigned int vb_entries;
	unsigned short vb_esize;
	/* pointer to data to use shared memory */
	void *vb_data;
};

static inline void
vr_btable_free(struct vr_btable *table)
{
	if (table) {
		/* never free shared memory */
	    vr_free(table);
	}
}

static inline struct vr_btable *
vr_btable_init(struct vr_btable *table,
	unsigned int num_entries, unsigned int entry_size,
	void *data)
{
	if (table) {
		table->vb_entries = num_entries;
		table->vb_esize = entry_size;
		table->vb_data = data;
	}
	return table;
}

/*
 * Allocate memory for btable header and data.
 */
static inline struct vr_btable *
vr_btable_alloc(unsigned int num_entries, unsigned int entry_size)
{
	struct vr_btable *table = vr_zalloc(sizeof(struct vr_btable)
		+ (num_entries * entry_size));

	/* data follows right after the header */
	return vr_btable_init(table, num_entries, entry_size,
		((void *)table + sizeof(struct vr_btable)));
}

/*
 * Allocate memory just for the btable header and use shared memory
 * pointer *data to store table entries.
 */
static inline struct vr_btable *
vr_btable_alloc_shmem(unsigned int num_entries, unsigned int entry_size,
	void *data)
{
	struct vr_btable *table = vr_zalloc(sizeof(struct vr_btable));

	return vr_btable_init(table, num_entries, entry_size, data);
}

static inline unsigned int
vr_btable_entries(struct vr_btable *table)
{
    return table->vb_entries;
}

static inline unsigned int
vr_btable_size(struct vr_btable *table)
{
    return table->vb_entries * table->vb_esize;
}

static inline void *
vr_btable_get(struct vr_btable *table, unsigned int entry)
{
    if (entry >= table->vb_entries) {
        return NULL;
	}

    return table->vb_data + (entry * table->vb_esize);
}


#else /* !__DPDK__ */

#define VR_SINGLE_ALLOC_LIMIT   (4  * 1024 * 1024)

struct vr_btable_partition {
    unsigned int vb_offset;
    unsigned int vb_mem_size;
};

struct vr_btable {
    unsigned int    vb_entries;
    unsigned short  vb_esize;
    unsigned short  vb_partitions;
    void            **vb_mem;
    struct vr_btable_partition *vb_table_info;
};

struct vr_btable_partition *vr_btable_get_partition(struct vr_btable *,
        unsigned int);
void *vr_btable_get_address(struct vr_btable *, unsigned int);

void vr_btable_free(struct vr_btable *);
struct vr_btable *vr_btable_alloc(unsigned int, unsigned int);

static inline unsigned int
vr_btable_entries(struct vr_btable *table)
{
    return table->vb_entries;
}

static inline unsigned int
vr_btable_size(struct vr_btable *table)
{
    return table->vb_entries * table->vb_esize;
}

static inline void *
vr_btable_get(struct vr_btable *table, unsigned int entry)
{
    unsigned int t_index, t_offset;

    if (entry >= table->vb_entries)
        return NULL;

    t_index = (entry * table->vb_esize) / VR_SINGLE_ALLOC_LIMIT;
    t_offset = (entry * table->vb_esize) % VR_SINGLE_ALLOC_LIMIT;
    if (t_index >= table->vb_partitions)
        return NULL;

    return (table->vb_mem[t_index] + t_offset);
}

#endif /* __DPDK__ */

#endif /* __VR_BTABLE_H__ */
