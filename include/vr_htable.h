/*
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */

#ifndef __VR_HTABLE_H__
#define __VR_HTABLE_H__

#define VR_INVALID_HENTRY_INDEX ((unsigned int)-1)

typedef struct vr_hentry {
    struct vr_hentry *hentry_next;
    unsigned int hentry_index;
    unsigned int hentry_bucket_index;
    unsigned int hentry_next_index;
} vr_hentry_t;

typedef void *vr_hentry_key;
typedef struct vr_htable_opaque *vr_htable_t;
typedef vr_hentry_key (*get_hentry_key)(vr_htable_t, vr_hentry_t *,
        unsigned int *);
typedef void (*htable_trav_cb)(vr_htable_t , vr_hentry_t *, unsigned int,
        void *);

vr_htable_t vr_htable_create(unsigned int , unsigned int ,
                                unsigned int , unsigned int , unsigned int,
                                get_hentry_key);
void vr_htable_delete(vr_htable_t );
vr_hentry_t *vr_find_hentry(vr_htable_t , void *, unsigned int);
int vr_find_duplicate_hentry_index(vr_htable_t , vr_hentry_t *);
vr_hentry_t *vr_get_hentry_by_index(vr_htable_t , unsigned int );
vr_hentry_t *vr_find_free_hentry(vr_htable_t , void *, unsigned int );
void vr_htable_trav(vr_htable_t , unsigned int , htable_trav_cb , void *);
void vr_release_hentry(vr_htable_t, vr_hentry_t *);
unsigned int vr_htable_size(vr_htable_t);
void *vr_htable_get_address(vr_htable_t, uint64_t);

#endif
