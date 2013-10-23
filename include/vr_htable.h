/*
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */

#ifndef __VR_HTABLE_H__
#define __VR_HTABLE_H__

typedef void* vr_hentry_t;
typedef struct vr_htable_opaque *vr_htable_t;
typedef bool (*is_hentry_valid)(vr_htable_t , vr_hentry_t, unsigned int);
typedef void (*htable_trav_cb)(vr_htable_t , vr_hentry_t, unsigned int,
        void *);
vr_htable_t vr_htable_create(unsigned int , unsigned int ,
                                unsigned int , unsigned int ,
                                is_hentry_valid );
void vr_htable_delete(vr_htable_t );
vr_hentry_t vr_find_hentry(vr_htable_t , void *, unsigned int *);
int vr_find_duplicate_hentry_index(vr_htable_t , vr_hentry_t );
vr_hentry_t vr_get_hentry_by_index(vr_htable_t , unsigned int );
vr_hentry_t vr_find_free_hentry(vr_htable_t , void *, unsigned int *);
void vr_htable_trav(vr_htable_t , unsigned int , htable_trav_cb , void *);


#endif
