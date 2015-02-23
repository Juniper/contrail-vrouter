/*
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#ifndef __VR_INDEX_TABLE_H__
#define __VR_INDEX_TABLE_H__

typedef struct vr_itable_opaque *vr_itable_t;
typedef int (*vr_itable_trav_cb_t)(unsigned int index, void *data, void *udata);
typedef void (*vr_itable_del_cb_t)(unsigned int index, void *data);

#define VR_ITABLE_ERR_PTR ((void *)-1)

vr_itable_t vr_itable_create(unsigned int index_len, unsigned int stride_cnt, ...);
void vr_itable_delete(vr_itable_t t, vr_itable_del_cb_t func);

void *vr_itable_get(vr_itable_t t, unsigned int index);
void *vr_itable_del(vr_itable_t t, unsigned int index);
void *vr_itable_set(vr_itable_t t, unsigned int index, void *data);
int vr_itable_trav(vr_itable_t t, vr_itable_trav_cb_t func,
                               unsigned int marker, void *udata);


#endif /* __VR_INDEX_TABLE_H__ */

