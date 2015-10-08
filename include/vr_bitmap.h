/*
 * Copyright (c) 2015 Juniper Networks, Inc. All rights reserved.
 */
#ifndef __VR_BITMAP_H__
#define __VR_BITMAP_H__

#include "vr_defs.h"
#include "vrouter.h"

typedef struct vr_bmap_opaque  *vr_bmap_t;

unsigned int vr_bitmap_used_bits(vr_bmap_t);
int vr_bitmap_alloc_bit(vr_bmap_t);
bool vr_bitmap_clear_bit(vr_bmap_t, unsigned int);
void vr_bitmap_delete(vr_bmap_t);
vr_bmap_t vr_bitmap_create(unsigned int);

#endif

