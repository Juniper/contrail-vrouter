/*
 * se ts=4;se expandtab
 *
 * vrouter.c -- virtual router
 *
 * Copyright (c) 2015 Juniper Networks, Inc. All rights reserved.
 */

#include <vr_os.h>
#if defined(__linux__)
#include <linux/version.h>
#endif
#include <vr_bitmap.h>


struct vr_bitmap {
    unsigned int bmap_bits;
    unsigned int bmap_size;
    unsigned char bmap_data[0];
};


bool
vr_bitmap_valid_bit(vr_bmap_t b, unsigned int bit)
{
    uint8_t data;
    struct vr_bitmap *bmap = (struct vr_bitmap *)b;

    if (!bmap)
        return false;

    if (bit >= bmap->bmap_bits)
        return false;

    data = bmap->bmap_data[(bit / 8)];
    if (data && (1 << (bit % 8)))
        return true;

    return false;
}

bool
vr_bitmap_set_bit(vr_bmap_t b, unsigned int bit)
{
    struct vr_bitmap *bmap = (struct vr_bitmap *)b;
    uint8_t *data;

    if (!bmap)
        return false;

    if (bit >= bmap->bmap_bits)
        return false;

    data = &bmap->bmap_data[(bit / 8)];
    *data |= (1 << (bit % 8));

    return true;
}

int
vr_bitmap_get_first_free_bit(vr_bmap_t b)
{
    uint8_t data;
    int i, ind;
    struct vr_bitmap *bmap = (struct vr_bitmap *)b;

    if (!bmap)
        return -1;

    for (i = 0; i < bmap->bmap_size; i++) {
        if (bmap->bmap_data[i] != 0xFF) {
            data = ~bmap->bmap_data[i];
            ind = (i * 8) + (__builtin_ffs(data) - 1);
            return ind;
        }
    }

    return -1;
}

bool
vr_bitmap_is_set_bit(vr_bmap_t b, unsigned int bit)
{
    unsigned int bit_data;
    struct vr_bitmap *bmap = (struct vr_bitmap *)b;

    bit_data = bmap->bmap_data[(bit / 8)];
    if (bit_data & (1 << (bit % 8)))
        return true;

    return false;
}

bool
vr_bitmap_clear_bit(vr_bmap_t b, unsigned int bit)
{
    uint8_t *data;
    struct vr_bitmap *bmap = (struct vr_bitmap *)b;

    if (!bmap || bit >= bmap->bmap_bits)
        return false;

    data = &bmap->bmap_data[(bit / 8)];
    *data &= (~(1 << (bit % 8)));

    return true;
}

void
vr_bitmap_delete(vr_bmap_t b)
{
    struct vr_bitmap *bmap = (struct vr_bitmap *)b;

    if (bmap)
        vr_free(bmap, VR_BITMAP_OBJECT);

    return;
}


vr_bmap_t
vr_bitmap_create(unsigned int nbits)
{
    unsigned int bytes, bitmap_size;
    struct vr_bitmap *bmap;

    /* Make it 64 bit boundary */
    bitmap_size = (nbits + 64) & ~64;

    /* Convert to bytes */
    bitmap_size /= 8;
    bytes = bitmap_size + sizeof(struct vr_bitmap);
    bmap = vr_zalloc(bytes, VR_BITMAP_OBJECT);
    if (!bmap)
        return NULL;

    bmap->bmap_bits = nbits;
    bmap->bmap_size = bitmap_size;

    return (vr_bmap_t)bmap;
}
