/*
 * se ts=4;se expandtab
 *
 * vr_bitmap.c -- Bitmap handling
 *
 * Copyright (c) 2015 Juniper Networks, Inc. All rights reserved.
 */

#include <vr_os.h>
#if defined(__linux__)
#include <linux/version.h>
#endif
#include <vr_bitmap.h>


#define VR_BITMAP_STRIDE_LEN (8 * (sizeof(unsigned int)))

struct vr_bitmap {
    unsigned int bmap_bits;
    unsigned int bmap_size;
    unsigned int bmap_last_free_stride;
    unsigned int bmap_used_bits;
    unsigned int bmap_data[0];
};

unsigned int
vr_bitmap_used_bits(vr_bmap_t b)
{
    struct vr_bitmap *bmap = (struct vr_bitmap *)b;

    if (bmap)
        return bmap->bmap_used_bits;

    return 0;
}

int
vr_bitmap_alloc_bit(vr_bmap_t b)
{
    int i, j, stride_num;
    unsigned int data, free_bit;
    struct vr_bitmap *bmap = (struct vr_bitmap *)b;

    /* If no bitmap or if bitmap is full */
    if ((!bmap) || (!(bmap->bmap_bits - bmap->bmap_used_bits)))
        return -1;

    stride_num = bmap->bmap_last_free_stride;

    for (i = 0; i < bmap->bmap_size; i++, stride_num++) {

        if (stride_num >= bmap->bmap_size)
            stride_num = 0;

        for (j = 0; ((bmap->bmap_data[stride_num] != 0xFFFFFFFF) &&
                    (j < VR_BITMAP_STRIDE_LEN)); j++) {
            data = bmap->bmap_data[stride_num];

            free_bit = __builtin_ffs(~data);
            /* If there is no free bit goto next byte */
            if (!free_bit)
                break;

            free_bit -= 1;
            if (__sync_bool_compare_and_swap(&bmap->bmap_data[stride_num],
                                data, (data | (1 << free_bit)))) {
                bmap->bmap_last_free_stride = stride_num;
                (void)__sync_add_and_fetch(&bmap->bmap_used_bits, 1);
                return ((stride_num * VR_BITMAP_STRIDE_LEN) + free_bit);
            }
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
    struct vr_bitmap *bmap = (struct vr_bitmap *)b;

    if (!bmap || bit >= bmap->bmap_bits)
        return false;

    (void)__sync_and_and_fetch(&bmap->bmap_data[(bit / VR_BITMAP_STRIDE_LEN)],
                            (~(1 << (bit % VR_BITMAP_STRIDE_LEN))));
    (void)__sync_sub_and_fetch(&bmap->bmap_used_bits, 1);

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
    bmap->bmap_size = bitmap_size / sizeof(unsigned int);
    bmap->bmap_last_free_stride = 0;

    return (vr_bmap_t)bmap;
}
