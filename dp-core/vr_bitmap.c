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
    unsigned int bmap_last_free_byte;
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
vr_bitmap_set_first_free_bit(vr_bmap_t b)
{
    int i, j, byte_num;
    uint8_t data, free_bit;
    struct vr_bitmap *bmap = (struct vr_bitmap *)b;

    if (!bmap)
        return -1;

    byte_num = bmap->bmap_last_free_byte;

    for (i= 0; i < bmap->bmap_size; i++, byte_num++) {

        if (byte_num >= bmap->bmap_size)
            byte_num = 0;

        for (j = 0; ((bmap->bmap_data[byte_num] != 0xFF) && (j < 8)); j++) {
            data = bmap->bmap_data[byte_num];

            free_bit = __builtin_ffs(~data);
            /* If there is no free bit goto next byte */
            if (!free_bit)
                break;

            free_bit -= 1;
            if (__sync_bool_compare_and_swap(&bmap->bmap_data[byte_num],
                                data, (data | (1 << free_bit)))) {
                bmap->bmap_last_free_byte = byte_num;
                return ((byte_num * 8) + free_bit);
            }
        }
    }

    return -1;
}

bool
vr_bitmap_clear_bit(vr_bmap_t b, unsigned int bit)
{
    struct vr_bitmap *bmap = (struct vr_bitmap *)b;

    if (!bmap || bit >= bmap->bmap_bits)
        return false;

    __sync_and_and_fetch(&bmap->bmap_data[(bit / 8)], (~(1 << (bit % 8))));

    return true;
}

void
vr_bitmap_delete(vr_bmap_t b)
{
    struct vr_bitmap *bmap = (struct vr_bitmap *)b;

    if (bmap)
        vr_free(bmap);

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
    bmap = vr_zalloc(bytes);
    if (!bmap)
        return NULL;

    bmap->bmap_bits = nbits;
    bmap->bmap_size = bitmap_size;

    return (vr_bmap_t)bmap;
}
