/*
 * vr_hash.h
 *
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */

#ifndef _VR_HASH_H
#define _VR_HASH_H

#include "vr_os.h"

/* vr_hash.h: Jenkins hash support.
 *
 * Copyright (C) 2006. Bob Jenkins (bob_jenkins@burtleburtle.net)
 *
 * http://burtleburtle.net/bob/hash/
 *
 * These are the credits from Bob's sources:
 *
 * lookup3.c, by Bob Jenkins, May 2006, Public Domain.
 *
 * These are functions for producing 32-bit hashes for hash table lookup.
 * hashword(), hashlittle(), hashlittle2(), hashbig(), mix(), and final()
 * are externally useful functions.  Routines to test the hash are included
 * if SELF_TEST is defined.  You can use this free for any purpose.  It's in
 * the public domain.  It has no warranty.
 *
 * Copyright (C) 2009-2010 Jozsef Kadlecsik (kadlec@blackhole.kfki.hu)
 *
 * I've modified Bob's hash to be useful in the Linux kernel, and
 * any bugs present are my fault.
 * Jozsef
 */

/* Best hash sizes are of power of two */
#define vr_hash_size(n)   ((uint32_t)1<<(n))
/* Mask the hash value, i.e (value & vr_hash_mask(n)) instead of (value % n) */
#define vr_hash_mask(n)   (vr_hash_size(n)-1)

#define rolword(x,k) (((x)<<(k)) | ((x)>>(32-(k))))

/* __vr_hash_mix -- mix 3 32-bit values reversibly. */
#define __vr_hash_mix(a, b, c)              \
{                                           \
    a -= c;  a ^= rolword(c, 4);  c += b;   \
    b -= a;  b ^= rolword(a, 6);  a += c;   \
    c -= b;  c ^= rolword(b, 8);  b += a;   \
    a -= c;  a ^= rolword(c, 16); c += b;   \
    b -= a;  b ^= rolword(a, 19); a += c;   \
    c -= b;  c ^= rolword(b, 4);  b += a;   \
}

/* __vr_hash_final - final mixing of 3 32-bit values (a,b,c) into c */
#define __vr_hash_final(a, b, c)            \
{                                           \
    c ^= b; c -= rolword(b, 14);            \
    a ^= c; a -= rolword(c, 11);            \
    b ^= a; b -= rolword(a, 25);            \
    c ^= b; c -= rolword(b, 16);            \
    a ^= c; a -= rolword(c, 4);             \
    b ^= a; b -= rolword(a, 14);            \
    c ^= b; c -= rolword(b, 24);            \
}

/* An arbitrary initial parameter */
#define VR_HASH_INITVAL     0xdeadbeef

__attribute__packed__open__
struct __unaligned_u32 {
    uint32_t x;
} __attribute__packed__close__;

static inline uint32_t __get_unaligned_word(const void *p)
{
    union {
        uint8_t bytes[sizeof(uint32_t)];
        struct __unaligned_u32 u32;
    } word;

    size_t i;
    for (i = 0; i < sizeof(struct __unaligned_u32); i++) {
        word.bytes[i] = ((uint8_t *) p)[i];
    }
    return word.u32.x;
}


/* vr_hash - hash an arbitrary key
 * @k: sequence of bytes as key
 * @length: the length of the key
 * @initval: the previous hash, or an arbitray value
 *
 * The generic version, hashes an arbitrary sequence of bytes.
 * No alignment or length assumptions are made about the input key.
 *
 * Returns the hash value of the key. The result depends on endianness.
 */
static inline uint32_t vr_hash(const void *key, uint32_t length, uint32_t initval)
{
    uint32_t a, b, c;
    const uint8_t *k = key;

    /* Set up the internal state */
    a = b = c = VR_HASH_INITVAL + length + initval;

    /* All but the last block: affect some 32 bits of (a,b,c) */
    while (length > 12) {
        a += __get_unaligned_word(k);
        b += __get_unaligned_word(k + 4);
        c += __get_unaligned_word(k + 8);
        __vr_hash_mix(a, b, c);
        length -= 12;
        k += 12;
    }
    /* Last block: affect all 32 bits of (c) */
    /* All the case statements fall through */
    switch (length) {
    case 12: c += (uint32_t)k[11]<<24;
    case 11: c += (uint32_t)k[10]<<16;
    case 10: c += (uint32_t)k[9]<<8;
    case 9:  c += k[8];
    case 8:  b += (uint32_t)k[7]<<24;
    case 7:  b += (uint32_t)k[6]<<16;
    case 6:  b += (uint32_t)k[5]<<8;
    case 5:  b += k[4];
    case 4:  a += (uint32_t)k[3]<<24;
    case 3:  a += (uint32_t)k[2]<<16;
    case 2:  a += (uint32_t)k[1]<<8;
    case 1:  a += k[0];
         __vr_hash_final(a, b, c);
    case 0: /* Nothing left to add */
        break;
    }

    return c;
}

/* vr_hash2 - hash an array of u32's
 * @k: the key which must be an array of u32's
 * @length: the number of u32's in the key
 * @initval: the previous hash, or an arbitray value
 *
 * Returns the hash value of the key.
 */
static inline uint32_t vr_hash2(const uint32_t *k, uint32_t length, uint32_t initval)
{
    uint32_t a, b, c;

    /* Set up the internal state */
    a = b = c = VR_HASH_INITVAL + (length<<2) + initval;

    /* Handle most of the key */
    while (length > 3) {
        a += k[0];
        b += k[1];
        c += k[2];
        __vr_hash_mix(a, b, c);
        length -= 3;
        k += 3;
    }

    /* Handle the last 3 u32's: all the case statements fall through */
    switch (length) {
    case 3: c += k[2];
    case 2: b += k[1];
    case 1: a += k[0];
        __vr_hash_final(a, b, c);
    case 0:    /* Nothing left to add */
        break;
    }

    return c;
}


/* vr_hash_3words - hash exactly 3, 2 or 1 word(s) */
static inline uint32_t vr_hash_3words(uint32_t a, uint32_t b, uint32_t c, uint32_t initval)
{
    a += VR_HASH_INITVAL;
    b += VR_HASH_INITVAL;
    c += initval;

    __vr_hash_final(a, b, c);

    return c;
}

static inline uint32_t vr_hash_2words(uint32_t a, uint32_t b, uint32_t initval)
{
    return vr_hash_3words(a, b, 0, initval);
}

static inline uint32_t vr_hash_1word(uint32_t a, uint32_t initval)
{
    return vr_hash_3words(a, 0, 0, initval);
}

#endif /* _VR_HASH_H */
