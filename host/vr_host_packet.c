/*
 * vr_host_packet.c -- host packet representation
 *
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#include "vr_os.h"
#include "vr_packet.h"
#include "vr_proto.h"
#include "vrouter.h"
#include "host/vr_host_packet.h"

int
vr_hpacket_copy(unsigned char *dst, struct vr_hpacket *hpkt_src,
        unsigned int offset, unsigned int len)
{
    unsigned short tocopy, copied;
    unsigned char *src;

    while (hpkt_src && offset > hpkt_src->hp_end) {
        offset -= (hpkt_src->hp_tail - hpkt_src->hp_data);
        hpkt_src = hpkt_src->hp_next;
    }

    if (!hpkt_src)
        return -EINVAL;

    tocopy = len;
    src = hpkt_src->hp_head + hpkt_src->hp_data + offset;
    copied = 0;

    while (len) {
        if (len > hpkt_src->hp_tail - (hpkt_src->hp_data + offset))
            tocopy = hpkt_src->hp_tail - (hpkt_src->hp_data + offset);
        memcpy(dst + copied, src, tocopy);
        len -= tocopy;
        copied += tocopy;
        hpkt_src = hpkt_src->hp_next;
        if (!hpkt_src)
            return copied;
        src = hpkt_data(hpkt_src);
    }

    return copied;
}


void
vr_hpacket_free(struct vr_hpacket *hpkt)
{
    struct vr_hpacket_tail *hpkt_tail;
    struct vr_hpacket *hpkt_next;

    while (hpkt) {
        hpkt_next = hpkt->hp_next;
        hpkt_tail = (struct vr_hpacket_tail *)hpkt_end(hpkt);
        hpkt_tail->hp_users--;
        if (hpkt->hp_flags & VR_HPACKET_FLAGS_CLONED) {
            if (!hpkt_tail->hp_users)
                free(hpkt->hp_head);
            free(hpkt);
            return;
        }

        if (hpkt->hp_pool) {
            if (hpkt_tail->hp_users) {
                hpkt->hp_head = malloc(hpkt->hp_end +
                        sizeof(struct vr_hpacket_tail));
                hpkt_tail = (struct vr_hpacket_tail *)hpkt_end(hpkt);
                hpkt_tail->hp_users = 1;
            }
            vr_hpacket_pool_free(hpkt);
        } else {
            free(hpkt->hp_head);
            free(hpkt);
        }

        hpkt = hpkt_next;
    }

    return;
}

struct vr_hpacket *
vr_hpacket_alloc(unsigned int size)
{
    struct vr_hpacket *hpkt;
    struct vr_hpacket_tail *hpkt_tail;
    struct vr_packet *pkt;

    hpkt = (struct vr_hpacket *)malloc(sizeof(*hpkt));
    if (!hpkt)
        return NULL;

    hpkt->hp_head = malloc(size + VR_HPACKET_HEAD_SPACE +
            sizeof(struct vr_hpacket_tail));
    if (!hpkt->hp_head) {
        free(hpkt);
        return NULL;
    }

    hpkt->hp_data = hpkt->hp_tail = VR_HPACKET_HEAD_SPACE;
    hpkt->hp_end = size - 1;
    hpkt_tail = (struct vr_hpacket_tail *)hpkt_end(hpkt);
    hpkt_tail->hp_users = 1;
    pkt = &hpkt->hp_packet;
    pkt->vp_head = hpkt->hp_head;
    pkt->vp_data = hpkt->hp_data;
    pkt->vp_end = hpkt->hp_end;
    pkt->vp_len = 0;
    pkt->vp_if = NULL;

    return hpkt;
}

struct vr_hpacket *
vr_hpacket_clone(struct vr_hpacket *hpkt)
{
    struct vr_hpacket *hpkt_c;
    struct vr_hpacket_tail *hpkt_tail;

    hpkt_c = (struct vr_hpacket *)malloc(sizeof(struct vr_hpacket));
    if (!hpkt_c)
        return NULL;

    memcpy(hpkt_c, hpkt, sizeof(*hpkt));

    /* increase the reference count for the buffer */
    hpkt_tail = (struct vr_hpacket_tail *)hpkt_end(hpkt);
    hpkt_tail->hp_users++;

    hpkt_c->hp_flags |= VR_HPACKET_FLAGS_CLONED;
    return hpkt_c;
}

struct vr_hpacket *
vr_hpacket_pool_alloc(struct vr_hpacket_pool *pool)
{
    struct vr_hpacket *hpkt;
    struct vr_packet *pkt;

    hpkt = pool->pool_head;
    pool->pool_head = hpkt->hp_next;
    hpkt->hp_next = NULL;
    pkt = &hpkt->hp_packet;
    pkt->vp_data = hpkt->hp_data;
    return hpkt;
}

void
vr_hpacket_pool_free(struct vr_hpacket *hpkt)
{
    struct vr_hpacket_pool *pool = hpkt->hp_pool;
    struct vr_packet *pkt;

    hpkt->hp_next = pool->pool_head;
    pool->pool_head = hpkt;
    pkt = &hpkt->hp_packet;
    pkt->vp_data = hpkt->hp_data;
    pkt->vp_len = 0;
    pkt->vp_if = NULL;

    return;
}

void
vr_hpacket_pool_destroy(struct vr_hpacket_pool *pool)
{
    struct vr_hpacket *hpkt, *n_hpkt;

    hpkt = pool->pool_head;
    while (hpkt) {
        n_hpkt = hpkt->hp_next;
        hpkt->hp_next = NULL;
        hpkt->hp_pool = NULL;
        vr_hpacket_free(hpkt);
        hpkt = n_hpkt;
    }
    vr_free(pool, VR_HPACKET_POOL_OBJECT);

    return;
}

struct vr_hpacket_pool *
vr_hpacket_pool_create(unsigned int pool_size, unsigned int psize)
{
    unsigned int i;
    struct vr_hpacket_pool *pool;
    struct vr_hpacket *hpkt;

    if (!pool_size)
        return NULL;

    pool = vr_zalloc(sizeof(*pool), VR_HPACKET_POOL_OBJECT);
    if (!pool)
        goto cleanup;

    for (i = 0; i < pool_size; i++) {
        hpkt = vr_hpacket_alloc(psize);
        if (!hpkt)
            goto cleanup;

        if (!pool->pool_head)
            pool->pool_head = hpkt;
        else {
            hpkt->hp_next = pool->pool_head->hp_next;
            pool->pool_head->hp_next = hpkt;
        }
        hpkt->hp_pool = pool;
    }

    return pool;

cleanup:
    if (pool)
        vr_hpacket_pool_destroy(pool);

    return NULL;
}

