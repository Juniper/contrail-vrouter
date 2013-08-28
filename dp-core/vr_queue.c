/*
 * vr_queue.c -- queue implementation for vrouter
 *
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#include <vr_os.h>
#include "vr_queue.h"

void
vr_queue_init(struct vr_qhead *head)
{
    head->q_first = NULL;
    return;
}

void
vr_queue_enqueue(struct vr_qhead *head, struct vr_qelem *p)
{
    struct vr_qelem *elem = head->q_first;

    p->q_next = NULL;

    if (!elem) {
        head->q_first = p;
        return;
    }

    while (elem && elem->q_next)
        elem = elem->q_next;

    elem->q_next = p;
    return;
}

struct vr_qelem *
vr_queue_dequeue(struct vr_qhead *head)
{
    struct vr_qelem *elem = head->q_first;

    if (elem)
        head->q_first = elem->q_next;

    return elem;
}

bool
vr_queue_empty(struct vr_qhead *head)
{
    if (head->q_first)
        return false;
    return true;
}
