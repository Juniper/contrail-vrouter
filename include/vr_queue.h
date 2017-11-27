/*
 * vr_queue.h --
 *
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#ifndef __VR_QUEUE_H__
#define __VR_QUEUE_H__

#include "vr_os.h"

struct vr_qelem {
    struct vr_qelem *q_next;
};

struct vr_qhead {
    struct vr_qelem *q_first;
};

void vr_queue_init(struct vr_qhead *);
void vr_queue_enqueue(struct vr_qhead *, struct vr_qelem *);
struct vr_qelem *vr_queue_dequeue(struct vr_qhead *);
bool vr_queue_empty(struct vr_qhead *);

#endif /* __VR_QUEUE_H__ */
