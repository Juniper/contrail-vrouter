/*
 * vr_sandesh.h --
 *
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#ifndef __VR_SANDESH_H__
#define __VR_SANDESH_H__

#define VR_FLOW_MAX_CPUS    128

struct sandesh_object_md {
    unsigned int obj_len;
    char *obj_type_string;
    unsigned int (*obj_get_size)(void *);
};

void *sandesh_alloc(unsigned int);
void sandesh_free(unsigned char *);
int sandesh_enqueue_response(unsigned char *, unsigned int);
int vr_sandesh_init(void);
void vr_sandesh_exit(void);

#endif /* __VR_SANDESH_H__ */
