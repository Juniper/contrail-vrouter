/*
 * vr_uvhost.h - header for user-space vhost server that peers with
 * the vhost client inside qemu (version 2.1 and later).
 *
 * Copyright (c) 2014 Juniper Networks, Inc. All rights reserved.
 */

#ifndef __VR_UVHOST_H__
#define __VR_UVHOST_H__

typedef void (*vr_uvh_exit_callback_t)(void);

#define VR_UVH_NL_SOCK_NAME "vr_uvh_nl"
#define VR_NL_UVH_SOCK_NAME "vr_nl_uvh"

int vr_uvhost_init(pthread_t *th, vr_uvh_exit_callback_t exit_fn);
void *vr_uvhost_start(void *arg);
void vr_uvhost_wakeup(void);

/* Global variables */
extern vr_uvh_exit_callback_t vr_uvhost_exit_fn;


#endif /* __VR_UVHOST_H__ */

