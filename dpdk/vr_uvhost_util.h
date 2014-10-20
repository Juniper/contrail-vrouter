/*
 * vr_uvhost_util.h - header for utils for user-space vhost server that peers 
 * with the vhost client inside qemu (version 2.1 and later).
 *
 * Copyright (c) 2014 Juniper Networks, Inc. All rights reserved.
 */

#ifndef __VR_UVHOST_UTIL_H__
#define __VR_UVHOST_UTIL_H__    

typedef int (*uvh_fd_handler_t)(int fd, void *arg);

typedef enum uvh_fd_type {
    UVH_FD_READ = 1,
    UVH_FD_WRITE = 2
} uvh_fd_type_t;

void vr_uvhost_fdset_init(void);
int vr_uvhost_add_fd(int fd, uvh_fd_type_t fd_type, void *fd_handler_arg,
                     uvh_fd_handler_t fd_handler);
int vr_uvhost_del_fd(int fd, uvh_fd_type_t fd_type);
void vr_uvh_reset_max_fd(void);
void vr_uvhost_log(const char *format, ...);
int vr_uvh_max_fd(void);
fd_set *vr_uvh_rfdset_p(void);
fd_set *vr_uvh_wfdset_p(void);
int vr_uvh_call_fd_handlers(void);

#endif /* __VR_UVHOST_UTIL_H__ */
