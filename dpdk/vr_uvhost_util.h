/*
 * vr_uvhost_util.h - header for utils for user-space vhost server that peers
 * with the vhost client inside qemu (version 2.1 and later).
 *
 * Copyright (c) 2014 Juniper Networks, Inc. All rights reserved.
 */

#ifndef __VR_UVHOST_UTIL_H__
#define __VR_UVHOST_UTIL_H__

#include <sys/poll.h>

#define MAX_UVHOST_FDS VR_MAX_INTERFACES

typedef int (*uvh_fd_handler_t)(int fd, void *arg);

typedef enum uvh_fd_type {
    UVH_FD_READ = 1,
    UVH_FD_WRITE = 2
} uvh_fd_type_t;

void vr_uvhost_fds_init(void);
int vr_uvhost_add_fd(int fd, uvh_fd_type_t fd_type, void *fd_handler_arg,
                     uvh_fd_handler_t fd_handler);
int vr_uvhost_del_fd(int fd, uvh_fd_type_t fd_type);
int vr_uvhost_del_fds_by_arg(void *arg);
void vr_uvhost_log(const char *format, ...)
        __attribute__((format(printf, 1, 2)));
void vr_uvh_call_fd_handlers(struct pollfd *fds, nfds_t nfds);
void vr_uvh_init_pollfds(struct pollfd *fds, nfds_t *nfds);

#endif /* __VR_UVHOST_UTIL_H__ */
