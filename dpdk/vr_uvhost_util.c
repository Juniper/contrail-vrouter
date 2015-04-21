/*
 * vr_uvhost_util.c - utils for user-space vhost server that peers with
 * the vhost client inside qemu (version 2.1 and later).
 *
 * Copyright (c) 2014 Juniper Networks, Inc. All rights reserved.
 */
#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/select.h>
#include <pthread.h>

#include "vr_dpdk.h"
#include "vr_uvhost.h"
#include "vr_uvhost_util.h"

#define MAX_UVHOST_FDS 1024

typedef struct uvh_fd_s {
    int uvh_fd;
    void *uvh_fd_arg;
    uvh_fd_handler_t uvh_fd_fn;
} uvh_fd_t;

/* Global variables */
static uvh_fd_t uvh_rfds[MAX_UVHOST_FDS];
static uvh_fd_t uvh_wfds[MAX_UVHOST_FDS];
static fd_set uvh_rfdset, uvh_wfdset;
static int uvh_max_fd = 0;

/*
 * vr_uvhost_log - logs user space vhost messages to a file.
 */
void
vr_uvhost_log(const char *format, ...)
{
    va_list ap;
    FILE *f = stderr; /* TODO _ change to a different file */

    fprintf(f, "UVHOST: ");
    va_start(ap, format);
    vfprintf(f, format, ap);
    fflush(f);

    return;
}

/*
 * vr_uvhost_del_fd - deletes a FD from the read/write list that the
 * user space vhost server is listening on. fd_type indicates if it
 * is a read/write socket. The FD passed in will be closed.
 *
 * Returns 0 on success, -1 otherwise.
 */
int
vr_uvhost_del_fd(int fd, uvh_fd_type_t fd_type)
{
    int i;
    uvh_fd_t *fds;

    RTE_LOG(DEBUG, UVHOST, "Deleting FD %d from the select pool...\n", fd);
    if (fd_type == UVH_FD_READ) {
        fds = uvh_rfds;
    } else if (fd_type == UVH_FD_WRITE) {
        fds = uvh_wfds;
    } else {
        return -1;
    }

    for (i = 0; i < MAX_UVHOST_FDS; i++) {
        if (fds[i].uvh_fd == fd) {
            break;
        }
    }

    if (i == MAX_UVHOST_FDS) {
        /* The descriptor could be deleted on read error, so no need to
         * print the error message.
         */
        return -1;
    }

    fds[i].uvh_fd = -1;
    vr_uvh_recalc_max_fd();

    close(fd);

    return 0;
}

/*
 * vr_uvhost_add_fd - adds the specified FD into the read/write list that
 * the user space vhost server is waiting on. The type indicates if it
 * is a read/write socket and the handler is the function that is called when
 * there is an event on the socket.
 *
 * Returns 0 on success, -1 otherwise.
 */
int
vr_uvhost_add_fd(int fd, uvh_fd_type_t fd_type, void *fd_handler_arg,
                 uvh_fd_handler_t fd_handler)
{
    int i;
    uvh_fd_t *fds;

    RTE_LOG(DEBUG, UVHOST, "Adding FD %d to the select pool...\n", fd);
    if (fd_type == UVH_FD_READ) {
        fds = uvh_rfds;
    } else if (fd_type == UVH_FD_WRITE) {
        fds = uvh_wfds;
    } else {
        return -1;
    }

    for (i = 0; i < MAX_UVHOST_FDS; i++) {
        if (fds[i].uvh_fd == -1) {
            fds[i].uvh_fd = fd;
            fds[i].uvh_fd_arg = fd_handler_arg;
            fds[i].uvh_fd_fn = fd_handler;

            if (fd > uvh_max_fd) {
                uvh_max_fd = fd;
            }

            return 0;
        }
    }

    vr_uvhost_log("Error adding FD %d: no space left\n", fd);

    return -1;
}

/*
 * vr_uvhost_fdset_init - initializes the read and write FD sets before
 * we enter the select loop.
 */
void
vr_uvhost_fdset_init(void)
{
    int i;

    FD_ZERO(&uvh_rfdset);
    FD_ZERO(&uvh_wfdset);

    for (i = 0; i < MAX_UVHOST_FDS; i++) {
        uvh_rfds[i].uvh_fd = -1;
        uvh_wfds[i].uvh_fd = -1;
    }

    return;
}

/*
 * vr_uvh_max_fd - returns the max FD for select.
 */
int
vr_uvh_max_fd(void)
{
    return uvh_max_fd;
}

/*
 * vr_uvh_recalc_max_fd - recalculates the max FD to -1.
 */
void
vr_uvh_recalc_max_fd(void)
{
    int i;

    uvh_max_fd = -1;
    for (i = 0; i < MAX_UVHOST_FDS; i++) {
        if (uvh_rfds[i].uvh_fd != -1
            && uvh_rfds[i].uvh_fd > uvh_max_fd) {
            uvh_max_fd = uvh_rfds[i].uvh_fd;
        }
        if (uvh_wfds[i].uvh_fd != -1
            && uvh_wfds[i].uvh_fd > uvh_max_fd) {
            uvh_max_fd = uvh_wfds[i].uvh_fd;
        }
    }
}

/*
 * vr_uvh_rfdset_p - returns a pointer to the fdset corresponding to the
 * read fds.
 */
fd_set *
vr_uvh_rfdset_p(void)
{
    int i;

    FD_ZERO(&uvh_rfdset);

    for (i = 0; i < MAX_UVHOST_FDS; i++) {
        if (uvh_rfds[i].uvh_fd == -1) {
            continue;
        }

        FD_SET(uvh_rfds[i].uvh_fd, &uvh_rfdset);
    }

    return &uvh_rfdset;
}

/*
 * vr_uvh_wfdset_p - returns a pointer to the write fdset.
 */
fd_set *
vr_uvh_wfdset_p(void)
{
    int i;

    FD_ZERO(&uvh_wfdset);

    for (i = 0; i < MAX_UVHOST_FDS; i++) {
        if (uvh_wfds[i].uvh_fd == -1) {
            continue;
        }

        FD_SET(uvh_wfds[i].uvh_fd, &uvh_wfdset);
    }

    return &uvh_wfdset;
}

/*
 * vr_uvh_call_fd_handlers_internal - internal function to call the handler
 * for all fds that are set in the fd_set.
 *
 * Returns 0 on success, error FD otherwise.
 */
static int
vr_uvh_call_fd_handlers_internal(uvh_fd_t *fd_arr, fd_set *fdset_ptr)
{
    int i, ret = 0;

    for (i = 0; i < MAX_UVHOST_FDS; i++) {
        if (fd_arr[i].uvh_fd == -1) {
            continue;
        }

        if (FD_ISSET(fd_arr[i].uvh_fd, fdset_ptr)) {
            ret = fd_arr[i].uvh_fd_fn(fd_arr[i].uvh_fd, fd_arr[i].uvh_fd_arg);
            if (ret)
                return fd_arr[i].uvh_fd;
        }
    }

    return 0;
}

/*
 * vr_uvh_call_fd_handlers - call the handler for each FD that is set upon
 * return from select().
 *
 * Returns 0 on success, -1 otherwise.
 */
int
vr_uvh_call_fd_handlers(void)
{
    int ret;

    ret = vr_uvh_call_fd_handlers_internal(uvh_rfds, &uvh_rfdset);
    if (ret)
        vr_uvhost_del_fd(ret, UVH_FD_READ);

    ret = vr_uvh_call_fd_handlers_internal(uvh_wfds, &uvh_wfdset);
    if (ret)
        vr_uvhost_del_fd(ret, UVH_FD_WRITE);

    return 0;
}
