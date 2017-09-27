/*
 * vr_uvhost_util.c - utils for user-space vhost server that peers with
 * the vhost client inside qemu (version 2.1 and later).
 *
 * Copyright (c) 2014 Juniper Networks, Inc. All rights reserved.
 */

#include "vr_dpdk.h"
#include "vr_uvhost_util.h"

typedef struct uvh_fd_s {
    int uvh_fd;
    void *uvh_fd_arg;
    uvh_fd_handler_t uvh_fd_fn;
} uvh_fd_t;

/* Global variables */
static uvh_fd_t uvh_rfds[MAX_UVHOST_FDS];
static uvh_fd_t uvh_wfds[MAX_UVHOST_FDS];

/*
 * vr_uvhost_log - logs user space vhost messages to a file.
 */
void
vr_uvhost_log(const char *format, ...)
{
    va_list args;

    if (RTE_LOGTYPE_UVHOST & rte_logs.type) {
        char buf[VR_DPDK_STR_BUF_SZ] = "UVHOST: ";

        strncat(buf, format, sizeof(buf) - strlen(buf) - 1);
        buf[sizeof(buf) - 1] = '\0';

        va_start(args, format);
        rte_vlog(RTE_LOG_INFO, RTE_LOGTYPE_UVHOST, buf, args);
        va_end(args);
    }
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

    RTE_LOG_DP(DEBUG, UVHOST, "Deleting FD %d...\n", fd);
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
    fds[i].uvh_fd_arg = NULL;

    close(fd);

    return 0;
}

/*
 * vr_uvhost_del_fds_by_arg - deletes all FDs from the read/write lists matching
 * the given argument (pointer to a client). All the FDs found will be closed.
 *
 * Returns 0 on success, -1 otherwise.
 */
int
vr_uvhost_del_fds_by_arg(void *arg)
{
    int i;

    for (i = 0; i < MAX_UVHOST_FDS; i++) {
        if (uvh_rfds[i].uvh_fd > 0 && uvh_rfds[i].uvh_fd_arg == arg)
            vr_uvhost_del_fd(uvh_rfds[i].uvh_fd, UVH_FD_READ);
        if (uvh_wfds[i].uvh_fd > 0 && uvh_wfds[i].uvh_fd_arg == arg)
            vr_uvhost_del_fd(uvh_wfds[i].uvh_fd, UVH_FD_WRITE);
    }

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

    RTE_LOG_DP(DEBUG, UVHOST, "Adding FD %d...\n", fd);
    if (fd_type == UVH_FD_READ) {
        fds = uvh_rfds;
    } else if (fd_type == UVH_FD_WRITE) {
        fds = uvh_wfds;
    } else {
        return -1;
    }

    for (i = 0; i < MAX_UVHOST_FDS; i++) {
        if (fds[i].uvh_fd == fd || fds[i].uvh_fd == -1) {
            fds[i].uvh_fd = fd;
            fds[i].uvh_fd_arg = fd_handler_arg;
            fds[i].uvh_fd_fn = fd_handler;

            return 0;
        }
    }

    vr_uvhost_log("Error adding FD %d: no room for a new FD\n", fd);

    return -1;
}

/*
 * vr_uvhost_fds_init - initializes the read and write fds before
 * we enter the poll loop.
 */
void
vr_uvhost_fds_init(void)
{
    int i;

    for (i = 0; i < MAX_UVHOST_FDS; i++) {
        uvh_rfds[i].uvh_fd = -1;
        uvh_wfds[i].uvh_fd = -1;
    }

    return;
}

/*
 * vr_uvh_call_fd_handlers_internal - call the handler associated with the 
 * given fd. 
 *
 * Returns 0 on success, -1 otherwise.
 */
static int
vr_uvh_call_fd_handlers_internal(uvh_fd_t *fd_arr, int fd)
{
    int i, ret = 0;

    for (i = 0; i < MAX_UVHOST_FDS; i++) {
        if (fd_arr[i].uvh_fd != fd) {
            continue;
        }

        ret = fd_arr[i].uvh_fd_fn(fd_arr[i].uvh_fd, fd_arr[i].uvh_fd_arg);
        if (ret) {
            return -1;
        } else {
            return 0;
        }
    }

    return -1;
}

/*
 * vr_uvh_call_fd_handlers - call the handler for each FD that is set upon
 * return from poll().
 *
 * Returns nothing.
 */
void
vr_uvh_call_fd_handlers(struct pollfd *fds, nfds_t nfds)
{
    unsigned int i;
    int ret;

    for (i = 0; i < nfds; i++) {
        if (fds[i].fd >= 0) {
            if (fds[i].revents & POLLIN) {
                ret = vr_uvh_call_fd_handlers_internal(uvh_rfds, fds[i].fd);
                if (ret) {
                    vr_uvhost_del_fd(fds[i].fd, UVH_FD_READ);
                }
            }
        }
    }

    return;
}

/*
 * vr_uvh_init_pollfds - initializes the array to pass to poll based on the
 * state of the fds.
 *
 * Returns nothing.
 */
void
vr_uvh_init_pollfds(struct pollfd *fds, nfds_t *nfds)
{
    unsigned int i, count = 0;

    for (i = 0; i < MAX_UVHOST_FDS; i++) {
        if (uvh_rfds[i].uvh_fd != -1) {
            fds[count].fd = uvh_rfds[i].uvh_fd;
            fds[count].events = POLLIN;
            count++;
        }
    }

    *nfds = count;

    return;
}
