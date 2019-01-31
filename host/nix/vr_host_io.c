/*
 * vr_host_io.c -- simplistic io scheduler
 *
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#include <string.h>
#include <poll.h>
#include <errno.h>
#include <stdbool.h>

#define VR_MAX_IO_CBS      256

struct vr_io_cb {
    int io_fd;
    int (*io_process)(void *);
    void *io_arg;
} vr_io_cbs[VR_MAX_IO_CBS];

unsigned int pollfd_to_cb[VR_MAX_IO_CBS];
struct pollfd vr_io_pollfds[VR_MAX_IO_CBS];
unsigned int vr_io_n_pollfds;

void
vhost_remove_xconnect(void)
{
    return;
}

void
vr_host_io_unregister(int fd)
{
    int i;
    struct pollfd *pfd;

    for (i = 0; i < VR_MAX_IO_CBS; i++) {
        pfd = &vr_io_pollfds[i];
        if (pfd->fd == fd) {
            memcpy((char *)pfd, (char *)(pfd + 1),
                    (vr_io_n_pollfds - (i + 1)) * sizeof(struct pollfd));
            memcpy((char *)&pollfd_to_cb[i], (char *)&pollfd_to_cb[i + 1],
                        (vr_io_n_pollfds - (i + 1)) * sizeof(unsigned int));

            vr_io_n_pollfds--;

            bzero((char *)&pollfd_to_cb[vr_io_n_pollfds],
                    (VR_MAX_IO_CBS - vr_io_n_pollfds) * sizeof(unsigned int));
            bzero((char *)&vr_io_pollfds[vr_io_n_pollfds],
                    (VR_MAX_IO_CBS - vr_io_n_pollfds) * sizeof(struct pollfd));
            break;
        }
    }

    return;
}

int
vr_host_io_register(unsigned int fd, int (*cb)(void *), void *arg)
{
    int i;
    struct vr_io_cb *io_cb;
    struct pollfd *pfd;

    if (vr_io_n_pollfds >= VR_MAX_IO_CBS)
        return -ENOSPC;

    for (i = 0; i < VR_MAX_IO_CBS; i++) {
        io_cb = &vr_io_cbs[i];
        if (io_cb->io_fd < 0) {
            io_cb->io_fd = fd;
            io_cb->io_process = cb;
            io_cb->io_arg = arg;
            pollfd_to_cb[vr_io_n_pollfds] = i;
            break;
        }
    }

    if (i == VR_MAX_IO_CBS)
        return -ENOSPC;

    /* setup the pollfd */
    pfd = &vr_io_pollfds[vr_io_n_pollfds++];
    pfd->fd = fd;
    pfd->events = POLLIN;
    pfd->revents = 0;

    return 0;
}

int
vr_host_io_init(void)
{
    int i;
    struct vr_io_cb *io_cb;

    for (i = 0; i < VR_MAX_IO_CBS; i++) {
        io_cb = &vr_io_cbs[i];
        io_cb->io_fd  = -1;
    }

    return 0;
}

int
vr_host_io(void)
{
    int ret, processed = 0;
    unsigned int i;
    struct pollfd *p_pfd;
    struct vr_io_cb *io_cb;

    while (true) {
        ret = poll(vr_io_pollfds, vr_io_n_pollfds, -1);
        if (ret < 0)
            return ret;

        for (i = 0; i < vr_io_n_pollfds; i++) {
            p_pfd = &vr_io_pollfds[i];
            if (p_pfd->revents & POLLIN) {
                io_cb = &vr_io_cbs[pollfd_to_cb[i]];
                io_cb->io_process(io_cb->io_arg);
            }

            if (++processed == ret)
                break;
        }
    }

    return 0;
}
