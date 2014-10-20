/*
 * vr_uvhost_client.c - client handling in user space vhost server that
 * peers with the vhost client inside qemu (version 2.1 and later).
 *
 * Copyright (c) 2014 Juniper Networks, Inc. All rights reserved.
 */

#include <sys/socket.h>
#include <linux/vhost.h>
#include <stdint.h>
#include <string.h>

#include "qemu_uvhost.h"
#include "vr_uvhost_client.h"

#include <stddef.h>

static vr_uvh_client_t vr_uvh_clients[VR_UVH_MAX_CLIENTS];

/*
 * vr_uvhost_client_init - initialize the client array.
 */
void
vr_uvhost_client_init(void)
{
    int i;

    for (i = 0; i < VR_UVH_MAX_CLIENTS; i++) {
        vr_uvh_clients[i].vruc_fd = -1;
    }

    return;
}

/*
 * vr_uvhost_new_client - initializes state for a new user space vhost client 
 * fd is a file descriptor for the client socket. path is the UNIX domain
 * socket path. cidx is the index of the client.
 *
 * Returns a pointer to the client state on success, NULL otherwise.
 */
vr_uvh_client_t *
vr_uvhost_new_client(int fd, char *path, int cidx)
{
    if (cidx >= VR_UVH_MAX_CLIENTS) {
        return NULL;
    }

    if (vr_uvh_clients[cidx].vruc_fd != -1) {
        return NULL;
    }

    vr_uvh_clients[cidx].vruc_fd = fd;
    strncpy(vr_uvh_clients[cidx].vruc_path, path, VR_UNIX_PATH_MAX);

    return &vr_uvh_clients[cidx];
}

/*
 * vr_uvhost_del_client - removes a vhost client.
 *
 * Returns nothing.
 */
void
vr_uvhost_del_client(vr_uvh_client_t *vru_cl)
{
    vru_cl->vruc_fd = -1;

    return;
}

/*
 * vr_uvhost_cl_set_fd - set the fd for a user space vhost client
 */
void
vr_uvhost_cl_set_fd(vr_uvh_client_t *vru_cl, int fd)
{
    vru_cl->vruc_fd = fd;

    return;
}

/*
 * vr_uvhost_get_client - Returns the client at the specified index, NULL if
 * it cannot be found.
 */
vr_uvh_client_t *
vr_uvhost_get_client(unsigned int cidx)
{
    if (cidx >= VR_UVH_MAX_CLIENTS) {
        return NULL;
    }

    return &vr_uvh_clients[cidx];
} 
