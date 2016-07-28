
/*
 * client.h
 *
 * Copyright (c) 2015 Juniper Networks, Inc. All rights reserved.
*/
#ifndef CLIENT_H
#define CLIENT_H

#include <unistd.h>
#include <sys/socket.h>

#include "util.h"
#include "uvhost.h"

/* FDs First initialization value
 *
 * The value is set, cause to be sure, that FD is not opened and/or
 * the function open does not returns an error.
 *
 */
#define CLIENT_INIT_FD_VAL (-2)
#define QEMU_PROT_VERSION (0x01)

typedef struct Client {
    char socket_path[UNIX_PATH_MAX];
    int socket;
    char sh_mem_path[UNIX_PATH_MAX];
    int sh_mem_fds[VHOST_MEMORY_MAX_NREGIONS];
} Client;


typedef enum {
    E_CLIENT_OK = EXIT_SUCCESS,
    E_CLIENT_ERR,
    E_CLIENT_ERR_ALLOC,
    E_CLIENT_ERR_UNK,
    E_CLIENT_ERR_FARG,
    E_CLIENT_ERR_SOCK,
    E_CLIENT_ERR_CONN,
    E_CLIENT_ERR_IOCTL_SEND,
    E_CLIENT_ERR_IOCTL_REPLY,
    E_CLIENT_ERR_VIOCTL,
    E_CLIENT_VIOCTL_REPLY,
    E_CLIENT_LAST
} CLIENT_H_RET_VAL;

int client_close_fds(Client *client);
int client_disconnect_socket(Client *client);
int client_init_Client(Client *client, const char *path);
int client_vhost_ioctl(Client *client, VhostUserRequest request, void *req_ptr);
#endif

