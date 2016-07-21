/*
 * client.c
 *
 *  Initialization procedures for Client data structure
 *  and communication procedures witth virtio device.
 *
 * Copyright (c) 2015 Juniper Networks, Inc. All rights reserved.
*/

#include <errno.h>
#include <libgen.h>
#include <linux/vhost.h>
#include <limits.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <linux/un.h>


#include "client.h"
#include "util.h"
#include "vhost_net.h"
#include "virtio_hdr.h"

static int client_connect_socket(Client *client);
static int client_init_socket(Client *client);
static int client_vhost_ioctl_set_recv_msg(VhostUserRequest request, void *req_ptr, VhostUserMsg *msg);
static int client_vhost_ioctl_recv_fds_handler(struct cmsghdr *cmsgh, int *fds, size_t *fd_num);
static int client_vhost_ioctl_send_fds(VhostUserMsg *msg, int fd, int *fds, size_t fd_num);
static int client_vhost_ioctl_set_send_msg(Client *client, VhostUserRequest request,
                         void *req_ptr, VhostUserMsg *msg, int *fd, size_t *fd_num);

static int client_init_path(Client *client, const char *path);
int
client_init_Client(Client *client, const char *path) {

    CLIENT_H_RET_VAL client_ret_val = E_CLIENT_OK;

    if (!client || !path) {
        fprintf(stderr, "%s(): Error initializing client: no client\n",
            __func__);
        return E_CLIENT_ERR_FARG;
    }

    client_ret_val = client_init_path(client, path);
    if (client_ret_val != E_CLIENT_OK) {
        return client_ret_val;
    }

    client_ret_val = client_init_socket(client);
    if (client_ret_val != E_CLIENT_OK) {
        return client_ret_val;
    }

    client_ret_val = client_connect_socket(client);
    if (client_ret_val != E_CLIENT_OK) {
        return client_ret_val;
    }
    memset(&client->sh_mem_fds,
            -2, sizeof(int) * VHOST_MEMORY_MAX_NREGIONS);

    return E_CLIENT_OK;
}


static int
client_init_path(Client *client, const char *path)
{
    if (!client || !path || strlen(path) == 0 || strlen(path) > (UNIX_PATH_MAX - 1)) {
        fprintf(stderr, "%s(): Error initializing client path: no client\n",
            __func__);
        return E_CLIENT_ERR_FARG;
    }
   strncpy(client->socket_path, path, sizeof(client->socket_path));
   strncpy(client->sh_mem_path, path, sizeof(client->sh_mem_path));

   return E_CLIENT_OK;
}

static int
client_init_socket(Client *client) {

    if (!client) {
        fprintf(stderr, "%s(): Error initializing client socket: no client\n",
            __func__);
        return E_CLIENT_ERR_FARG;
    }

    client->socket = socket(AF_UNIX, SOCK_STREAM, 0);
    if (client->socket == -1) {
        fprintf(stderr, "%s(): Error creating socket: %s (%d)\n",
            __func__, strerror(errno), errno);
        return E_CLIENT_ERR_SOCK;
    }
    return E_CLIENT_OK;

}

static int
client_connect_socket(Client *client) {

    struct sockaddr_un unix_socket;
    size_t addrlen = 0;
    struct stat unix_socket_stat;
    unsigned int connect_retry = 0;

    if (!client->socket || strlen(client->socket_path) == 0) {
        fprintf(stderr, "%s(): Error connecting socket: no socket\n",
            __func__);
        return E_CLIENT_ERR_FARG;
    }

    /* The fakechroot(1) utility does not support stat() syscals. */

    memset(&unix_socket, 0, sizeof(struct sockaddr_un));

    unix_socket.sun_family = AF_UNIX;
    strncpy(unix_socket.sun_path, client->socket_path, sizeof(unix_socket.sun_path) - 1);
    addrlen = strlen(unix_socket.sun_path) + sizeof(AF_UNIX);

    /**
     * Sometimes we try to connect before vRouter creates socket.
     * Try to connect couple of times before failing.
     */

    while (connect(client->socket, (struct sockaddr *)&unix_socket, addrlen)  == -1) {
        sleep(3);
        if (++connect_retry > 10) {
            fprintf(stderr, "%s(): Error connecting socket: %s (%d)\n",
                __func__, strerror(errno), errno);
            return E_CLIENT_ERR_CONN;
        }
    }

    return E_CLIENT_OK;
}

int
client_disconnect_socket(Client *client) {

    if (!client) {
        return E_CLIENT_ERR_FARG;
    }

    if (!(client->socket < 0)) {
        close(client->socket);
        client->socket = -2;
    }
    return E_CLIENT_OK;
}

int
client_close_fds(Client *client) {

    if (!client) {
        return E_CLIENT_ERR_FARG;
    }

    for (size_t i = 0; i < VHOST_MEMORY_MAX_NREGIONS; i++) {
        if (client->sh_mem_fds[i] >= 0 ) {
            close(client->sh_mem_fds[i]);
            client->sh_mem_fds[i] = -2;
        }
    }
    return E_CLIENT_OK;
}

int
client_vhost_ioctl(Client *client, VhostUserRequest request, void *req_ptr) {

    Client *const cl = client;
    int fds[VHOST_MEMORY_MAX_NREGIONS] = {-2};
    VhostUserMsg message;
    CLIENT_H_RET_VAL ret_val = E_CLIENT_OK;
    CLIENT_H_RET_VAL ret_set_val = E_CLIENT_VIOCTL_REPLY;
    size_t fd_num = 0;

    if (!client) {
        return E_CLIENT_ERR_FARG;
    }

    /* Function argument pointer (req_ptr) for following messages
     * SHOULD not be NULL. */
    switch (request) {
        case VHOST_USER_SET_MEM_TABLE:
        case VHOST_USER_SET_LOG_BASE:
        case VHOST_USER_SET_LOG_FD:
        case VHOST_USER_SET_VRING_KICK:
        case VHOST_USER_SET_VRING_CALL:
        case VHOST_USER_SET_VRING_ERR:
            if (!req_ptr) {
                return E_CLIENT_ERR_FARG;
            }
            break;

        default:
            break;
    }

    memset(&message, 0, sizeof(VhostUserMsg));

    message.request = request;
    message.flags &= ~VHOST_USER_VERSION_MASK;
    message.flags |= QEMU_PROT_VERSION;

    /* Set message structure for sending data. */
    ret_set_val = client_vhost_ioctl_set_send_msg(cl, request, req_ptr, &message, fds, &fd_num);

    if (!(ret_set_val == E_CLIENT_OK || ret_set_val == E_CLIENT_VIOCTL_REPLY)) {
        return E_CLIENT_ERR_VIOCTL;
    }

    ret_val = client_vhost_ioctl_send_fds(&message, cl->socket, fds, fd_num );
    if (ret_val != E_CLIENT_OK) {
        return ret_val;
    }

    if (ret_set_val == E_CLIENT_VIOCTL_REPLY) {

        /* Set message structure after receive data */
        ret_val = client_vhost_ioctl_set_recv_msg(request, req_ptr, &message);
        if (!(ret_val == E_CLIENT_OK)) {
            return E_CLIENT_ERR_VIOCTL;
        }


    }

    return E_CLIENT_OK;
}

static int
client_vhost_ioctl_set_send_msg(Client *client, VhostUserRequest request, void *req_ptr,
                     VhostUserMsg *msg, int *fds, size_t *fd_num ) {

    VhostUserMsg *const message = msg;
    bool msg_has_reply = false;

    VhostUserMemory sizeof_VhostUserMem = {0};
    VhostUserMsg sizeof_VhostUserMsg = {0};

    size_t *const l_fd_num = fd_num;
    struct vring_file {unsigned int index; int fd;} *file;

    if (!client || !msg || !fds || !fd_num) {

        return E_CLIENT_ERR_FARG;
    }

    switch (request) {

        case VHOST_USER_NONE:
            break;

        case VHOST_USER_GET_FEATURES:
        case VHOST_USER_GET_VRING_BASE:
            msg_has_reply = true;
            break;

        case VHOST_USER_SET_FEATURES:
        case VHOST_USER_SET_LOG_BASE:
            message->u64 = *((uint64_t *) req_ptr);
            message->size = sizeof(sizeof_VhostUserMsg.u64);
            /* if VHOST_USER_PROTOCOL_F_LOG_SHMFD
            msg_has_reply = true;
            */
            break;

        case VHOST_USER_SET_OWNER:
        case VHOST_USER_RESET_OWNER:
            break;

        case VHOST_USER_SET_MEM_TABLE:
            memcpy(&message->memory, req_ptr, sizeof(VhostUserMemory));
            message->size = sizeof(sizeof_VhostUserMem.padding);
            message->size += sizeof(sizeof_VhostUserMem.nregions);

            for (*l_fd_num = 0; *l_fd_num < message->memory.nregions; (*l_fd_num)++) {
                fds[*l_fd_num] = client->sh_mem_fds[*l_fd_num];
                message->size = message->size + sizeof(VhostUserMemoryRegion);
            }
            break;

        case VHOST_USER_SET_LOG_FD:
            fds[++(*l_fd_num)] = *((int *) req_ptr);
            break;

        case VHOST_USER_SET_VRING_NUM:
        case VHOST_USER_SET_VRING_BASE:
            memcpy(&message->state, req_ptr, sizeof(sizeof_VhostUserMsg.state));
            message->size = sizeof(sizeof_VhostUserMsg.state);
            break;

        case VHOST_USER_SET_VRING_ADDR:
            memcpy(&message->addr, req_ptr, sizeof(sizeof_VhostUserMsg.addr));
            message->size = sizeof(sizeof_VhostUserMsg.addr);
            break;

        case VHOST_USER_SET_VRING_KICK:
        case VHOST_USER_SET_VRING_CALL:
        case VHOST_USER_SET_VRING_ERR:
            file = req_ptr;
            message->u64 = file->index;
            message->size = sizeof(sizeof_VhostUserMsg.u64);
            if (file->fd > 0 ) {
                fds[(*l_fd_num)++] = file->fd;
            }
            break;

        default:
            return E_CLIENT_ERR_IOCTL_SEND;

    }
    if (msg_has_reply) {
       return E_CLIENT_VIOCTL_REPLY;
    }

    return E_CLIENT_OK;
}

int
client_vhost_ioctl_set_recv_msg(VhostUserRequest request, void *req_ptr, VhostUserMsg *msg) {

    VhostUserMsg *const message = msg;

    if (!msg) {

        return E_CLIENT_ERR_FARG;
    }

    switch (request) {
        case VHOST_USER_GET_FEATURES:
            *((uint64_t *) req_ptr) = message->u64;
            break;
        case VHOST_USER_GET_VRING_BASE:
            memcpy(req_ptr, &message->state, sizeof(struct vhost_vring_state));

        default:
            return E_CLIENT_ERR_IOCTL_REPLY;
    }

    return E_CLIENT_OK;
}

static int
client_vhost_ioctl_send_fds(VhostUserMsg *msg, int fd, int *fds, size_t fd_num) {

    struct iovec iov;
    struct msghdr msgh;
    struct cmsghdr *cmsgh = NULL;
    char controlbuf[CMSG_SPACE(fd_num * sizeof(int))];

    VhostUserMsg sizeof_VhostUserMsg = {0};

    size_t vhost_user_msg_member_size = ((sizeof(sizeof_VhostUserMsg.request)) +
    (sizeof(sizeof_VhostUserMsg.flags)) + (sizeof(sizeof_VhostUserMsg.size)));

    const VhostUserMsg *const message = msg;
    int ret = 0;

    if (!msg || !fds) {
        return E_CLIENT_ERR_FARG;
    }

    memset(controlbuf, 0, sizeof(controlbuf));
    memset(&msgh, 0, sizeof(struct msghdr));
    memset(&iov, 0, sizeof(struct iovec));

    iov.iov_base = (void *) message;
    iov.iov_len = vhost_user_msg_member_size + message->size;

    msgh.msg_iov = &iov;
    msgh.msg_iovlen = 1;

    if (fd_num) {
        msgh.msg_name = NULL;
        msgh.msg_namelen = 0;
        msgh.msg_control = controlbuf;
        msgh.msg_controllen = sizeof(controlbuf);

        cmsgh = CMSG_FIRSTHDR(&msgh);
        cmsgh->cmsg_len = CMSG_LEN(sizeof(int) * fd_num);
        cmsgh->cmsg_level = SOL_SOCKET;
        cmsgh->cmsg_type = SCM_RIGHTS;


        memcpy(CMSG_DATA(cmsgh), fds, sizeof(int) * fd_num);

    } else {
        msgh.msg_control = NULL;
        msgh.msg_controllen = 0;
    }

    do {
        ret = sendmsg(fd, &msgh, 0);

    } while (ret < 0 && errno == EINTR);

    if (ret < 0) {
        return E_CLIENT_ERR_IOCTL_SEND;
    }

    return E_CLIENT_OK;
}

