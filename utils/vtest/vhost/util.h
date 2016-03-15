/*
 * util.h
 * Copyright (c) 2016 Juniper Networks, Inc. All rights reserved.
 */
#ifndef UTIL_H
#define UTIL_H

#include <sys/time.h>
#include <stdlib.h>
#include <stdint.h>
#include <linux/un.h>

#define VHOST_USER_HDR_SIZE (sizeof(struct virtio_net_hdr))
#define VHOST_MEMORY_MAX_NREGIONS    8

#define VHOST_CLIENT_PAGE_SIZE \
        ALIGN(sizeof(struct uvhost_virtq) + VIRTQ_DESC_BUFF_SIZE * VIRTQ_DESC_MAX_SIZE, 1024 * 1024)

#define ALIGN(v,b)   (((long int)v + (long int)b - 1)&(-(long int)b))


#define FD_LIST_SIZE (16)

struct fd_rw_element;

typedef int (*fd_handler)(struct fd_rw_element *arg);

typedef enum {
    FD_TYPE_READ = 0,
    FD_TYPE_WRITE,
    FD_TYPE_MAX
} fd_type;

typedef struct fd_rw_element{
    int fd;
    void *context;
    fd_handler fd_handler;
} fd_rw_element;

typedef struct {
   fd_rw_element rwfds[FD_TYPE_MAX][FD_LIST_SIZE];
   fd_set rwfd_set[FD_TYPE_MAX];
   /* For select() purpose. */
   int rwfdmax;
   struct timeval tv;
} fd_rw_t;

typedef int (*poll_func_handler)(void *context, void *src_buf, size_t *src_buf_len);

struct uvhost_app_handler {
    void *context;
    poll_func_handler poll_func_handler;
};

typedef enum  {
    CLIENT_TYPE_RX,
    CLIENT_TYPE_TX,
    CLIENT_TYPE_LAST

} CLIENT_TYPE;

typedef struct {
    char socket_path[UNIX_PATH_MAX];
    int socket;
    char sh_mem_path[UNIX_PATH_MAX];
    int sh_mem_fds[VHOST_MEMORY_MAX_NREGIONS];
    fd_rw_t fd_rw_list;
    struct uvhost_app_handler vhost_net_app_handler;
} Client;

typedef enum {
    E_UTILS_OK = EXIT_SUCCESS,
    E_UTILS_ERR_ALLOC,
    E_UTILS_ERR_UNK,
    E_UTILS_ERR_FARG,
    E_UTILS_ERR,
    E_UTILS_ERR_FD_ADD,
    E_UTILS_LAST
} UTILS_H_RET_VAL;

int utils_init_fd_rw_t(fd_rw_t *fd_rw_list, struct timeval tv);
int utils_add_fd_to_fd_rw_t(fd_rw_t *fd_rw_list, fd_type fd_type, int fd,
                         void* fd_handler_arg, fd_handler fd_handler);
#endif

