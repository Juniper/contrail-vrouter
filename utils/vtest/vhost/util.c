/*
 * util.c
 *
 *  The following procedures we actually do not need -> vRouter is in polling mode
 *
 *  Procedures creates sockets listen on them.
 *
 *
 * Copyright (c) 2016 Juniper Networks, Inc. All rights reserved.
 */

#include <sys/select.h>
#include "util.h"
#include "virt_queue.h"

//todo select()

int
utils_init_fd_rw_t(fd_rw_t *fd_rw_list, struct timeval tv) {

    fd_rw_t *const l_fd_rw_list = fd_rw_list;

    if (!fd_rw_list) {
        return E_UTILS_ERR_FARG;
    }

    FD_ZERO(&(fd_rw_list->rwfd_set[FD_TYPE_READ]));
    FD_ZERO(&(fd_rw_list->rwfd_set[FD_TYPE_WRITE]));

    l_fd_rw_list->rwfdmax = -2;
    l_fd_rw_list->tv = tv;

    for (size_t j = 0; j  < FD_TYPE_MAX; j++ ) {
        for (size_t i = 0; i < FD_LIST_SIZE; i++) {
            l_fd_rw_list->rwfds[j][i].fd = -2;
            l_fd_rw_list->rwfds[j][i].context = NULL;
            l_fd_rw_list->rwfds[j][i].fd_handler = 0;
        }
    }

    return E_UTILS_OK;
}

int
utils_init_fd_rw_element(fd_rw_element *fd_rw_element) {

    if (!fd_rw_element) {
        return E_UTILS_ERR_FARG;
    }

    return E_UTILS_OK;
}


int
utils_add_fd_to_fd_rw_t(fd_rw_t *fd_rw_list, fd_type fd_type, int fd,
                         void* context, fd_handler fd_handler) {

    fd_rw_t *const l_fd_rw_list = fd_rw_list;
    fd_rw_element *l_fd_rw_element = NULL;

    if (!fd_rw_list) {
        return E_UTILS_ERR_FARG;
    }

    if ((fd_type == FD_TYPE_READ) || (fd_type == FD_TYPE_WRITE)) {
        l_fd_rw_element = l_fd_rw_list->rwfds[FD_TYPE_READ];

    } else {
        return E_UTILS_ERR_FARG;
    }

    for (size_t i = 0; i < FD_LIST_SIZE; i++) {

        if (!(l_fd_rw_element->fd < 0)) {
            continue;
        }

        l_fd_rw_element->fd = fd;
        l_fd_rw_element->context = context;
        l_fd_rw_element->fd_handler = fd_handler;

        if (l_fd_rw_list->rwfdmax < fd) {
            l_fd_rw_list->rwfdmax = fd;
        }
        return E_UTILS_OK;
    }

    return E_UTILS_ERR_FD_ADD;
}

static int
utils_add_fd_to_fdset(fd_rw_t *fd_rw_list) {

    int *rw_fd = NULL;
    fd_set *wr_fds = NULL;
    if (!fd_rw_list) {
        return E_UTILS_ERR_FARG;
    }
    wr_fds = fd_rw_list->rwfd_set;

    for (size_t type = 0; type < FD_TYPE_MAX; type++) {
        FD_ZERO(&wr_fds[type]);
        for (size_t i = 0; i < FD_LIST_SIZE; i++) {
            rw_fd = &fd_rw_list->rwfds[type][i].fd;
            if (!(*rw_fd< 0)) {
                continue;
            }
            FD_SET(*rw_fd, &wr_fds[type]);
            fd_rw_list->rwfdmax = (fd_rw_list->rwfdmax > *rw_fd?
                    fd_rw_list->rwfdmax : *rw_fd);

        }
    }
    return E_UTILS_OK;
}

int
utils_travers_fd_rw_t(fd_rw_t *fd_rw_list) {

    fd_set *wr_fds;

    fd_rw_t *const l_fd_rw_list = fd_rw_list;
    fd_rw_element *fd_rw_element = NULL;
    int select_return = 0;

    if (!fd_rw_list) {
        return E_UTILS_ERR_FARG;
    }

    wr_fds = l_fd_rw_list->rwfd_set;
    utils_add_fd_to_fdset(fd_rw_list);

    select_return = select(l_fd_rw_list->rwfdmax, &wr_fds[FD_TYPE_WRITE],
            &wr_fds[FD_TYPE_MAX], 0, &l_fd_rw_list->tv);

    if (select_return > 0) {
        for (size_t type = 0; type < FD_TYPE_MAX; type++) {
            for (size_t i = 0; i < FD_LIST_SIZE; i++) {
                fd_rw_element = &fd_rw_list->rwfds[type][i];
                if (FD_ISSET(fd_rw_element->fd, &wr_fds[type])){
                    fd_rw_element->fd_handler(fd_rw_element->context);
                }
            }
        }
    } else if (!select_return) {
    //TODO timeout
    ;;
    } else {
      //TODO something wrong select()
    ;;
    }
    return E_UTILS_OK;
}

