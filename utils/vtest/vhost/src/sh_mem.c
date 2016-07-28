/*
 * sh_mem.c
 *
 * Shared memory procedures initialization, link, unlink and mmap/unmmap.
 *
 * Copyright (c) 2015 Juniper Networks, Inc. All rights reserved.
 */

#include <errno.h>
#include <stdio.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>


#include "sh_mem.h"


int
sh_mem_init_fd(const char* file_path, int *fd) {

    int ret_fd = 0;

    if (!file_path || !fd) {
        fprintf(stderr, "%s(): Error initing shared memory: no file\n",
            __func__);
        return E_SH_MEM_ERR_FARG;
    }

   /*
    * Access permissions for shared memory is set to:
    *   rw-|---|---|
    */
    ret_fd = open(file_path, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR );
    if (ret_fd < 0 ) {
        fprintf(stderr, "%s(): Error initing shared memory: %s (%d)\n",
            __func__, strerror(errno), errno);
        return E_SH_MEM_ERR_SHM_OPEN;
    } else {
        *fd = ret_fd;
    }


    return E_SH_MEM_OK;
}

int
sh_mem_unlink(const char *path) {

    int ret = 0;

    if (!path) {
        return E_SH_MEM_ERR_FARG;
    }

    ret = unlink(path);
    if (ret != 0 )
        return E_SH_MEM_ERR_SHM_UNLINK;

    return E_SH_MEM_OK;
}

void *
sh_mem_mmap(int fd, size_t length) {

    if (ftruncate(fd, length)) {
        fprintf(stderr, "%s(): Error truncating shared memory file: %s (%d)\n",
            __func__, strerror(errno), errno);
        return NULL;
    }

    void *mmaped_mem = mmap(0, length, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

    if (mmaped_mem == MAP_FAILED) {
        fprintf(stderr, "%s(): Error mmapping shared memory: %s (%d)\n",
            __func__, strerror(errno), errno);
        return NULL;
    }

    return mmaped_mem;
}

int
sh_mem_unmmap(void *mem_ptr, size_t length) {

    if (!mem_ptr) {
        return E_SH_MEM_ERR_FARG;
    }

    int ret = 0;
    ret = munmap(mem_ptr, length);
    if (ret != 0 )
        return E_SH_MEM_ERR_SHM_UNMAP;

    mem_ptr = NULL;

    return E_SH_MEM_OK;
}

