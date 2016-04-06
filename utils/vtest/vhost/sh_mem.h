/*
 * sh_mem.h
 *
 * Copyright (c) 2015 Juniper Networks, Inc. All rights reserved.
 */
#ifndef SHM_MEM_H
#define SHM_MEM_H

#include <stdlib.h>


typedef enum {
    E_SH_MEM_OK = EXIT_SUCCESS,
    E_SH_MEM_ERR_UNK,
    E_SH_MEM_ERR_FARG,
    E_SH_MEM_ERR_SHM_OPEN,
    E_SH_MEM_ERR_SHM_UNMAP,
    E_SH_MEM_ERR_SHM_UNLINK,
    E_SH_MEM_LAST
} SH_MEM_H_RET_VAL;

int sh_mem_init_fd(const char* file_path, int *fd);
int sh_mem_unlink(const char *path);

void* sh_mem_mmap(int fd, size_t length);
int sh_mem_unmmap(void *mem_ptr, size_t length);

#endif

