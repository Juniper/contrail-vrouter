/*
 * Copyright (C) 2014 Semihalf.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation version 2.
 *
 * This program is distributed "as is" WITHOUT ANY WARRANTY of any
 * kind, whether express or implied; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * vr_shmem -- to share flow tables with the Agent
 */

#ifndef __VR_SHMEM_H__
#define __VR_SHMEM_H__

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <limits.h>

/* mmap file mode */
#define SHMEM_FILE_MODE            (S_IRUSR | S_IWUSR)

/* TODO: we use static vrouter ID 0 as there is no such a function
 * in the vrouter?
 */
static inline int
vr_shmem_get_vrouter_id(void)
{
    return 0;
}

/*
 * Allocate shared memory i.e. create or open shared memory object
 */
inline void *
vr_shmem_alloc(const char *name, size_t size)
{
    int fd, ret;
    void *shmem;
    char fname[PATH_MAX];

    /* append current vrouter ID to the name */
    ret = snprintf(fname, PATH_MAX, "%s.%i", name,
        vr_shmem_get_vrouter_id());
    if (0 > ret) {
        return NULL;
    }
    if (PATH_MAX <= ret) {
        return NULL;
    }

    /* open shared memory object or create a new one */
    fd = shm_open(fname, O_RDWR | O_CREAT, SHMEM_FILE_MODE);
    if (0 > fd) {
        return NULL;
    }

    /* set file size */
    if (0 > ftruncate(fd, size)) {
        close(fd);
        return NULL;
    }

    /* mmap file */
    shmem = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    /* close file descriptor */
    close(fd);

    return shmem;
}

/*
 * Free shared memory i.e. unmap shared memory object
 */
inline void
vr_shmem_free(void *shmem, size_t size)
{
    munmap(shmem, size);
}

#endif
