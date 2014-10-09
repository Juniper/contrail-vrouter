/*
 * vr_dpdk_flow_mem.c -- memory allocation for flow table
 *
 * Copyright(c) 2014, Juniper Networks Inc.,
 * All rights reserved
 */
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "vr_dpdk.h"

#include "vr_btable.h"

#define MAX_LINE_SIZE   128
#define HPI_MAX         16
#define MOUNT_TABLE     "/proc/mounts"

struct vr_hugepage_info {
    char *mnt;
    unsigned int page_size;
    unsigned int num_pages;
    unsigned int size;
} vr_hugepage_md[HPI_MAX];

extern struct vr_btable *vr_flow_table;
extern struct vr_btable *vr_oflow_table;
extern unsigned char *vr_flow_path;

static int
vr_hugepage_info_init(void)
{
    unsigned int i = 0, multiple = 1;
    char *str, *token;

    char *dev, *mnt, *fs, *options, *size;
    char *size_attr, *sys_hp_file;
    FILE *fp = NULL, *sys_fp = NULL;
    struct vr_hugepage_info *hp;

    char line[MAX_LINE_SIZE];
    char nr_pages[MAX_LINE_SIZE];


    fp = fopen(MOUNT_TABLE, "r");
    if (!fp)
        return -errno;

    while (fgets(line, MAX_LINE_SIZE, fp)) {
        if (i >= HPI_MAX)
            break;

        if ((str = strstr(line, "hugetlbfs"))) {
            hp = &vr_hugepage_md[i++];
            dev = strtok(line, " ");
            mnt = strtok(NULL, " ");
            fs = strtok(NULL, " ");
            options = strtok(NULL, " ");

            RTE_SET_USED(fs);
            RTE_SET_USED(dev);
            RTE_SET_USED(token);

            hp->mnt = malloc(strlen(mnt) + 1);
            memcpy(hp->mnt, mnt, strlen(mnt) + 1);

            if (strstr(options, "pagesize=1G")) {
                hp->page_size = (1024 * 1024 * 1024);
                sys_hp_file =
                    "/sys/kernel/mm/hugepages/hugepages-1048576kB/nr_hugepages";
            } else {
                hp->page_size = (2 * 1024 * 1024);
                sys_hp_file =
                    "/sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages";
            }

            size = strstr(options, "size=");
            if (size && (size != options) && (*(size - 1) != ','))
                size = strstr(size + 1, "size=");

            if (size && ((size == options) || (*(size - 1) == ','))) {
                size += strlen("size=");
                size = strtok(size, ",");
                size_attr = size + strlen(size) - 1;
                switch (*size_attr) {
                case 'k':
                case 'K':
                    multiple = 1024;
                    *size_attr = '\0';
                    break;

                case 'M':
                case 'm':
                    multiple = 1024 * 1024;
                    *size_attr = '\0';
                    break;

                case 'G':
                case 'g':
                    multiple = 1024 * 1024 * 1024;
                    *size_attr = '\0';
                    break;
                }

                hp->size = strtoul(size, NULL, 0) * multiple;
                hp->num_pages = hp->size / hp->page_size;
            } else {
                sys_fp = fopen(sys_hp_file, "r");
                if (!sys_fp)
                    goto exit_func;

                str = fgets(nr_pages, MAX_LINE_SIZE, sys_fp);
                if (str == NULL)
                    goto exit_func;
                hp->num_pages = strtoul(nr_pages, NULL, 0);
                hp->size = hp->num_pages * hp->page_size;
            }

        }
    }

exit_func:
    if (fp)
        fclose(fp);

    if (sys_fp)
        fclose(sys_fp);

    return 0;
}

int
vr_dpdk_flow_mem_init(void)
{
    int ret, i, fd;
    unsigned int num_sizes;
    size_t size, flow_table_size;
    struct vr_hugepage_info *hpi;
    char *file_name, *touse_file_name = NULL;
    struct stat f_stat;

    RTE_SET_USED(num_sizes);

    ret = vr_hugepage_info_init();
    if (ret < 0) {
        fprintf(stderr, "Error initializing hugepage info: %s (%d)\n",
            strerror(-ret), -ret);
        return ret;
    }

    flow_table_size = VR_FLOW_TABLE_SIZE + VR_OFLOW_TABLE_SIZE;

    for (i = 0; i < HPI_MAX; i++) {
        hpi = &vr_hugepage_md[i];
        if (!hpi->mnt)
            continue;
        file_name = malloc(strlen(hpi->mnt) + strlen("/flow") + 1);
        sprintf(file_name, "%s/flow", hpi->mnt);
        if (stat(file_name, &f_stat)) {
            if (!touse_file_name) {
                size = hpi->size;
                if (size >= flow_table_size) {
                    touse_file_name = file_name;
                } else {
                    free(file_name);
                }
            }
        } else {
            touse_file_name = file_name;
            break;
        }
    }

    if (touse_file_name) {
        fd = open(touse_file_name, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
        if (fd == -1) {
            fprintf(stderr, "Error opening file %s: %s (%d)\n",
                touse_file_name, strerror(errno), errno);
            return -errno;
        }
        vr_dpdk.flow_table = mmap(NULL, flow_table_size, PROT_READ | PROT_WRITE,
                MAP_SHARED, fd, 0);
        if (vr_dpdk.flow_table == MAP_FAILED) {
            fprintf(stderr, "Error mmapping file %s: %s (%d)\n",
                touse_file_name, strerror(errno), errno);
            return -errno;
        }
        bzero(vr_dpdk.flow_table, flow_table_size);
        vr_flow_path = (unsigned char *)touse_file_name;
    }

    if (!vr_dpdk.flow_table)
        return -ENOMEM;

    return 0;
}

int
vr_dpdk_flow_init(void)
{
    struct iovec iov;

    iov.iov_base = vr_dpdk.flow_table;
    iov.iov_len = VR_FLOW_TABLE_SIZE;
    vr_flow_table = vr_btable_attach(&iov, 1, sizeof(struct vr_flow_entry));
    if (!vr_flow_table)
        return -1;

    iov.iov_base = ((unsigned char *)vr_dpdk.flow_table + VR_FLOW_TABLE_SIZE);
    iov.iov_len = VR_OFLOW_TABLE_SIZE;
    vr_oflow_table = vr_btable_attach(&iov, 1, sizeof(struct vr_flow_entry));
    if (!vr_oflow_table)
        return -1;

    return 0;
}
