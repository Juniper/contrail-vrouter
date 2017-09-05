/*
 * vr_dpdk_flow_mem.c -- memory allocation for flow table
 *
 * Copyright(c) 2014, Juniper Networks Inc.,
 * All rights reserved
 */

#include <stdint.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "vr_dpdk.h"
#include "vr_btable.h"
#include "vr_mem.h"
#include "nl_util.h"

#include <rte_errno.h>

#define MAX_LINE_SIZE   128
#define HPI_MAX         16
#define MOUNT_TABLE     "/proc/mounts"

struct vr_hugepage_info {
    char *mnt;
    size_t page_size;
    size_t size;
    uint32_t num_pages;
} vr_hugepage_md[HPI_MAX];

extern void *vr_flow_table, *vr_oflow_table;
extern void *vr_bridge_table, *vr_bridge_otable;
extern unsigned char *vr_flow_path, *vr_bridge_table_path;

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
vr_dpdk_table_mem_init(unsigned int table, unsigned int entries,
        unsigned long size, unsigned int oentries, unsigned long osize)
{
    int ret, i, fd;

    void **table_p;
    char shm_file[VR_UNIX_PATH_MAX];
    char *file_name, *touse_file_name = NULL;
    char *shmem_name, *hp_file_name;
    unsigned char **path;

    struct stat f_stat;
    struct vr_hugepage_info *hpi;

    if (!oentries) {
        oentries = (entries / 5 + 1023) & ~1023;
        osize = (size / entries) * oentries;
    }

    size += osize;

    switch (table) {
    case VR_MEM_FLOW_TABLE_OBJECT:
        shmem_name = "flow.shmem";
        hp_file_name = "flow";
        table_p = &vr_dpdk.flow_table;
        path = &vr_flow_path;
        vr_oflow_entries = oentries;
        break;

    case VR_MEM_BRIDGE_TABLE_OBJECT:
        shmem_name = "bridge.shmem";
        hp_file_name = "bridge";
        table_p = &vr_dpdk.bridge_table;
        path = &vr_bridge_table_path;
        vr_bridge_oentries = oentries;
        break;

    default:
        return -EINVAL;
    }

    if (no_huge_set) {
        /* Create a shared memory under the socket directory. */
        ret = snprintf(shm_file, sizeof(shm_file), "%s/%s",
                vr_socket_dir, shmem_name);
        if (ret >= sizeof(shm_file)) {
            RTE_LOG(ERR, VROUTER, "Error creating shared memory file\n");
            return -ENOMEM;
        }
        touse_file_name = shm_file;
    } else {
        ret = vr_hugepage_info_init();
        if (ret < 0) {
            RTE_LOG(ERR, VROUTER, "Error initializing hugepage info: %s (%d)\n",
                rte_strerror(-ret), -ret);
            return ret;
        }

        for (i = 0; i < HPI_MAX; i++) {
            hpi = &vr_hugepage_md[i];
            if (!hpi->mnt)
                continue;
            file_name = malloc(strlen(hpi->mnt) + strlen(hp_file_name) + 2);
            sprintf(file_name, "%s/%s", hpi->mnt, hp_file_name);
            if (stat(file_name, &f_stat) == -1) {
                if (!touse_file_name) {
                    if (hpi->size >= size) {
                        touse_file_name = file_name;
                    } else {
                        free(file_name);
                    }
                }
            } else {
                free(touse_file_name);
                touse_file_name = file_name;
                break;
            }
        }
    }

    if (touse_file_name) {
        fd = open(touse_file_name, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
        if (fd == -1) {
            RTE_LOG(ERR, VROUTER, "Error opening file \"%s\": %s (%d)\n",
                touse_file_name, rte_strerror(errno), errno);
            return -errno;
        }

        if (no_huge_set) {
            ret = ftruncate(fd, size);
            if (ret == -1) {
                RTE_LOG(ERR, VROUTER, "Error truncating file %s: %s (%d)\n",
                    touse_file_name, rte_strerror(errno), errno);
                return -errno;
            }
        }

        *table_p = mmap(NULL, size, PROT_READ | PROT_WRITE,
                MAP_SHARED, fd, 0);
        /* the file descriptor is no longer needed */
        close(fd);
        if (*table_p == MAP_FAILED) {
            RTE_LOG(ERR, VROUTER, "Error mmapping file %s: %s (%d)\n",
                touse_file_name, rte_strerror(errno), errno);
            return -errno;
        }
        memset(*table_p, 0, size);
        *path = (unsigned char *)touse_file_name;
    }

    return 0;
}

int
vr_dpdk_bridge_init(void)
{
    if (!vr_dpdk.bridge_table)
        return -1;

    vr_bridge_table = vr_dpdk.bridge_table;
    vr_bridge_otable = vr_dpdk.bridge_table + VR_BRIDGE_TABLE_SIZE;

    return 0;
}

int
vr_dpdk_flow_init(void)
{
    if (!vr_dpdk.flow_table)
        return -1;

    vr_flow_table = vr_dpdk.flow_table;
    vr_oflow_table = vr_dpdk.flow_table + VR_FLOW_TABLE_SIZE;

    if (!vr_flow_table)
        return -1;

    vr_flow_hold_limit = VR_DPDK_MAX_FLOW_TABLE_HOLD_COUNT;
    RTE_LOG(INFO, VROUTER, "Max HOLD flow entries set to %u\n",
            vr_flow_hold_limit);

    return 0;
}
