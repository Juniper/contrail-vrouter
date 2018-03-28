/*
 * vr_dpdk_filestore.c - implements a persistent store
 * to store/retrieve the VM feature set.
 *
 * Copyright (c) 2014 Juniper Networks, Inc. All rights reserved.
 */

/* For sched_getaffinity() */
#define _GNU_SOURCE

#include <stdint.h>
#include <getopt.h>
#include <signal.h>
#include <sys/time.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

#include "vr_dpdk.h"
#define FEATURE_STORE_PATH "/var/lib/contrail/vm_feature"

int vr_dpdk_store_feature(char *tapdev_name, unsigned long feature_set)
{
    char fname[NAME_MAX];
    struct stat fstat;
    FILE *fp;

    if (stat(FEATURE_STORE_PATH, &fstat) != 0) {
        if (mkdir(FEATURE_STORE_PATH, 0755) < 0) {
            RTE_LOG(ERR, USOCK, "mkdir failed with error %d\n", errno);
        }
    }
    if (snprintf(fname, NAME_MAX, FEATURE_STORE_PATH"/%s", tapdev_name) < 0)
        return -1;
    RTE_LOG_DP(DEBUG, USOCK, "Write %s\n", fname);
    fp = fopen(fname, "w");
    if (fp == NULL) {
        return -1;
    }
    rewind(fp);
    fprintf(fp, "%016lx", feature_set);
    fclose(fp);
    return 0;
}

int vr_dpdk_load_feature(char *tapdev_name, unsigned long *feature_set)
{
    char fname[NAME_MAX];
    struct stat fstat;
    FILE *fp;

    if (stat(FEATURE_STORE_PATH, &fstat) != 0) {
        if (mkdir(FEATURE_STORE_PATH, 0755) < 0) {
            RTE_LOG(ERR, USOCK, "mkdir failed with error %d\n", errno);
        }
    }
    if (snprintf(fname, NAME_MAX, FEATURE_STORE_PATH"/%s", tapdev_name) < 0)
        return -1;
    RTE_LOG_DP(DEBUG, USOCK, "Read %s\n", fname);
    if (stat(fname, &fstat) == 0) {
        fp = fopen(fname, "r");
        if (fp == NULL) {
            return -1;
        }
        rewind(fp);
        if(fscanf(fp, "%016lx", feature_set) == EOF) {
            if (errno) {
                RTE_LOG(ERR, USOCK, "EOF reached with error %d\n", errno);
                fclose(fp);
                return -1;
            }
        }
        RTE_LOG_DP(DEBUG, USOCK, "Feature Set Read %lx\n", *feature_set);
        fclose(fp);
        return 0;
    } else {
        return -1;
    }
}
