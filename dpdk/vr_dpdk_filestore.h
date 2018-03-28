/*
 * vr_dpdk_filestore.h - header for persistent store
 * to store/retrieve the VM feature set.
 *
 * Copyright (c) 2014 Juniper Networks, Inc. All rights reserved.
 */

#ifndef __VR_DPDK_FILESTORE_H__
#define __VR_DPDK_FILESTORE_H__

int vr_dpdk_store_feature(char *tapdev_name, unsigned long feature_set);
int vr_dpdk_load_feature(char *tapdev_name, unsigned long *feature_set);

#endif /* __VR_DPDK_FILESTORE_H__ */
