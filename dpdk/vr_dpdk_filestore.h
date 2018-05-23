/*
 * vr_dpdk_filestore.h - header for persistent store
 * to store/retrieve the VM feature set.
 *
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */

#ifndef __VR_DPDK_FILESTORE_H__
#define __VR_DPDK_FILESTORE_H__

int vr_dpdk_store_persist_feature(char *tapdev_name, unsigned long feature_set);
int vr_dpdk_load_persist_feature(char *tapdev_name, unsigned long *feature_set);
void vr_dpdk_del_persist_feature(char *tapdev_name);

#endif /* __VR_DPDK_FILESTORE_H__ */
