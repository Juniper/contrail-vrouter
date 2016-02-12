/*
 * vr_uvhost_client.h - header file for client state handling in user
 * space vhost server that peers with the vhost client inside qemu (version
 * 2.1 and later).
 *
 * Copyright (c) 2014 Juniper Networks, Inc. All rights reserved.
 */

#ifndef __VR_UVHOST_CLIENT_H__
#define __VR_UVHOST_CLIENT_H__

#include "qemu_uvhost.h"
#include "vr_dpdk_usocket.h"

/*
 * VR_UVH_MAX_CLIENTS needs to be the same as VR_MAX_INTERFACES.
 */
#define VR_UVH_MAX_CLIENTS VR_MAX_INTERFACES
#define VR_UVH_VIF_PREFIX VR_SOCKET_DIR"/uvh_vif_"

typedef struct vr_uvh_client_mem_region {
    uint64_t vrucmr_phys_addr;
    uint64_t vrucmr_size;
    uint64_t vrucmr_size_aligned;
    uint64_t vrucmr_user_space_addr;
    uint64_t vrucmr_mmap_addr;
    void    *vrucmr_mmap_addr_aligned;
    uint64_t vrucmr_blksize;            /**< FD block size */
} vr_uvh_client_mem_region_t;

typedef struct vr_uvh_client {
    int vruc_fd;
    char vruc_path[VR_UNIX_PATH_MAX];
    char vruc_cmsg[CMSG_SPACE(VHOST_MEMORY_MAX_NREGIONS * sizeof(int))];
    int vruc_msg_bytes_read;
    int vruc_fds_sent[VHOST_MEMORY_MAX_NREGIONS];
    int vruc_num_fds_sent;
    int vruc_num_mem_regions;
    vr_uvh_client_mem_region_t vruc_mem_regions[VHOST_MEMORY_MAX_NREGIONS];
    VhostUserMsg vruc_msg;

    unsigned int vruc_idx;
    unsigned int vruc_nrxqs;
    unsigned int vruc_ntxqs;
    pthread_t vruc_owner;
#define VR_UVH_CLIENT_STARTED 1U
    uint32_t vruc_flags;
} vr_uvh_client_t;

#define vr_uvhost_client_name(vru_cl) (vru_cl->vruc_path + strlen(VR_UVH_VIF_PREFIX))

void vr_uvhost_client_init(void);
vr_uvh_client_t *vr_uvhost_new_client(int fd, char *path, int cidx);
void vr_uvhost_del_client(vr_uvh_client_t *vru_cl);
void vr_uvhost_cl_set_fd(vr_uvh_client_t *vru_cl, int fd);
vr_uvh_client_t *vr_uvhost_get_client(unsigned int cidx);
int vr_uvhost_client_mmap(vr_uvh_client_t *vru_cl);
int vr_uvhost_client_stop(vr_uvh_client_t *vru_cl, bool force);
int vr_uvhost_client_start(vr_uvh_client_t *vru_cl);

#endif /* __VR_UVHOST_CLIENT_H__ */

