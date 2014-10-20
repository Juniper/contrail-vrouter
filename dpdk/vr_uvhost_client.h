/*
 * vr_uvhost_client.h - header file for client state handling in user
 * space vhost server that peers with the vhost client inside qemu (version 
 * 2.1 and later).
 *
 * Copyright (c) 2014 Juniper Networks, Inc. All rights reserved.
 */

#ifndef __VR_UVHOST_CLIENT_H__
#define __VR_UVHOST_CLIENT_H__

/*
 * VR_UVH_MAX_CLIENTS needs to be the same as VR_MAX_INTERFACES.
 */
#define VR_UVH_MAX_CLIENTS (256 + 4096) 
#define VR_UNIX_PATH_MAX 108

typedef struct vr_uvh_client_mem_region {
    uint64_t vrucmr_phys_addr;
    uint64_t vrucmr_size;
    uint64_t vrucmr_user_space_addr;
    uint64_t vrucmr_mmap_addr;
} vr_uvh_client_mem_region_t; 

typedef struct vr_uvh_client_vring {
    struct vring_desc *vrucv_desc;
    struct vring_avail *vrucv_avail;
    struct vring_used *vrucv_used;
    unsigned int vrucv_base_idx;
} vr_uvh_client_vring_t;

typedef struct vr_uvh_client {
    int vruc_fd;
    char vruc_path[VR_UNIX_PATH_MAX];
    char vruc_cmsg[CMSG_SPACE(VHOST_MEMORY_MAX_NREGIONS * sizeof(int))];
    int vruc_msg_bytes_read;
    int vruc_fds_sent[VHOST_MEMORY_MAX_NREGIONS];
    int vruc_num_fds_sent;
    int vruc_num_mem_regions;
    vr_uvh_client_mem_region_t vruc_mem_regions[VHOST_MEMORY_MAX_NREGIONS];
    struct vhost_vring_state vruc_vvs[VHOST_CLIENT_MAX_VRINGS];
    VhostUserMsg vruc_msg;

    unsigned int vruc_idx;
    unsigned int vruc_nrxqs;
    unsigned int vruc_ntxqs;

    /*
     * TODO - the following fields need to tied to the vif.
     */
    vr_uvh_client_vring_t vruc_vvr[VHOST_CLIENT_MAX_VRINGS]; 
} vr_uvh_client_t;

void vr_uvhost_client_init(void);
vr_uvh_client_t *vr_uvhost_new_client(int fd, char *path, int cidx);
void vr_uvhost_del_client(vr_uvh_client_t *vru_cl);
void vr_uvhost_cl_set_fd(vr_uvh_client_t *vru_cl, int fd);
vr_uvh_client_t *vr_uvhost_get_client(unsigned int cidx);
#endif /* __VR_UVHOST_CLIENT_H__ */

