/*
 * vr_uvhost_client.c - client handling in user space vhost server that
 * peers with the vhost client inside qemu (version 2.1 and later).
 *
 * Copyright (c) 2014 Juniper Networks, Inc. All rights reserved.
 */

#include "vr_dpdk.h"
#include "vr_dpdk_virtio.h"
#include "vr_uvhost_client.h"
#include "vr_uvhost_util.h"

#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <rte_errno.h>

static vr_uvh_client_t vr_uvh_clients[VR_UVH_MAX_CLIENTS];

/*
 * uvhost_client_munmap - munmaps guest memory regions.
 *
 * Returns 0 on success, -1 otherwise.
 */
static int
uvhost_client_munmap(vr_uvh_client_t *vru_cl)
{
    int i, ret = 0;
    vr_uvh_client_mem_region_t *region;

    if (!vru_cl->vruc_num_mem_regions)
        return -1;

    vr_uvhost_log("Client %s: unmapping %u memory regions:\n",
            vr_uvhost_client_name(vru_cl), vru_cl->vruc_num_mem_regions);
    for (i = 0; i < vru_cl->vruc_num_mem_regions; i++) {
        region = &vru_cl->vruc_mem_regions[i];
        if (region->vrucmr_mmap_addr_aligned) {
            vr_uvhost_log("    %d: unmapping addr 0x%"PRIx64" size 0x%"PRIx64
                    "\n", i, region->vrucmr_phys_addr, region->vrucmr_size);

            if (munmap(region->vrucmr_mmap_addr_aligned,
                    region->vrucmr_size_aligned)) {
                ret = -1;
                vr_uvhost_log(
                        "Client %s: error unmapping memory region %d: %s (%d)\n",
                        vr_uvhost_client_name(vru_cl), i, strerror(errno), errno);
                /* Continue to unmap even after an error. */
            }

        }
    }
    /*
     * Possible memory leak when munmap fails. At this moment there is no
     * solution for that.
     */
    memset(vru_cl->vruc_mem_regions, 0, sizeof(vru_cl->vruc_mem_regions));
    vru_cl->vruc_num_mem_regions = 0;

    return ret;
}

/*
 * vr_uvhost_client_stop - stop polling the UVHost client and free all
 * the resources.
 *
 * Returns 0 on success, -1 otherwise.
 */
int
vr_uvhost_client_stop(vr_uvh_client_t *vru_cl, bool force)
{
    if (!(vru_cl->vruc_flags & VR_UVH_CLIENT_STARTED))
        return -1;

    if (vr_dpdk_virtio_stop(vru_cl->vruc_idx, force) != 0)
        return -1;

    vru_cl->vruc_flags &= ~VR_UVH_CLIENT_STARTED;
    vr_uvhost_log("Client %s: STOPPED\n", vr_uvhost_client_name(vru_cl));

    uvhost_client_munmap(vru_cl);

    return 0;
}

/*
 * vr_uvhost_client_start - start polling the UVHost client.
 *
 * Returns 0 on success, -1 otherwise.
 */
int
vr_uvhost_client_start(vr_uvh_client_t *vru_cl)
{
    if (vru_cl->vruc_flags & VR_UVH_CLIENT_STARTED)
        return -1;

    if (vr_dpdk_virtio_start(vru_cl->vruc_idx) != 0)
        return -1;

    vru_cl->vruc_flags |= VR_UVH_CLIENT_STARTED;
    vr_uvhost_log("Client %s: STARTED\n", vr_uvhost_client_name(vru_cl));

    return 0;
}

/*
 * vr_uvhost_client_mmap - mmaps guest memory regions.
 *
 * Returns 0 on success, -1 otherwise.
 */
int
vr_uvhost_client_mmap(vr_uvh_client_t *vru_cl)
{
    int i;
    vr_uvh_client_mem_region_t *region;
    VhostUserMemory *vum_msg;
    uint64_t size;
    struct stat fd_stat;

    /* Always unmap previously mmaped guest memory. */
    uvhost_client_munmap(vru_cl);

    vum_msg = &vru_cl->vruc_msg.memory;
    vr_uvhost_log("Client %s: mapping %u memory regions:\n",
            vr_uvhost_client_name(vru_cl), vum_msg->nregions);

    if (vum_msg->nregions > VHOST_MEMORY_MAX_NREGIONS) {
        vr_uvhost_log("Client %s: error mapping guest memory: too many regions"
                "(%"PRIu32" > %d)\n",
                vr_uvhost_client_name(vru_cl), vum_msg->nregions,
                VHOST_MEMORY_MAX_NREGIONS);
      return -1;
    }
    for (i = 0; i < vum_msg->nregions; i++) {
        vr_uvhost_log("    %d: FD %d addr 0x%" PRIx64 " size 0x%"
                PRIx64 " off 0x%" PRIx64 "\n",
                i, vru_cl->vruc_fds_sent[i],
                vum_msg->regions[i].guest_phys_addr,
                vum_msg->regions[i].memory_size,
                vum_msg->regions[i].mmap_offset);

        if (vru_cl->vruc_fds_sent[i]) {
            region = &vru_cl->vruc_mem_regions[i];

            region->vrucmr_phys_addr = vum_msg->regions[i].guest_phys_addr;
            region->vrucmr_size = vum_msg->regions[i].memory_size;
            region->vrucmr_user_space_addr = vum_msg->regions[i].userspace_addr;

            size = vum_msg->regions[i].mmap_offset +
                       vum_msg->regions[i].memory_size;
            region->vrucmr_mmap_addr = (uint64_t)
                    mmap(0, size, PROT_READ | PROT_WRITE, MAP_SHARED,
                            vru_cl->vruc_fds_sent[i], 0);

            if (region->vrucmr_mmap_addr == ((uint64_t)MAP_FAILED)) {
                vr_uvhost_log("Client %s: error mmaping FD %d size 0x%" PRIx64
                        ": %s (%d)\n",
                        vr_uvhost_client_name(vru_cl),
                        vru_cl->vruc_fds_sent[i], size,
                        rte_strerror(errno), errno);
                /*
                 * The file descriptors will be closed in vr_uvh_cl_msg_handler()
                 */
                return -1;
            }

            /* Get block size for the munmap(2). */
            memset(&fd_stat, 0, sizeof(stat));
            if (fstat(vru_cl->vruc_fds_sent[i], &fd_stat) != 0) {
                vr_uvhost_log("Client %s: error getting block size for FD %d\n",
                        vr_uvhost_client_name(vru_cl),
                        vru_cl->vruc_fds_sent[i]);
                return -1;
            }
            region->vrucmr_blksize = (uint64_t)fd_stat.st_blksize;

            /* Align mmap address and size. */
            region->vrucmr_mmap_addr_aligned = (void *)(uintptr_t)
                RTE_ALIGN_FLOOR(region->vrucmr_mmap_addr,
                        region->vrucmr_blksize);
            region->vrucmr_size_aligned = RTE_ALIGN_CEIL(size,
                    region->vrucmr_blksize);

            /*
             * Prevent guest memory from being dumped in vrouter-dpdk core.
             */
            if (madvise(region->vrucmr_mmap_addr_aligned,
                    region->vrucmr_size_aligned, MADV_DONTDUMP)) {
                vr_uvhost_log("Client %s: error in madvise at addr 0x%" PRIx64 ", size 0x%"
                              PRIx64 "for FD %d: %s (%d)\n",
                              vr_uvhost_client_name(vru_cl),
                              region->vrucmr_mmap_addr,
                              size, vru_cl->vruc_fds_sent[i],
                              rte_strerror(errno), errno);
                /*
                 * Failure is not catastrophic, so continue below.
                 */
            }

            /* The file descriptor is no longer needed. */
            close(vru_cl->vruc_fds_sent[i]);
            vru_cl->vruc_fds_sent[i] = -1;
            region->vrucmr_mmap_addr += vum_msg->regions[i].mmap_offset;
        }
    }

    /* Save the number of regions. */
    vru_cl->vruc_num_mem_regions = vum_msg->nregions;

    return 0;
}

/*
 * vr_uvhost_client_init - initialize the client array.
 */
void
vr_uvhost_client_init(void)
{
    int i;

    for (i = 0; i < VR_UVH_MAX_CLIENTS; i++) {
        vr_uvh_clients[i].vruc_fd = -1;
    }

    return;
}

/*
 * vr_uvhost_new_client - initializes state for a new user space vhost client
 * FD is a file descriptor for the client socket. path is the UNIX domain
 * socket path. cidx is the index of the client.
 *
 * Returns a pointer to the client state on success, NULL otherwise.
 */
vr_uvh_client_t *
vr_uvhost_new_client(int fd, char *path, int cidx)
{
    if (cidx >= VR_UVH_MAX_CLIENTS) {
        return NULL;
    }

    if (vr_uvh_clients[cidx].vruc_fd != -1) {
        return NULL;
    }

    vr_uvh_clients[cidx].vruc_fd = fd;
    strncpy(vr_uvh_clients[cidx].vruc_path, path, VR_UNIX_PATH_MAX - 1);

    return &vr_uvh_clients[cidx];
}

/*
 * vr_uvhost_del_client - removes a vhost client.
 *
 * Returns nothing.
 */
void
vr_uvhost_del_client(vr_uvh_client_t *vru_cl)
{
    /* Remove both the socket we listen for and the socket we have accepted */
    vr_uvhost_del_fds_by_arg(vru_cl);

    vru_cl->vruc_fd = -1;
    unlink(vru_cl->vruc_path);

    return;
}

/*
 * vr_uvhost_cl_set_fd - set the FD for a user space vhost client
 */
void
vr_uvhost_cl_set_fd(vr_uvh_client_t *vru_cl, int fd)
{
    vru_cl->vruc_fd = fd;

    return;
}

/*
 * vr_uvhost_get_client - Returns the client at the specified index, NULL if
 * it cannot be found.
 */
vr_uvh_client_t *
vr_uvhost_get_client(unsigned int cidx)
{
    if (cidx >= VR_UVH_MAX_CLIENTS) {
        return NULL;
    }

    return &vr_uvh_clients[cidx];
}
