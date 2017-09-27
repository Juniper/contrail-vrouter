/*
 * vr_uvhost_msg.c - handlers for messages received by the user space
 * vhost thread.
 *
 * Copyright (c) 2014 Juniper Networks, Inc. All rights reserved.
 */

#include <sys/poll.h>

#include "vr_dpdk.h"
#include "vr_dpdk_virtio.h"
#include "vr_dpdk_usocket.h"
#include "vr_uvhost_client.h"
#include "vr_uvhost_msg.h"
#include "vr_uvhost_util.h"

#include <fcntl.h>
#include <linux/virtio_net.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/timerfd.h>

#include <rte_errno.h>
#include <rte_hexdump.h>

typedef int (*vr_uvh_msg_handler_fn)(vr_uvh_client_t *vru_cl);
#define uvhm_client_name(vru_cl) (vru_cl->vruc_path + strlen(vr_socket_dir) \
    + sizeof(VR_UVH_VIF_PFX) - 1)

/*
 * Prototypes for user space vhost message handlers
 */
static int vr_uvmh_get_features(vr_uvh_client_t *vru_cl);
static int vr_uvmh_set_features(vr_uvh_client_t *vru_cl);
static int vr_uvmh_get_protocol_features(vr_uvh_client_t *vru_cl);
static int vr_uvmh_set_protocol_features(vr_uvh_client_t *vru_cl);
static int vr_uvhm_set_mem_table(vr_uvh_client_t *vru_cl);
static int vr_uvhm_set_vring_num(vr_uvh_client_t *vru_cl);
static int vr_uvhm_set_vring_addr(vr_uvh_client_t *vru_cl);
static int vr_uvhm_set_vring_base(vr_uvh_client_t *vru_cl);
static int vr_uvhm_get_vring_base(vr_uvh_client_t *vru_cl);
static int vr_uvhm_set_vring_call(vr_uvh_client_t *vru_cl);
static int vr_uvhm_get_queue_num(vr_uvh_client_t *vru_cl);
static int vr_uvhm_set_vring_enable(vr_uvh_client_t *vru_cl);
static int vr_uvh_cl_timer_setup(vr_uvh_client_t *vru_cl);

static vr_uvh_msg_handler_fn vr_uvhost_cl_msg_handlers[] = {
    NULL,
    vr_uvmh_get_features,
    vr_uvmh_set_features,
    NULL,
    NULL,
    vr_uvhm_set_mem_table,
    NULL,
    NULL,
    vr_uvhm_set_vring_num,
    vr_uvhm_set_vring_addr,
    vr_uvhm_set_vring_base,
    vr_uvhm_get_vring_base,
    NULL,
    vr_uvhm_set_vring_call,
    NULL,
    vr_uvmh_get_protocol_features,
    vr_uvmh_set_protocol_features,
    vr_uvhm_get_queue_num,
    vr_uvhm_set_vring_enable,
    NULL,
};

/*
 * uvhm_mem_table_mmap - mmaps guest memory regions.
 *
 * Returns 0 on success, -1 otherwise.
 */
static int
uvhm_client_mmap(vr_uvh_client_t *vru_cl)
{
    int i;
    int ret;
    vr_uvh_client_mem_region_t *region;
    VhostUserMemory *vum_msg;
    uint64_t size;

    vum_msg = &vru_cl->vruc_msg.memory;
    vr_uvhost_log("Client %s: mapping %u memory regions:\n",
            uvhm_client_name(vru_cl), vum_msg->nregions);

    if (vum_msg->nregions > VHOST_MEMORY_MAX_NREGIONS) {
        vr_uvhost_log("Client %s: error mapping guest memory: too many regions"
                "(%"PRIu32" > %d)\n",
                uvhm_client_name(vru_cl), vum_msg->nregions,
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
                        uvhm_client_name(vru_cl),
                        vru_cl->vruc_fds_sent[i], size,
                        rte_strerror(errno), errno);
                /*
                 * The file descriptors will be closed in vr_uvh_cl_msg_handler()
                 */
                return -1;
            }
            /* Get block size for the munmap(2). */
            ret = vr_dpdk_virtio_uvh_get_blk_size(vru_cl->vruc_fds_sent[i],
                    &region->vrucmr_blksize);
            if (ret) {
                vr_uvhost_log("Client %s: error getting block size for FD %d\n",
                        uvhm_client_name(vru_cl),
                        vru_cl->vruc_fds_sent[i]);
                return -1;
            }
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
                              uvhm_client_name(vru_cl),
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
 * uvhm_mem_table_munmap - munmaps guest memory regions.
 */
static void
uvhm_client_munmap(vr_uvh_client_t *vru_cl)
{
    int i, ret;
    vr_uvh_client_mem_region_t *region;

    /* Make sure the device has stopped before the munmap. */
    vr_dpdk_virtio_stop(vru_cl->vruc_idx);

    vr_uvhost_log("Client %s: unmapping %u memory regions:\n",
            uvhm_client_name(vru_cl), vru_cl->vruc_num_mem_regions);
    for (i = 0; i < vru_cl->vruc_num_mem_regions; i++) {
        region = &vru_cl->vruc_mem_regions[i];
        if (region->vrucmr_mmap_addr_aligned) {
            vr_uvhost_log("    %d: unmapping addr 0x%"PRIx64" size 0x%"PRIx64
                    "\n", i, region->vrucmr_phys_addr, region->vrucmr_size);

            ret = munmap(region->vrucmr_mmap_addr_aligned,
                    region->vrucmr_size_aligned);
            if (ret) {
                vr_uvhost_log(
                        "Client %s: error unmapping memory region %d: %s (%d)\n",
                        uvhm_client_name(vru_cl), i, strerror(errno), errno);
            }

        }
    }
    /*
     * Possible memory leak when munmap fails. At this moment there is no
     * solution for that.
     */
    memset(vru_cl->vruc_mem_regions, 0, sizeof(vru_cl->vruc_mem_regions));
    vru_cl->vruc_num_mem_regions = 0;

    return;
}

/*
 * vr_uvmh_get_features - handle VHOST_USER_GET_FEATURES message from user space
 * vhost client.
 *
 * Returns 0 on success, -1 otherwise.
 */
static int
vr_uvmh_get_features(vr_uvh_client_t *vru_cl)
{
    /* TODO: Implement VHOST_F_LOG_ALL handler */
    /* VIRTIO_NET_F_CTRL_VQ is enough for vMX and FreeBSD */
    vru_cl->vruc_msg.u64 = (1ULL << VIRTIO_NET_F_CTRL_VQ) |
                           (1ULL << VIRTIO_NET_F_CSUM) |
                           (1ULL << VIRTIO_NET_F_GUEST_CSUM) |
                           (1ULL << VIRTIO_NET_F_MQ) |
                           (1ULL << VHOST_USER_F_PROTOCOL_FEATURES) |
                           (1ULL << VHOST_F_LOG_ALL);

    if (dpdk_check_rx_mrgbuf_disable() == 0)
        vru_cl->vruc_msg.u64 |= (1ULL << VIRTIO_NET_F_MRG_RXBUF); 

    if (vr_perfs)
        vru_cl->vruc_msg.u64 |= (1ULL << VIRTIO_NET_F_GUEST_TSO4)|
                                (1ULL << VIRTIO_NET_F_HOST_TSO4) |
                                (1ULL << VIRTIO_NET_F_GUEST_TSO6)|
                                (1ULL << VIRTIO_NET_F_HOST_TSO6);

    vr_uvhost_log("    GET FEATURES: returns 0x%"PRIx64"\n",
                                            vru_cl->vruc_msg.u64);

    vru_cl->vruc_msg.size = sizeof(vru_cl->vruc_msg.u64);

    return 0;
}

/*
 * vr_uvmh_set_features - handle VHOST_USER_SET_FEATURES message from user space
 * vhost client.
 *
 * Returns 0 on success, -1 otherwise.
 */
static int
vr_uvmh_set_features(vr_uvh_client_t *vru_cl)
{
    struct vr_interface *vif;
    uint8_t is_gso_vm = 1;
    vr_uvhost_log("    SET FEATURES: 0x%"PRIx64"\n",
                                            vru_cl->vruc_msg.u64);

    vif = __vrouter_get_interface(vrouter_get(0), vru_cl->vruc_idx);
    is_gso_vm =  (vru_cl->vruc_msg.u64 & (1ULL << VIRTIO_NET_F_GUEST_TSO4)) | 
                 (vru_cl->vruc_msg.u64 & (1ULL << VIRTIO_NET_F_HOST_TSO4))  |
                 (vru_cl->vruc_msg.u64 & (1ULL << VIRTIO_NET_F_GUEST_TSO6)) |
                 (vru_cl->vruc_msg.u64 & (1ULL << VIRTIO_NET_F_HOST_TSO6));

    /* TODO: For now, assume if a VM can't do GSO, it can't do GRO either
     * as there is no virtio feature bit for GRO
     */
    if (vif) {
        if (!!is_gso_vm) {
            vif->vif_flags |= VIF_FLAG_GRO_NEEDED; 
        } else {
            vif->vif_flags &= ~VIF_FLAG_GRO_NEEDED; 
        }
    }

    if (vru_cl->vruc_msg.u64 & (1ULL << VIRTIO_NET_F_MRG_RXBUF)) {
        vif->vif_flags |= VIF_FLAG_MRG_RXBUF;
        vr_dpdk_set_vhost_send_func(vru_cl->vruc_idx, 1);
    } else {
        vif->vif_flags &= ~VIF_FLAG_MRG_RXBUF; 
        vr_dpdk_set_vhost_send_func(vru_cl->vruc_idx, 0);
    }
    return 0;
}

static int
vr_uvmh_get_protocol_features(vr_uvh_client_t *vru_cl)
{
    vru_cl->vruc_msg.u64 = (1ULL << VHOST_USER_PROTOCOL_F_MQ);
    vr_uvhost_log("    GET PROTOCOL FEATURES: returns 0x%"PRIx64"\n",
                  vru_cl->vruc_msg.u64);

    vru_cl->vruc_msg.size = sizeof(vru_cl->vruc_msg.u64);

    return 0;
}

static int
vr_uvmh_set_protocol_features(vr_uvh_client_t *vru_cl)
{
    vr_uvhost_log("    SET PROTOCOL FEATURES: 0x%"PRIx64"\n",
                  vru_cl->vruc_msg.u64);

    return 0;
}

/*
 * vr_uvhm_set_mem_table - handles VHOST_USER_SET_MEM_TABLE message from
 * user space vhost client to learn the memory map of the guest.
 *
 * Returns 0 on success, -1 otherwise.
 */
static int
vr_uvhm_set_mem_table(vr_uvh_client_t *vru_cl)
{
    vr_uvhost_log("    SET MEM TABLE:\n");

    /* Unmap previously mmaped guest memory. */
    uvhm_client_munmap(vru_cl);
    return uvhm_client_mmap(vru_cl);
}

/*
 * vr_uvhm_set_vring_num - handles VHOST_USER_SET_VRING_NUM message from
 * the user space vhost client to set the number of descriptors in the virtio
 * ring.
 *
 * Returns 0 on success, -1 otherwise.
 */
static int
vr_uvhm_set_vring_num(vr_uvh_client_t *vru_cl)
{
    VhostUserMsg *vum_msg;
    unsigned int vring_idx;

    vum_msg = &vru_cl->vruc_msg;
    vring_idx = vum_msg->state.index;
    vr_uvhost_log("    SET VRING NUM: vring %u num %u\n", vring_idx,
                                 vum_msg->state.num);

    if (vring_idx >= VHOST_CLIENT_MAX_VRINGS) {
        vr_uvhost_log("Client %s: error setting vring %u num: invalid vring index\n",
                        uvhm_client_name(vru_cl), vring_idx);
        return -1;
    }
    if (vr_dpdk_set_ring_num_desc(vru_cl->vruc_idx, vring_idx,
                                  vum_msg->state.num)) {
        vr_uvhost_log("Client %s: error setting vring %u size %u\n",
                    uvhm_client_name(vru_cl), vring_idx, vum_msg->state.num);
        return -1;
    }

    return 0;
}

/*
 * vr_uvhm_map_addr - map a virtual address sent by the vhost client into
 * a server virtual address.
 *
 * Returns a pointer to the corresponding location on success, NULL otherwise.
 */
static void *
vr_uvhm_map_addr(vr_uvh_client_t *vru_cl, uint64_t addr)
{
    int i;
    uint64_t vmr_addr, vmr_size, ret_addr;

    for (i = 0; i < vru_cl->vruc_num_mem_regions; i++) {
        vmr_addr = vru_cl->vruc_mem_regions[i].vrucmr_user_space_addr;
        vmr_size = vru_cl->vruc_mem_regions[i].vrucmr_size;

        if ((vmr_addr <= addr) && (addr < (vmr_addr + vmr_size))) {
             ret_addr = vru_cl->vruc_mem_regions[i].vrucmr_mmap_addr +
                        (addr - vmr_addr);
             return (void *) ret_addr;
        }
    }

    return NULL;
}

/*
 * uvhm_check_vring_ready - check if virtual queue is ready to use and
 * set the ready status.
 *
 * Returns 1 if vring ready, 0 otherwise.
 */
static int
uvhm_check_vring_ready(vr_uvh_client_t *vru_cl, unsigned int vring_idx)
{
    unsigned int vif_idx = vru_cl->vruc_idx;
    vr_dpdk_virtioq_t *vq;

    if (vif_idx >= VR_MAX_INTERFACES) {
        return 0;
    }

    if (vring_idx & 1) {
        vq = &vr_dpdk_virtio_rxqs[vif_idx][vring_idx/2];
    } else {
        vq = &vr_dpdk_virtio_txqs[vif_idx][vring_idx/2];
    }

    /* vring is ready when addresses are set. */
    if (vq->vdv_desc && vq->vdv_ready_state != VQ_READY) {
        /*
         * Now the virtio queue is ready for forwarding.
         * TODO - need a memory barrier here for non-x86 CPU?
         */
        if (vr_dpdk_set_virtq_ready(vru_cl->vruc_idx, vring_idx, VQ_READY)) {
            vr_uvhost_log("Client %s: error setting vring %u ready state\n",
                    uvhm_client_name(vru_cl), vring_idx);
            return -1;
        }

        vr_uvhost_log("Client %s: vring %d is ready\n",
                uvhm_client_name(vru_cl), vring_idx);

        return 1;
    }

    return 0;
}

/*
 * vr_uvhm_set_vring_addr - handles a VHOST_USER_SET_VRING_ADDR message from
 * the user space vhost client to set the address of the virtio rings.
 *
 * Returns 0 on success, -1 otherwise.
 */
static int
vr_uvhm_set_vring_addr(vr_uvh_client_t *vru_cl)
{
    struct vhost_vring_addr *vaddr;
    unsigned int vring_idx;
    struct vring_desc *vrucv_desc;
    struct vring_avail *vrucv_avail;
    struct vring_used *vrucv_used;

    vaddr = &vru_cl->vruc_msg.addr;
    vring_idx = vaddr->index;
    vr_uvhost_log("    SET VRING ADDR: vring %u flags 0x%x desc 0x%llx"
                     " used 0x%llx avail 0x%llx\n",
                     vring_idx, vaddr->flags, vaddr->desc_user_addr,
                     vaddr->used_user_addr, vaddr->avail_user_addr);

    if (vring_idx >= VHOST_CLIENT_MAX_VRINGS) {
        vr_uvhost_log("Client %s: error setting vring %u addr: invalid vring index\n",
                        uvhm_client_name(vru_cl), vring_idx);
        return -1;
    }

    vrucv_desc = (struct vring_desc *)
        vr_uvhm_map_addr(vru_cl, vaddr->desc_user_addr);
    vrucv_avail = (struct vring_avail *)
        vr_uvhm_map_addr(vru_cl, vaddr->avail_user_addr);
    vrucv_used = (struct vring_used *)
        vr_uvhm_map_addr(vru_cl, vaddr->used_user_addr);

    if (!vrucv_desc || !vrucv_avail || !vrucv_used)
        return -1;

    if (vr_dpdk_set_vring_addr(vru_cl->vruc_idx, vring_idx, vrucv_desc,
                               vrucv_avail, vrucv_used)) {
        vr_uvhost_log("Client %s: error setting vring %u addresses\n",
                uvhm_client_name(vru_cl), vring_idx);
        return -1;
    }

    /* Try to recover from the vRouter crash. */
    vr_dpdk_virtio_recover_vring_base(vru_cl->vruc_idx, vring_idx);

    uvhm_check_vring_ready(vru_cl, vring_idx);

    return 0;
}

/*
 * vr_uvhm_set_vring_base - handles a VHOST_USER_SET_VRING_BASE messsage
 * from the vhost user client to set the based index of a vring.
 *
 * Returns 0 on success, -1 otherwise.
 */
static int
vr_uvhm_set_vring_base(vr_uvh_client_t *vru_cl)
{
    VhostUserMsg *vum_msg;
    unsigned int vring_idx;

    vum_msg = &vru_cl->vruc_msg;
    vring_idx = vum_msg->state.index;
    vr_uvhost_log("    SET VRING BASE: vring %u base %u\n",
                     vring_idx, vum_msg->state.num);

    if (vring_idx >= VHOST_CLIENT_MAX_VRINGS) {
        vr_uvhost_log("Client %s: error setting vring %u base: invalid vring index\n",
                        uvhm_client_name(vru_cl), vring_idx);
        return -1;
    }

    if (vr_dpdk_virtio_set_vring_base(vru_cl->vruc_idx, vring_idx,
                                      vum_msg->state.num)) {
        vr_uvhost_log("Client %s: error setting vring %u base %u\n",
                uvhm_client_name(vru_cl), vring_idx, vum_msg->state.num);
        return -1;
    }

    return 0;
}

/*
 * vr_uvhm_get_vring_base - handles a VHOST_USER_GET_VRING_BASE messsage
 * from the vhost user client to get the base index of a vring.
 *
 * Returns 0 on success, -1 otherwise.
 */
static int
vr_uvhm_get_vring_base(vr_uvh_client_t *vru_cl)
{
    VhostUserMsg *vum_msg;
    unsigned int vring_idx;

    vum_msg = &vru_cl->vruc_msg;
    vring_idx = vum_msg->state.index;
    vr_uvhost_log("    GET VRING BASE: vring %u\n", vring_idx);

    if (vring_idx >= VHOST_CLIENT_MAX_VRINGS) {
        vr_uvhost_log("Client %s: error getting vring %u base: invalid vring index\n",
                        uvhm_client_name(vru_cl), vring_idx);
        return -1;
    }

    if (vr_dpdk_virtio_get_vring_base(vru_cl->vruc_idx, vring_idx,
                                     &vum_msg->state.num)) {
        vr_uvhost_log("Client %s: error getting vring %u base index\n",
                uvhm_client_name(vru_cl), vring_idx);
        return -1;
    }

    vum_msg->size = sizeof(struct vhost_vring_state);
    vr_uvhost_log("    GET VRING BASE: returns %u\n", vum_msg->state.num);

    return 0;
}

/*
 * vr_uvhm_set_vring_call - handles a VHOST_USER_SET_VRING_CALL message
 * from the vhost user client to set the eventfd to be used to interrupt the
 * guest, if required.
 *
 * Returns 0 on success, -1 otherwise.
 */
static int
vr_uvhm_set_vring_call(vr_uvh_client_t *vru_cl)
{
    VhostUserMsg *vum_msg;
    unsigned int vring_idx;

    vum_msg = &vru_cl->vruc_msg;
    vring_idx = vum_msg->state.index;
    vr_uvhost_log("    SET VRING CALL: vring %u FD %d\n", vring_idx,
                                                vru_cl->vruc_fds_sent[0]);

    if (!(vring_idx & VHOST_USER_VRING_NOFD_MASK)) {
        if (vring_idx >= VHOST_CLIENT_MAX_VRINGS) {
            vr_uvhost_log(
                "Client %s: error setting vring %u call: invalid vring index\n",
                uvhm_client_name(vru_cl), vring_idx);
            return -1;
        }

        if (vr_dpdk_set_ring_callfd(vru_cl->vruc_idx, vring_idx,
                                    vru_cl->vruc_fds_sent[0])) {
            vr_uvhost_log("Client %s: error setting vring %u call FD %d\n",
                    uvhm_client_name(vru_cl), vring_idx, vru_cl->vruc_fds_sent[0]);
            return -1;
        }
    } else {
        vr_uvhost_log("Client %s: not setting call fd due to mask 0x%x\n",
                        uvhm_client_name(vru_cl), vring_idx);

        vring_idx &= (~VHOST_USER_VRING_NOFD_MASK);
    }

    /* set FD to -1, so we do not close it in vr_uvh_cl_msg_handler() */
    vru_cl->vruc_fds_sent[0] = -1;

    uvhm_check_vring_ready(vru_cl, vring_idx);

    return 0;
}

/*
 * Handle the VHOST_USER_SET_VRING_ENABLE vhost-user protocol message.
 */
static int
vr_uvhm_set_vring_enable(vr_uvh_client_t *vru_cl)
{
    VhostUserMsg *vum_msg;
    unsigned int vring_idx;
    unsigned int queue_num;
    bool enable;

    vum_msg = &vru_cl->vruc_msg;
    vring_idx = vum_msg->state.index;
    enable = (bool)vum_msg->state.num;

    /* QEMU should NEVER send the disable command for queue 0 */
    if ((vring_idx == 0 || vring_idx == 1) && !enable) {
        RTE_LOG(ERR, UVHOST, "%s: Can not disable RX/TX queue 0\n", __func__);
        return -1;
    }

    /*
     * If the queue is higher than the number supported by vrouter, silently
     * fail here (as there is no error message returned to qemu).
     */
    if ((vring_idx / 2) >= vr_dpdk.nb_fwd_lcores) {
        RTE_LOG(ERR, UVHOST, "%s: Can not %s %s queue %d (only %d queues)\n",
            __func__, enable ? "enable" : "disable",
            (vring_idx & 1) ? "RX" : "TX", vring_idx / 2,
            vr_dpdk.nb_fwd_lcores);
        return 0;
    }

    vr_uvhost_log("Client %s: setting vring %u ready state %d\n",
                  uvhm_client_name(vru_cl), vring_idx, enable);

    uvhm_check_vring_ready(vru_cl, vring_idx);

    queue_num = vring_idx / 2;

    if (vring_idx & 1) {
        /* RX queues */
        vr_dpdk_virtio_rx_queue_enable_disable(vru_cl->vruc_idx,
                                               vru_cl->vruc_vif_gen, queue_num,
                                               enable);
    } else {
        /* TX queues */
        vr_dpdk_virtio_tx_queue_enable_disable(vru_cl->vruc_idx,
                                               vru_cl->vruc_vif_gen, queue_num,
                                               enable);
    }

    return 0;
}

/*
 * vr_uvh_cl_call_handler - calls message specific handler for messages
 * from user space vhost client.
 *
 * Returns 0 on success, -1 otherwise.
 */
static int
vr_uvh_cl_call_handler(vr_uvh_client_t *vru_cl)
{
    VhostUserMsg *msg = &vru_cl->vruc_msg;

    if ((msg->request <= VHOST_USER_NONE) ||
            (msg->request >= VHOST_USER_MAX)) {
        return -1;
    }

    if (vr_uvhost_cl_msg_handlers[msg->request]) {
        vr_uvhost_log("Client %s: handling message %d\n",
                uvhm_client_name(vru_cl), msg->request);
        return vr_uvhost_cl_msg_handlers[msg->request](vru_cl);
    } else {
        vr_uvhost_log("Client %s: no handler defined for message %d\n",
                uvhm_client_name(vru_cl), msg->request);
    }

    return 0;
}

static int
vr_uvhm_get_queue_num(vr_uvh_client_t *vru_cl)
{
    /* We support up to number of forwarding lcores queues as they are the only
     * lcores that handle rx queues. However, this causes a failure when spawning
     * the VM if the number of VCPUs in the VM is higher than the number of
     * forwarding cores in vrouter. So, return VR_DPDK_VIRTIO_MAX_QUEUES here,
     * but siliently fail the enable/disable of queues higher than the number
     * of forwarding cores when the message is received from qemu later. The
     * expectation is that the VM should not enable more queues that that.
     */
    vru_cl->vruc_msg.u64 = VR_DPDK_VIRTIO_MAX_QUEUES;
    vr_uvhost_log("    GET QUEUE NUM: returns 0x%"PRIx64"\n",
                  vru_cl->vruc_msg.u64);

    vru_cl->vruc_msg.size = sizeof(vru_cl->vruc_msg.u64);

    return 0;
}

/*
 * vr_uvh_cl_send_reply - send a reply to the vhost user client if
 * required.
 *
 * Returns 0 on success, -1 otherwise.
 */
static int
vr_uvh_cl_send_reply(int fd, vr_uvh_client_t *vru_cl)
{
    int ret;
    VhostUserMsg *msg = &vru_cl->vruc_msg;

    switch(msg->request) {
        case VHOST_USER_GET_FEATURES:
        case VHOST_USER_GET_VRING_BASE:
        case VHOST_USER_GET_PROTOCOL_FEATURES:
        case VHOST_USER_GET_QUEUE_NUM:
            /*
             * Send reply for these messages only.
             */
            msg->flags &= (~VHOST_USER_VERSION_MASK);
            msg->flags |= VHOST_USER_VERSION;
            msg->flags |= VHOST_USER_REPLY_MASK;

            if (vru_cl->vruc_owner != pthread_self()) {
                if (vru_cl->vruc_owner)
                    RTE_LOG(WARNING, UVHOST, "WARNING: thread %lx is trying to write"
                        " to uvhost client FD %d owned by thread %lx\n",
                        pthread_self(), fd, vru_cl->vruc_owner);
                vru_cl->vruc_owner = pthread_self();
            }
            ret = send(fd, (void *) msg,
                       VHOST_USER_HSIZE + msg->size, MSG_DONTWAIT);
            if ((ret < 0) || (ret != (VHOST_USER_HSIZE + msg->size))) {
                /*
                 * Socket to qemu should never be full as it sleeps waiting
                 * for a reply to the previous request.
                 */
                vr_uvhost_log("Client %s: error sending vhost user reply\n",
                        uvhm_client_name(vru_cl));
                return -1;
             }

            break;

        default:
            /*
             * No reply needed.
             */
            break;
    }

    return 0;
}

/*
 * vr_uvh_cl_msg_handler - handler for messages from user space vhost
 * clients. Calls the appropriate handler based on the message type.
 *
 * Returns 0 on success, -1 on error.
 *
 * TODO: upon error, this function currently makes the process exit.
 * Instead, it should close the socket and continue serving other clients.
 */
static int
vr_uvh_cl_msg_handler(int fd, void *arg)
{
    vr_uvh_client_t *vru_cl = (vr_uvh_client_t *) arg;
    struct msghdr mhdr;
    struct iovec iov;
    int i, err, ret = 0, read_len = 0;
    struct cmsghdr *cmsg;

    memset(&mhdr, 0, sizeof(mhdr));

    if (vru_cl->vruc_msg_bytes_read == 0) {
        mhdr.msg_control = &vru_cl->vruc_cmsg;
        mhdr.msg_controllen = sizeof(vru_cl->vruc_cmsg);

        iov.iov_base = (void *) &vru_cl->vruc_msg;
        iov.iov_len = VHOST_USER_HSIZE;

        mhdr.msg_iov = &iov;
        mhdr.msg_iovlen = 1;

        ret = recvmsg(fd, &mhdr, MSG_DONTWAIT);
        if (ret < 0) {
            if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
                ret = 0;
                goto cleanup;
            }

            vr_uvhost_log("Client %s: error receiving message: %s (%d)\n",
                    uvhm_client_name(vru_cl), strerror(errno), errno);
            ret = -1;
            goto cleanup;
        } else if (ret > 0) {
            if (mhdr.msg_flags & MSG_CTRUNC) {
                vr_uvhost_log("Client %s: error receiving message: truncated\n",
                        uvhm_client_name(vru_cl));
                ret = -1;
                goto cleanup;
            }

            cmsg = CMSG_FIRSTHDR(&mhdr);
            if (cmsg && (cmsg->cmsg_len > 0) &&
                   (cmsg->cmsg_level == SOL_SOCKET) &&
                   (cmsg->cmsg_type == SCM_RIGHTS)) {
                   vru_cl->vruc_num_fds_sent = (cmsg->cmsg_len - CMSG_LEN(0))/
                                                   sizeof(int);
                   if (vru_cl->vruc_num_fds_sent > VHOST_MEMORY_MAX_NREGIONS) {
                        vr_uvhost_log("Client %s: error handling FDs: too many FDs (%d > %d)\n",
                                uvhm_client_name(vru_cl),
                                vru_cl->vruc_num_fds_sent,
                                VHOST_MEMORY_MAX_NREGIONS);
                       vru_cl->vruc_num_fds_sent = VHOST_MEMORY_MAX_NREGIONS;
                   }

                   memcpy(vru_cl->vruc_fds_sent, CMSG_DATA(cmsg),
                          vru_cl->vruc_num_fds_sent*sizeof(int));
            }

            vru_cl->vruc_msg_bytes_read = ret;
            if (ret < VHOST_USER_HSIZE) {
                ret = 0;
                goto cleanup;
            }

            read_len = vru_cl->vruc_msg.size;
        } else {
            /*
             * recvmsg returned 0, so return error.
             */
            vr_uvhost_log("Client %s: shutdown at message receiving\n",
                    uvhm_client_name(vru_cl));
            ret = -1;
            goto cleanup;
        }
    } else if (vru_cl->vruc_msg_bytes_read < VHOST_USER_HSIZE) {
        read_len = VHOST_USER_HSIZE - vru_cl->vruc_msg_bytes_read;
    } else {
        read_len = vru_cl->vruc_msg.size -
                       (vru_cl->vruc_msg_bytes_read - VHOST_USER_HSIZE);
    }

    if (read_len) {
        if (vru_cl->vruc_owner != pthread_self()) {
            if (vru_cl->vruc_owner)
                RTE_LOG(WARNING, UVHOST, "WARNING: thread %lx is trying to read"
                    " uvhost client FD %d owned by thread %lx\n",
                    pthread_self(), fd, vru_cl->vruc_owner);
            vru_cl->vruc_owner = pthread_self();
        }
        ret = read(fd, (((char *)&vru_cl->vruc_msg) + vru_cl->vruc_msg_bytes_read),
                   read_len);
#ifdef VR_DPDK_RX_PKT_DUMP
        if (ret > 0) {
            RTE_LOG_DP(DEBUG, UVHOST, "%s[%lx]: FD %d read %d bytes\n", __func__,
                pthread_self(), fd, ret);
            rte_hexdump(stdout, "uvhost full message dump:",
                (((char *)&vru_cl->vruc_msg)),
                    ret + vru_cl->vruc_msg_bytes_read);
        } else if (ret < 0) {
            RTE_LOG_DP(DEBUG, UVHOST, "%s[%lx]: FD %d read returned error %d: %s (%d)\n", __func__,
                pthread_self(), fd, ret, rte_strerror(errno), errno);
        }
#endif
        if (ret < 0) {
            if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
                ret = 0;
                goto cleanup;
            }

            vr_uvhost_log(
                "Client %s: error reading message: %s (%d)\n",
                uvhm_client_name(vru_cl), strerror(errno), errno);
            ret = -1;
            goto cleanup;
        } else if (ret == 0) {
            vr_uvhost_log("Client %s: shutdown at message reading\n",
                     uvhm_client_name(vru_cl));
            ret = -1;
            goto cleanup;
        }

        vru_cl->vruc_msg_bytes_read += ret;
        if (vru_cl->vruc_msg_bytes_read < VHOST_USER_HSIZE) {
            ret = 0;
            goto cleanup;
        }

        if (vru_cl->vruc_msg_bytes_read <
                (vru_cl->vruc_msg.size + VHOST_USER_HSIZE)) {
            ret = 0;
            goto cleanup;
        }
    }

    ret = vr_uvh_cl_call_handler(vru_cl);
    if (ret < 0) {
        vr_uvhost_log("Client %s: error handling message %d\n",
                uvhm_client_name(vru_cl), vru_cl->vruc_msg.request);
        ret = -1;
        goto cleanup;
    }

    ret = vr_uvh_cl_send_reply(fd, vru_cl);
    if (ret < 0) {
        vr_uvhost_log("Client %s: error sending reply for message %d\n",
                uvhm_client_name(vru_cl), vru_cl->vruc_msg.request);
        ret = -1;
        goto cleanup;
    }

cleanup:
    err = errno;
    /* close all the FDs received */
    for (i = 0; i < vru_cl->vruc_num_fds_sent; i++) {
        if (vru_cl->vruc_fds_sent[i] > 0)
            close(vru_cl->vruc_fds_sent[i]);
    }
    if (ret == -1) {
        /* We set VQ_NOT_READY state and reset the queues in uvhm_client_munmap() */
        uvhm_client_munmap(vru_cl);
        if (vru_cl->vruc_vhostuser_mode == VRNU_VIF_MODE_SERVER) {
            /* existing FD (stored in local variable in caller to
             * this funcition) will be closed after return from this function
             * reset the value to -1, so that new fd will be created
             */
            vru_cl->vruc_fd = -1;
            if (vr_uvh_cl_timer_setup(vru_cl)) {
                vr_uvhost_log("Client %s: timer creation failed\n",
                        uvhm_client_name(vru_cl));
            }
        }
    }
    /* clear state for next message from this client. */
    vru_cl->vruc_msg_bytes_read = 0;
    memset(&vru_cl->vruc_msg, 0, sizeof(vru_cl->vruc_msg));
    memset(vru_cl->vruc_cmsg, 0, sizeof(vru_cl->vruc_cmsg));
    memset(vru_cl->vruc_fds_sent, 0, sizeof(vru_cl->vruc_fds_sent));
    vru_cl->vruc_num_fds_sent = 0;
    errno = err;
    return ret;
}

/*
 * vr_uvh_cl_listen_handler - handler for connections from user space vhost
 * clients. Accepts the connections and sets up a message handler for the
 * client in the server.
 *
 * Returns 0 on success, -1 otherwise.
 */
static int
vr_uvh_cl_listen_handler(int fd, void *arg)
{
    int s = 0, err;
    struct sockaddr_un sun;
    socklen_t len = sizeof(sun);
    vr_uvh_client_t *vru_cl = (vr_uvh_client_t *) arg;

    vr_uvhost_log("Handling client connection FD %d\n", fd);
    s = accept(fd, (struct sockaddr *) &sun, &len);
    if (s < 0) {
        if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
            return 0;
        }

        vr_uvhost_log("    error accepting client connection FD %d\n", fd);
        return -1;
    }
    vr_uvhost_log("    FD %d accepted new client connection FD %d\n", fd, s);

    /* We still need to listen for the original socket to support VM
     * shut off/restart, since we create the socket at vif --add
     * and we get vif --add at the VM spawning, not VM (re)starting
     */

    /* Do not set new client FD, since we still need to close parent FD
     * on vif delete.
     * We will get the client FD in our handler as an argument.
     */

    if (vr_uvhost_add_fd(s, UVH_FD_READ, vru_cl, vr_uvh_cl_msg_handler)) {
        vr_uvhost_log("    error adding client %s FD %d read handler\n",
                      sun.sun_path, fd);
        goto error;
    }

    return 0;

error:

    err = errno;
    if (s) {
        close(s);
    }

    if (vru_cl) {
        vr_uvhost_del_client(vru_cl);
    }
    errno = err;

    return -1;
}

/*
 * vr_uvh_cl_timer_handler - handler for timer events for 
 * clients when Qemu in server mode
 *
 * Returns 0 on success, -1 on error.
 *
 */
static int
vr_uvh_cl_timer_handler(int fd, void *arg)
{
    vr_uvh_client_t *vru_cl = (vr_uvh_client_t *) arg;
    struct sockaddr_un sun;
    int ret = 0;

    memset(&sun, 0, sizeof(sun));
    sun.sun_family = AF_UNIX;
    strncpy(sun.sun_path, vru_cl->vruc_path, sizeof(sun.sun_path) - 1);

    ret = connect(vru_cl->vruc_fd, (struct sockaddr *) &sun, sizeof(sun));
    if (ret == -1) {
        ret = vr_uvh_cl_timer_setup(vru_cl);
    } else {
        /*
         * socket connected
         * add to msg handler
         */
        ret = vr_uvhost_add_fd(vru_cl->vruc_fd, UVH_FD_READ, vru_cl,
                                vr_uvh_cl_msg_handler);
        if (ret == -1) {
            vr_uvhost_log("    error adding vif %u socket FD %d\n",
                            vru_cl->vruc_idx, vru_cl->vruc_fd);
        }
    }

    return ret;
}

/*
 * vr_uvh_cl_timer_setup - Setup timer to reconnect to the
 * Qemu server.
 *
 * Returns 0 on success, -1 on error.
 *
 */
static int
vr_uvh_cl_timer_setup(vr_uvh_client_t *vru_cl)
{
    int ret = 0;
    struct itimerspec cl_timer;

    cl_timer.it_interval.tv_sec  = 0;
    cl_timer.it_interval.tv_nsec = 0;
    cl_timer.it_value.tv_sec  = 5;
    cl_timer.it_value.tv_nsec = 0;

    if (vru_cl->vruc_fd == -1) {
        vru_cl->vruc_fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (vru_cl->vruc_fd == -1) {
            vr_uvhost_log("    error creating vif %u socket: %s (%d)\n",
                            vru_cl->vruc_idx, rte_strerror(errno), errno);
            ret = -1;
            goto error;
        }
    }

    if (vru_cl->vruc_timer_fd == -1)
        vru_cl->vruc_timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);

    if (vru_cl->vruc_timer_fd == -1) {
        ret = -1;
    } else {
        ret = timerfd_settime(vru_cl->vruc_timer_fd, 0, &cl_timer, NULL);
        if (ret == -1) {
            close(vru_cl->vruc_timer_fd);
            vru_cl->vruc_timer_fd = -1;
        } else {
            if (vr_uvhost_add_fd(vru_cl->vruc_timer_fd, UVH_FD_READ, vru_cl,
                        vr_uvh_cl_timer_handler)) {
                ret = -1;
                vr_uvhost_log("    error adding timer FD %d read handler\n",
                      vru_cl->vruc_timer_fd);
                close(vru_cl->vruc_timer_fd);
                vru_cl->vruc_timer_fd = -1;
            }
        }
    }

error:
    return ret;
}

/*
 * vr_uvh_nl_vif_del_handler - handle a message from the netlink thread
 * to delete a vif.
 *
 * Returns 0 on success, -1 otherwise.
 */
int
vr_uvh_nl_vif_del_handler(vrnu_vif_del_t *msg)
{
    unsigned int cidx = msg->vrnu_vif_idx;
    vr_uvh_client_t *vru_cl;

    vr_uvhost_log("Deleting vif %d virtual device\n", cidx);

    if (cidx >= VR_UVH_MAX_CLIENTS) {
        vr_uvhost_log("    error deleting vif %u: invalid vif index\n", cidx);
        return -1;
    }

    vr_dpdk_virtio_set_vif_client(cidx, NULL);

    vru_cl = vr_uvhost_get_client(cidx);
    if (vru_cl == NULL) {
        vr_uvhost_log("    error deleting vif %d: no client found\n",
                      cidx);
        return -1;
    }
    /* Unmmap guest memory. */
    uvhm_client_munmap(vru_cl);
    vr_uvhost_del_client(vru_cl);

    return 0;
}


/*
 * vr_uvh_nl_vif_add_handler - handle a vif add message from the netlink
 * thread. In response, the vhost server thread starts listening on the
 * UNIX domain socket corresponding to this vif.
 *
 * Returns 0 on success, -1 otherwise.
 */
static int
vr_uvh_nl_vif_add_handler(vrnu_vif_add_t *msg)
{
    int s = 0, ret = -1, err, sock_connected = 0;
    struct sockaddr_un sun;
    int flags;
    vr_uvh_client_t *vru_cl = NULL;
    mode_t umask_mode;

    if (msg == NULL) {
        vr_uvhost_log("    error adding vif %u: message is NULL\n",
                        msg->vrnu_vif_idx);
        return -1;
    }

    vr_uvhost_log("Adding vif %d virtual device %s\n", msg->vrnu_vif_idx,
                        msg->vrnu_vif_name);
    s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s == -1) {
        vr_uvhost_log("    error creating vif %u socket: %s (%d)\n",
                        msg->vrnu_vif_idx, rte_strerror(errno), errno);
        goto error;
    }
    vr_uvhost_log("    vif %u socket %s FD is %d\n",
                            msg->vrnu_vif_idx, msg->vrnu_vif_name, s);

    memset(&sun, 0, sizeof(sun));
    sun.sun_family = AF_UNIX;
    strncpy(sun.sun_path, vr_socket_dir, sizeof(sun.sun_path) - 1);
    strncat(sun.sun_path, "/"VR_UVH_VIF_PFX, sizeof(sun.sun_path)
        - strlen(sun.sun_path) - 1);
    strncat(sun.sun_path, msg->vrnu_vif_name,
        sizeof(sun.sun_path) - strlen(sun.sun_path) - 1);

    mkdir(vr_socket_dir, VR_DEF_SOCKET_DIR_MODE);
    /* qemu in server mode needs rw access */
    chmod(vr_socket_dir, 0777);

    /*
     * Client mode Qemu
     * vrouter-dpdk listens on the socket path
     */
    if (msg->vrnu_vif_vhostuser_mode == VRNU_VIF_MODE_CLIENT) {

        unlink(sun.sun_path);

        /*
         * Ensure RW permissions for the socket files such that QEMU process is
         * able to connect.
         */
        umask_mode = umask(~(S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH |
                S_IWOTH));

        ret = bind(s, (struct sockaddr *) &sun, sizeof(sun));
        if (ret == -1) {
            vr_uvhost_log("    error binding vif %u FD %d to %s: %s (%d)\n",
                msg->vrnu_vif_idx, s, sun.sun_path, rte_strerror(errno), errno);
            goto error;
        }

        umask(umask_mode);

        /*
         * Set the socket to non-blocking
         */
        flags = fcntl(s, F_GETFL, 0);
        fcntl(s, flags | O_NONBLOCK);

        ret = listen(s, 1);
        if (ret == -1) {
            vr_uvhost_log("    error listening vif %u socket FD %d: %s (%d)\n",
                            msg->vrnu_vif_idx, s, rte_strerror(errno), errno);
            goto error;
        }

    } else {
        /*
         * Server mode Qemu
         * Connect to the socket
         */
        ret = connect(s, (struct sockaddr *) &sun, sizeof(sun));
        if (ret == -1) {
            vr_uvhost_log("    error connecting uvhost socket FD %d to %s:"
                " %s (%d)\n", s, sun.sun_path, rte_strerror(errno), errno);
        } else {
            vr_uvhost_log("connected to sock    vif %u socket %s FD is %d\n",
                            msg->vrnu_vif_idx, msg->vrnu_vif_name, s);
            sock_connected = 1;
        }
    }

    vru_cl = vr_uvhost_new_client(s, sun.sun_path, msg->vrnu_vif_idx);
    if (vru_cl == NULL) {
        vr_uvhost_log("    error creating vif %u socket %s new vhost client\n",
                      msg->vrnu_vif_idx, sun.sun_path);
        goto error;
    }

    vru_cl->vruc_idx = msg->vrnu_vif_idx;
    vru_cl->vruc_nrxqs = msg->vrnu_vif_nrxqs;
    vru_cl->vruc_ntxqs = msg->vrnu_vif_ntxqs;
    vru_cl->vruc_vif_gen = msg->vrnu_vif_gen;
    vru_cl->vruc_vhostuser_mode = msg->vrnu_vif_vhostuser_mode;
    vru_cl->vruc_timer_fd = -1;

    if (msg->vrnu_vif_vhostuser_mode == VRNU_VIF_MODE_CLIENT) {
        /*
         * Client mode Qemu
         * add to listen handler
         */
        ret = vr_uvhost_add_fd(s, UVH_FD_READ, vru_cl, vr_uvh_cl_listen_handler);
        if (ret == -1) {
            vr_uvhost_log("    error adding vif %u socket FD %d\n",
                            msg->vrnu_vif_idx, s);
            goto error;
        }
    } else {
        if (sock_connected) {
            /*
             * Server mode Qemu
             * add to client handler
             */
            vr_uvhost_log("adding to msg handler    vif %u socket %s FD is %d\n",
                                msg->vrnu_vif_idx, msg->vrnu_vif_name, s);
            if (vr_uvhost_add_fd(s, UVH_FD_READ, vru_cl, vr_uvh_cl_msg_handler)) {
                vr_uvhost_log("    error adding client %s FD %d read handler\n",
                              sun.sun_path, s);
                goto error;
            }
        } else {
            if (vr_uvh_cl_timer_setup(vru_cl)) {
                vr_uvhost_log("    error adding vif %u socket %s to timer\n",
                            msg->vrnu_vif_idx, sun.sun_path);
                goto error;
            }
        }
    }

    vr_dpdk_virtio_set_vif_client(msg->vrnu_vif_idx, vru_cl);

    return 0;

error:

    err = errno;
    if (s) {
        close(s);
    }

    if (vru_cl) {
        vr_uvhost_del_client(vru_cl);
    }
    errno = err;

    return ret;
}


/*
 * vr_uvh_nl_msg_handler - handles messages received form the netlink
 * thread. This is usually to convey the name of the UNIX domain socket
 * that the user space vhost server should listen on for connections from
 * qemu.
 *
 * Returns 0, but logs a message if an error occurs. Returning error would
 * result in connection to netlink being removed from poll().
 */
static int
vr_uvh_nl_msg_handler(int fd, void *arg)
{
    vrnu_msg_t msg;
    int ret;

    ret = recv(fd, (void *) &msg, sizeof(msg), MSG_DONTWAIT);
    if (ret < 0) {
        if ((errno != EAGAIN) && (errno != EWOULDBLOCK)) {
            vr_uvhost_log("Error %d in netlink msg receive in vhost server\n",
                          errno);
            return 0;
        } else {
            return 0;
        }
    }

    if (ret != sizeof(msg)) {
        vr_uvhost_log("Received msg of length %d, expected %zu in vhost server",
                      ret, sizeof(msg));
        return 0;
    }

    switch (msg.vrnum_type) {
        case VRNU_MSG_VIF_ADD:
            ret = vr_uvh_nl_vif_add_handler(&msg.vrnum_vif_add);
            break;

        case VRNU_MSG_VIF_DEL:
            ret = vr_uvh_nl_vif_del_handler(&msg.vrnum_vif_del);
            break;

        default:
            vr_uvhost_log("Unknown netlink msg %d received in vhost server\n",
                          msg.vrnum_type);
            ret = -1;
            break;
    }

    return 0;
}

/*
 * vr_uvh_nl_listen_handler - handles conenctions from the netlink
 * thread.
 *
 * Returns 0 on success, -1 otherwise.
 */
int
vr_uvh_nl_listen_handler(int fd, void *arg)
{
    int s;
    struct sockaddr_un sun;
    socklen_t len = sizeof(sun);

    vr_uvhost_log("Handling connection FD %d...\n", fd);
    s = accept(fd, (struct sockaddr *) &sun, &len);
    if (s < 0) {
        vr_uvhost_log("    error accepting NetLink connection FD %d\n", fd);
        return -1;
    }
    vr_uvhost_log("    FD %d accepted new NetLink connection FD %d\n", fd, s);

    if (vr_uvhost_add_fd(s, UVH_FD_READ, NULL, vr_uvh_nl_msg_handler)) {
        vr_uvhost_log("    error adding socket %s FD %d read handler\n",
                      sun.sun_path, fd);
        return -1;
    }

    return 0;
}
