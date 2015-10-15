/*
 * vr_uvhost_msg.c - handlers for messages received by the user space
 * vhost thread.
 *
 * Copyright (c) 2014 Juniper Networks, Inc. All rights reserved.
 */

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

#include <rte_errno.h>
#include <rte_hexdump.h>
typedef int (*vr_uvh_msg_handler_fn)(vr_uvh_client_t *vru_cl);

/*
 * Prototypes for user space vhost message handlers
 */
static int vr_uvmh_get_features(vr_uvh_client_t *vru_cl);
static int vr_uvhm_set_mem_table(vr_uvh_client_t *vru_cl);
static int vr_uvhm_set_ring_num_desc(vr_uvh_client_t *vru_cl);
static int vr_uvhm_set_vring_addr(vr_uvh_client_t *vru_cl);
static int vr_uvhm_set_vring_base(vr_uvh_client_t *vru_cl);
static int vr_uvhm_get_vring_base(vr_uvh_client_t *vru_cl);
static int vr_uvhm_set_call_fd(vr_uvh_client_t *vru_cl);

static vr_uvh_msg_handler_fn vr_uvhost_cl_msg_handlers[] = {
    NULL,
    vr_uvmh_get_features,
    NULL,
    NULL,
    NULL,
    vr_uvhm_set_mem_table,
    NULL,
    NULL,
    vr_uvhm_set_ring_num_desc,
    vr_uvhm_set_vring_addr,
    vr_uvhm_set_vring_base,
    vr_uvhm_get_vring_base,
    NULL,
    vr_uvhm_set_call_fd,
    NULL
};

/*
 * vr_uvmh_get_features - handle VHOST_USER_GET_FEATURES message from user space
 * vhost client.
 *
 * Returns 0 on success, -1 otherwise.
 */
static int
vr_uvmh_get_features(vr_uvh_client_t *vru_cl)
{
    /* TODO Implement VHOST_F_LOG_ALL handler */
    /* VIRTIO_NET_F_CTRL_VQ is enough for vMX and FreeBSD */
    vru_cl->vruc_msg.u64 = (1ULL << VIRTIO_NET_F_CTRL_VQ) |
                           (1ULL << VIRTIO_NET_F_CSUM) |
                           (1ULL << VIRTIO_NET_F_GUEST_CSUM) |
                           (1ULL << VHOST_F_LOG_ALL);

    vru_cl->vruc_msg.size = sizeof(vru_cl->vruc_msg.u64);

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
    int i;
    int ret;
    vr_uvh_client_mem_region_t *region;
    VhostUserMemory *vum_msg;
    uint64_t size;
    vr_dpdk_uvh_vif_mmap_addr_t *const vif_mmap_addrs = (
                             &(vr_dpdk_virtio_uvh_vif_mmap[vru_cl->vruc_idx]));

    vum_msg = &vru_cl->vruc_msg.memory;
    vr_uvhost_log("Number of memory regions: %d\n", vum_msg->nregions);
    for (i = 0; i < vum_msg->nregions; i++) {
        vr_uvhost_log("Region %d: physical address 0x%" PRIx64 ", size 0x%"
                PRIx64 ", offset 0x%" PRIx64 "\n",
                i, vum_msg->regions[i].guest_phys_addr,
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
                                            mmap(0,
                                            size,
                                            PROT_READ | PROT_WRITE,
                                            MAP_SHARED,
                                            vru_cl->vruc_fds_sent[i],
                                            0);

            if (region->vrucmr_mmap_addr == ((uint64_t)MAP_FAILED)) {
                vr_uvhost_log("mmap for size 0x%" PRIx64 " failed for FD %d"
                        " on vhost client %s (%s)\n",
                        size,
                        vru_cl->vruc_fds_sent[i],
                        vru_cl->vruc_path, rte_strerror(errno));
                /* the file descriptor is no longer needed */
                close(vru_cl->vruc_fds_sent[i]);
                vru_cl->vruc_fds_sent[i] = -1;
                return -1;
            }
            /* Set values for munmap(2) function. */
            ret = vr_dpdk_virtio_uvh_get_blk_size(vru_cl->vruc_fds_sent[i],
                                 &vif_mmap_addrs->vu_mmap_data[i].unmap_blksz);
            if (ret) {
                vr_uvhost_log("Get block size failed for FD %d on vhost client %s \n",
                              vru_cl->vruc_fds_sent[i], vru_cl->vruc_path);
                return -1;
            }

            vif_mmap_addrs->vu_mmap_data[i].unmap_mmap_addr = ((uint64_t)
                                                       region->vrucmr_mmap_addr);
            vif_mmap_addrs->vu_mmap_data[i].unmap_size = size;

            /* the file descriptor is no longer needed */
            close(vru_cl->vruc_fds_sent[i]);
            vru_cl->vruc_fds_sent[i] = -1;
            region->vrucmr_mmap_addr += vum_msg->regions[i].mmap_offset;
        }
    }

    /* Save the number of regions. */
    vru_cl->vruc_num_mem_regions = vum_msg->nregions;
    vif_mmap_addrs->vu_nregions = vum_msg->nregions;

    return 0;
}

/*
 * vr_uvhm_set_ring_num_desc - handles VHOST_USER_SET_VRING_NUM message from
 * the user space vhost client to set the number of descriptors in the virtio
 * ring.
 *
 * Returns 0 on success, -1 otherwise.
 */
static int
vr_uvhm_set_ring_num_desc(vr_uvh_client_t *vru_cl)
{
    VhostUserMsg *vum_msg;
    unsigned int vring_idx;

    vum_msg = &vru_cl->vruc_msg;
    vring_idx = vum_msg->state.index;

    if (vring_idx >= VHOST_CLIENT_MAX_VRINGS) {
        vr_uvhost_log("Bad ring index %d received by vhost server\n",
                      vring_idx);
        return -1;
    }
    if (vr_dpdk_set_ring_num_desc(vru_cl->vruc_idx, vring_idx,
                                  vum_msg->state.num)) {
        vr_uvhost_log("Could set number of vring descriptors in vhost server"
                      " %d %d %d\n",
                      vru_cl->vruc_idx, vring_idx,
                      vum_msg->state.num);
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
    if (vring_idx >= VHOST_CLIENT_MAX_VRINGS) {
        vr_uvhost_log("Bad ring index %d received by vhost server\n",
                      vring_idx);
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
        vr_uvhost_log("Couldn't set vring addresses in vhost server, %d %d\n",
                      vru_cl->vruc_idx, vring_idx);
        return -1;
    }

    /*
     * Now that the addresses have been set, the virtio queue is ready for
     * forwarding.
     *
     * TODO - need a memory barrier here. Also , queue may need to be set to
     * READY after callfd is set.
     */
    if (vr_dpdk_set_virtq_ready(vru_cl->vruc_idx, vring_idx, VQ_READY)) {
        vr_uvhost_log("Couldn't set virtio queue ready in vhost server, "
                      "%d %d\n",
                      vru_cl->vruc_idx, vring_idx);
        return -1;
    }

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

    if (vring_idx >= VHOST_CLIENT_MAX_VRINGS) {
        vr_uvhost_log("Bad ring index %d received by vhost server\n",
                      vring_idx);
        return -1;
    }

    if (vr_dpdk_virtio_set_vring_base(vru_cl->vruc_idx, vring_idx,
                                      vum_msg->state.num)) {
        vr_uvhost_log("Couldn't set vring base in vhost server %d %d %d\n",
                      vru_cl->vruc_idx, vring_idx, vum_msg->state.num);
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

    if (vring_idx >= VHOST_CLIENT_MAX_VRINGS) {
        vr_uvhost_log("Bad ring index %d received by vhost server\n",
                      vring_idx);
        return -1;
    }

    if (vr_dpdk_virtio_get_vring_base(vru_cl->vruc_idx, vring_idx,
                                     &vum_msg->state.num)) {
        vr_uvhost_log("Couldn't get vring base in vhost server %d %d\n",
                      vru_cl->vruc_idx, vring_idx);
        return -1;
    }

    vum_msg->size = sizeof(struct vhost_vring_state);

    return 0;
}

/*
 * vr_uvhm_set_call_fd - handles a VHOST_USER_SET_VRING_CALL messsage
 * from the vhost user client to set the eventfd to be used to interrupt the
 * guest, if required.
 *
 * Returns 0 on success, -1 otherwise.
 */
static int
vr_uvhm_set_call_fd(vr_uvh_client_t *vru_cl)
{
    VhostUserMsg *vum_msg;
    unsigned int vring_idx;

    vum_msg = &vru_cl->vruc_msg;
    vring_idx = vum_msg->state.index;

    if (vring_idx >= VHOST_CLIENT_MAX_VRINGS) {
        vr_uvhost_log("Bad ring index %d received by vhost server in callfd\n",
                      vring_idx);
        return -1;
    }

    if (vr_dpdk_set_ring_callfd(vru_cl->vruc_idx, vring_idx,
                                vru_cl->vruc_fds_sent[0])) {
        vr_uvhost_log("Could not set callfd in vhost server"
                      " %d %d %d\n",
                      vru_cl->vruc_idx, vring_idx,
                      vru_cl->vruc_fds_sent[0]);
        return -1;
    }
    /* set FD to -1, so we do not close it on cleanup */
    vru_cl->vruc_fds_sent[0] = -1;

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
    int i;

    if ((msg->request <= VHOST_USER_NONE) ||
            (msg->request >= VHOST_USER_MAX)) {
        return -1;
    }

    if (vr_uvhost_cl_msg_handlers[msg->request]) {
        vr_uvhost_log("Client %s: handling message %d\n",
            /* strip socket prefix */
            vru_cl->vruc_path + strlen(VR_UVH_VIF_PREFIX), msg->request);
        if (vru_cl->vruc_num_fds_sent > 0) {
            for (i = 0; i < vru_cl->vruc_num_fds_sent; i++) {
                vr_uvhost_log("    message %d sent FD: %d\n",
                    msg->request, vru_cl->vruc_fds_sent[i]);
            }
        }
        return vr_uvhost_cl_msg_handlers[msg->request](vru_cl);
    } else {
        vr_uvhost_log("Client %s: no handler defined for message %d\n",
            /* strip socket prefix */
            vru_cl->vruc_path + strlen(VR_UVH_VIF_PREFIX), msg->request);
    }

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
                 * TODO - handle EAGAIN/EWOULDBLOCK
                 */
                vr_uvhost_log("Error sending vhost user reply to %s\n",
                              vru_cl->vruc_path);
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

            vr_uvhost_log("Receive returned %d in vhost server for client %s\n",
                          ret, vru_cl->vruc_path);
            ret = -1;
            goto cleanup;
        } else if (ret > 0) {
            if (mhdr.msg_flags & MSG_CTRUNC) {
                vr_uvhost_log("Truncated control message from vhost client %s\n",
                             vru_cl->vruc_path);
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
                        vr_uvhost_log("Too many FDs sent for client %s: %d\n",
                                vru_cl->vruc_path,  vru_cl->vruc_num_fds_sent);
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
            vr_uvhost_log("Receive returned %d in vhost server for client %s\n",
                          ret, vru_cl->vruc_path);
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
            RTE_LOG(DEBUG, UVHOST, "%s[%lx]: FD %d read %d bytes\n", __func__,
                pthread_self(), fd, ret);
            rte_hexdump(stdout, "uvhost full message dump:",
                (((char *)&vru_cl->vruc_msg)),
                    ret + vru_cl->vruc_msg_bytes_read);
        } else if (ret < 0) {
            RTE_LOG(DEBUG, UVHOST, "%s[%lx]: FD %d read returned error %d: %s (%d)\n", __func__,
                pthread_self(), fd, ret, rte_strerror(errno), errno);
        }
#endif
        if (ret < 0) {
            if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
                ret = 0;
                goto cleanup;
            }

            vr_uvhost_log(
                "Error: read returned %d, %d %d %d in vhost server for client %s\n",
                ret, errno, read_len,
                vru_cl->vruc_msg_bytes_read, vru_cl->vruc_path);
            ret = -1;
            goto cleanup;
        } else if (ret == 0) {
             vr_uvhost_log("Read returned %d in vhost server for client %s\n",
                           ret, vru_cl->vruc_path);
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
        vr_uvhost_log("Error handling message %d client %s\n",
                      vru_cl->vruc_msg.request, vru_cl->vruc_path);
        ret = -1;
        goto cleanup;
    }

    ret = vr_uvh_cl_send_reply(fd, vru_cl);
    if (ret < 0) {
        vr_uvhost_log("Error sending reply for message %d client %s\n",
                      vru_cl->vruc_msg.request, vru_cl->vruc_path);
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
        /* set VQ_NOT_READY state to vif's queues. */
        for (i = 0; i < VR_DPDK_VIRTIO_MAX_QUEUES; i++) {
            vr_dpdk_virtio_rxqs[vru_cl->vruc_idx][i].vdv_ready_state = VQ_NOT_READY;
            vr_dpdk_virtio_txqs[vru_cl->vruc_idx][i].vdv_ready_state = VQ_NOT_READY;
        }
        rte_wmb();
        synchronize_rcu();
        /*
        * Unmaps qemu's FDs.
        */
        vr_dpdk_virtio_uvh_vif_munmap(&vr_dpdk_virtio_uvh_vif_mmap[vru_cl->vruc_idx]);
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

    if (cidx >= VR_UVH_MAX_CLIENTS) {
        vr_uvhost_log("Couldn't delete vhost client due to bad index %d\n",
                      cidx);
        return -1;
    }

    vr_dpdk_virtio_set_vif_client(cidx, NULL);

    vru_cl = vr_uvhost_get_client(cidx);
    if (vru_cl == NULL) {
        vr_uvhost_log("Couldn't find vhost client %d for deletion\n",
                      cidx);
        return -1;
    }
    /*
     * Unmmaps Qemu's FD
     */
    vr_dpdk_virtio_uvh_vif_munmap(&vr_dpdk_virtio_uvh_vif_mmap[cidx]);
    if (vru_cl->vruc_fd != -1) {
        vr_uvhost_del_fd(vru_cl->vruc_fd, UVH_FD_READ);
    }

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
    int s = 0, ret = -1, err;
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
    strncpy(sun.sun_path, VR_UVH_VIF_PREFIX, sizeof(sun.sun_path) - 1);
    strncat(sun.sun_path, msg->vrnu_vif_name,
        sizeof(sun.sun_path) - strlen(sun.sun_path) - 1);
    sun.sun_family = AF_UNIX;

    mkdir(VR_SOCKET_DIR, VR_SOCKET_DIR_MODE);
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

    vru_cl = vr_uvhost_new_client(s, sun.sun_path, msg->vrnu_vif_idx);
    if (vru_cl == NULL) {
        vr_uvhost_log("    error creating vif %u socket %s new vhost client\n",
                      msg->vrnu_vif_idx, sun.sun_path);
        goto error;
    }

    vru_cl->vruc_idx = msg->vrnu_vif_idx;
    vru_cl->vruc_nrxqs = msg->vrnu_vif_nrxqs;
    vru_cl->vruc_ntxqs = msg->vrnu_vif_ntxqs;

    ret = vr_uvhost_add_fd(s, UVH_FD_READ, vru_cl, vr_uvh_cl_listen_handler);
    if (ret == -1) {
        vr_uvhost_log("    error adding vif %u socket FD %d\n",
                        msg->vrnu_vif_idx, s);
        goto error;
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
 * Returns 0 on success, -1 otherwise.
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
            return ret;
        } else {
            return 0;
        }
    }

    if (ret != sizeof(msg)) {
        vr_uvhost_log("Received msg of length %d, expected %d in vhost server",
                      ret, sizeof(msg));
        return -1;
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

    return ret;
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
