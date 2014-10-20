/*
 * vr_uvhost_msg.c - handlers for messages received by the user space
 * vhost thread.
 *
 * Copyright (c) 2014 Juniper Networks, Inc. All rights reserved.
 */
#include <sys/select.h>
#include <sys/un.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <linux/vhost.h>
#include <stdint.h>
#include <sys/mman.h>
#include <fcntl.h>

#include "vr_uvhost_util.h"
#include "vr_uvhost_msg.h"
#include "qemu_uvhost.h"
#include "vr_uvhost_client.h"

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
    NULL,
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
    vru_cl->vruc_msg.u64 = 0;
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
    vr_uvh_client_mem_region_t *region;
    VhostUserMemory *vum_msg;
    uint64_t size;

    vum_msg = &vru_cl->vruc_msg.memory;

    for (i = 0; i < vum_msg->nregions; i++) {
        if (vru_cl->vruc_fds_sent[i]) {
            region = &vru_cl->vruc_mem_regions[i];
            
            region->vrucmr_phys_addr = vum_msg->regions[i].guest_phys_addr;
            region->vrucmr_size = vum_msg->regions[i].memory_size;
            region->vrucmr_user_space_addr = vum_msg->regions[i].userspace_addr;

            size = vum_msg->regions[i].mmap_offset + 
                       vum_msg->regions[i].memory_size;
            region->vrucmr_mmap_addr = (uint64_t) 
                                            mmap(0, size, 
                                            PROT_READ | PROT_WRITE,
                                            MAP_SHARED,
                                            vru_cl->vruc_fds_sent[i], 0);
            
            if (region->vrucmr_mmap_addr == ((uint64_t)MAP_FAILED)) {
                vr_uvhost_log("mmap failed for fd %d on vhost client %s\n",
                              vru_cl->vruc_fds_sent[i],
                              vru_cl->vruc_path);
                return -1;
            }

            region->vrucmr_mmap_addr += vum_msg->regions[i].mmap_offset;
        }           
    }

    vru_cl->vruc_num_mem_regions = vum_msg->nregions;

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

    vru_cl->vruc_vvs[vring_idx].index = vum_msg->state.index;
    vru_cl->vruc_vvs[vring_idx].num = vum_msg->state.num;
    
    return 0;
}

/*
 * vr_uvhm_map_addr - map a virtual address sent by the vhost client into
 * a server virtual address.
 *
 * Returns a pointer to teh corresponding location on success, NULL otherwise.
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

    vaddr = &vru_cl->vruc_msg.addr;

    vring_idx = vaddr->index;
    if (vring_idx >= VHOST_CLIENT_MAX_VRINGS) {
        vr_uvhost_log("Bad ring index %d received by vhost server\n",
                      vring_idx);
        return -1;
    }

    vru_cl->vruc_vvr[vring_idx].vrucv_desc = (struct vring_desc *)
        vr_uvhm_map_addr(vru_cl, vaddr->desc_user_addr);
    vru_cl->vruc_vvr[vring_idx].vrucv_avail = (struct vring_avail *)
        vr_uvhm_map_addr(vru_cl, vaddr->avail_user_addr);
    vru_cl->vruc_vvr[vring_idx].vrucv_used = (struct vring_used *)
        vr_uvhm_map_addr(vru_cl, vaddr->used_user_addr);

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

    vru_cl->vruc_vvr[vring_idx].vrucv_base_idx = vum_msg->state.num;

    return 0;
}

/*
 * vr_uvhm_get_vring_base - handles a VHOST_USER_GET_VRING_BASE messsage
 * from the vhost user client to get the based index of a vring.
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

    vum_msg->state.num = vru_cl->vruc_vvr[vring_idx].vrucv_base_idx; 
    vum_msg->size = sizeof(struct vhost_vring_state);

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
        vr_uvhost_log("Calling handler for message %d\n", msg->request);
        return vr_uvhost_cl_msg_handlers[msg->request](vru_cl);
    } else {
        vr_uvhost_log("No handler defined for message %d\n", msg->request);
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
vr_uvh_cl_send_reply(vr_uvh_client_t *vru_cl)
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

            ret = send(vru_cl->vruc_fd, (void *) msg, 
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
    int ret, read_len = 0;
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
                return 0;
            }

            vr_uvhost_log("Receive returned %d in vhost server for client %s\n", 
                          ret, vru_cl->vruc_path);
            return -1;
        } else if (ret > 0) {
            if (mhdr.msg_flags & MSG_CTRUNC) {
                vr_uvhost_log("Truncated control message from vhost client %s\n",
                             vru_cl->vruc_path);
                return -1;
            }

            cmsg = CMSG_FIRSTHDR(&mhdr);
            if (cmsg && (cmsg->cmsg_len > 0) &&
                   (cmsg->cmsg_level == SOL_SOCKET) &&
                   (cmsg->cmsg_type == SCM_RIGHTS)) {  
                   vru_cl->vruc_num_fds_sent = (cmsg->cmsg_len - CMSG_LEN(0))/
                                                   sizeof(int);
                   if (vru_cl->vruc_num_fds_sent > VHOST_MEMORY_MAX_NREGIONS) {
                       vru_cl->vruc_num_fds_sent = VHOST_MEMORY_MAX_NREGIONS;
                   }

                   memcpy(vru_cl->vruc_fds_sent, CMSG_DATA(cmsg),
                          vru_cl->vruc_num_fds_sent*sizeof(int));
            }

            vru_cl->vruc_msg_bytes_read = ret;
            if (ret < VHOST_USER_HSIZE) {
                return 0;
            }

            read_len = vru_cl->vruc_msg.size; 
        } else { 
            /*
             * recvmsg returned 0, so return error.
             */
            vr_uvhost_log("Receive returned %d in vhost server for client %s\n",
                          ret, vru_cl->vruc_path);
            return -1;
        }    
    } else if (vru_cl->vruc_msg_bytes_read < VHOST_USER_HSIZE) {
        read_len = VHOST_USER_HSIZE - vru_cl->vruc_msg_bytes_read;
    } else {
        read_len = vru_cl->vruc_msg.size - 
                       (vru_cl->vruc_msg_bytes_read - VHOST_USER_HSIZE);
    }        
   
    if (read_len) { 
        ret = read(fd, (((char *)&vru_cl->vruc_msg) + vru_cl->vruc_msg_bytes_read),
                   read_len);
        if (ret < 0) {
            if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
                return 0;
            }

            vr_uvhost_log(
                "Read returned %d, %d %d %d in vhost server for client %s\n",
                ret, errno, read_len,
                vru_cl->vruc_msg_bytes_read, vru_cl->vruc_path);
            return -1;
        } else if (ret == 0) {
             vr_uvhost_log("Read returned %d in vhost server for client %s\n",
                           ret, vru_cl->vruc_path); 
            return -1;
        }  
      
        vru_cl->vruc_msg_bytes_read += ret; 
        if (vru_cl->vruc_msg_bytes_read < VHOST_USER_HSIZE) {
            return 0;
        }

        if (vru_cl->vruc_msg_bytes_read < 
                (vru_cl->vruc_msg.size + VHOST_USER_HSIZE)) {
            return 0;
        }
    }

    ret = vr_uvh_cl_call_handler(vru_cl);
    if (ret < 0) {
        vr_uvhost_log("Error calling message handler for client %s\n",
                      vru_cl->vruc_path);
        return -1;
    }

    ret = vr_uvh_cl_send_reply(vru_cl);
    if (ret < 0) {
        vr_uvhost_log("Error sending reply to vhost client %s\n",
                      vru_cl->vruc_path);
        return -1;
    }

    /*
     * Message received successully, so clear state for next message from
     * this client.
     */        
    vru_cl->vruc_msg_bytes_read = 0;
    memset(&vru_cl->vruc_msg, 0, sizeof(vru_cl->vruc_msg));
    memset(vru_cl->vruc_cmsg, 0, sizeof(vru_cl->vruc_cmsg));
    memset(vru_cl->vruc_fds_sent, 0, sizeof(vru_cl->vruc_fds_sent));
    vru_cl->vruc_num_fds_sent = 0;

    return 0;
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
    int s = 0;
    struct sockaddr_un sun;
    socklen_t len = sizeof(sun);
    vr_uvh_client_t *vru_cl = (vr_uvh_client_t *) arg;

    s = accept(fd, (struct sockaddr *) &sun, &len);
    if (s < 0) {
        if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
            return 0;
        }

        vr_uvhost_log("Error in client connection accept in vhost server\n");
        return -1;
    }

    /*
     * Don't need to listen on the socket any more.
     */
    vr_uvhost_del_fd(fd, UVH_FD_READ);
    vr_uvhost_cl_set_fd(vru_cl, s);

    if (vr_uvhost_add_fd(s, UVH_FD_READ, vru_cl, vr_uvh_cl_msg_handler)) {
        vr_uvhost_log("Error adding message fd for vhost client %s\n",
                      sun.sun_path);
        goto error;
    }

    return 0;

error:

    if (s) {
        close(s);
    }

    if (vru_cl) {
        vr_uvhost_del_client(vru_cl);
    }

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

    vru_cl = vr_uvhost_get_client(cidx);
    if (vru_cl == NULL) {
        vr_uvhost_log("Couldn't find vhost client %d for deletion\n",
                      cidx);
        return -1;
    }

    if (vru_cl->vruc_fd != -1) {
        vr_uvhost_del_fd(vru_cl->vruc_fd, UVH_FD_READ);
    }

    vru_cl->vruc_fd = -1;

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
    int s = 0, ret = -1;
    struct sockaddr_un sun;
    int flags;
    vr_uvh_client_t *vru_cl = NULL;

    if (msg == NULL) {
        return -1;
    }

    s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s < 0) {
        vr_uvhost_log("Error %d creating socket in vhost server\n",
                      errno);
        goto error;
    }

    strncpy(sun.sun_path, VR_UVH_VIF_PREFIX, VR_UVH_VIF_PREFIX_SIZE+1);
    strncat(sun.sun_path, msg->vrnu_vif_name, VR_UVH_VIF_NAME_SIZE);
    sun.sun_family = AF_UNIX;

    unlink(sun.sun_path);
            
    ret = bind(s, (struct sockaddr *) &sun, sizeof(sun));
    if (ret < 0) {
        vr_uvhost_log("Error %d binding vhost server socket %s\n", 
                      errno, sun.sun_path);
        goto error;
    }

    /* 
     * Set the socket to non-blocking
     */
    flags = fcntl(s, F_GETFL, 0);
    fcntl(s, flags | O_NONBLOCK);

    ret = listen(s, 1);
    if (ret < 0) {
        vr_uvhost_log("Error %d listening on vhost server socket %s\n",
                      errno, sun.sun_path);
        goto error;
    }

    vru_cl = vr_uvhost_new_client(s, sun.sun_path, msg->vrnu_vif_idx);
    if (vru_cl == NULL) {
        vr_uvhost_log("Error creating new vhost client for %s\n",
                      sun.sun_path);
        goto error;
    }

    vru_cl->vruc_idx =  msg->vrnu_vif_idx;
    vru_cl->vruc_nrxqs = msg->vrnu_vif_nrxqs;
    vru_cl->vruc_ntxqs = msg->vrnu_vif_ntxqs;

    ret = vr_uvhost_add_fd(s, UVH_FD_READ, vru_cl, vr_uvh_cl_listen_handler);
    if (ret) {
        vr_uvhost_log("Error adding listen fd for vhost client %s\n",
                      sun.sun_path);
        goto error;
    }

    return 0;

error:

    if (s) {
        close(s);
    }

    if (vru_cl) {
        vr_uvhost_del_client(vru_cl);
    }
 
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

    s = accept(fd, (struct sockaddr *) &sun, &len);
    if (s < 0) {
        vr_uvhost_log("Error in netlink connection accept in vhost server\n");
        return -1;
    }

    if (vr_uvhost_add_fd(s, UVH_FD_READ, NULL, vr_uvh_nl_msg_handler)) {
        vr_uvhost_log("Error adding netlink socket fd in vhost server\n");
        return -1;
    }
 
    return 0;
}
