/*
 * uvrouter.c -- vrouter application
 *
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#include <stdio.h>
#include <unistd.h>

#include "vr_types.h"
#include "vr_os.h"
#include "vr_packet.h"
#include "vr_message.h"
#include "vr_interface.h"

#include "host/vr_host.h"
#include "host/vr_host_packet.h"
#include "host/vr_host_interface.h"

extern int vrouter_host_init(unsigned int);

#define PACKET_SIZE            2000
#define UVR_AGENT_BUFFER_SIZE  2000
#define UVR_AGENT_PORT         55555

static char *uvr_agent_buffer;
static int uvr_agent_fd = -1;

void
get_random_bytes(void *buf, int nbytes)
{
}

uint32_t
jhash(void *key, uint32_t length, uint32_t initval)
{
    uint32_t ret;
    int i;
    unsigned char *data = (unsigned char *)key;

    for (i = 0; i < length; i ++)
        ret +=  data[i];

    return ret;
}


static int
uvrouter_agent_rx(void *arg)
{
    int ret;
    struct sockaddr_in sock_addr;
    struct msghdr mhdr;
    struct iovec iov;
    struct vr_message request, *response;

    iov.iov_base = uvr_agent_buffer;
    iov.iov_len = UVR_AGENT_BUFFER_SIZE;

    bzero(&mhdr, sizeof(mhdr));
    mhdr.msg_iov = &iov;
    mhdr.msg_iovlen = 1;
    mhdr.msg_name = &sock_addr;
    mhdr.msg_namelen = sizeof(sock_addr);

    ret = recvmsg(uvr_agent_fd, &mhdr, MSG_DONTWAIT);
    if (ret <= 0)
        return ret;

    request.vr_message_buf = uvr_agent_buffer;
    request.vr_message_len = ret;
    vr_message_request(&request);

    while ((response = vr_message_dequeue_response())) {
        iov.iov_base = response->vr_message_buf;
        iov.iov_len = response->vr_message_len;
        ret = sendmsg(uvr_agent_fd, &mhdr, 0);
        vr_message_free(response);
        if (ret <= 0)
            break;
    }

    return ret;
}

static int
uvrouter_interface_init(void)
{
    int i = 0;
    struct vr_hinterface *hif = NULL;
    struct vr_hinterface *agent_hif = NULL, *eth_hif = NULL;

    agent_hif = vr_hinterface_create(HIF_AGENT_INTERFACE_INDEX, HIF_TYPE_UDP,
            VIF_TYPE_AGENT);
    if (!agent_hif)
        return -1;

    eth_hif = vr_hinterface_create(HIF_PHYSICAL_INTERFACE_INDEX, HIF_TYPE_UDP,
            VIF_TYPE_PHYSICAL);
    if (!eth_hif)
        goto cleanup;

    for (i = 0; i < HIF_NUM_VIRTUAL_INTERFACES; i++) {
        hif = vr_hinterface_create(HIF_VIRTUAL_INTERFACE_INDEX_START + i,
                HIF_TYPE_UDP, VIF_TYPE_VIRTUAL);
        if (!hif)
            goto cleanup;
    }

    return 0;

cleanup:
    if (agent_hif)
        vr_hinterface_delete(agent_hif);

    if (eth_hif)
        vr_hinterface_delete(eth_hif);

    for (--i; i >= 0; i--) {
        hif = vr_hinterface_get(i);
        if (hif) {
            vr_hinterface_put(hif);
            vr_hinterface_delete(hif);
        }
    }

    return -1;
}

static int
uvrouter_agent_sock_init(void)
{
    int ret;
    struct sockaddr_in sock_addr;

    uvr_agent_buffer = malloc(UVR_AGENT_BUFFER_SIZE);
    if (!uvr_agent_buffer)
        return -ENOMEM;

    uvr_agent_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (uvr_agent_fd < 0)
        return uvr_agent_fd;

    bzero(&sock_addr, sizeof(sock_addr));
    sock_addr.sin_family = AF_INET;
    sock_addr.sin_port = htons(UVR_AGENT_PORT);
    ret = bind(uvr_agent_fd, (const struct sockaddr *)&sock_addr,
            sizeof(sock_addr));
    if (ret < 0)
        goto cleanup;

    ret = vr_host_io_register(uvr_agent_fd, uvrouter_agent_rx, NULL);
    if (ret)
        goto cleanup;

    return 0;
cleanup:
    if (uvr_agent_fd >= 0)
        close(uvr_agent_fd);
    return ret;
}

int
main(int argc, const char *argv[])
{
    int ret;

    /* daemonize... */
    if (daemon(0, 0) < 0) {
        return -1;
	}
    vr_host_io_init();

    /* init the vrouter */
    ret = vrouter_host_init(VR_MPROTO_SANDESH);
    if (ret)
        return ret;

    /* create all the host interfaces statically */
    ret = uvrouter_interface_init();
    if (ret)
        return ret;

    /* init the communication sock with agent */
    ret = uvrouter_agent_sock_init();
    if (ret)
        return ret;

    /* vr_host_io does not return */
    vr_host_io();

    return 0;
}
