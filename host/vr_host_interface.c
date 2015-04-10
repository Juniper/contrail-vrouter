/*
 * vr_host_interface.c -- host interfaces
 *
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#include <sys/socket.h>

#include "vr_os.h"
#include "vr_packet.h"
#include "vr_interface.h"
#include "vrouter.h"
#include "host/vr_host.h"
#include "host/vr_host_packet.h"
#include "host/vr_host_interface.h"

struct hif_interface_md {
    unsigned short hif_udp_port;
    unsigned short hif_max_ports;
    unsigned int hif_num_ports;
} hif_interface_info[VIF_TYPE_MAX] = {
    [VIF_TYPE_HOST] = {
        .hif_udp_port       =       HIF_VHOST_UDP_PORT_START,
        .hif_max_ports      =       1,
    },

    [VIF_TYPE_AGENT] = {
        .hif_udp_port       =       HIF_AGENT_UDP_PORT_START,
        .hif_max_ports      =       1,
    },

    [VIF_TYPE_PHYSICAL] = {
        .hif_udp_port       =       HIF_PHYSICAL_UDP_PORT_START,
        .hif_max_ports      =       32,
    },

    [VIF_TYPE_VIRTUAL] = {
        .hif_udp_port       =       HIF_VIRTUAL_UDP_PORT_START,
        .hif_max_ports      =       32,
    },
};

static void
vr_netif_rx(struct vr_hinterface *hif, struct vr_hpacket *hpkt)
{
    struct vr_interface *vif = hif->hif_vif;

    if (vif)
        vif->vif_rx(vif, &hpkt->hp_packet, VLAN_ID_INVALID);
    else
        vr_hpacket_pool_free(hpkt);

    return;
}

static int
hif_udp_rx(void *arg)
{
    int ret = 0;
    struct vr_hinterface *hif = (struct vr_hinterface *)arg;
    struct vr_hpacket *hpkt;
    struct vr_packet *pkt;

    hpkt = vr_hpacket_pool_alloc(hif->hif_pkt_pool);
    if (!hpkt)
        assert(!hpkt);

    ret = read(hif->hif_fd, hpkt_data(hpkt), hpkt_size(hpkt));
    if (ret > 0) {
        hpkt->hp_tail += ret;
        pkt = &hpkt->hp_packet;
        pkt->vp_len = ret;
        pkt->vp_tail = hpkt->hp_tail;
        pkt->vp_if = hif->hif_vif;
        vr_netif_rx(hif, hpkt);
    } else {
        vr_hpacket_pool_free(hpkt);
    }

    return ret;
}

static unsigned int
hif_udp_tx(struct vr_hinterface *hif, struct vr_hpacket *hpkt)
{
    int i = 0;
    struct msghdr msg;
    struct vr_hpacket *hpkt_tmp = hpkt;
    struct iovec msg_iov[64];

    bzero(&msg, sizeof(msg));
    msg.msg_iov = msg_iov;
    while (hpkt_tmp && i < 64) {
        msg_iov[i].iov_base = hpkt_data(hpkt);
        msg_iov[i].iov_len = hpkt->hp_packet.vp_len;
        i++;
        hpkt_tmp = hpkt_tmp->hp_next;
    }

    msg.msg_iovlen = i;
    sendmsg(hif->hif_fd, &msg, 0);
    vr_hpacket_free(hpkt);
    return 0;
}

int
vr_hif_udp_create(struct vr_hinterface *hif, unsigned int vif_type)
{
    int sock = -1, port, ret;
    struct hif_interface_md *hif_info;
    struct sockaddr_in sock_addr;

    if (vif_type >= VIF_TYPE_MAX)
        return -EINVAL;

    hif_info = &hif_interface_info[vif_type];
    if (hif_info->hif_num_ports >= hif_info->hif_max_ports)
        return -ENOSPC;

    port = hif_info->hif_udp_port + hif_info->hif_num_ports;
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0 && (ret = sock))
        goto cleanup;

    bzero(&sock_addr, sizeof(sock_addr));
    sock_addr.sin_family = AF_INET;
    sock_addr.sin_port = htons(port);
    ret = bind(sock, (const struct sockaddr *)&sock_addr, sizeof(sock_addr));
    if (ret < 0)
        goto cleanup;

    bzero(&sock_addr, sizeof(sock_addr));
    sock_addr.sin_family = AF_INET;
    sock_addr.sin_port = htons(port - HIF_SOURCE_UDP_PORT_START +
            HIF_DESTINATION_UDP_PORT_START);
    ret = connect(sock, (const struct sockaddr *)&sock_addr, sizeof(sock_addr));
    if (ret < 0)
        goto cleanup;

    hif_info->hif_num_ports++;
    hif->hif_vif_type = vif_type;
    hif->hif_fd = sock;
    hif->hif_tx = hif_udp_tx;
    hif->hif_rx = hif_udp_rx;
    hif->hif_pkt_pool = vr_hpacket_pool_create(100, 2000);
    if (!hif->hif_pkt_pool)
        goto cleanup;

    ret = vr_host_io_register(hif->hif_fd, hif_udp_rx, hif);
    if (ret < 0)
        goto cleanup;

    return 0;
cleanup:
    if (sock >= 0)
        close(sock);

    if (hif && hif->hif_pkt_pool) {
        vr_hpacket_pool_destroy(hif->hif_pkt_pool);
        hif->hif_pkt_pool = NULL;
    }

    return ret;
}

static void
vr_hif_udp_destroy(struct vr_hinterface *hif)
{
    struct hif_interface_md *hif_info;

    vr_host_io_unregister(hif->hif_fd);

    hif_info = &hif_interface_info[hif->hif_vif_type];
    hif_info->hif_num_ports--;

    close(hif->hif_fd);
    free(hif);

    return;
}

struct vr_hinterface *
vr_hinterface_create(unsigned int index, unsigned int hif_type,
        unsigned int vif_type)
{
    int ret;
    struct vr_hinterface *hif;

    if (index >= HIF_MAX_INTERFACES)
        return NULL;

    if (hif_table[index])
        return NULL;

    hif = calloc(sizeof(*hif), 1);
    if (!hif)
        return NULL;

    switch (hif_type) {
    case HIF_TYPE_UDP:
        ret = vr_hif_udp_create(hif, vif_type);
        if (ret)
            goto cleanup;

        break;

    default:
        goto cleanup;
    }

    hif->hif_type = hif_type;
    hif->hif_index = index;
    hif->hif_users++;
    hif_table[index] = hif;

    return hif;
cleanup:
    if (hif)
        free(hif);

    return NULL;
}

void
vr_hinterface_destroy(struct vr_hinterface *hif)
{
    switch (hif->hif_type) {
    case HIF_TYPE_UDP:
        vr_hif_udp_destroy(hif);
        break;

    default:
        assert(0);
        break;
    }

    return;
}


struct vr_hinterface *
vr_hinterface_get(unsigned int index)
{
    struct vr_hinterface *hif;

    if (index >= HIF_MAX_INTERFACES)
        return NULL;

    hif = hif_table[index];
    if (hif)
        hif->hif_users++;

    return hif;
}

void
vr_hinterface_put(struct vr_hinterface *hif)
{
    /*
     * del & put are tightly bound. moment del happens hif_index
     * will turn to -1, and hence we should not hit the assert
     */
    if (hif->hif_index >= 0)
        assert(hif->hif_users > 1);

    assert(hif->hif_users > 0);
    if (!--hif->hif_users)
        vr_hinterface_destroy(hif);

    return;
}

void
vr_hinterface_delete(struct vr_hinterface *hif)
{
    hif_table[hif->hif_index] = NULL;
    hif->hif_index = -1;
    vr_hinterface_put(hif);

    return;
}


static int
vr_lib_interface_rx(struct vr_interface *vif, struct vr_packet *pkt)
{
    return 0;
}

static int
vr_lib_interface_tx(struct vr_interface *vif, struct vr_packet *pkt)
{
    struct vr_hinterface *hif = (struct vr_hinterface *)vif->vif_os;
    struct vr_hpacket *hpkt = VR_PACKET_TO_HPACKET(pkt);

    if (!hif) {
        vr_hpacket_free(hpkt);
        return 0;
    }

    return hif->hif_tx(hif, hpkt);
}

static int
vr_lib_interface_del_tap(struct vr_interface *vif)
{
    return 0;
}

static int
vr_lib_interface_add_tap(struct vr_interface *vif)
{
    return 0;
}

static int
vr_lib_interface_del(struct vr_interface *vif)
{
    struct vr_hinterface *hif = (struct vr_hinterface *)vif->vif_os;

    vif->vif_os = NULL;
    hif->hif_vif = NULL;
    vr_hinterface_put(hif);

    return 0;
}

static int
vr_lib_interface_add(struct vr_interface *vif)
{
    struct vr_hinterface *hif;

    hif = vr_hinterface_get(vif->vif_os_idx);
    if (!hif)
        return -ENODEV;

    hif->hif_vif = vif;
    vif->vif_os = (void *)hif;
    return 0;
}

struct vr_host_interface_ops vr_lib_interface_ops = {
    .hif_add            =   vr_lib_interface_add,
    .hif_del            =   vr_lib_interface_del,
    .hif_add_tap        =   vr_lib_interface_add_tap,
    .hif_del_tap        =   vr_lib_interface_del_tap,
    .hif_tx             =   vr_lib_interface_tx,
    .hif_rx             =   vr_lib_interface_rx,
};

void
vr_host_vif_init(struct vrouter *router)
{
    return;
}

void
vr_host_interface_exit(void)
{
    struct vr_hinterface *hif;
    int i;

    for (i = 0; i < HIF_MAX_INTERFACES; i++) {
        hif = hif_table[i];
        if (hif)
            vr_hinterface_delete(hif);
    }
}

struct vr_host_interface_ops *
vr_host_interface_init(void)
{
    return &vr_lib_interface_ops;
}
