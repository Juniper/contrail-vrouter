/*-
 * Copyright (c) 2014 Semihalf
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#ifndef __VR_FREEBSD_H__
#define __VR_FREEBSD_H__

#include "vr_packet.h"

#define VROUTER_VERSIONID 1

/* Vrouter communication socket's ("fake Netlink") sizes of buffers */
#if PAGE_SIZE > 4096UL
#define VR_SOCK_SEND_BUFF_SIZE 4096UL
#define VR_SOCK_RECV_BUFF_SIZE 4096UL
#else
#define VR_SOCK_SEND_BUFF_SIZE PAGE_SIZE
#define VR_SOCK_RECV_BUFF_SIZE PAGE_SIZE
#endif

extern int vr_log_level;

enum {
    VR_ERR,
    VR_INFO,
    VR_DEBUG
};

#define vr_log(lvl, fmt, args...) \
    do {\
        if (vr_log_level >= lvl) \
            printf("%s:"fmt, __func__, ##args); \
    } while (0)

struct vr_packet_wrapper {
    /*
     * NOTE!
     * 'pkt' field must be first as we cast between wrapper and packet
     */
    struct vr_packet    vrw_pkt;
    struct mbuf     *vrw_m;
};

/* mbuf<=>packet conversion */
static __inline__ struct mbuf *
vp_os_packet(struct vr_packet *pkt)
{
    /* Fetch original mbuf from packet structure */
    return (((struct vr_packet_wrapper *)pkt)->vrw_m);
}

struct vr_packet * freebsd_get_packet(struct mbuf *m,
    struct vr_interface *vif);
int freebsd_to_vr(struct vr_interface *vif, struct mbuf* m);

/* Contrail socket initialization/clean */
int contrail_socket_init(void);
void contrail_socket_destroy(void);

/* Sandesh protocol and messages */
int vr_transport_init(void);
void vr_transport_exit(void);
int vr_transport_request(struct socket *so, char *buf, size_t len);

/* vhost && vif connection */
void vhost_if_add(struct vr_interface *vif);
void vhost_if_del(struct ifnet* ifp);

#endif /* __VR_FREEBSD_H__ */
