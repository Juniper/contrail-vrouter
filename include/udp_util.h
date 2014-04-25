/*
 * udp_util.h --
 *
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */

#ifndef __UDP_UTIL_H__
#define __UDP_UTIL_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "vr_utils.h"
#define UDP_RESP_DEFAULT_SIZE        512
#define UDP_MSG_DEFAULT_SIZE         4096

#define UDP_IFTYPE_PHYSICAL          0
#define UDP_IFTYPE_AGENT             1
#define UDP_IFTYPE_VIRTUAL           2

#define UVR_MORE                     0x00000001
#define UVR_IF_MSG                   0x00010000

struct uvr_msg_hdr {
    uint32_t seq_no;
    uint32_t msg_len;
    uint32_t flags;
};

struct udp_response {
    unsigned int udp_len;
    uint8_t  *udp_data;
};

struct udp_client {
    char *cl_buf;
    /* length of the buffer in cl_buf */
    unsigned int cl_buf_len;
    int cl_sock;

    uint32_t cl_buf_offset;
    /* length of the message received from recvmsg */
    uint32_t cl_recv_len;
    struct udp_response cl_resp;
};

extern struct udp_client *udp_register_client(void);
extern void udp_free_client(struct udp_client *);
extern int udp_socket(struct udp_client *, uint16_t port);
extern int udp_sendmsg(struct udp_client *);
extern int udp_recvmsg(struct udp_client *);
extern struct udp_response *udp_parse_reply(struct udp_client *);
extern uint8_t *udp_get_buf_ptr(struct udp_client *);
extern uint32_t udp_get_buf_len(struct udp_client *);
extern void udp_update_len(struct udp_client *, unsigned int);

extern int uvr_nametoindex(const char *);
extern int uvr_nametotype(const char *);
#ifdef __cplusplus
}
#endif
#endif /* __UDP_UTIL_H__ */

