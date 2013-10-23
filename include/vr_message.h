/*
 * vr_message.h -- messaging
 *
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#ifndef __VR_MESSAGE_H__
#define __VR_MESSAGE_H__

#include "vr_queue.h"

#define VR_MESSAGE_DUMP_INCOMPLETE      (0x1 << 30)
#define VR_MPROTO_SANDESH               1
#define VR_MPROTO_DIET                  2

#define VR_MESSAGE_TYPE_REQUEST         0
#define VR_MESSAGE_TYPE_RESPONSE        1

#define VR_NULL_OBJECT_ID               0
#define VR_INTERFACE_OBJECT_ID          1
#define VR_NEXTHOP_OBJECT_ID            2
#define VR_ROUTE_OBJECT_ID              3
#define VR_MPLS_OBJECT_ID               4
#define VR_MIRROR_OBJECT_ID             5
#define VR_FLOW_OBJECT_ID               6
#define VR_RESPONSE_OBJECT_ID           7
#define VR_VRF_ASSIGN_OBJECT_ID         8
#define VR_VRF_STATS_OBJECT_ID          9
#define VR_DROP_STATS_OBJECT_ID         10
#define VR_VXLAN_OBJECT_ID              11

#define VR_MESSAGE_PAGE_SIZE            (4096 - 128)

struct vr_mproto {
    unsigned int mproto_type;
    unsigned int (*mproto_buf_len)(unsigned int, void *);
    int         (*mproto_encode)(char *, unsigned int,
            unsigned int, void *, unsigned int);
    int         (*mproto_encode_response)(char *, unsigned int, unsigned int,
                                            void *, int);
    int         (*mproto_decode)(char *, unsigned int,
            int (*)(void *, unsigned int, void *), void *);
};

struct vr_mtransport {
    char    *(*mtrans_alloc)(unsigned int);
    void    (*mtrans_free)(char *);
};

struct vr_message {
    char *vr_message_buf;
    unsigned int vr_message_len;
    struct vr_qelem vr_message_queue;
};

struct vr_message_handler {
    struct vr_mproto *vm_proto;
    struct vr_mtransport *vm_trans;
    struct vr_qhead vm_response_queue;
};

struct vr_message_dumper {
    void *dump_req;
    unsigned int dump_been_to_marker;
    unsigned int dump_num_dumps;
    unsigned int dump_num_dumped;
    char *dump_buffer;
    unsigned int dump_buf_len;
    unsigned int dump_resp_len;
    unsigned int dump_offset;
};


int vr_message_transport_register(struct vr_mtransport *);
void vr_message_transport_unregister(struct vr_mtransport *);
int vr_message_proto_register(struct vr_mproto *);
void vr_message_proto_unregister(struct vr_mproto *);
struct vr_message_dumper *vr_message_dump_init(void *);
void vr_message_dump_exit(void *, int);

int vr_message_request(struct vr_message *);
int vr_message_response(unsigned int, void *, int);
int vr_message_make_request(unsigned int, void *);
int vr_message_process_response(int (*)(void *, unsigned int, void *), void *);
int vr_message_dump_object(void *, unsigned int, void *);
void *vr_mtrans_alloc(unsigned int);
void vr_mtrans_free(void *);

struct vr_message *vr_message_dequeue_response(void);
void vr_message_free(struct vr_message *message);
bool vr_response_queue_empty(void);

#endif /* __VR_MESSAGE_H__ */
