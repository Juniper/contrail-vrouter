/*
 * vr_message.c -- message protocol and transport independent interface for
 * vrouter
 *
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#include <vr_os.h>
#include <vrouter.h>
#include "vr_message.h"

static char *
vr_message_default_malloc(unsigned int size)
{
    return vr_malloc(size);
}

static void
vr_message_default_free(char *buf)
{
    if (buf)
        vr_free(buf);
    return;
}

static struct vr_mtransport default_transport = {
    .mtrans_alloc       =   vr_message_default_malloc,
    .mtrans_free        =   vr_message_default_free,
};

static struct vr_message_handler message_h = {
    .vm_trans           =   &default_transport,
};

void *
vr_mtrans_alloc(unsigned int size)
{
    if (!message_h.vm_trans)
        return NULL;

    return message_h.vm_trans->mtrans_alloc(size);
}

void
vr_mtrans_free(void *buf)
{
    if (!message_h.vm_trans)
        return;

    message_h.vm_trans->mtrans_free(buf);
    return;
}

int
vr_message_request(struct vr_message *message)
{
    if (!message_h.vm_proto)
        return 0;

    if (vr_not_ready)
        return -ENETRESET;

    if (vr_not_ready)
#if defined(__FreeBSD__)
        return -EBADF;
#else
        return -EBADFD;
#endif

    message_h.vm_proto->mproto_decode(message->vr_message_buf,
            message->vr_message_len, NULL, NULL);
    return 0;
}

static int
vr_message_queue_response(char *buf, int len)
{
    struct vr_message *response;

    response = vr_zalloc(sizeof(*response));
    if (!response)
        return -ENOMEM;

    response->vr_message_buf = buf;
    response->vr_message_len = len;
    vr_queue_enqueue(&message_h.vm_response_queue,
            &response->vr_message_queue);

    return 0;
}

struct vr_message *
vr_message_dequeue_response(void)
{
    struct vr_qelem *elem;

    elem = vr_queue_dequeue(&message_h.vm_response_queue);
    if (elem)
        return CONTAINER_OF(vr_message_queue, struct vr_message, elem);

    return NULL;
}

bool
vr_response_queue_empty(void)
{
    return vr_queue_empty(&message_h.vm_response_queue);
}

void
vr_message_free(struct vr_message *message)
{
    if (message) {
        if (message->vr_message_buf)
            vr_mtrans_free(message->vr_message_buf);
        vr_free(message);
    }

    return;
}

int
vr_message_make_request(unsigned int object_type, void *object)
{
    char *buf = NULL;
    int ret;
    unsigned int len;
    struct vr_mproto *proto;
    struct vr_mtransport *trans;
    struct vr_message request;

    proto = message_h.vm_proto;
    trans = message_h.vm_trans;
    if (!proto || !trans)
        return 0;

    len = proto->mproto_buf_len(object_type, object);
    buf = trans->mtrans_alloc(len);
    if (!buf)
        return -ENOMEM;

    ret = proto->mproto_encode(buf, len, object_type, object,
            VR_MESSAGE_TYPE_REQUEST);
    if (ret < 0)
        goto request_fail;

    request.vr_message_buf = buf;
    request.vr_message_len = ret;

    vr_message_request(&request);

request_fail:
    if (buf)
        trans->mtrans_free(buf);

    return ret;
}

int
vr_message_process_response(int (*cb)(void *, unsigned int, void *),
        void *cb_arg)
{
    struct vr_message *response;
    struct vr_mproto *proto;
    struct vr_mtransport *trans;

    proto = message_h.vm_proto;
    trans = message_h.vm_trans;
    if (!proto || !trans)
        return 0;

    while ((response = vr_message_dequeue_response())) {
        proto->mproto_decode(response->vr_message_buf,
                response->vr_message_len, cb, cb_arg);
        vr_message_free(response);
    }

    return 0;
}

int
vr_message_response(unsigned int object_type, void *object, int ret)
{
    char *buf = NULL;
    unsigned int len = 0;
    struct vr_mproto *proto;
    struct vr_mtransport *trans;

    proto = message_h.vm_proto;
    trans = message_h.vm_trans;
    if (!proto || !trans)
        return 0;


    len = proto->mproto_buf_len(object_type, object);
    len += proto->mproto_buf_len(VR_RESPONSE_OBJECT_ID, NULL);

    buf = trans->mtrans_alloc(len);
    if (!buf)
        return -ENOMEM;

    ret = proto->mproto_encode_response(buf, len, object_type,
            object, ret);
    if (ret < 0)
        goto response_fail;

    return vr_message_queue_response(buf, ret);

response_fail:
    if (buf)
        trans->mtrans_free(buf);

    vr_send_response(ret);
    return ret;
}

int
vr_send_response(int code)
{
    return vr_message_response(VR_NULL_OBJECT_ID, NULL, code);
}

int
vr_message_dump_object(void *arg, unsigned int object_type, void *object)
{
    int ret;
    struct vr_mproto *proto;
    struct vr_mtransport *trans;
    struct vr_message_dumper *dumper = (struct vr_message_dumper *)arg;

    proto = message_h.vm_proto;
    trans = message_h.vm_trans;
    if (!proto || !trans)
        return 0;

    ret = proto->mproto_encode(dumper->dump_buffer + dumper->dump_offset,
            dumper->dump_buf_len - dumper->dump_offset,
            object_type, object, VR_MESSAGE_TYPE_RESPONSE);
    if (ret < 0) {
        /* we have more to dump, but we have to exit early */
        dumper->dump_num_dumped |= VR_MESSAGE_DUMP_INCOMPLETE;
        return ret;
    }

    dumper->dump_offset += ret;
    dumper->dump_num_dumped++;
    return ret;
}

void
vr_message_dump_exit(void *context, int ret)
{
    struct vr_mproto *proto;
    struct vr_mtransport *trans;
    struct vr_message_dumper *dumper = (struct vr_message_dumper *)context;

    proto = message_h.vm_proto;
    trans = message_h.vm_trans;
    if (!proto || !trans)
        return;

    if (dumper)
        ret = dumper->dump_num_dumped;

    vr_send_response(ret);

    if (dumper) {
        if (!dumper->dump_offset) {
            if (dumper->dump_buffer)
                trans->mtrans_free(dumper->dump_buffer);
        } else
            vr_message_queue_response(dumper->dump_buffer,
                    dumper->dump_offset);

        vr_free(dumper);
    }

    return;
}

struct vr_message_dumper *
vr_message_dump_init(void *req)
{
    char *buf;
    struct vr_message_dumper *dumper;
    struct vr_mproto *proto;
    struct vr_mtransport *trans;

    proto = message_h.vm_proto;
    trans = message_h.vm_trans;
    if (!proto || !trans)
        return NULL;

    dumper = vr_zalloc(sizeof(*dumper));
    if (!dumper)
        return NULL;

    buf = trans->mtrans_alloc(VR_MESSAGE_PAGE_SIZE);
    if (!buf) {
        vr_free(dumper);
        return NULL;
    }

    dumper->dump_buffer = buf;
    dumper->dump_buf_len = VR_MESSAGE_PAGE_SIZE;
    dumper->dump_offset = 0;
    dumper->dump_req = req;

    return dumper;
}

void
vr_message_transport_unregister(struct vr_mtransport *trans)
{
    if (message_h.vm_trans == trans)
        message_h.vm_trans = NULL;

    return;
}

int
vr_message_transport_register(struct vr_mtransport *trans)
{
    message_h.vm_trans = trans;
    return 0;
}

void
vr_message_proto_unregister(struct vr_mproto *proto)
{
    if (message_h.vm_proto == proto)
        message_h.vm_proto = NULL;

    return;
}

int
vr_message_proto_register(struct vr_mproto *proto)
{
    if (message_h.vm_proto)
        return -EEXIST;

    message_h.vm_proto = proto;
    return 0;
}

