/*
 * vr_host_mtransport.c -- messaging for host
 *
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#include "vr_os.h"
#include "vr_types.h"
#include "vr_queue.h"
#include "vr_message.h"
#include "vrouter.h"

#define VR_HTRANSPORT_MAX_REQUESTS        1

struct request {
    struct vr_qhead req_responses;
    int req_ret;
    unsigned int req_obj_type;
    void *req_obj;
};

struct response {
    struct vr_qelem resp_queue_elem;
    void *resp_object;
};

struct request requests[VR_HTRANSPORT_MAX_REQUESTS];

void
vr_free_req(void *req)
{
    vr_mtrans_free(req);
    return;
}

int
vr_process_response(void *arg, unsigned int obj_type, void *object)
{
    struct request *request_i;
    struct response *response_i;
    vr_response *vr_response_i;

    request_i = (struct request *)arg;

    if (obj_type == VR_RESPONSE_OBJECT_ID) {
        vr_response_i = (vr_response *)object;
        request_i->req_ret = vr_response_i->resp_code;
        vr_mtrans_free(object);
        return 0;
    }

    response_i = calloc(1, sizeof(*response_i));
    if (!response_i) {
        request_i->req_ret = -ENOMEM;
        return -ENOMEM;
    }

    response_i->resp_object = object;
    vr_queue_enqueue(&request_i->req_responses,
            &response_i->resp_queue_elem);

    return 0;
}

/*
 * very simple - send the object to VR and return the result of
 * the operation
 */
int
vr_send(unsigned int obj_type, void *object, unsigned int len)
{
    struct request *request_i = &requests[0];

    bzero(request_i, sizeof(*request_i));
    request_i->req_obj_type = obj_type;
    request_i->req_obj = object;
    vr_queue_init(&request_i->req_responses);

    vr_message_make_request(obj_type, object);
    vr_message_process_response(&vr_process_response, request_i);

    return request_i->req_ret;
}

void *
vr_recv(void)
{
    struct vr_qelem *elem;
    struct request *request_i = &requests[0];
    struct response *resp_i;
    void *object;

    elem = vr_queue_dequeue(&request_i->req_responses);
    if (!elem)
        return NULL;

    resp_i = CONTAINER_OF(resp_queue_elem, struct response, elem);
    object = resp_i->resp_object;
    free(resp_i);

    return object;
}

