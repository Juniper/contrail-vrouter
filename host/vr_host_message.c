/*
 * vr_host_message.c -- messaging infrastructure to interface with dp-core when
 *                      run as a library
 *
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#include "vr_os.h"
#include "vr_queue.h"
#include "vr_message.h"
#include "vrouter.h"

/*
 * we need a way to identify the type of the object, and the type of
 * the message (request/response)
 */
struct diet_message {
    /* m_type = REQUEST | RESPONSE */
    unsigned int m_type;
    unsigned int m_id;
    /* m_oid = VR_*_OBJECT_ID */
    unsigned int m_oid;
    /* finally, the object itself */
    char m_object[0];
};

struct diet_object_md {
    /*
     * when encoded, how much length will this object take. since encode
     * and decode does not do much to the object, encode/decode lengths
     * are the same
     */
    unsigned int obj_len;
    /* depending on the object, we need a method to copy */
    int (*obj_copy)(char *, unsigned int, void *);
    /* the request and the response callbacks */
    void (*obj_request)(void *);
    int (*obj_response)(struct diet_message *, void *,
            int (*)(void *, unsigned int, void *), void *);
};
int diet_dropstats_object_copy(char *, unsigned int, void *);
int diet_interface_object_copy(char *, unsigned int, void *);
int diet_nexthop_object_copy(char *, unsigned int, void *);
int diet_mpls_object_copy(char *, unsigned int, void *);
int diet_route_object_copy(char *, unsigned int, void *);
int diet_response_object_copy(char *, unsigned int, void *);
int diet_object_response(struct diet_message *, void *,
        int (*)(void *, unsigned int, void *), void *);
unsigned int diet_object_buf_len(unsigned int, void *);

struct diet_object_md diet_md[] = {
    [VR_NULL_OBJECT_ID]         =   {
        .obj_len                =       0,
    },
    [VR_INTERFACE_OBJECT_ID]    =   {
        .obj_len                =       sizeof(vr_interface_req) +
                                        VR_ETHER_ALEN,

        .obj_copy               =       diet_interface_object_copy,
        .obj_request            =       vr_interface_req_process,
        .obj_response           =       diet_object_response,
    },
    [VR_NEXTHOP_OBJECT_ID]    =   {
        .obj_len                =       sizeof(vr_nexthop_req) +
                                        VR_ETHER_HLEN,

        .obj_copy               =       diet_nexthop_object_copy,
        .obj_request            =       vr_nexthop_req_process,
        .obj_response           =       diet_object_response,
    },
    [VR_MPLS_OBJECT_ID]    =   {
        .obj_len                =       sizeof(vr_mpls_req),
        .obj_copy               =       diet_mpls_object_copy,
        .obj_request            =       vr_mpls_req_process,
        .obj_response           =       diet_object_response,
    },
    [VR_ROUTE_OBJECT_ID]    =   {
        .obj_len                =       sizeof(vr_route_req),
        .obj_copy               =       diet_route_object_copy,
        .obj_request            =       vr_route_req_process,
        .obj_response           =       diet_object_response,
    },
    [VR_RESPONSE_OBJECT_ID]    =   {
        .obj_len                =       sizeof(vr_response),
        .obj_copy               =       diet_response_object_copy,
        .obj_response           =       diet_object_response,
    },
    [VR_DROP_STATS_OBJECT_ID]   =   {
        .obj_len                =       sizeof(vr_drop_stats_req),
        .obj_copy               =       diet_dropstats_object_copy,
        .obj_response           =       diet_object_response,
     }
};

int
diet_dropstats_object_copy(char *dst, unsigned int buf_len, void *object)
{
    vr_drop_stats_req *src = (vr_drop_stats_req *)object;

    if (buf_len < diet_md[VR_DROP_STATS_OBJECT_ID].obj_len)
        return -ENOSPC;

    memcpy(dst, src, sizeof(*src));
    return sizeof(*src);
}

int
diet_route_object_copy(char *dst, unsigned int buf_len, void *object)
{
    vr_route_req *src = (vr_route_req *)object;

    if (buf_len < diet_md[VR_ROUTE_OBJECT_ID].obj_len)
        return -ENOSPC;

    memcpy(dst, src, sizeof(*src));
    return sizeof(*src);
}

int
diet_mpls_object_copy(char *dst, unsigned int buf_len, void *object)
{
    vr_mpls_req *src = (vr_mpls_req *)object;

    if (buf_len < diet_md[VR_MPLS_OBJECT_ID].obj_len)
        return -ENOSPC;

    memcpy(dst, src, sizeof(*src));
    return sizeof(*src);
}

int
diet_nexthop_object_copy(char *dst, unsigned int buf_len, void *object)
{
    vr_nexthop_req *tmp, *src = (vr_nexthop_req *)object;
    unsigned int total_len = sizeof(vr_nexthop_req);

    if (src->nhr_encap_size)
        total_len += src->nhr_encap_size;

    if (buf_len < total_len)
        return -ENOSPC;

    memcpy(dst, src, sizeof(vr_nexthop_req));
    tmp = (vr_nexthop_req *)dst;
    if (src->nhr_encap_size) {
        tmp->nhr_encap = (signed char *)(tmp + 1);
        memcpy(tmp->nhr_encap, src->nhr_encap,
                src->nhr_encap_size);
    }

    return total_len;
}

int
diet_interface_object_copy(char *dst, unsigned int buf_len, void *object)
{
    vr_interface_req *tmp, *src = (vr_interface_req *)object;
    unsigned int total_len = sizeof(vr_interface_req);

    if (src->vifr_mac_size)
        total_len += src->vifr_mac_size;

    if (buf_len < total_len)
        return -ENOSPC;

    memcpy(dst, src, sizeof(vr_interface_req));
    tmp = (vr_interface_req *)dst;
    if (src->vifr_mac_size) {
        tmp->vifr_mac = (signed char *)(tmp + 1);
        memcpy(tmp->vifr_mac, src->vifr_mac,
                src->vifr_mac_size);
    }

    return total_len;
}

int
diet_response_object_copy(char *dst, unsigned int len, void *object)
{
    vr_response *src = (vr_response *)object;

    memcpy(dst, (char *)src, sizeof(vr_response));
    return sizeof(vr_response);
}

int
diet_object_response(struct diet_message *hdr, void *object,
        int (*cb)(void *, unsigned int, void *), void *arg)
{
    int ret;
    char *dst_buf = vr_mtrans_alloc(diet_md[hdr->m_oid].obj_len);

    if (!dst_buf)
        return -ENOMEM;

    ret = diet_md[hdr->m_oid].obj_copy(dst_buf,
            diet_md[hdr->m_oid].obj_len, object);

    if (ret > 0) {
        cb(arg, hdr->m_oid, dst_buf);
    }
    vr_mtrans_free(dst_buf);

    return ret;
}


static int
diet_object_copy(char *dst, unsigned int len,
        unsigned int object_type, void *src)
{
    return diet_md[object_type].obj_copy(dst, len, src);
}

static int
diet_encode(char *buf, unsigned int len,
        unsigned int object_type, void *object, unsigned int message_type)
{
    unsigned int encode_length = 0;
    struct diet_message *hdr;

    if (!object)
        return 0;

    encode_length += diet_object_buf_len(object_type, object);
    if (len < encode_length)
        return -ENOSPC;

    hdr = (struct diet_message *)buf;
    hdr->m_type = message_type;
    hdr->m_id = 0;
    hdr->m_oid = object_type;
    encode_length = diet_object_copy((char *)(hdr + 1), len - sizeof(hdr),
            object_type, object);
    encode_length += sizeof(*hdr);

    return encode_length;
}

static int
diet_encode_response(char *buf, unsigned int len,
        unsigned int object_type, void *object, int ret)
{
    int encoded_length = 0;
    vr_response resp;

    resp.h_op = SANDESH_OP_RESPONSE;
    resp.resp_code = ret;

    ret = diet_encode(buf, len, VR_RESPONSE_OBJECT_ID,
            &resp, VR_MESSAGE_TYPE_RESPONSE);
    if (ret < 0)
        return ret;

    encoded_length += ret;

    if (object) {
        ret = diet_encode(buf + ret, len - ret, object_type,
                object, VR_MESSAGE_TYPE_RESPONSE);
        if (ret < 0)
            return ret;

        encoded_length += ret;
    }

    return encoded_length;
}


static int
diet_object_decode(struct diet_message *hdr,
        int (*cb)(void *, unsigned int, void *), void *cb_arg)
{
    int ret = 0;

    if (hdr->m_type == VR_MESSAGE_TYPE_REQUEST)
        diet_md[hdr->m_oid].obj_request(hdr + 1);
    else
        ret = diet_md[hdr->m_oid].obj_response(hdr, hdr + 1, cb, cb_arg);

    return ret;
}

static int
diet_decode(char *buf, unsigned int len,
        int (*cb)(void *, unsigned int, void *), void *cb_arg)
{
    int ret, processed;
    struct diet_message *hdr;

    while (len) {
        hdr = (struct diet_message *)buf;
        ret = diet_object_decode(hdr, cb, cb_arg);
        if (ret <= 0)
            return ret;
        processed = sizeof(*hdr) + ret;
        len -= processed;
        buf += processed;
    }

    return 0;
}

/*
 * when encoded, how much length will be needed to hold 'obj_type' object.
 * since all encoded objects will be preceeded by 'diet_message' header,
 * add that length + sizeof the actual object.
 */
unsigned int
diet_object_buf_len(unsigned int obj_type, void *object)
{
    unsigned int len;

    len = sizeof(struct diet_message);
    if (obj_type == VR_RESPONSE_OBJECT_ID || object)
        len += diet_md[obj_type].obj_len;
    return len;
}

static struct vr_mproto diet_message_proto = {
    .mproto_type                =       VR_MPROTO_DIET,
    .mproto_buf_len             =       diet_object_buf_len,
    .mproto_encode              =       diet_encode,
    .mproto_encode_response     =       diet_encode_response,
    .mproto_decode              =       diet_decode,
};

void
vr_diet_message_proto_exit(void)
{
    vr_message_proto_unregister(&diet_message_proto);
    return;
}

int
vr_diet_message_proto_init(void)
{
    vr_message_proto_register(&diet_message_proto);
    return 0;
}

