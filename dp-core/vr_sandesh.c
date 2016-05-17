/*
 * vr_sandesh.c -- sandesh messaging protocol for datapath
 *
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#include "vr_os.h"
#include "vr_types.h"
#include "vr_message.h"
#include "vr_sandesh.h"
#include "vrouter.h"

struct sandesh_object_md sandesh_md[] = {
    [VR_NULL_OBJECT_ID]         =   {
        .obj_len                =       sizeof(vr_response),
        .obj_type_string        =       "vr_null_object",
    },
    [VR_INTERFACE_OBJECT_ID]    =   {
        .obj_len                =       4 * sizeof(vr_interface_req),
        .obj_type_string        =       "vr_interface_req",
    },
    [VR_NEXTHOP_OBJECT_ID]      =   {
        .obj_len                =       4 * sizeof(vr_nexthop_req),
        .obj_get_size           =       vr_nexthop_req_get_size,
        .obj_type_string        =       "vr_nexthop_req",
    },
    [VR_ROUTE_OBJECT_ID]        =   {
        .obj_len                =       4 * sizeof(vr_route_req),
        .obj_type_string        =       "vr_route_req",
    },
    [VR_MPLS_OBJECT_ID]         =   {
        .obj_len                =       4 * sizeof(vr_mpls_req),
        .obj_type_string        =       "vr_mpls_req"
    },
    [VR_MIRROR_OBJECT_ID]       =   {
        .obj_len                =       4 * sizeof(vr_mirror_req),
        .obj_type_string        =       "vr_mirror_req",
    },
    [VR_FLOW_OBJECT_ID]         =   {
        .obj_len                =       4 * sizeof(vr_flow_req),
        .obj_type_string        =       "vr_flow_req",
    },
    [VR_VRF_ASSIGN_OBJECT_ID]     =   {
        .obj_len                =       4 * sizeof(vr_vrf_assign_req),
        .obj_type_string        =       "vr_vrf_assign_req",
    },
    [VR_VRF_STATS_OBJECT_ID]     =   {
        .obj_len                =       4 * sizeof(vr_vrf_stats_req),
        .obj_type_string        =       "vr_vrf_stats_req",
    },
    [VR_DROP_STATS_OBJECT_ID]     =   {
        .obj_len                =       4 * sizeof(vr_vrf_stats_req),
        .obj_type_string        =       "vr_drop_stats_req",
    },
    [VR_RESPONSE_OBJECT_ID]     =   {
        .obj_len                =       4 * sizeof(vr_response),
        .obj_type_string        =       "vr_response",
    },
    [VR_VXLAN_OBJECT_ID]     =   {
        .obj_len                =       4 * sizeof(vr_vxlan_req),
        .obj_type_string        =       "vr_vxlan_req",
    },
    [VR_VROUTER_OPS_OBJECT_ID]     =   {
        .obj_len                =       4 * sizeof(vrouter_ops),
        .obj_type_string        =       "vrouter_ops",
    },
    [VR_FLOW_INFO_OBJECT_ID]         =   {
        .obj_len                =       ((4 * sizeof(vr_flow_req)) +
                    (VR_FLOW_MAX_CPUS * sizeof(unsigned int))),
        .obj_type_string        =       "vr_flow_req",
    },
    [VR_MEM_STATS_OBJECT_ID]     =   {
        .obj_len                =       4 * sizeof(vr_mem_stats_req),
        .obj_type_string        =       "vr_mem_stats_req",
    },
    [VR_QOS_MAP_OBJECT_ID]     =   {
        .obj_len                =       4 * sizeof(vr_qos_map_req),
        .obj_get_size           =       vr_qos_map_req_get_size,
        .obj_type_string        =       "vr_qos_map_req",
    },
    [VR_FC_MAP_OBJECT_ID]     =   {
        .obj_len                =       4 * sizeof(vr_fc_map_req),
        .obj_type_string        =       "vr_fc_map_req",
    },
};

static unsigned int
sandesh_proto_buf_len(unsigned int object_type, void *object)
{
    if (!object && object_type != VR_RESPONSE_OBJECT_ID)
        return 0;

    if (sandesh_md[object_type].obj_get_size)
        return sandesh_md[object_type].obj_get_size(object);

    return sandesh_md[object_type].obj_len;
}

static int
sandesh_proto_encode(char *buf, unsigned int len,
        unsigned int object_type, void *object,
        unsigned int message_type)
{
    int off = 0, error = 0;

    if (object)
        off = sandesh_encode(object,
                sandesh_md[object_type].obj_type_string,
                vr_find_sandesh_info, (unsigned char *)buf, len, &error);

    if (error)
        return -1;

    return off;
}

static int
sandesh_proto_encode_response(char *buf, unsigned int len,
        unsigned int object_type, void *object, int ret)
{
    int off, error;
    vr_response resp;

    resp.h_op = SANDESH_OP_RESPONSE;
    resp.resp_code = ret;

    off = sandesh_encode(&resp, "vr_response", vr_find_sandesh_info,
            (unsigned char *)buf, len, &error);
    if (off < 0)
        return off;

    error = sandesh_proto_encode(buf + off, len - off,
            object_type, object, VR_MESSAGE_TYPE_RESPONSE);
    if (error < 0)
        return error;

    return off + error;
}

static int
sandesh_proto_decode(char *buf, unsigned int len,
        int (*cb)(void *, unsigned int, void *), void *cb_arg)
{
    int ret = 0;

    return sandesh_decode((unsigned char *)buf, len,
            vr_find_sandesh_info, &ret);
}

static struct vr_mproto sandesh_mproto = {
    .mproto_type            =       VR_MPROTO_SANDESH,
    .mproto_buf_len         =       sandesh_proto_buf_len,
    .mproto_encode          =       sandesh_proto_encode,
    .mproto_encode_response =       sandesh_proto_encode_response,
    .mproto_decode          =       sandesh_proto_decode,
};

void
vr_sandesh_exit(void)
{
    vr_message_proto_unregister(&sandesh_mproto);
    return;
}

int
vr_sandesh_init(void)
{
    vr_message_proto_register(&sandesh_mproto);
    return 0;
}
