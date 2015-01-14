/*
 * vr_vrf_assign.c -- association map of vif to vrf
 *
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#include <vr_os.h>
#include <vr_types.h>
#include "vr_message.h"
#include "vr_sandesh.h"
#include "vr_packet.h"
#include <vr_interface.h>
#include <vr_response.h>

static int
vr_vrf_assign_dump(vr_vrf_assign_req *req)
{
    int ret = 0, i;
    vr_vrf_assign_req resp;
    struct vr_interface *vif = NULL;
    struct vr_message_dumper *dumper;

    dumper = vr_message_dump_init(req);
    if (!dumper) {
        ret = -ENOMEM;
        goto generate_response;
    }

    vif = vrouter_get_interface(req->var_rid, req->var_vif_index);
    if (!vif) {
        ret = -EINVAL;
        goto generate_response;
    }

    memcpy(&resp, req, sizeof(resp));
    for (i = req->var_marker + 1; i < VIF_VRF_TABLE_ENTRIES; i++) {
        resp.var_vlan_id = i;
        ret = vif_vrf_table_get(vif, &resp);
        if (ret)
            break;

        if (resp.var_vif_vrf == -1)
            continue;

        ret = vr_message_dump_object(dumper, VR_VRF_ASSIGN_OBJECT_ID, &resp);
        if (ret <= 0)
            break;
    }

generate_response:
    if (vif)
        vrouter_put_interface(vif);

    vr_message_dump_exit(dumper, ret);
    return 0;
}

static int
vr_vrf_assign_get(vr_vrf_assign_req *req)
{
    int ret;
    vr_vrf_assign_req resp;
    struct vr_interface *vif;

    vif = vrouter_get_interface(req->var_rid, req->var_vif_index);
    if (!vif) {
        ret = -EINVAL;
        goto exit_get;
    }

    memcpy(&resp, req, sizeof(*req));
    ret = vif_vrf_table_get(vif, &resp);
    vrouter_put_interface(vif);
exit_get:
    vr_message_response(VR_VRF_ASSIGN_OBJECT_ID, ret ? NULL : &resp, ret);
    return 0;
}

static int
vr_vrf_assign_set(vr_vrf_assign_req *req)
{
    int ret;
    struct vr_interface *vif;

    vif = vrouter_get_interface(req->var_rid, req->var_vif_index);
    if (!vif) {
        ret = -EINVAL;
        goto exit_set;
    }

    ret = vif_vrf_table_set(vif, req->var_vlan_id, req->var_vif_vrf,
            req->var_nh_id);
exit_set:
    if (vif)
        vrouter_put_interface(vif);

    vr_send_response(ret);
    return ret;
}

void
vr_vrf_assign_req_process(void *s_req)
{
    int ret;
    vr_vrf_assign_req *req = (vr_vrf_assign_req *)s_req;

    switch (req->h_op) {
    case SANDESH_OP_ADD:
        ret = vr_vrf_assign_set(req);
        break;

    case SANDESH_OP_GET:
        ret = vr_vrf_assign_get(req);
        break;

    case SANDESH_OP_DUMP:
        ret = vr_vrf_assign_dump(req);
        break;

    case SANDESH_OP_DELETE:
        req->var_vif_vrf = -1;
        ret = vr_vrf_assign_set(req);
        break;

    default:
        ret = -EINVAL;
        goto error;
    }

    return;

error:
    vr_send_response(ret);
    return;
}
