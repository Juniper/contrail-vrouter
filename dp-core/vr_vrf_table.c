/*
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */

#include "vr_os.h"
#include "vr_types.h"
#include "vr_packet.h"
#include "vr_interface.h"
#include "vr_sandesh.h"
#include "vr_message.h"
#include "vr_vrf_table.h"
#include "vr_offloads_dp.h"

struct vr_vrf_table_entry *
vrouter_get_vrf_table(unsigned int rid, unsigned int index)
{
    struct vrouter *router = vrouter_get(rid);

    if (!router || index >= router->vr_max_vrfs)
        return NULL;

    return router->vr_vrf_table[index];
}

static void
vr_vrf_table_defer_delete(struct vrouter *router, void *arg)
{
    struct vr_defer_data *defer = (struct vr_defer_data *)arg;

    vr_free(defer->vdd_data, VR_VRF_TABLE_ENTRY_OBJECT);

    return;
}

int
__vr_vrf_table_entry_del(struct vrouter *router, unsigned int index)
{
    struct vr_interface *hbf_l, *hbf_r;
    struct vr_vrf_table_entry *vrf_table_entry;
    struct vr_defer_data *defer;

    if (index >= router->vr_max_vrfs)
        return -EINVAL;

    vrf_table_entry = router->vr_vrf_table[index];
    if (!vrf_table_entry)
        return -EINVAL;

    if (vrf_table_entry->vrf_flags & VRF_FLAG_HBF_L_VALID) {
        hbf_l = vrf_table_entry->hbf_l_vif;
        vrf_table_entry->hbf_l_vif = NULL;
    }

    if (vrf_table_entry->vrf_flags & VRF_FLAG_HBF_R_VALID) {
        hbf_r = vrf_table_entry->hbf_r_vif;
        vrf_table_entry->hbf_r_vif = NULL;
    }

    router->vr_vrf_table[index] = NULL;

    if (!vr_not_ready) {
        defer = vr_get_defer_data(sizeof(*defer));
        if (defer) {
            defer->vdd_data = (void *)vrf_table_entry;
            vr_defer(router, vr_vrf_table_defer_delete, (void *)defer);
        } else {
            vr_delay_op();
            vr_free(vrf_table_entry, VR_VRF_TABLE_ENTRY_OBJECT);
        }
    } else {
        vr_free(vrf_table_entry, VR_VRF_TABLE_ENTRY_OBJECT);
    }

    if (hbf_l)
        vrouter_put_interface(hbf_l);
    if (hbf_r)
        vrouter_put_interface(hbf_r);

    vr_offload_vrf_table_entry_del(index);

    return 0;
}

int
vr_vrf_table_entry_del(vr_vrf_req *req)
{
    int ret = -EINVAL;
    struct vrouter *router;

    router = vrouter_get(req->vrf_rid);
    if (router)
        ret = __vr_vrf_table_entry_del(router, req->vrf_idx);

    vr_send_response(ret);

    return ret;
}

int
vr_vrf_table_entry_add(vr_vrf_req *req)
{
    int ret = 0;
    struct vrouter *router;
    struct vr_interface *hbf_l = NULL, *hbf_r = NULL;
    struct vr_interface *old_hbf_l = NULL, *old_hbf_r = NULL;
    struct vr_vrf_table_entry *vrf_table_entry;

    router = vrouter_get(req->vrf_rid);
    if (!router) {
        ret = -EINVAL;
        goto generate_resp;
    }

    if ((unsigned int)req->vrf_idx >= router->vr_max_vrfs) {
        ret = -EINVAL;
        goto generate_resp;
    }

    hbf_l = vrouter_get_interface(req->vrf_rid, req->vrf_hbfl_vif_idx);
    if (!hbf_l) {
        ret = -EINVAL;
        goto generate_resp;
    }

    hbf_r = vrouter_get_interface(req->vrf_rid, req->vrf_hbfr_vif_idx);
    if (!hbf_r) {
        ret = -EINVAL;
        goto generate_resp;
    }

    vrf_table_entry = router->vr_vrf_table[req->vrf_idx];
    if (!vrf_table_entry) {
        vrf_table_entry = vr_zalloc(sizeof(*vrf_table_entry), VR_VRF_TABLE_ENTRY_OBJECT);
        if (!vrf_table_entry) {
            ret = -ENOMEM;
            if (hbf_l)
                vrouter_put_interface(hbf_l);
            if (hbf_r)
                vrouter_put_interface(hbf_r);
            goto generate_resp;
        }
    } else {
        if (vrf_table_entry->vrf_flags & VRF_FLAG_HBF_L_VALID)
            old_hbf_l = vrf_table_entry->hbf_l_vif;
        if (vrf_table_entry->vrf_flags & VRF_FLAG_HBF_R_VALID)
            old_hbf_r = vrf_table_entry->hbf_r_vif;
    }

    if (hbf_l)
        vrf_table_entry->hbf_l_vif = hbf_l;
    if (hbf_r)
        vrf_table_entry->hbf_r_vif = hbf_r;
    vrf_table_entry->rid = req->vrf_rid;
    vrf_table_entry->vrf_flags = req->vrf_flags | VRF_FLAG_VALID;
    router->vr_vrf_table[req->vrf_idx] = vrf_table_entry;

    if (old_hbf_l)
        vrouter_put_interface(old_hbf_l);
    if (old_hbf_r)
        vrouter_put_interface(old_hbf_r);

    /* if offload failed, release the newly added vrf_table entry.
     */
    ret = vr_offload_vrf_table_entry_add(vrf_table_entry, req->vrf_idx);
    if (ret)
        __vr_vrf_table_entry_del(router, req->vrf_idx);

generate_resp:
    vr_send_response(ret);

    return ret;
}


static void
vr_vrf_table_make_req(vr_vrf_req *req, struct vr_vrf_table_entry *vrf_table_entry,
                unsigned short index)
{
    req->vrf_idx = index;
    if (vrf_table_entry->hbf_l_vif)
        req->vrf_hbfl_vif_idx = vrf_table_entry->hbf_l_vif->vif_idx;
    if (vrf_table_entry->hbf_r_vif)
        req->vrf_hbfr_vif_idx = vrf_table_entry->hbf_r_vif->vif_idx;

    req->vrf_flags = vrf_table_entry->vrf_flags;
    req->vrf_rid = vrf_table_entry->rid;
    return;
}


static int
vr_vrf_table_dump(vr_vrf_req *r)
{
    int ret = 0;
    unsigned int i;
    struct vrouter *router = vrouter_get(r->vrf_rid);
    vr_vrf_req req;
    struct vr_vrf_table_entry *vrf_table_entry;
    struct vr_message_dumper *dumper = NULL;

    if (!router && (ret = -ENODEV))
        goto generate_response;

    if ((unsigned int)(r->vrf_marker + 1) >= router->vr_max_vrfs)
        goto generate_response;

    dumper = vr_message_dump_init(r);
    if (!dumper && (ret = -ENOMEM))
        goto generate_response;

    for (i = (unsigned int)(r->vrf_marker + 1);
            i < router->vr_max_vrfs; i++) {
        vrf_table_entry = router->vr_vrf_table[i];
        if (vrf_table_entry) {
           vr_vrf_table_make_req(&req, vrf_table_entry, i);
           vr_offload_vrf_table_entry_get(&req);
           ret = vr_message_dump_object(dumper, VR_VRF_TABLE_OBJECT_ID, &req);
           if (ret <= 0)
               break;
        }
    }

generate_response:
    vr_message_dump_exit(dumper, ret);

    return 0;
}

static int
vr_vrf_table_entry_get(vr_vrf_req *req)
{
    int ret = 0;
    struct vrouter *router;
    struct vr_vrf_table_entry *vrf_table_entry = NULL;

    router = vrouter_get(req->vrf_rid);
    if (!router ||
            (unsigned int)req->vrf_idx >= router->vr_max_vrfs) {
        ret = -ENODEV;
    } else {
        vrf_table_entry = router->vr_vrf_table[req->vrf_idx];
        if (!vrf_table_entry)
            ret = -ENOENT;
    }

    if (vrf_table_entry) {
        vr_vrf_table_make_req(req, vrf_table_entry, req->vrf_idx);
        /* Debug comparison to check if matching entry is programmed on NIC */
        vr_offload_vrf_table_entry_get(req);
    } else
        req = NULL;

    return vr_message_response(VR_VRF_TABLE_OBJECT_ID, req, ret, false);
}

void
vr_vrf_req_process(void *s_req)
{
    vr_vrf_req *req = (vr_vrf_req *)s_req;

    switch (req->h_op) {
    case SANDESH_OP_ADD:
        vr_vrf_table_entry_add(req);
        break;

    case SANDESH_OP_GET:
        vr_vrf_table_entry_get(req);
        break;

    case SANDESH_OP_DUMP:
        vr_vrf_table_dump(req);
        break;

    case SANDESH_OP_DEL:
        vr_vrf_table_entry_del(req);
        break;

    default:
        break;
    }

    return;
}

void
vr_vrf_table_exit(struct vrouter *router, bool soft_reset)
{
    unsigned int i;

    if (router->vr_vrf_table)
        for (i = 0; i < router->vr_max_vrfs; i++)
            if (router->vr_vrf_table[i])
                __vr_vrf_table_entry_del(router, i);

    if (!soft_reset) {
        vr_free(router->vr_vrf_table, VR_VRF_TABLE_OBJECT);
        router->vr_vrf_table = NULL;
    }

    return;
}

int
vr_vrf_table_init(struct vrouter *router)
{
    unsigned int size;

    if (!router->vr_vrf_table) {
        size = sizeof(struct vr_vrf_table_entry *) * router->vr_max_vrfs;
        router->vr_vrf_table = vr_zalloc(size, VR_VRF_TABLE_OBJECT);
        if (!router->vr_vrf_table)
            return vr_module_error(-ENOMEM, __FUNCTION__, __LINE__, size);
    }

    return 0;
}
