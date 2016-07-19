/*
 * vr_qos.c -- QOS implementation for vRouter datapath
 *
 * Copyright (c) 2015, Juniper Networks Inc.
 * All rights reserved
 */
#include <vr_os.h>
#include <vr_types.h>
#include <vr_packet.h>

#include "vr_message.h"
#include "vr_sandesh.h"
#include "vr_interface.h"
#include "vr_datapath.h"
#include "vr_qos.h"

unsigned int vr_qos_map_entries = VR_DEF_QOS_MAP_ENTRIES;
unsigned int vr_fc_map_entries = VR_DEF_FC_MAP_ENTRIES;
unsigned int vr_qos_map_entry_size = VR_QOS_MAP_ENTRY_SIZE;

static void
vr_qos_message_error(int error)
{
    vr_send_response(error);
    return;
}

unsigned int
vr_qos_map_req_get_size(void *object)
{
    unsigned int size;
    vr_qos_map_req *req = (vr_qos_map_req *)object;

    size = 4 * sizeof(*req);
    size += 4 * req->qmr_dscp_size;
    size += 4 * req->qmr_dscp_fc_id_size;
    size += 4 * req->qmr_mpls_qos_size;
    size += 4 * req->qmr_mpls_qos_fc_id_size;
    size += 4 * req->qmr_dotonep_size;
    size += 4 * req->qmr_dotonep_fc_id_size;

    return size;
}

static int
vr_qos_map_request_validate(vr_qos_map_req *req)
{
    if (req->qmr_id >= vr_qos_map_entries)
        return -EINVAL;

    if (req->qmr_dscp_size != req->qmr_dscp_fc_id_size)
        return -EINVAL;

    if (req->qmr_mpls_qos_size != req->qmr_mpls_qos_fc_id_size)
        return -EINVAL;

    if (req->qmr_dotonep_size != req->qmr_dotonep_fc_id_size)
        return -EINVAL;

    return 0;
}

static struct vr_forwarding_class *
vr_qos_map_get_fc(struct vrouter *router, unsigned int id)
{
    if (id >= vr_qos_map_entries)
        return NULL;

    return router->vr_qos_map[id];
}

static int
vr_qos_map_set_fc(struct vrouter *router, unsigned int id,
        struct vr_forwarding_class *fc_p)
{
    if (id >= vr_qos_map_entries)
        return -EINVAL;

    router->vr_qos_map[id] = fc_p;
    return 0;
}

static void
vr_qos_map_req_destroy(vr_qos_map_req *req)
{
    if (!req)
        return;

    if (req->qmr_dscp && req->qmr_dscp_size) {
        vr_free(req->qmr_dscp, VR_QOS_MAP_OBJECT);
        req->qmr_dscp = NULL;
        req->qmr_dscp_size = 0;
        if (req->qmr_dscp_fc_id) {
            vr_free(req->qmr_dscp_fc_id, VR_QOS_MAP_OBJECT);
            req->qmr_dscp_fc_id_size = 0;
        }
    }

    if (req->qmr_mpls_qos && req->qmr_mpls_qos_size) {
        vr_free(req->qmr_mpls_qos, VR_QOS_MAP_OBJECT);
        req->qmr_mpls_qos = NULL;
        req->qmr_mpls_qos_size = 0;
        if (req->qmr_mpls_qos_fc_id) {
            vr_free(req->qmr_mpls_qos_fc_id, VR_QOS_MAP_OBJECT);
            req->qmr_mpls_qos_fc_id = NULL;
            req->qmr_mpls_qos_fc_id_size = 0;
        }
    }

    if (req->qmr_dotonep && req->qmr_dotonep_size) {
        vr_free(req->qmr_dotonep, VR_QOS_MAP_OBJECT);
        req->qmr_dotonep = NULL;
        req->qmr_dotonep_size = 0;
        if (req->qmr_dotonep_fc_id) {
            vr_free(req->qmr_dotonep_fc_id, VR_QOS_MAP_OBJECT);
            req->qmr_dotonep_fc_id = NULL;
            req->qmr_dotonep_fc_id_size = 0;
        }
    }

    vr_free(req, VR_QOS_MAP_OBJECT);
    return;
}

static vr_qos_map_req *
vr_qos_map_req_get(void)
{
    vr_qos_map_req *req;

    req = vr_zalloc(sizeof(vr_qos_map_req), VR_QOS_MAP_OBJECT);
    if (!req)
        return NULL;

    req->qmr_dscp =
        vr_zalloc(sizeof(uint8_t) * VR_DSCP_QOS_ENTRIES, VR_QOS_MAP_OBJECT);
    if (!req->qmr_dscp) {
        goto alloc_failure;
    }
    req->qmr_dscp_size = VR_DSCP_QOS_ENTRIES;

    req->qmr_dscp_fc_id =
        vr_zalloc(sizeof(uint8_t) * VR_DSCP_QOS_ENTRIES, VR_QOS_MAP_OBJECT);
    if (!req->qmr_dscp_fc_id) {
        goto alloc_failure;
    }
    req->qmr_dscp_fc_id_size = VR_DSCP_QOS_ENTRIES;

    req->qmr_mpls_qos =
        vr_zalloc(sizeof(uint8_t) * VR_MPLS_QOS_ENTRIES, VR_QOS_MAP_OBJECT);
    if (!req->qmr_mpls_qos) {
        goto alloc_failure;
    }
    req->qmr_mpls_qos_size = VR_MPLS_QOS_ENTRIES;

    req->qmr_mpls_qos_fc_id =
        vr_zalloc(sizeof(uint8_t) * VR_MPLS_QOS_ENTRIES, VR_QOS_MAP_OBJECT);
    if (!req->qmr_mpls_qos_fc_id) {
        goto alloc_failure;
    }
    req->qmr_mpls_qos_fc_id_size = VR_MPLS_QOS_ENTRIES;

    req->qmr_dotonep =
        vr_zalloc(sizeof(uint8_t) * VR_DOTONEP_QOS_ENTRIES, VR_QOS_MAP_OBJECT);
    if (!req->qmr_dotonep) {
        goto alloc_failure;
    }
    req->qmr_dotonep_size = VR_DOTONEP_QOS_ENTRIES;

    req->qmr_dotonep_fc_id =
        vr_zalloc(sizeof(uint8_t) * VR_DOTONEP_QOS_ENTRIES, VR_QOS_MAP_OBJECT);
    if (!req->qmr_dotonep_fc_id) {
        goto alloc_failure;
    }
    req->qmr_dotonep_fc_id_size = VR_DOTONEP_QOS_ENTRIES;

    return req;

alloc_failure:
    vr_qos_map_req_destroy(req);
    return NULL;
}

static void
vr_qos_map_make_req(unsigned int qmrid, vr_qos_map_req *resp,
        struct vr_forwarding_class *fc_p)
{
    unsigned int i;

    resp->qmr_id = qmrid;

    for (i = 0; i < VR_DSCP_QOS_ENTRIES; i++) {
        if (!fc_p[i].vfc_valid)
            continue;

        resp->qmr_dscp[i] = fc_p[i].vfc_dscp;
        resp->qmr_dscp_fc_id[i] = fc_p[i].vfc_id;
    }

    for (i = 0; i < VR_MPLS_QOS_ENTRIES; i++) {
        if (!fc_p[i].vfc_valid)
            continue;

        resp->qmr_mpls_qos[i] = fc_p[VR_DSCP_QOS_ENTRIES + i].vfc_mpls_qos;
        resp->qmr_mpls_qos_fc_id[i] = fc_p[VR_DSCP_QOS_ENTRIES + i].vfc_id;
    }

    for (i = 0; i < VR_DOTONEP_QOS_ENTRIES; i++) {
        if (!fc_p[i].vfc_valid)
            continue;

        resp->qmr_dotonep[i] =
            fc_p[VR_DSCP_QOS_ENTRIES + VR_MPLS_QOS_ENTRIES + i].vfc_dotonep_qos;
        resp->qmr_dotonep_fc_id[i] =
            fc_p[VR_DSCP_QOS_ENTRIES + VR_MPLS_QOS_ENTRIES + i].vfc_id;
    }

    return;
}

static void
vr_qos_map_free_fc_cb(struct vrouter *router, void *data)
{
    struct vr_defer_data *defer = (struct vr_defer_data *)data;

    if (!defer)
        return;

    vr_free(defer->vdd_data, VR_QOS_MAP_OBJECT);
    return;
}

static int
vr_qos_map_free_fc_defer(struct vrouter *router,
        struct vr_forwarding_class *fc_p)
{
    struct vr_defer_data *defer;

    defer = vr_get_defer_data(sizeof(*defer));
    if (!defer)
        return -ENOMEM;

    defer->vdd_data = fc_p;
    vr_defer(router, vr_qos_map_free_fc_cb, (void *)defer);

    return 0;
}

static void
vr_qos_map_delete(vr_qos_map_req *req)
{
    int ret = 0;

    struct vr_forwarding_class *fc_p;
    struct vrouter *router = vrouter_get(req->qmr_rid);

    if (req->qmr_id >= vr_qos_map_entries) {
        ret = -EINVAL;
        goto generate_response;
    }

    fc_p = vr_qos_map_get_fc(router, req->qmr_id);
    if (!fc_p) {
        ret = 0;
        goto generate_response;
    }

    vr_qos_map_set_fc(router, req->qmr_id, NULL);
    if (vr_qos_map_free_fc_defer(router, fc_p)) {
        vr_delay_op();
        vr_free(fc_p, VR_QOS_MAP_OBJECT);
    }

generate_response:
    vr_send_response(ret);
    return;
}

static void
vr_qos_map_dump(vr_qos_map_req *req)
{
    int ret = 0;
    unsigned int i;

    vr_qos_map_req *resp;
    struct vr_forwarding_class *fc_p;
    struct vrouter *router = vrouter_get(req->qmr_rid);
    struct vr_message_dumper *dumper = NULL;

    if (req->qmr_marker + 1 >= vr_qos_map_entries)
        goto generate_response;

    dumper = vr_message_dump_init(req);
    if (!dumper) {
        ret = -ENOMEM;
        goto generate_response;
    }

    for (i = (req->qmr_marker + 1); i < vr_qos_map_entries; i++) {
        fc_p = vr_qos_map_get_fc(router, i);
        if (!fc_p)
            continue;

        resp = vr_qos_map_req_get();
        if (!resp) {
            ret = -ENOMEM;
            goto generate_response;
        }

        vr_qos_map_make_req(i, resp, fc_p);
        ret = vr_message_dump_object(dumper, VR_QOS_MAP_OBJECT_ID, resp);
        vr_qos_map_req_destroy(resp);
        if (ret <= 0)
            break;
    }

generate_response:
    vr_message_dump_exit(dumper, ret);
    return;
}

static void
vr_qos_map_get(vr_qos_map_req *req)
{
    int ret = 0;

    vr_qos_map_req *resp;
    struct vrouter *router = vrouter_get(req->qmr_rid);
    struct vr_forwarding_class *fc_p = NULL;

    if (req->qmr_id >= vr_qos_map_entries) {
        ret = -EINVAL;
        goto get_error;
    }

    fc_p = vr_qos_map_get_fc(router, req->qmr_id);
    if (!fc_p) {
        ret = -ENOENT;
        goto get_error;
    }

    resp = vr_qos_map_req_get();
    if (!resp) {
        ret = -ENOMEM;
        goto get_error;
    }

    vr_qos_map_make_req(req->qmr_id, resp, fc_p);
    vr_message_response(VR_QOS_MAP_OBJECT_ID, resp, ret);
    if (resp) {
        vr_qos_map_req_destroy(resp);
    }

    return;

get_error:
    vr_send_response(ret);
    return;
}

static void
vr_qos_map_add(vr_qos_map_req *req)
{
    int ret = 0;
    bool need_set = false;
    unsigned int size, i;

    struct vrouter *router = vrouter_get(req->qmr_rid);
    struct vr_forwarding_class *fc_p, *fc_e;

    ret = vr_qos_map_request_validate(req);
    if (ret) {
        goto generate_response;
    }

    fc_p = vr_qos_map_get_fc(router, req->qmr_id);
    if (!fc_p) {
        size = vr_qos_map_entry_size * sizeof(struct vr_forwarding_class);
        fc_p = vr_zalloc(size, VR_QOS_MAP_OBJECT);
        if (!fc_p) {
            ret = -ENOMEM;
            goto generate_response;
        }
        need_set = true;
    }

    for (i = 0; i < req->qmr_dscp_size; i++) {
        if (req->qmr_dscp[i] >= VR_DSCP_QOS_ENTRIES)
            continue;

        fc_e = &fc_p[req->qmr_dscp[i]];
        fc_e->vfc_dscp = req->qmr_dscp[i];
        fc_e->vfc_id = req->qmr_dscp_fc_id[i];
        fc_e->vfc_valid = 1;
    }

    for (i = 0; i < req->qmr_mpls_qos_size; i++) {
        if (req->qmr_mpls_qos[i] >= VR_MPLS_QOS_ENTRIES)
            continue;

        fc_e = &fc_p[VR_DSCP_QOS_ENTRIES + req->qmr_mpls_qos[i]];
        fc_e->vfc_mpls_qos = req->qmr_mpls_qos[i];
        fc_e->vfc_id = req->qmr_mpls_qos_fc_id[i];
        fc_e->vfc_valid = 1;
    }

    for (i = 0; i < req->qmr_dotonep_size; i++) {
        if (req->qmr_dotonep[i] >= VR_DOTONEP_QOS_ENTRIES)
            continue;

        fc_e = &fc_p[VR_DSCP_QOS_ENTRIES + VR_MPLS_QOS_ENTRIES +
            req->qmr_dotonep[i]];
        fc_e->vfc_dotonep_qos = req->qmr_dotonep[i];
        fc_e->vfc_id = req->qmr_dotonep_fc_id[i];
        fc_e->vfc_valid = 1;
    }

    if (need_set) {
        vr_qos_map_set_fc(router, req->qmr_id, fc_p);
    }

generate_response:
    vr_send_response(ret);
    return;
}
        
void
vr_qos_map_req_process(void *s_req)
{
    vr_qos_map_req *req = (vr_qos_map_req *)s_req;

    switch (req->h_op) {
    case SANDESH_OP_ADD:
        vr_qos_map_add(req);
        break;

    case SANDESH_OP_GET:
        vr_qos_map_get(req);
        break;

    case SANDESH_OP_DUMP:
        vr_qos_map_dump(req);
        break;

    case SANDESH_OP_DELETE:
        vr_qos_map_delete(req);
        break;

    default:
        vr_qos_message_error(-EINVAL);
        break;
    }

    return;
}

struct vr_forwarding_class *
vr_fc_map_get_fc(struct vrouter *router, unsigned int i)
{
    if (i >= vr_fc_map_entries)
        return NULL;

    return &router->vr_fc_table[i];
}

static void
vr_fc_map_req_destroy(vr_fc_map_req *req)
{
    if (!req)
        return;

    if (req->fmr_id) {
        vr_free(req->fmr_id, VR_FC_OBJECT);
        req->fmr_id_size = 0;
    }

    if (req->fmr_dscp) {
        vr_free(req->fmr_dscp, VR_FC_OBJECT);
        req->fmr_dscp_size = 0;
    }

    if (req->fmr_mpls_qos) {
        vr_free(req->fmr_mpls_qos, VR_FC_OBJECT);
        req->fmr_mpls_qos_size = 0;
    }

    if (req->fmr_dotonep) {
        vr_free(req->fmr_dotonep, VR_FC_OBJECT);
        req->fmr_dotonep_size = 0;
    }

    if (req->fmr_queue_id) {
        vr_free(req->fmr_queue_id, VR_FC_OBJECT);
        req->fmr_queue_id_size = 0;
    }

    vr_free(req, VR_FC_OBJECT);
    return;
}

static vr_fc_map_req *
vr_fc_map_req_get(unsigned int entries)
{
    vr_fc_map_req *req;

    req = vr_zalloc(sizeof(*req), VR_FC_OBJECT);
    if (!req)
        return NULL;

    req->fmr_id = vr_zalloc(entries, VR_FC_OBJECT);
    if (!req->fmr_id) {
        goto error;
    }
    req->fmr_id_size = entries;

    req->fmr_dscp = vr_zalloc(entries, VR_FC_OBJECT);
    if (!req->fmr_dscp) {
        goto error;
    }
    req->fmr_dscp_size = entries;

    req->fmr_mpls_qos = vr_zalloc(entries, VR_FC_OBJECT);
    if (!req->fmr_mpls_qos) {
        goto error;
    }
    req->fmr_mpls_qos_size = entries;

    req->fmr_dotonep = vr_zalloc(entries, VR_FC_OBJECT);
    if (!req->fmr_dotonep) {
        goto error;
    }
    req->fmr_dotonep_size = entries;

    req->fmr_queue_id = vr_zalloc(entries, VR_FC_OBJECT);
    if (!req->fmr_queue_id) {
        goto error;
    }
    req->fmr_queue_id_size = entries;

    return req;

error:
    vr_fc_map_req_destroy(req);
    return NULL;
}

static void
vr_fc_map_delete(vr_fc_map_req *req)
{
    int ret = 0;

    struct vrouter *router = vrouter_get(req->fmr_rid);
    struct vr_forwarding_class *fc_p;

    if (!req->fmr_id) {
        ret = -EINVAL;
        goto generate_response;
    }

    if (req->fmr_id[0] >= vr_fc_map_entries) {
        ret = -EINVAL;
        goto generate_response;
    }

    fc_p = vr_fc_map_get_fc(router, req->fmr_id[0]);
    if (!fc_p) {
        ret = -EINVAL;
        goto generate_response;
    }

    memset(fc_p, 0, sizeof(*fc_p));
    vr_send_response(0);

    return;

generate_response:
    vr_send_response(ret);
    return;
}

static void
vr_fc_map_dump(vr_fc_map_req *req)
{
    int ret = 0;
    unsigned int i;

    vr_fc_map_req *resp;
    struct vr_forwarding_class *fc_p;
    struct vrouter *router = vrouter_get(req->fmr_rid);
    struct vr_message_dumper *dumper = NULL;

    if (req->fmr_marker + 1 >= vr_fc_map_entries)
        goto generate_response;

    dumper = vr_message_dump_init(req);
    if (!dumper) {
        ret = -ENOMEM;
        goto generate_response;
    }

    for (i = (req->fmr_marker + 1); i < vr_fc_map_entries; i++) {
        fc_p = vr_fc_map_get_fc(router, i);
        if (!fc_p || !fc_p->vfc_valid)
            continue;

        resp = vr_fc_map_req_get(1);
        if (!resp) {
            ret = -ENOMEM;
            goto generate_response;
        }

        resp->fmr_id[0] = i;
        resp->fmr_dscp[0] = fc_p->vfc_dscp;
        resp->fmr_mpls_qos[0] = fc_p->vfc_mpls_qos;
        resp->fmr_dotonep[0] = fc_p->vfc_dotonep_qos;
        resp->fmr_queue_id[0] = fc_p->vfc_queue_id;

        ret = vr_message_dump_object(dumper, VR_FC_MAP_OBJECT_ID, resp);
        vr_fc_map_req_destroy(resp);
        if (ret <= 0)
            break;
    }

generate_response:
    vr_message_dump_exit(dumper, ret);
    return;
}

static void
vr_fc_map_get(vr_fc_map_req *req)
{
    int ret = 0;

    vr_fc_map_req *resp;
    struct vrouter *router = vrouter_get(req->fmr_rid);
    struct vr_forwarding_class *fc_p;

    if (!req->fmr_id) {
        ret = -EINVAL;
        goto generate_response;
    }

    if (req->fmr_id[0] >= vr_fc_map_entries) {
        ret = -EINVAL;
        goto generate_response;
    }

    fc_p = vr_fc_map_get_fc(router, req->fmr_id[0]);
    if (!fc_p || !fc_p->vfc_valid) {
        ret = -ENOENT;
        goto generate_response;
    }

    resp = vr_fc_map_req_get(1);
    if (!resp) {
        ret = -ENOMEM;
        goto generate_response;
    }

    resp->fmr_id[0] = req->fmr_id[0];
    resp->fmr_dscp[0] = fc_p->vfc_dscp;
    resp->fmr_mpls_qos[0] = fc_p->vfc_mpls_qos;
    resp->fmr_dotonep[0] = fc_p->vfc_dotonep_qos;
    resp->fmr_queue_id[0] = fc_p->vfc_queue_id;

generate_response:
    vr_message_response(VR_FC_MAP_OBJECT_ID, ret < 0 ? NULL : resp, ret);
    if (resp)
        vr_fc_map_req_destroy(resp);

    return;
}

static void
vr_fc_map_add(vr_fc_map_req *req)
{
    int ret = 0;
    unsigned int i;

    struct vrouter *router = vrouter_get(req->fmr_rid);
    struct vr_forwarding_class *fc_p;

    if (!req->fmr_id || !req->fmr_id_size ||
            !req->fmr_dscp || !req->fmr_dscp_size ||
            !req->fmr_mpls_qos || !req->fmr_mpls_qos_size ||
            !req->fmr_dotonep || !req->fmr_dotonep_size ||
            !req->fmr_queue_id || !req->fmr_queue_id_size) {
        ret = -EINVAL;
        goto generate_response;
    }

    for (i = 0; i < req->fmr_id_size; i++) {
        fc_p = vr_fc_map_get_fc(router, req->fmr_id[i]);
        if (!fc_p) {
            ret = -EINVAL;
            goto generate_response;
        }

        fc_p->vfc_id = req->fmr_id[i];
        fc_p->vfc_dscp = req->fmr_dscp[i];
        fc_p->vfc_mpls_qos = req->fmr_mpls_qos[i];
        fc_p->vfc_dotonep_qos = req->fmr_dotonep[i];
        fc_p->vfc_queue_id = req->fmr_queue_id[i];
        fc_p->vfc_valid = 1;
    }

generate_response:
    vr_send_response(ret);
    return;
}

void
vr_fc_map_req_process(void *s_req)
{
    vr_fc_map_req *req = (vr_fc_map_req *)s_req;

    switch (req->h_op) {
    case SANDESH_OP_ADD:
        vr_fc_map_add(req);
        break;

    case SANDESH_OP_GET:
        vr_fc_map_get(req);
        break;

    case SANDESH_OP_DUMP:
        vr_fc_map_dump(req);
        break;

    case SANDESH_OP_DELETE:
        vr_fc_map_delete(req);
        break;

    default:
        vr_qos_message_error(-EINVAL);
        break;
    }

    return;
}

struct vr_forwarding_class_qos *
vr_qos_get_forwarding_class(struct vrouter *router, struct vr_packet *pkt,
        struct vr_forwarding_md *fmd)
{
    int8_t tos;
    int16_t qos_id = -1;
    unsigned int fc_id;

    struct vr_interface *vif;
    struct vr_forwarding_class *fc_p;

    vif = pkt->vp_if;

    if (fmd->fmd_flow_index >= 0) {
        qos_id = vr_flow_get_qos(router, pkt, fmd);
    }

    if (qos_id < 0) {
        qos_id = vif->vif_qos_map_index;
    }

    if (qos_id >= 0) {
        fc_p = vr_qos_map_get_fc(router, qos_id);
        if (!fc_p)
            return NULL;

        if (pkt->vp_type == VP_TYPE_IP || pkt->vp_type == VP_TYPE_IP6) {
            tos = fmd->fmd_dscp;
        } else {
            tos = fmd->fmd_dotonep;
            if (tos >= 0)
                tos += VR_DSCP_QOS_ENTRIES + VR_MPLS_QOS_ENTRIES;
        }

        if (tos >= 0) {
            fc_id = fc_p[tos].vfc_id;
            fc_p = vr_fc_map_get_fc(router, fc_id);
            if (!fc_p->vfc_valid)
                return NULL;

            return &fc_p->vfc_qos;
        }
    }

    return NULL;
}

void
vr_qos_exit(struct vrouter *router, bool soft_reset)
{
    unsigned int i;
    unsigned long size;

    if (soft_reset) {
        size = vr_qos_map_entries * sizeof(struct vr_forwarding_class *);
        if (router->vr_qos_map) {
            memset(router->vr_qos_map, 0, size);
        }
        size = vr_fc_map_entries * sizeof(struct vr_forwarding_class);
        if (router->vr_fc_table) {
            memset(router->vr_fc_table, 0, size);
        }
    } else {
        if (router->vr_qos_map) {
            for (i = 0; i < vr_qos_map_entries; i++) {
                if (router->vr_qos_map[i]) {
                    vr_free(router->vr_qos_map[i], VR_QOS_MAP_OBJECT);
                    router->vr_qos_map[i] = NULL;
                }
            }
            vr_free(router->vr_qos_map, VR_QOS_MAP_OBJECT);
            router->vr_qos_map = NULL;
        }

        if (router->vr_fc_table) {
            vr_free(router->vr_fc_table, VR_FC_OBJECT);
            router->vr_fc_table = NULL;
        }
    }

    return;
}

int
vr_qos_init(struct vrouter *router)
{
    unsigned long size;

    if (!router->vr_qos_map) {
        size = vr_qos_map_entries * sizeof(struct vr_forwarding_class *);
        router->vr_qos_map = vr_zalloc(size, VR_QOS_MAP_OBJECT);
        if (!router->vr_qos_map) {
            return vr_module_error(-ENOMEM, __FUNCTION__, __LINE__, size);
        }
    }

    if (!router->vr_fc_table) {
        size = vr_fc_map_entries * sizeof(struct vr_forwarding_class);
        router->vr_fc_table = vr_zalloc(size, VR_FC_OBJECT);
        if (!router->vr_fc_table) {
            return vr_module_error(-ENOMEM, __FUNCTION__, __LINE__, size);
        }
    }

    return 0;
}
