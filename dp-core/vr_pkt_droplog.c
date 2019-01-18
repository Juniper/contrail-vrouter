/*
 * vr_pkt_droplog.c -- Log drop packet information.
 *
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */
#include <vr_os.h>
#include <vr_types.h>
#include <vr_packet.h>
#include "vr_message.h"
#include "vr_btable.h"

int vr_pkt_drop_log_init(struct vrouter *router);
void vr_pkt_drop_log_exit(struct vrouter *router);

/* vr_pkt_droplog_bufsz used for
 * changing packet buffer size for each core during load time */
unsigned int vr_pkt_droplog_bufsz = VR_PKT_DROP_LOG_MAX;

/* Enabling/disbaling packet log during load time, If its disabled packet log
 * memory buffers for each core wouldn't  be allocated */
unsigned int vr_pkt_droplog_buf_en = 1;

/* It's sysctl implementation of enabling/disabling log during runtime */
unsigned int vr_pkt_droplog_sysctl_en = 1;

/* It's sysctl implementation of enabling/disabling minimum log during runtime
 * It will log only timestamp, drop reason, file & line no */
unsigned int vr_pkt_droplog_min_sysctl_en = 1;

/* Function to return buffer size and its used by sandesh for memory allocation
 * */
unsigned int vr_pkt_drop_log_req_get_size(void *object)
{
    unsigned int size = 0;
    vr_pkt_drop_log_req *req = (vr_pkt_drop_log_req *)object;

    return size = 4 * sizeof(*req) + (vr_pkt_droplog_bufsz *
            sizeof(vr_pkt_drop_log_t));
}

/* Function to repond packet drop log buffer for requested core */
static void
vr_pkt_drop_log_get(unsigned int rid, short core, int index)
{
    int ret = 0, pkt_buffer_size = 0;

    struct vrouter *router = vrouter_get(rid);
    vr_pkt_drop_log_req *response;

    /* Allocate memory for response */
    response = vr_zalloc(sizeof(*response), VR_PKT_DROP_LOG_REQ_OBJECT);
    if (!response)
    {
        vr_module_error(-ENOMEM, __FUNCTION__, __LINE__, sizeof(*response));
        goto exit_get;
    }

    /* Check if sysctl for packet drop log is enabled*/
    if(vr_pkt_droplog_sysctl_en == 1)
    {
        /* Check packet drop log is enabled at load time*/
        if(vr_pkt_droplog_buf_en == 1)
        {
            /* Check if packet log buffer is greater than allowed buffer size */
            if( vr_pkt_droplog_bufsz - index > VR_PKT_DROPLOG_MAX_ALLOW_BUFSZ )
                pkt_buffer_size = VR_PKT_DROPLOG_MAX_ALLOW_BUFSZ;
            else
                pkt_buffer_size = vr_pkt_droplog_bufsz - index;

            /* Calculate the buffer size in bytes for message transfer via
             * sandesh*/
            response->vdl_pkt_droplog_arr_size = pkt_buffer_size *
                sizeof(vr_pkt_drop_log_t);

            response->vdl_pkt_droplog_arr = (char *)vr_zalloc(
                response->vdl_pkt_droplog_arr_size, VR_PKT_DROP_LOG_REQ_OBJECT);
            if(!response->vdl_pkt_droplog_arr)
            {
                vr_module_error(-ENOMEM, __FUNCTION__, __LINE__,
                        vr_pkt_droplog_bufsz * sizeof(vr_pkt_drop_log_t));
                goto exit_get;
            }

            /* When packet drop log is requested for 0, it log for all cores
             * Since physical core always starts with 0, so we decrement by 1
             * at request side and increment by 1n while sending respnse*/
            response->vdl_core = core+1;
            response->vdl_log_idx = index;
            response->vdl_max_num_cores = vr_num_cpus;
            response->vdl_pkt_droplog_en = vr_pkt_droplog_buf_en;
            response->vdl_pkt_droplog_sysctl_en = vr_pkt_droplog_sysctl_en;
            response->vdl_pkt_droplog_max_bufsz = vr_pkt_droplog_bufsz;

            if(core == -1){
                /* When the core is requested as 0, process for all cores*/
                core = 0;
            }
            memcpy(response->vdl_pkt_droplog_arr,
                    router->vr_pkt_drop->vr_pkt_drop_log[core]+(index),
                    response->vdl_pkt_droplog_arr_size);
            }
        else
        {
            /* When packet drop log is disabled, copy sysctl and buffer enable
             * at load time value  in response
             * so that corresponding message would be displayed at utils side*/
            response->vdl_pkt_droplog_sysctl_en = vr_pkt_droplog_sysctl_en;
            response->vdl_pkt_droplog_en = vr_pkt_droplog_buf_en;
        }
    }
    else
    {
        /* Send response when sysctl for pkt drop log is not enabled */
        response->vdl_pkt_droplog_sysctl_en = vr_pkt_droplog_sysctl_en;
    }
    /* Response message for packet drop log */
    ret = vr_message_response(VR_PKT_DROP_LOG_OBJECT_ID, response, 0, false);
exit_get:
    if(vr_pkt_droplog_buf_en == 1)
        if(response->vdl_pkt_droplog_arr != NULL)
            vr_free(response->vdl_pkt_droplog_arr,VR_PKT_DROP_LOG_REQ_OBJECT);

    if(response != NULL)
        vr_free(response,VR_PKT_DROP_LOG_REQ_OBJECT);
}

void
vr_pkt_drop_log_req_process(void *s_req)
{
    int ret=0,core=1,index=0;
    vr_pkt_drop_log_req *req = (vr_pkt_drop_log_req *)s_req;

    if (req->h_op != SANDESH_OP_GET)
        vr_send_response(ret);
    core = req->vdl_core;
    index = req->vdl_log_idx;

    vr_pkt_drop_log_get(req->vdl_rid,core-1,index);

}

int vr_pkt_drop_log_init(struct vrouter *router)
{
    unsigned int size = 0, i = 0;

    if(vr_pkt_droplog_buf_en == 1)
    {
        /* Initialization of drop pkt log buffer*/
        size = sizeof(uint64_t *) * vr_num_cpus; /* Calculate number of cores */

        router->vr_pkt_drop = vr_zalloc(sizeof(struct vr_pkt_drop_st),
                VR_PKT_DROP_LOG_OBJECT);
        if (!router->vr_pkt_drop) {
            vr_module_error(-ENOMEM, __FUNCTION__,
                    __LINE__, size);
            goto cleanup;
        }

        struct vr_pkt_drop_st *vr_pkt_drop = router->vr_pkt_drop;

        /* Create log buffer object for each core*/
        vr_pkt_drop->vr_pkt_drop_log = vr_zalloc(size, VR_PKT_DROP_LOG_OBJECT);
        if (!vr_pkt_drop->vr_pkt_drop_log) {
            vr_module_error(-ENOMEM, __FUNCTION__,
                    __LINE__, size);
            goto cleanup;
        }

        /* Calculate the MAX pkt log buffer*/
        size = vr_pkt_droplog_bufsz * sizeof(vr_pkt_drop_log_t);

        for (i = 0; i < vr_num_cpus; i++) {
            /* Create a MAX log buffer configured and assign to each core */
            vr_pkt_drop->vr_pkt_drop_log[i] = vr_zalloc(size,
                    VR_PKT_DROP_LOG_OBJECT);
            if (!vr_pkt_drop->vr_pkt_drop_log[i]) {
                vr_module_error(-ENOMEM, __FUNCTION__,
                        __LINE__, i);
                goto cleanup;
            }
        }
        /* Creating the circular buffer for each core  */
        size = sizeof(uint64_t) * vr_num_cpus;

        vr_pkt_drop->vr_pkt_drop_log_buffer_index = vr_zalloc(size,
                VR_PKT_DROP_LOG_OBJECT);
        if (!vr_pkt_drop->vr_pkt_drop_log_buffer_index) {
            vr_module_error(-ENOMEM, __FUNCTION__,
                    __LINE__, size);
            goto cleanup;
        }
    }
    return 0;

cleanup:
    vr_pkt_drop_log_exit(router);
    return -ENOMEM;
}

void vr_pkt_drop_log_exit(struct vrouter *router)
{
    unsigned int i = 0;

    struct vr_pkt_drop_st *vr_pkt_drop = router->vr_pkt_drop;

    for (i = 0; i < vr_num_cpus; i++) {
        if(!vr_pkt_drop->vr_pkt_drop_log[i])
            break;

        vr_free(vr_pkt_drop->vr_pkt_drop_log[i], VR_PKT_DROP_LOG_OBJECT);
        vr_pkt_drop->vr_pkt_drop_log[i] = NULL;
    }

    vr_free(vr_pkt_drop->vr_pkt_drop_log, VR_PKT_DROP_LOG_OBJECT);
    vr_free(vr_pkt_drop->vr_pkt_drop_log_buffer_index, VR_PKT_DROP_LOG_OBJECT);

    vr_pkt_drop->vr_pkt_drop_log = NULL;
    vr_pkt_drop->vr_pkt_drop_log_buffer_index = NULL;

    vr_free(router->vr_pkt_drop, VR_PKT_DROP_LOG_OBJECT);

    router->vr_pkt_drop = NULL;
}
