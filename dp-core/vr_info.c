/*
 * vr_info.c -- vr_info functions
 *
 * Copyright (c) 2020 Juniper Networks, Inc. All rights reserved.
 */

#include <vr_os.h>
#if defined(__linux__)
#include <linux/version.h>
#endif
#include "vr_types.h"
#include "vr_sandesh.h"
#include "vr_message.h"
//#include "vr_cpuid.h"
#include <vr_packet.h>

/* vr_info_buff_table_p pointer used to handle multiple clients in parallel.
 * When user callback function returns outbuf pointer, its stored in this
 * table and sends the msg buffer to its corresponding CLI client */
static struct vr_info_buff_table vr_info_buff_table_p[VR_INFO_MSG_BUF_TABLE];

/* Register the user callback function in below table */
struct vr_info_callback users_cb_reg[VR_INFO_MAX_CALLBACK];

/* Register callback using below function for vr_info.
 * */
static int
vr_info_callback_register(void)
{
    /* Below macro would be expanded and register each callback function in
     * users_cb_reg table */
    FOREACH_VR_INFO_CB_REG_INIT();

    return 0;
}

/* Sandesh handler for vr_info message */
void
vr_info_req_process(void *s_req)
{
    int i, ret = 0, buff_sz = 0, max_buff_sz = 0, len = 0;
    vr_info_t msg_req;
    vr_info_req *req = (vr_info_req *)s_req;
    vr_info_req resp;
    struct vr_message_dumper *dumper = NULL;
    bool vr_info_last_buf = 0;

    if (req->h_op != SANDESH_OP_DUMP) {
        goto generate_response;
    }

    /* Copy request to response */
    resp = *req;

    /* Initialize the dumper buffer */
    dumper = vr_message_dump_init(req);

    /* Register callabck function before processing client request */
    ret = vr_info_callback_register();
    if(ret < 0) {
        vr_printf("vr_info: Callback registration failed\n with %d\n", ret);
        goto generate_response;
    }

    /* When CLI request comes, call the registered callback function and store
     * the address in msg_buff_table, If msginfo is more than 4K, split the
     * data into 4k chunks and send it serially to client. The client will
     * request back with vdu_buff_table_id and its index.
     * */
    if(!req->vdu_buff_table_id) {
        /* Maximum supported Client by server is 64, so based on that message
         * buffer table size is determined.
         * Buf table_id[0] is unused, so starting i with '1' */
        for(i = 1; i < VR_INFO_MSG_BUF_TABLE; i++) {
            /* Iterate through message buffer table and find the free entry */
            if(vr_info_buff_table_p[i].buff == NULL) {

                memset(&msg_req, 0, sizeof(vr_info_t));

                /* Copy Inbuf request to msg_req */
                msg_req.inbuf = req->vdu_inbuf;
                msg_req.inbuf_len = req->vdu_inbuf_size;

                /* Check requested msginfo is within boundary range */
                if((req->vdu_msginfo <= 0) || (req->vdu_msginfo >= INFO_MAX)) {
                    vr_printf("vr_info: Callback function is not registered \
                            for msginfo %d", req->vdu_msginfo);
                    goto generate_response;
                }

                /* If --bufsz is sent from CLI, then copy the value as part of
                 * msg_req */
                if(req->vdu_outbufsz) {
                    msg_req.bufsz = req->vdu_outbufsz;
                }

                /* Check requested msginfo is avaialable in users callback
                 * registered table */
                if(req->vdu_msginfo ==
                        users_cb_reg[req->vdu_msginfo].msginfo) {
                    ret = users_cb_reg[req->vdu_msginfo].cb_fn(&msg_req);
                } else {
                    vr_printf("vr_info: Requested msginfo %d is not registered \
                            in VR_INFO_REG() table\n", req->vdu_msginfo);
                    goto generate_response;
                }

                /* Callback function returned failure msg */
                if(ret < 0) {
                    vr_printf("vr_info: User callback function returned \
                            failure for msg %d", req->vdu_msginfo);
                    /* Suppose if message buffer is not completed, we append
                     * "Message Truncated" in the buffer and send to client */
                    len = sizeof("Message Truncated\n");
                    snprintf(((msg_req.outbuf + msg_req.outbuf_len) - len),
                            VR_MESSAGE_PAGE_SIZE, "Message Truncated\n");
                }
                /* Copy buffer table id as part of response, so when
                 * dump_pending is true, will callback with same buf table id */
                resp.vdu_buff_table_id = i;

                /* Copy message buffer_ptr to buffer table */
                vr_info_buff_table_p[i].buff = msg_req.outbuf;
                /* Copy message buffer length to buff_table pointer */
                vr_info_buff_table_p[i].buf_len = msg_req.outbuf_len;

                /* Check if Output buffer has contents */
                if(msg_req.outbuf == NULL) {
                    vr_printf("vrinfo: Output buffer is not filled\n");
                    vr_info_last_buf = true;
                    goto exit_get;

                }
                /* If outbuf_len is not supplied from callback, calculate it */
                if(!msg_req.outbuf_len) {
                    buff_sz = strlen(msg_req.outbuf);
                } else {
                    buff_sz = msg_req.outbuf_len;
                }

                /* this is first iteration, so make vdu_marker as zero */
                req->vdu_marker = 0;
                break;
            }
        }
    } else {
        if(vr_info_buff_table_p[resp.vdu_buff_table_id].buff != NULL) {
            buff_sz = vr_info_buff_table_p[resp.vdu_buff_table_id].buf_len;
        } else {
            vr_printf("vr_info: vr_info_buff_table_p buf_id %d is NULL\n",
                    req->vdu_buff_table_id);
            vr_info_last_buf = true;
            goto generate_response;
        }
    }

    /* Sandesh has limitation of macro(VR_MESSAGE_PAGE_SIZE) size, so
     * calculating max buffer size, and those much amount of data would be sent
     * on each iteration */
    max_buff_sz = VR_MESSAGE_PAGE_SIZE - (sizeof(resp) +
            sizeof(struct vr_message_dumper));

    /* Check if the buffer size is greater than max buffer, If so, have to send
     * it through multiple iteration. */
    if(buff_sz > max_buff_sz) {
        /* To send whole buffer, (buff_sz/max_buff_sz + 1) => these many
         * number of times have to send it to client CLI. */
        while(1) {
            /* To find the last iteration */
            if( req->vdu_marker == buff_sz/max_buff_sz ) {
                /* Calculate the number of remaining bytes to send it to
                 * client CLI */
                resp.vdu_proc_info_size = (buff_sz -
                        (max_buff_sz * req->vdu_marker) + 1);
                vr_info_last_buf = true;
            } else {
                /* Increment with 1 to include the '\0' character */
                resp.vdu_proc_info_size = max_buff_sz + 1;
            }

            /* Update the index value, querying for next iteration */
            resp.vdu_index = (req->vdu_marker + 1);

            resp.vdu_proc_info = vr_zalloc((resp.vdu_proc_info_size *
                        sizeof(uint8_t)), VR_INFO_REQ_OBJECT);
            if(resp.vdu_proc_info == NULL) {
                vr_info_last_buf = true;
                goto exit_get;
            }

            /* Copy the message to "resp.vdu_proc_info" from
             * "vr_info_buff_table_p[id]+offset". Here offset is calculated
             * from (max_buff_sz * req->vdu_marker) */
            snprintf(resp.vdu_proc_info, (resp.vdu_proc_info_size),
                    (vr_info_buff_table_p[resp.vdu_buff_table_id].buff +
                        (max_buff_sz * req->vdu_marker)));

            /* If message buffer copy is not complete, it will return with -1.
             * so it will send to client and client will request back. */
            ret = vr_message_dump_object(dumper, VR_INFO_OBJECT_ID, &resp);

            if(resp.vdu_proc_info != NULL) {
                vr_free(resp.vdu_proc_info, VR_INFO_REQ_OBJECT);
            }
            if((ret <= 0) || vr_info_last_buf) {
                break;
            }
        }
    } else {
        /* Total message buffer size is less than 4k, so it can send in
         * one iteration. */
        vr_info_last_buf = true;
        resp.vdu_proc_info_size = buff_sz;

        resp.vdu_proc_info = vr_zalloc((resp.vdu_proc_info_size *
                    sizeof(uint8_t)), VR_INFO_REQ_OBJECT);
        if(resp.vdu_proc_info == NULL) {
            goto exit_get;
        }

        /* Copy message buffer */
        snprintf(resp.vdu_proc_info, resp.vdu_proc_info_size, msg_req.outbuf);
        vr_message_dump_object(dumper, VR_INFO_OBJECT_ID, &resp);
    }

generate_response:
    vr_message_dump_exit(dumper, ret);

/* Once last buffer element has reached, clear all message buffers.
 * Memory(malloc) is allocated by end users and infra will free the memory */
exit_get:
    if(vr_info_last_buf) {
        if(vr_info_buff_table_p[resp.vdu_buff_table_id].buff != NULL) {
            vr_free(vr_info_buff_table_p[resp.vdu_buff_table_id].buff,
                    VR_INFO_REQ_OBJECT);
            vr_info_buff_table_p[resp.vdu_buff_table_id].buff = NULL;
            vr_info_buff_table_p[resp.vdu_buff_table_id].buf_len = 0;
        } else {
            vr_printf("Memory free failed for vr_info pointer instance %d\n",
                    resp.vdu_buff_table_id);
        }
    }

    return;
}
