/*
 *Copyright (c) 2019 Juniper Networks, Inc. All rights reserved.
 */
#include <vr_os.h>
#include <vr_types.h>
#include <vr_packet.h>
#include "vr_message.h"
#include "vr_btable.h"
#include "vr_logger.h"

#define check_min(a, b) a<b?a:b

/*
 * Retrieve log index
 */
#define GET_LOG_BUF_IDX(module, level) \
    (router->vr_logger->vr_log_buf[module].buf_idx[level]\
    %router->vr_logger->vr_log_buf[module].log_size[level])

/*
 * Retrieve log
 */
#define GET_LOG_BUF(module, level) \
    (router->vr_logger->vr_log_buf[module].buf[level])

int vr_logger_init(struct vrouter *router);
void vr_logger_exit(struct vrouter *router);
int vr_pkt_drop_log_get(unsigned int rid, int module, int log_type, int index);

/*
 * Function to write logs to buffer
 */
inline void VR_LOG(int module, int level, char *fmt);

bool vr_logger_en = 1;
unsigned int buffer_hold = 0;
mod_log_ctrl log_ctrl[VR_NUM_MODS];
unsigned int log_entries_flow[VR_NUM_LEVELS];
unsigned int log_entries_interface[VR_NUM_LEVELS];
unsigned int log_entries_mirror[VR_NUM_LEVELS];
unsigned int log_entries_nexthop[VR_NUM_LEVELS];
unsigned int log_entries_qos[VR_NUM_LEVELS];
unsigned int log_entries_route[VR_NUM_LEVELS];
const char *level_id_to_name[] = {"none", "error", "warning", "info", "debug"};

/*
 * Initializing logger
 */
int vr_logger_init(struct vrouter *router)
{
    unsigned int i = 0, j = 0;
    struct vr_log_buf_st *vr_log;
    for(i=1;i<VR_NUM_LEVELS;i++) {
        log_entries_flow[i] = VR_LOG_DEFAULT_ENTRIES;
        log_entries_interface[i] = VR_LOG_DEFAULT_ENTRIES;
        log_entries_mirror[i] = VR_LOG_DEFAULT_ENTRIES;
        log_entries_nexthop[i] = VR_LOG_DEFAULT_ENTRIES;
        log_entries_qos[i] = VR_LOG_DEFAULT_ENTRIES;
        log_entries_route[i] = VR_LOG_DEFAULT_ENTRIES;
    }
    if(vr_logger_en == 1)
    {
        router->vr_logger = vr_zalloc(sizeof(struct vr_log_buf_st), VR_LOG_OBJECT);
        if(!router->vr_logger)
        {
            vr_module_error(-ENOMEM, __FUNCTION__, __LINE__, sizeof(struct vr_log_buf_st));
            goto cleanup;
        }
        vr_log = router->vr_logger;
        for(i=0;i<VR_NUM_MODS;i++)
        {
            log_ctrl[i].level = vr_debug;
        }
/*
 * Initialize each log buffer per module
 */
            for(j=1;j<VR_NUM_LEVELS;j++) {
                vr_log->vr_log_buf[0].log_size[j] = log_entries_flow[j]*
                                                    VR_LOG_ENTRY_LEN; 
                log_ctrl[0].entries[j] = log_entries_flow[j];
                vr_log->vr_log_buf[0].buf[j] = vr_zalloc(vr_log->vr_log_buf[0].log_size[j],
                                               VR_LOG_OBJECT);
                if(!vr_log->vr_log_buf[0].buf[j])
                {
                    vr_module_error(-ENOMEM, __FUNCTION__, __LINE__,
                                    vr_log->vr_log_buf[0].log_size[j]);
                    goto cleanup;
                }

                vr_log->vr_log_buf[1].log_size[j] = log_entries_interface[j]*
                                                    VR_LOG_ENTRY_LEN;
                log_ctrl[1].entries[j] = log_entries_interface[j];
                vr_log->vr_log_buf[1].buf[j] = vr_zalloc(vr_log->vr_log_buf[1].log_size[j],
                                               VR_LOG_OBJECT);
                if(!vr_log->vr_log_buf[1].buf[j])
                {
                    vr_module_error(-ENOMEM, __FUNCTION__, __LINE__,
                                    vr_log->vr_log_buf[1].log_size[j]);
                    goto cleanup;
                }

                vr_log->vr_log_buf[2].log_size[j] = log_entries_mirror[j]*
                                                    VR_LOG_ENTRY_LEN;
                log_ctrl[2].entries[j] = log_entries_mirror[j];
                vr_log->vr_log_buf[2].buf[j] = vr_zalloc(vr_log->vr_log_buf[2].log_size[j],
                                               VR_LOG_OBJECT);
                if(!vr_log->vr_log_buf[2].buf[j])
                {
                    vr_module_error(-ENOMEM, __FUNCTION__, __LINE__,
                                    vr_log->vr_log_buf[2].log_size[j]);
                    goto cleanup;
                }

                vr_log->vr_log_buf[3].log_size[j] = log_entries_nexthop[j]*
                                                    VR_LOG_ENTRY_LEN;
                log_ctrl[3].entries[j] = log_entries_nexthop[j];
                vr_log->vr_log_buf[3].buf[j] = vr_zalloc(vr_log->vr_log_buf[3].log_size[j],
                                                         VR_LOG_OBJECT);
                if(!vr_log->vr_log_buf[3].buf[j])
                {
                    vr_module_error(-ENOMEM, __FUNCTION__, __LINE__,
                                    vr_log->vr_log_buf[3].log_size[j]);
                    goto cleanup;
                }

                vr_log->vr_log_buf[4].log_size[j] = log_entries_qos[j]*
                                                    VR_LOG_ENTRY_LEN;
                log_ctrl[4].entries[j] = log_entries_qos[j];
                vr_log->vr_log_buf[4].buf[j] = vr_zalloc(vr_log->vr_log_buf[4].log_size[j],
                                                         VR_LOG_OBJECT);
                if(!vr_log->vr_log_buf[4].buf[j])
                {
                    vr_module_error(-ENOMEM, __FUNCTION__, __LINE__,
                                    vr_log->vr_log_buf[4].log_size[j]);
                    goto cleanup;
                }

                vr_log->vr_log_buf[5].log_size[j] = log_entries_route[j]*
                                                    VR_LOG_ENTRY_LEN;
                log_ctrl[5].entries[j] = log_entries_route[j];
                vr_log->vr_log_buf[5].buf[j] = vr_zalloc(vr_log->vr_log_buf[5].log_size[j],
                                                         VR_LOG_OBJECT);
                if(!vr_log->vr_log_buf[5].buf[j])
                {
                    vr_module_error(-ENOMEM, __FUNCTION__, __LINE__,
                                    vr_log->vr_log_buf[5].log_size[j]);
                    goto cleanup;
                }
            }
    }
    return 0;
    cleanup:
        vr_logger_exit(router);
        return -ENOMEM;
}

/*
 * LOG_READ_FUNCTION
 */
void vr_log_get(unsigned int rid, int module, int log_level, int index, int cur_index) {
    struct vrouter *router = vrouter_get(rid);
    char *log = GET_LOG_BUF(module, log_level);
    vr_log_req *response;
    unsigned int inc_index, log_bufsz, read_bytes, ret = 0;
    if(cur_index == -1) {
        cur_index = GET_LOG_BUF_IDX(module, log_level);
    }
    log_bufsz = router->vr_logger->vr_log_buf[module].log_size[log_level];
    response = vr_zalloc(sizeof(*response), VR_LOG_REQ_OBJECT);
    if(!response) {
        vr_module_error(-ENOMEM, __FUNCTION__, __LINE__, sizeof(*response));
        goto exit_get;
    }
/*
 * Check if logging is enabled
 */
    if(vr_logger_en == 1) {
        response->vdl_log_buf_en = vr_logger_en;
        response->vdl_vr_log_size = check_min(log_bufsz, MAX_READ);
        response->vdl_vr_log = vr_zalloc(response->vdl_vr_log_size,
                                         VR_LOG_REQ_OBJECT);
    if(!response->vdl_vr_log) {
        vr_module_error(ENOMEM, __FUNCTION__, __LINE__,
                        response->vdl_vr_log_size);
        goto exit_get;
    }
/*
 * First read from log buffer
 */
    if(index == 0) {
    if(cur_index == 0) {
/*
 * Case when log buffer is empty
 */
        if(strlen(log+cur_index) == 0) {
            vr_message_response(VR_LOG_OBJECT_ID, response, 0, false);
            return;
        }
    else {
        memcpy(response->vdl_vr_log, log+index, check_min(log_bufsz, MAX_READ));
        inc_index = check_min(log_bufsz, MAX_READ);
        if(index + inc_index >= log_bufsz) index = 0;
        else index += inc_index;
    }
    }
    else {
/*
 * Case when log buffer is partially filled.
 */
          if(strlen(log+cur_index) == 0) {
          memcpy(response->vdl_vr_log, log+index, check_min(cur_index-index,
                 MAX_READ));
          inc_index = check_min(cur_index-index, MAX_READ);
          if(index + inc_index >= log_bufsz) index = 0;
          else index += inc_index;
       }
       else {
/*
 * Case when log buffer is completely filled and is rolled over.
 */
          index = cur_index;
          if(log_bufsz-index >= MAX_READ) {
             memcpy(response->vdl_vr_log, log+index, MAX_READ);
             if(index + MAX_READ >= log_bufsz) index = 0;
             else index += MAX_READ;
          }
          else {
             memcpy(response->vdl_vr_log, log+index, log_bufsz-index);
             read_bytes = log_bufsz-index;
             index = 0;
             memcpy(response->vdl_vr_log+read_bytes, log+index,
                    check_min(cur_index-index, MAX_READ-read_bytes));
             inc_index = check_min(cur_index-index, MAX_READ-read_bytes);
             if(index + inc_index >= log_bufsz) index = 0;
             else index += inc_index;
          }
       }
    }
    }
/*
 * Later reads from log buffer
 */
    else {
        if(index >= cur_index) {
           if(log_bufsz-index >= MAX_READ) {
                 memcpy(response->vdl_vr_log, log+index, MAX_READ);
                 if(index + MAX_READ >= log_bufsz) index = 0;
                 else index += MAX_READ;
           }
           else {
              memcpy(response->vdl_vr_log, log+index, log_bufsz-index);
              read_bytes = log_bufsz-index;
              index = 0;
              memcpy(response->vdl_vr_log+read_bytes, log+index,
                     check_min(cur_index-index, MAX_READ-read_bytes));
              inc_index = check_min(cur_index-index, MAX_READ-read_bytes);
              if(index + inc_index >= log_bufsz) index = 0;
              else index += inc_index;
          }
        }
        else {
           memcpy(response->vdl_vr_log, log+index,
                  check_min(cur_index-index, MAX_READ));
           inc_index = check_min(cur_index-index, MAX_READ);
           if(index + inc_index >= log_bufsz) index = 0;
           else index += inc_index;
        }
    }
   }
   else {
        response->vdl_log_buf_en = vr_logger_en;
        response->vdl_vr_log_size = 0;
   }
   response->vdl_log_idx = index;
   response->vdl_cur_idx = cur_index;
   ret = vr_message_response(VR_LOG_OBJECT_ID, response, 0, false);
   return;
exit_get:
    if(vr_logger_en == 1) {
        if(response->vdl_vr_log != NULL) {
            vr_free(response->vdl_vr_log,VR_LOG_REQ_OBJECT);
        }
        if(response != NULL) {
            vr_free(response, VR_LOG_REQ_OBJECT);
        }
    }
}

void vr_logger_exit(struct vrouter *router)
{
    unsigned int i = 0, j = 0;

    struct vr_log_buf_st *vr_log = router->vr_logger;
    for(i=0;i<VR_NUM_MODS;i++)
    {
        for(j=1;j<VR_NUM_LEVELS;j++)
        {
            if(!vr_log->vr_log_buf[i].buf[j])
                break;
            vr_free(vr_log->vr_log_buf[i].buf[j], VR_LOG_OBJECT);
            vr_log->vr_log_buf[i].buf[j] = NULL;
        }
    }
    vr_free(vr_log, VR_LOG_OBJECT);
    vr_log = NULL;
    router->vr_logger = NULL;
}

/*
 * SANDESH request process
 */
void
vr_log_req_process(void *s_req)
{
    struct vrouter *router = vrouter_get(0);
    int module, log_level;
    int ret = 0, index, cur_index;
    char *log;
    vr_log_req *req = (vr_log_req *) s_req;
    module = req->vdl_module;
    log_level = req->vdl_level;
    if(req->vdl_clear_buf == 1) {
        log = GET_LOG_BUF(module, log_level);
        router->vr_logger->vr_log_buf[module].buf_idx[log_level] = 0;
        while(buffer_hold != 0);
        vr_free(router->vr_logger->vr_log_buf[module].buf[log_level], VR_LOG_OBJECT);
        router->vr_logger->vr_log_buf[module].buf[log_level] = 
        vr_zalloc(router->vr_logger->vr_log_buf[module].log_size[log_level],
                  VR_LOG_OBJECT);
    }
    if(req->h_op != SANDESH_OP_GET) {
        vr_send_response(ret);
        return;
    }
    index = req->vdl_log_idx;
    cur_index = req->vdl_cur_idx;
    vr_log_get(req->vdl_rid, module, log_level, index, cur_index);
}

inline void  VR_LOG(int module, int level, char *fmt) {
    struct vrouter *router;
    unsigned int idx;
    struct vr_log_buf_st *vr_log;
    char *log;
    if(VR_ALLOW_LOGGING(module, level)) {
        if(LOG_TO_CONSOLE(module)) {
            vr_printf("Level:%s %s", level_id_to_name[level], fmt);
            return;
        }
        router = vrouter_get(0);
        vr_log = router->vr_logger;
        if(vr_log != NULL) {
            log = router->vr_logger->vr_log_buf[module].buf[level];
            vr_sync_fetch_and_add_32u(&buffer_hold, 1);
            idx = vr_sync_fetch_and_add_32u(&vr_log->vr_log_buf[module].buf_idx[level],
                                            VR_LOG_ENTRY_LEN);
            idx %= vr_log->vr_log_buf[module].log_size[level];
            snprintf(log+idx, VR_LOG_ENTRY_LEN, "Level:%s %s\n",
                     level_id_to_name[level], fmt);
            vr_sync_fetch_and_add_32u(&buffer_hold, -1);
        }
    }
}
