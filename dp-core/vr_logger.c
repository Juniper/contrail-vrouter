/*
 *Copyright (c) 2019 Juniper Networks, Inc. All rights reserved.
 */
#include <vr_os.h>
#include <vr_types.h>
#include <vr_packet.h>
#include "vr_message.h"
#include "vr_btable.h"
#include "vr_logger.h"
#include "stdarg.h"

#define check_min(a, b) (a < b ? a : b)

/*
 * Retrieve log index
 */
#define GET_LOG_BUF_IDX(module, log_level) \
    (vr_logger.log_module[module].level_info[level].buf_idx % vr_logger.log_module[module].level_info[log_level].log_size)

/*
 * Retrieve log
 */
#define GET_LOG_BUF(module, log_level) \
    (vr_logger.log_module[module].level_info[level].buffer)

bool vr_logger_en = 0;
short vr_default_log_level = VR_DEBUG;
unsigned int vr_default_log_size = VR_DEFAULT_LOG_SIZE;
unsigned int buffer_hold = 0;

int vr_logger_init(struct vrouter *router);
void vr_logger_exit(struct vrouter *router);
int vr_pkt_drop_log_get(unsigned int rid, int module, int log_type, int index);

//unsigned int buffer_hold = 0;
struct vr_log vr_logger;
const char *level_id_to_name[] = {"none", "error", "warning", "info", "debug"};

/*
 * Initializing logger
 */
int vr_logger_init(struct vrouter *router)
{
    unsigned int i = 0, j = 0, log_size = 0;
    /*
     * Initialize each log buffer per module
     */
        for(i = 1;i < VR_NUM_MODS;i++)
        {
            vr_logger.log_module[i].level = vr_default_log_level;
            for(j = 1;j < VR_NUM_LEVELS;j++)
            {
                vr_logger.log_module[i].level_info[j].log_size = vr_default_log_size;
                log_size = vr_default_log_size;
                vr_logger.log_module[i].level_info[j].buffer = vr_zalloc(log_size,
                                                                   VR_LOG_OBJECT);
                vr_logger.log_module[i].level_info[j].num_records = VR_DEFAULT_LOG_RECORDS;
                if(!vr_logger.log_module[i].level_info[j].buffer)
                {
                    vr_module_error(-ENOMEM, __FUNCTION__, __LINE__, log_size);
                    vr_printf("Error allocating memory\n");
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
void vr_log_get(unsigned int rid, int module, int level, int index, int cur_index) {
    char *log = GET_LOG_BUF(module, level);
    vr_log_req *response;
    unsigned int inc_index, log_bufsz, read_bytes, ret = 0;
    if(cur_index == -1) {
        cur_index = GET_LOG_BUF_IDX(module, level);
    }
    log_bufsz = vr_logger.log_module[module].level_info[level].log_size;
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
        response->vdl_vr_log_size = check_min(log_bufsz, VR_LOG_MAX_READ);
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
                memcpy(response->vdl_vr_log, log+index, check_min(log_bufsz, VR_LOG_MAX_READ));
                inc_index = check_min(log_bufsz, VR_LOG_MAX_READ);
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
                        VR_LOG_MAX_READ));
                inc_index = check_min(cur_index-index, VR_LOG_MAX_READ);
                if(index + inc_index >= log_bufsz) index = 0;
                else index += inc_index;
            }
            else {
                /*
                 * Case when log buffer is completely filled and is rolled over.
                 */
                index = cur_index;
                if(log_bufsz-index >= VR_LOG_MAX_READ) {
                    memcpy(response->vdl_vr_log, log+index, VR_LOG_MAX_READ);
                    if(index + VR_LOG_MAX_READ >= log_bufsz) index = 0;
                    else index += VR_LOG_MAX_READ;
                }
                else {
                    memcpy(response->vdl_vr_log, log+index, log_bufsz-index);
                    read_bytes = log_bufsz-index;
                    index = 0;
                    memcpy(response->vdl_vr_log + read_bytes, log + index,
                            check_min(cur_index - index, VR_LOG_MAX_READ - read_bytes));
                    inc_index = check_min(cur_index - index, VR_LOG_MAX_READ - read_bytes);
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
           if(log_bufsz-index >= VR_LOG_MAX_READ) {
                 memcpy(response->vdl_vr_log, log + index, VR_LOG_MAX_READ);
                 if(index + VR_LOG_MAX_READ >= log_bufsz) index = 0;
                 else index += VR_LOG_MAX_READ;
           }
           else {
              memcpy(response->vdl_vr_log, log + index, log_bufsz - index);
              read_bytes = log_bufsz - index;
              index = 0;
              memcpy(response->vdl_vr_log + read_bytes, log + index,
                     check_min(cur_index - index, VR_LOG_MAX_READ - read_bytes));
              inc_index = check_min(cur_index - index, VR_LOG_MAX_READ - read_bytes);
              if(index + inc_index >= log_bufsz) index = 0;
              else index += inc_index;
          }
        }
        else {
           memcpy(response->vdl_vr_log, log + index,
                  check_min(cur_index - index, VR_LOG_MAX_READ));
           inc_index = check_min(cur_index - index, VR_LOG_MAX_READ);
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
    for(i=1;i<VR_NUM_MODS;i++)
    {
        for(j=1;j<VR_NUM_LEVELS;j++)
        {
            if(!vr_logger.log_module[i].level_info[j].buffer)
                continue;
            vr_free(vr_logger.log_module[i].level_info[j].buffer, VR_LOG_OBJECT);
            vr_logger.log_module[i].level_info[j].buffer = NULL;
        }
        vr_logger.log_module[i].enable = 0;
    }
    vr_logger_en = 0;
}

/*
 * SANDESH request process
 */
void
vr_log_req_process(void *s_req)
{
    int module, level;
    int ret = 0, index, cur_index;
    char *log;
    vr_log_req *req = (vr_log_req *) s_req;
    module = req->vdl_module;
    level = req->vdl_level;
    if(req->vdl_clear_buf == 1) {
        log = GET_LOG_BUF(module, level);
        vr_logger.log_module[module].level_info[level].buf_idx = 0;
        while(buffer_hold != 0);
        vr_free(vr_logger.log_module[module].level_info[level].buffer, VR_LOG_OBJECT);
        vr_logger.log_module[module].level_info[level].buffer =
        vr_zalloc(vr_logger.log_module[module].level_info[level].log_size,
                  VR_LOG_OBJECT);
    }
    if(req->h_op != SANDESH_OP_GET) {
        vr_send_response(ret);
        return;
    }
    index = req->vdl_log_idx;
    cur_index = req->vdl_cur_idx;
    vr_log_get(req->vdl_rid, module, level, index, cur_index);
}

char* prefix_to_string(int prefix_size, uint8_t *prefix)
{
     char *pref = vr_zalloc(prefix_size, VR_LOG_REQ_OBJECT);
     if (prefix_size != 0) {
         int i = 0, j = 0, len;
         while(prefix[i] != 0) {
             len = sprintf(pref+j, "%d.", prefix[i]);
             j += len;
             i++;
         }
     }
     return pref; 
}


/*
 * Inline function for logging contents into respective buffers
 */
inline void vr_log(int module, int level, char *fmt, ...) {
    unsigned int idx;
    char *log;
    va_list arglist;
    if (VR_ALLOW_LOGGING(module, level)) {
        if (LOG_TO_CONSOLE(module)) {
            vr_printf("[%s] ", level_id_to_name[level]);
            vr_printf("%s", fmt, arglist);
        }
        log = vr_logger.log_module[module].level_info[level].buffer;
        vr_sync_fetch_and_add_32u(&buffer_hold, 1);
        idx = vr_sync_fetch_and_add_32u(&vr_logger.log_module[module].level_info[level].buf_idx,
                                        VR_LOG_ENTRY_LEN);
        int len = sprintf(log+idx, "[%s] ", level_id_to_name[level]); 
        idx %= vr_logger.log_module[module].level_info[level].log_size;
        va_start(arglist, fmt);
        vsnprintf(log+idx+len, VR_LOG_ENTRY_LEN-len, fmt,
                 arglist);
        va_end(arglist);
        vr_sync_fetch_and_add_32u(&buffer_hold, -1);
    }
}
