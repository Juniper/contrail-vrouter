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

#define CHECK_MIN(a, b) (a < b ? a : b)

/*
 * Get the line number where current log is to be logged
 */
#define GET_LOG_LINE_IDX(module, log_level) \
    (logger.module[module].level_info[log_level].line_idx % \
    SIZE_TO_LINES(logger.module[module].level_info[log_level].log_size))

/*
 * Get the buffer index
 */
inline int GET_LOG_BUF_IDX(line_idx) {
    int shift_count = 0, tmp_len = VR_LOG_ENTRY_LEN;
    while (tmp_len != 1) {
        shift_count++;
	tmp_len = tmp_len >> 1;
    }
    return (line_idx << shift_count);
}

/*
 * Retrieve buffer log of particular module and log_level
 */
#define GET_LOG_BUF(module, log_level) \
    (logger.module[module].level_info[log_level].buffer)

/*
 * Boolean to check if logging is enabled
 */
bool vr_logger_en = true;
/*
 * Variable to determine default log level
 */
short vr_default_log_level = VR_DEBUG;
/*
 * Variable to determine default log size
 */
unsigned int vr_default_log_size = VR_DEFAULT_LOG_SIZE;

int vr_logger_init(struct vrouter *router);
void vr_logger_exit(struct vrouter *router);
void vr_log_get(unsigned int rid, int module, int level, int index, int line_index);

struct vr_log logger;
const char *level_id_to_name[] = {"none", "error", "warning", "info", "debug"};

/*
 * Initializing logger
 */
int vr_logger_init(struct vrouter *router)
{
    unsigned int i = 0, j = 0;
    /*
     * Initialize each log buffer per module
     */
        for(i = 1; i < VR_NUM_MODS; i++)
        {
            logger.module[i].level = vr_default_log_level;
            logger.module[i].enable = vr_logger_en;
            for(j = 1; j < VR_NUM_LEVELS; j++)
            {
                logger.module[i].level_info[j].log_size = vr_default_log_size;
                logger.module[i].level_info[j].buffer = vr_zalloc(
                    logger.module[i].level_info[j].log_size, VR_LOG_OBJECT);
                if (!logger.module[i].level_info[j].buffer)
                {
                    vr_module_error(-ENOMEM, __FUNCTION__, __LINE__,
                        logger.module[i].level_info[j].log_size);
                    vr_printf("Error while allocating memory for buffer\
		        with %d module and %d level\n", i, j);
                    goto cleanup;
                }
		logger.module[i].level_info[j].roll_over = false;
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
void vr_log_get(unsigned int rid, int module, int level, int index, int line_index)
{
    char *log_buf = GET_LOG_BUF(module, level);
    vr_log_req *response;
    int cur_index;
    unsigned int inc_index, log_bufsz, read_bytes, ret = 0;
    if (line_index == -1) {
	line_index = (GET_LOG_LINE_IDX(module, level));
    }
    cur_index = GET_LOG_BUF_IDX(line_index);

    log_bufsz = logger.module[module].level_info[level].log_size;
    response = vr_zalloc(sizeof(*response), VR_LOG_REQ_OBJECT);
    if (!response) {
        vr_module_error(-ENOMEM, __FUNCTION__, __LINE__, sizeof(*response));
        goto exit_get;
    }
    /*
     * Check if logging is disabled
     */
    if(!vr_logger_en) {
        response->vdl_log_buf_en = vr_logger_en;
        response->vdl_vr_log_size = 0;
        ret = vr_message_response(VR_LOG_OBJECT_ID, response, 0, false);
        return;
    }
        
    response->vdl_log_buf_en = vr_logger_en;
    response->vdl_vr_log_size = CHECK_MIN(log_bufsz, VR_LOG_MAX_READ);
    response->vdl_vr_log = vr_zalloc(response->vdl_vr_log_size,
                                     VR_LOG_REQ_OBJECT);
    if (!response->vdl_vr_log) {
        vr_module_error(ENOMEM, __FUNCTION__, __LINE__,
                    response->vdl_vr_log_size);
        goto exit_get;
    }
/*
 * First read from log buffer
 */
    if (index == 0) {
        if (cur_index == 0) {
        /*
         * Case when log buffer is empty
         */
            if (strlen(log_buf + cur_index) == 0 || logger.module[module].level_info[level].empty) {
                vr_message_response(VR_LOG_OBJECT_ID, response, 0, false);
                return;
            } else {
                memcpy(response->vdl_vr_log, log_buf + index, CHECK_MIN(log_bufsz, VR_LOG_MAX_READ));
                inc_index = CHECK_MIN(log_bufsz, VR_LOG_MAX_READ);
                if (index + inc_index >= log_bufsz) {
	            index = 0;
		    logger.module[module].level_info[level].roll_over = true;
		} else
		    index += inc_index;
            }
        } else {
         /*
          * Case when log buffer is partially filled.
          */
            if (logger.module[module].level_info[level].roll_over == false) {
                memcpy(response->vdl_vr_log, log_buf + index, CHECK_MIN(cur_index-index,
                    VR_LOG_MAX_READ));
                inc_index = CHECK_MIN(cur_index-index, VR_LOG_MAX_READ);
                if (index + inc_index >= log_bufsz) {
		    index = 0;
		    logger.module[module].level_info[level].roll_over = true;
		} else
		    index += inc_index;
            } else {
            /*
             * Case when log buffer is completely filled and is rolled over.
             */
                index = cur_index;
                if (log_bufsz-index >= VR_LOG_MAX_READ) {
                    memcpy(response->vdl_vr_log, log_buf + index, VR_LOG_MAX_READ);
                    if (index + VR_LOG_MAX_READ >= log_bufsz) {
	                index = 0;
			logger.module[module].level_info[level].roll_over = true;
		    } else
		        index += VR_LOG_MAX_READ;
                } else {
                    memcpy(response->vdl_vr_log, log_buf + index, log_bufsz-index);
                    read_bytes = log_bufsz - index;
                    index = 0;
                    memcpy(response->vdl_vr_log + read_bytes, log_buf + index,
                           CHECK_MIN(cur_index - index, VR_LOG_MAX_READ - read_bytes));
                    inc_index = CHECK_MIN(cur_index - index, VR_LOG_MAX_READ - read_bytes);
                    if (index + inc_index >= log_bufsz) {
		        index = 0;
			logger.module[module].level_info[level].roll_over = true;
		    } else
	                index += inc_index;
                }
            }
        }
    }
/*
 * Later reads from log buffer
 */
    else {
        if (index >= cur_index) {
            if (log_bufsz-index >= VR_LOG_MAX_READ) {
                memcpy(response->vdl_vr_log, log_buf + index, VR_LOG_MAX_READ);
                if (index + VR_LOG_MAX_READ >= log_bufsz) {
                    index = 0;
                    logger.module[module].level_info[level].roll_over = true;
                } else
                    index += VR_LOG_MAX_READ;
            } else {
                memcpy(response->vdl_vr_log, log_buf + index, log_bufsz - index);
                read_bytes = log_bufsz - index;
                index = 0;
                memcpy(response->vdl_vr_log + read_bytes, log_buf + index,
                       CHECK_MIN(cur_index - index, VR_LOG_MAX_READ - read_bytes));
                inc_index = CHECK_MIN(cur_index - index, VR_LOG_MAX_READ - read_bytes);
                if (index + inc_index >= log_bufsz) {
	            index = 0;
		    logger.module[module].level_info[level].roll_over = true;
	        } else 
		    index += inc_index;
            }
        } else {
            memcpy(response->vdl_vr_log, log_buf + index,
                    CHECK_MIN(cur_index - index, VR_LOG_MAX_READ));
            inc_index = CHECK_MIN(cur_index - index, VR_LOG_MAX_READ);
            if (index + inc_index >= log_bufsz) {
	        index = 0;
	        logger.module[module].level_info[level].roll_over = true;
	    } else
	        index += inc_index;
        }
    }
    response->vdl_log_idx = index;
    response->vdl_line_idx = line_index;
    ret = vr_message_response(VR_LOG_OBJECT_ID, response, 0, false);
    return;
exit_get:
    if (vr_logger_en == true) {
        if (response->vdl_vr_log != NULL) {
            vr_free(response->vdl_vr_log,VR_LOG_REQ_OBJECT);
        }
        if (response != NULL) {
            vr_free(response, VR_LOG_REQ_OBJECT);
        }
    }
}

void vr_logger_exit(struct vrouter *router)
{
    unsigned int i = 0, j = 0;
    for(i = 1; i < VR_NUM_MODS; i++)
    {
        for(j = 1; j < VR_NUM_LEVELS; j++)
        {
            if (!logger.module[i].level_info[j].buffer)
                continue;
            vr_free(logger.module[i].level_info[j].buffer, VR_LOG_OBJECT);
            logger.module[i].level_info[j].buffer = NULL;
        }
        logger.module[i].enable = 0;
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
    int ret = 0, index, line_index;
    vr_log_req *req = (vr_log_req *) s_req;
    module = req->vdl_module;
    level = req->vdl_level;
    if (req->vdl_clear_buf == 1) {
        logger.module[module].level_info[level].line_idx = 0;
	logger.module[module].level_info[level].roll_over = false;
	logger.module[module].level_info[level].empty = true;
    }
    if (req->h_op != SANDESH_OP_GET) {
        vr_send_response(ret);
        return;
    }
    index = req->vdl_log_idx;
    line_index = req->vdl_line_idx;
    vr_log_get(req->vdl_rid, module, level, index, line_index);
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
    unsigned int idx, line_idx;
    char *log_buf;
    va_list arglist;
    if (VR_ALLOW_LOGGING(module, level)) {
        log_buf = logger.module[module].level_info[level].buffer;
        line_idx = vr_sync_fetch_and_add_32u(&logger.module[module].level_info[level].line_idx, 1);
	if (line_idx >= SIZE_TO_LINES(logger.module[module].level_info[level].log_size)) {
            line_idx %= SIZE_TO_LINES(logger.module[module].level_info[level].log_size);
	    logger.module[module].level_info[level].roll_over = true;
	}
        idx = line_idx * VR_LOG_ENTRY_LEN;
        int len = sprintf(log_buf + idx, "[%s] ", level_id_to_name[level]);
        va_start(arglist, fmt);
        vsnprintf(log_buf + idx + len, VR_LOG_ENTRY_LEN - len, fmt,
                 arglist);
        va_end(arglist);
	if (LOG_TO_CONSOLE(module)) {
            vr_printf("%s\n", log_buf + idx);
	}
	logger.module[module].level_info[level].empty = false;
    }
}
