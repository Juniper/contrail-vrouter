#include <vr_os.h>
#include <vr_types.h>
#include <vr_packet.h>
#include "vr_message.h"
#include "vr_btable.h"

#define min(a, b) a<b?a:b

/*
 * Retrieve log index
 */
#define GET_LOG_IDX(Module) \
    (router->vr_logger->vr_log_buf[Module].buf_idx%VR_LOG_MAX)

/*
 * Retrieve log
 */
#define GET_LOG(Module) \
    (router->vr_logger->vr_log_buf[Module].buf)

int vr_logger_init(struct vrouter *router);
void vr_logger_exit(struct vrouter *router);
int vr_pkt_drop_log_get(unsigned int rid, int module, int log_type, int index);

unsigned int vr_logger_en = 1;
int vr_log_max_sz = VR_LOG_MAX;
mod_log_ctrl log_ctrl[VR_NUM_MODS];
short level[VR_NUM_MODS];
unsigned int entries[VR_NUM_MODS];

/*
 * Initializing logger
 */
int vr_logger_init(struct vrouter *router)
{
    unsigned int i = 0;
    if(vr_logger_en == 1)
    {
        router->vr_logger = vr_zalloc(sizeof(struct vr_log_buf_st), VR_LOG_REQ_OBJECT);
        if(!router->vr_logger)
        {
            vr_module_error(-ENOMEM, __FUNCTION__, __LINE__, sizeof(struct vr_log_buf_st));
            goto cleanup;
        }
        struct vr_log_buf_st *vr_log = router->vr_logger;
        for(i=0;i<VR_NUM_MODS;i++)
        {
            vr_log->vr_log_buf[i].log_size = VR_LOG_MAX; //To be changed for loadtime parameters.
/*
*Initialize each log buffer per module
*/
            vr_log->vr_log_buf[i].buf = vr_zalloc(vr_log->vr_log_buf[i].log_size, VR_LOG_REQ_OBJECT);
            if(!vr_log->vr_log_buf[i].buf)
            {
                vr_module_error(-ENOMEM, __FUNCTION__, __LINE__, vr_log->vr_log_buf[i].log_size);
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
int vr_log_get(unsigned int rid, int module, int index, int cur_index)
{
    struct vrouter *router = vrouter_get(rid);
    char *log = GET_LOG(module);
    int inc_index;
    if(cur_index == -1) {
        cur_index = GET_LOG_IDX(module);
    }
    vr_printf("%d\n", cur_index);
    int ret;
    unsigned int log_bufsz = (router->vr_logger->vr_log_buf[module].log_size/VR_LOG_ENTRY_LEN)*VR_LOG_ENTRY_LEN;
    vr_log_req *response;
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
        response->vdl_vr_log_size = min(log_bufsz, MAX_READ);
        response->vdl_vr_log = vr_zalloc(response->vdl_vr_log_size, VR_LOG_REQ_OBJECT);
    if(!response->vdl_vr_log) {
        vr_module_error(ENOMEM, __FUNCTION__, __LINE__, VR_LOG_MAX);
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
        if(strlen(log+cur_index) == 0) return -1;
    else {
        memcpy(response->vdl_vr_log, log+index, min(log_bufsz, MAX_READ));
        inc_index = min(log_bufsz, MAX_READ);
        if(index + inc_index >= VR_LOG_MAX) index = 0;
        else index += inc_index;
    }
    }
    else {
/*
 * Case when log buffer is partially filled.
 */
          if(strlen(log+cur_index) == 0) {
          memcpy(response->vdl_vr_log, log+index, min(cur_index-index, MAX_READ));
          inc_index = min(cur_index-index, MAX_READ);
          if(index + inc_index >= VR_LOG_MAX) index = 0;
          else index += inc_index;
       }
       else {
/*
 * Case when log buffer is completely filled and is rolled over.
 */
          index = cur_index;
          if(log_bufsz-index >= MAX_READ) {
             memcpy(response->vdl_vr_log, log+index, MAX_READ);
             if(index + MAX_READ >= VR_LOG_MAX) index = 0;
             else index += MAX_READ;
          }
          else { 
             memcpy(response->vdl_vr_log, log+index, log_bufsz-index);
             int read_bytes = log_bufsz-index;
             index = 0;
             memcpy(response->vdl_vr_log+read_bytes, log+index, min(cur_index-index, MAX_READ-read_bytes));
             inc_index = min(cur_index-index, MAX_READ-read_bytes);
             if(index + inc_index >= VR_LOG_MAX) index = 0;
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
                 if(index + MAX_READ >= VR_LOG_MAX) index = 0;
                 else index += MAX_READ;
           }
           else {
              memcpy(response->vdl_vr_log, log+index, log_bufsz-index);
              int read_bytes = log_bufsz-index;
              index = 0;
              memcpy(response->vdl_vr_log+read_bytes, log+index, min(cur_index-index, MAX_READ-read_bytes));
              inc_index = min(cur_index-index, MAX_READ-read_bytes);
              if(index + inc_index >= VR_LOG_MAX) index = 0;
              else index += inc_index;
          }
        }
        else {
           memcpy(response->vdl_vr_log, log+index, min(cur_index-index, MAX_READ));
           inc_index = min(cur_index-index, MAX_READ);
           if(index + inc_index >= VR_LOG_MAX) index = 0;
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
exit_get:
    if(vr_logger_en == 1) {
        if(response->vdl_vr_log != NULL) {
            vr_free(response->vdl_vr_log,VR_LOG_REQ_OBJECT);
        }
        if(response != NULL) {
            vr_free(response, VR_LOG_REQ_OBJECT);
        }
    }

return ret;
}

void vr_logger_exit(struct vrouter *router)
{
    unsigned int i = 0;

    struct vr_log_buf_st *vr_log = router->vr_logger;
    for(i=0;i<VR_NUM_MODS;i++)
    {
        if(!vr_log->vr_log_buf[i].buf)
            break;
        vr_free(vr_log->vr_log_buf[i].buf, VR_LOG_REQ_OBJECT);
        vr_log->vr_log_buf[i].buf = NULL;
    }
    vr_free(vr_log, VR_LOG_REQ_OBJECT);
    vr_log = NULL;
}

/*
 * SANDESH request process
 */
void
vr_log_req_process(void *s_req)
{
    int ret = 0, index, cur_index;
    vr_log_req *req = (vr_log_req *) s_req;
    struct vrouter *router = vrouter_get(0);
    int module = req->vdl_module;
    if(req->vdl_clear_buf == 1) {
        vr_printf("clear buf: %d\n", req->vdl_clear_buf);
        char *log = GET_LOG(module);
        router->vr_logger->vr_log_buf[module].buf_idx = 0;
        vr_free(router->vr_logger->vr_log_buf[module].buf, VR_LOG_REQ_OBJECT);
        router->vr_logger->vr_log_buf[module].buf = vr_zalloc(router->vr_logger->vr_log_buf[module].log_size, VR_LOG_REQ_OBJECT);
    }
    if(req->h_op != SANDESH_OP_GET) vr_send_response(ret);
    index = req->vdl_log_idx;
    cur_index = req->vdl_cur_idx;
    return vr_log_get(req->vdl_rid, module, index, cur_index);
}
