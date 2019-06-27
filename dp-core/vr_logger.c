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
    (router->vr_logger->vr_log_buf[Module].buf_idx)

/*
 * Retrieve log
 */
#define GET_LOG(Module) \
    (router->vr_logger->vr_log_buf[Module].buf)

int vr_logger_init(struct vrouter *router);
void vr_logger_exit(struct vrouter *router);
int vr_pkt_drop_log_get(unsigned int rid, int module, int log_type, int index);

int temp_vr_logger_en = 1;
unsigned int vr_logger_en = 1;
int vr_log_max_sz = VR_LOG_MAX;
mod_log_ctrl log_ctrl[VR_NUM_MODS];
short level[VR_NUM_MODS];
unsigned int sizes[VR_NUM_MODS];

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
int vr_pkt_drop_log_get(unsigned int rid, int module, int index, int cur_index)
{
    struct vrouter *router = vrouter_get(rid);
    char *log = GET_LOG(module);
    int inc_index;
    if(cur_index == -1) cur_index = GET_LOG_IDX(module);
    int ret;
    unsigned int vr_log_bufsz = router->vr_logger->vr_log_buf[module].log_size;
    vr_pkt_log_req *response;
    response = vr_zalloc(sizeof(*response), VR_LOG_REQ_OBJECT);
    if(!response) {
        vr_module_error(-ENOMEM, __FUNCTION__, __LINE__, sizeof(*response));
        goto exit_get;
    }
    if(vr_logger_en == 1 && level[module] != none) {
	response->vdl_log_buf_en = vr_logger_en;
        response->vdl_vr_log_size = min(vr_log_bufsz, MAX_READ);
        response->vdl_vr_log = vr_zalloc(response->vdl_vr_log_size, VR_LOG_REQ_OBJECT);
    if(!response->vdl_vr_log) {
        vr_module_error(ENOMEM, __FUNCTION__, __LINE__, VR_LOG_MAX);
        goto exit_get;
    }
    if(index == 0) {
    if(cur_index == 0) {
        if(strlen(log+cur_index) == 0) return -1;
    else {
        memcpy(response->vdl_vr_log, log+index, min(vr_log_bufsz, MAX_READ));
	inc_index = min(vr_log_bufsz, MAX_READ+1);
        index = (index + inc_index)%vr_log_bufsz;
    }
    }
    else {
          if(strlen(log+cur_index) == 0) {
          memcpy(response->vdl_vr_log, log+index, min(cur_index-index, MAX_READ));
	  inc_index = min(cur_index-index, MAX_READ+1);
          index = (index+inc_index)%vr_log_bufsz;
       }
       else {
          index = cur_index;
          if(vr_log_bufsz-index >= MAX_READ) {
             memcpy(response->vdl_vr_log, log+index, MAX_READ);
             index = (index + MAX_READ + 1)%vr_log_bufsz;
          }
          else {
             memcpy(response->vdl_vr_log, log+index, vr_log_bufsz-index);
             int read_bytes = (vr_log_bufsz-index);
             index = 0;
             memcpy(response->vdl_vr_log+read_bytes, log+index, min(cur_index-index, MAX_READ-read_bytes));
	     inc_index = min(cur_index-index, MAX_READ-read_bytes+1);
	     index = (index + inc_index)%vr_log_bufsz;
          }
       }
    }
    }
    else {
        if(index >= cur_index) {
           if(vr_log_bufsz-index >= MAX_READ) {
                 memcpy(response->vdl_vr_log, log+index, MAX_READ);
                 index = (index + MAX_READ + 1)%vr_log_bufsz;
              }
              else {
                 memcpy(response->vdl_vr_log, log+index, vr_log_bufsz-index);
                 int read_bytes = (vr_log_bufsz-index);
                 index = 0;
                 memcpy(response->vdl_vr_log+read_bytes, log+index, min(cur_index-index, MAX_READ-read_bytes));
		 inc_index = min(cur_index-index, MAX_READ-read_bytes+1);
                 index = (index+inc_index)%vr_log_bufsz;
              }
        }
        else {
           memcpy(response->vdl_vr_log, log+index, MAX_READ);
           inc_index = min(cur_index-index, MAX_READ+1);
           index = (index + inc_index)%vr_log_bufsz;
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
vr_pkt_log_req_process(void *s_req)
{
    int ret = 0, index, cur_index;
    vr_pkt_log_req *req = (vr_pkt_log_req *) s_req;
    struct vrouter *router = vrouter_get(req->vdl_rid);
    if(req->h_op != SANDESH_OP_GET) vr_send_response(ret); 
    index = req->vdl_log_idx;
    cur_index = req->vdl_cur_idx;
    return vr_pkt_drop_log_get(req->vdl_rid, req->vdl_module, index, cur_index);
}
