#include <vr_os.h>
#include <vr_types.h>
#include <vr_packet.h>
#include "vr_message.h"
#include "vr_btable.h"

//Maximum bytes that can be read from log buffer
#define MAX_READ 4000*sizeof(char)
#define min(a, b) a<b?a:b

//Retrieve log index
#define GET_LOG_IDX(Module) \
    (router->vr_logger->vr_log_buf[Module].buf_idx)

//Retrieve log
#define GET_LOG(Module) \
    (router->vr_logger->vr_log_buf[Module].buf)

int vr_logger_init(struct vrouter *router);
void vr_logger_exit(struct vrouter *router);
int vr_pkt_drop_log_get(unsigned int rid, int module, int log_type, int index);

int test = 10;
int temp_en = 1;
int vr_logger_en = 1;
int vr_log_max_sz = VR_LOG_MAX;
mod_log_ctrl log_ctrl[VR_NUM_MODS];
short level[VR_NUM_MODS];
int sizes[VR_NUM_MODS];

//Initializing logger
int vr_logger_init(struct vrouter *router)
{ 
    unsigned int size = 0, i = 0;
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
	    vr_log->vr_log_buf[i].log_size = VR_LOG_MAX;
	    //Initialize each log buffer per module
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

//LOG_READ_FUNCTION
int vr_pkt_drop_log_get(unsigned int rid, int module, int log_type, int index)
{
    struct vrouter *router = vrouter_get(rid);
    int cur_index = GET_LOG_IDX(module);
    char *log = GET_LOG(module);
    int ret, pkt_buffer_size;
    unsigned int vr_log_bufsz = router->vr_logger->vr_log_buf[module].log_size;
    vr_pkt_log_req *response;
    response = vr_zalloc(sizeof(*response), VR_LOG_REQ_OBJECT);
    if(!response) {
        vr_module_error(-ENOMEM, __FUNCTION__, __LINE__, sizeof(*response));
        goto exit_get;
    }
    if(vr_logger_en == 1 && level[module] != none) {
        response->vdl_vr_log_size = VR_LOG_MAX;
        response->vdl_vr_log = (char *) vr_zalloc(VR_LOG_MAX, VR_LOG_REQ_OBJECT);
    if(!response->vdl_vr_log) {
        vr_module_error(ENOMEM, __FUNCTION__, __LINE__, VR_LOG_MAX);
        goto exit_get;
    }
    if(index == 0) {
    if(cur_index == 0) {
        if(strlen(log+cur_index) == 0) return -1;
    else {
        memcpy(response->vdl_vr_log, log+index, min(vr_log_bufsz, MAX_READ));
        response->vdl_log_max_size = vr_log_bufsz;
        index = (index+min(vr_log_bufsz, MAX_READ))%vr_log_bufsz;
    }
    }
    else {
          if(strlen(log+cur_index) == 0) {
          memcpy(response->vdl_vr_log, log+index, min(cur_index-index, MAX_READ));
          response->vdl_log_max_size = cur_index-index;
          index = (index+min(cur_index, MAX_READ))%vr_log_bufsz;
       }
       else {
          index = cur_index;
          if(vr_log_bufsz-index >= MAX_READ) {
             memcpy(response->vdl_vr_log, log+index, MAX_READ);
             response->vdl_log_max_size = vr_log_bufsz;
             index = (index + MAX_READ)%vr_log_bufsz;
          }
          else {
             memcpy(response->vdl_vr_log, log+index, vr_log_bufsz-index);
             int read_bytes = vr_log_bufsz-index;
             index = 0;
             memcpy(response->vdl_vr_log+read_bytes, log+index, min(cur_index-index, MAX_READ-read_bytes));
             response->vdl_log_max_size = vr_log_bufsz;
             index = (index+min(cur_index-index, MAX_READ-read_bytes))%vr_log_bufsz;
          }
       }
    }
    }
    else {
        if(index >= cur_index) {
           if(vr_log_bufsz-index >= MAX_READ) {
                 memcpy(response->vdl_vr_log, log+index, MAX_READ);
                 index = (index + MAX_READ)%vr_log_bufsz;
              }
              else {
                 memcpy(response->vdl_vr_log, log+index, vr_log_bufsz-index);
                 int read_bytes = vr_log_bufsz-index;
                 index = 0;
                 memcpy(response->vdl_vr_log+read_bytes, log+index, min(cur_index-index, MAX_READ-read_bytes));
                 index = (index+min(cur_index-index, MAX_READ-read_bytes))%vr_log_bufsz;
              }
        }
        else {
           memcpy(response->vdl_vr_log, log+index, min(cur_index-index, MAX_READ));
           index = index+min(cur_index-index, MAX_READ)%vr_log_bufsz;
        }
    }
   }
   else {
        response->vdl_log_buf_en = vr_logger_en;
   }
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

void
vr_pkt_log_req_process(void *s_req)
{
    int ret = 0, index = 0, log_type;
    vr_pkt_log_req *req = (vr_pkt_log_req *) s_req;
    if(req->h_op != SANDESH_OP_GET) vr_send_response(ret); 
    index = req->vdl_log_idx;
    log_type = level[req->vdl_module] & LOG_CON_MASK;
    int ind = vr_pkt_drop_log_get(req->vdl_rid, req->vdl_module, log_type, index);
}
