#ifndef VR_LOGGER_H
#define VR_LOGGER_H

#include "vr_defs.h"
#include "vr_qos.h"
#include "vr_flow.h"
#include "vrouter.h"
#include "vr_btable.h"
#include "vr_bridge.h"
#include "vr_mirror.h"
#include "vr_os.h"

/*
 * MAX size of a log entry
 */
#define VR_LOG_ENTRY_LEN 120

/*
 * Max Number of log Entries
 */
#define VR_LOG_ENTRIES 2000

#define VR_LOG_MAX VR_LOG_ENTRY_LEN*VR_LOG_ENTRIES

/*
 * Maximum size of buffer that can be sent through SANDESH
 */
#define MAX_READ (4000/VR_LOG_ENTRY_LEN)*VR_LOG_ENTRY_LEN

/*
 * For CLI purposes
 */
#define MAX_PARS_PER_MOD 3
#define MAXLEN_COMMAND 20

/*
 * For priority level of module
 */
#define LOG_LVL_MASK 0x7
/*
 * For log_type of module
 */
#define LOG_CON_MASK 0x8

#define VR_ALLOW_LOG(Module, Level) \
    ((log_ctrl[Module].level & LOG_LVL_MASK) && (Level <= log_ctrl[Module].level))
/*
 * API to check log_type of module
 */
#define LOG_TO_CON(Module) \
    (log_ctrl[Module].level & LOG_CON_MASK)

#define SET_MOD_CLI(Module) \
    (log_ctrl[Module].cli = true)

/*
 * API to set log_type of console to module
 */
#define SET_CON_LOG(Module) \
    (log_ctrl[Module].level |= LOG_CON_MASK)
/*
 * API to set level of module
 */
#define SET_MOD_LOG(Module, Level) \
    (log_ctrl[Module].level = (log_ctrl[Module].level&LOG_CON_MASK) | Level)
/*
 * API to check if log for a module is enabled
 */
#define IS_LOG_ENABLED(Module) \
    (log_ctrl[Module].level & LOG_LVL_MASK)
/*
 * API to write logs to buffer
 */
#define VR_LOG(mod, lev, fmt, ...) {\
     if((level[mod] & LOG_LVL_MASK) && (lev <= level[mod])) {\
     struct vrouter *router = vrouter_get(0);\
     struct vr_log_buf_st *vr_log = router->vr_logger;\
     const char *level_to_name[] = {"none", "error", "warning", "info", "debug"};\
     if(vr_log != NULL) {\
         char *log = vr_log->vr_log_buf[mod].buf;\
	 uint64_t m_sec = 0, n_sec = 0;\
         vr_get_time(&m_sec, &n_sec);\
         unsigned int time = (unsigned int) m_sec;\
         int idx = vr_sync_fetch_and_add_32u(&vr_log->vr_log_buf[mod].buf_idx, VR_LOG_ENTRY_LEN);\
         idx %= VR_LOG_MAX;\
         if(level[mod] & LOG_CON_MASK)\
             vr_printf(fmt, ##__VA_ARGS__); \
         else {\
             int length = snprintf(log+idx, VR_LOG_ENTRY_LEN, "%d Level:%s ",time, level_to_name[level[mod]]);\
             idx += length;\
             length = snprintf(log+idx, VR_LOG_ENTRY_LEN, fmt, ##__VA_ARGS__); \
         } \
     }\
     }\
}


/*
 * List of available Modules
 */
enum MODULE_MAP
{
    Flow, Interface, Mirror, NextHop, Qos, Route, VR_NUM_MODS
};
/*
 * List of log Levels
 */
enum LEVEL_MAP
{
    none, error, warning, info, debug, VR_NUM_LEVELS
};

#define str(x) #x
extern unsigned int vr_logger_en;
extern int vr_log_max_sz;
extern short level[VR_NUM_MODS];
extern unsigned int entries[VR_NUM_MODS];

typedef struct module_log_ctrl
{
    short level;
    int size;
    bool cli;
} mod_log_ctrl;

/*
 * Log buffer data structure
 */
struct vr_log_buf
{
    char *buf;
    unsigned int log_size;
    unsigned int buf_idx;
};

struct vr_log_buf_st
{
    struct vr_log_buf vr_log_buf[VR_NUM_MODS];
} ; 
extern mod_log_ctrl log_ctrl[VR_NUM_MODS];
#endif
