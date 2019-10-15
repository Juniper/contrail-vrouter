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
#define VR_LOG_ENTRY_LEN 150

/*
 * Max Number of log Entries
 */
#define VR_LOG_ENTRIES 2000

#define VR_LOG_MAX VR_LOG_ENTRY_LEN*VR_LOG_ENTRIES

/*
 * Maximum size of buffer that can be sent through SANDESH
 */
#define MAX_READ (4000/VR_LOG_ENTRY_LEN)*VR_LOG_ENTRY_LEN //To ensure uniformity  while reading buffer

/*
 * For priority level of module
 */
#define LOG_LVL_MASK 0x7
/*
 * For log_type of module
 */
#define LOG_CON_MASK 0x8

#define VR_ALLOW_LOG(Module, Level) \
    ((level[Module] & LOG_LVL_MASK) && (Level <= level[Module]))
/*
 * Macro to check log_type of module
 */
#define IS_LOG_TO_CON(Module) \
    (log_ctrl[Module].level & LOG_CON_MASK)

#define SET_MOD_CLI(Module) \
    (log_ctrl[Module].cli = true)

#define SET_MOD_LOG_SIZE(Module, entries) \
    (log_ctrl[Module].size = entries)
/*
 * API to set log_type of console to module
 */
#define SET_CON_LOG(Module) \
    (log_ctrl[Module].level |= LOG_CON_MASK)
/*
 * API to set level of module
 */
#define SET_MOD_LOG_LEVEL(Module, Level) \
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
     struct vrouter *router;\
     unsigned int time, idx, length;\
     uint64_t m_sec = 0, n_sec = 0;\
     char *log;\
     struct vr_log_buf_st *vr_log;\
     const char *level_to_name[] = {"none", "error", "warning", "info", "debug"};\
     if(VR_ALLOW_LOG(mod, lev)) {\
     if(IS_LOG_TO_CON(mod)) {\
         vr_printf(fmt, ##__VA_ARGS__);\
     }\
     router = vrouter_get(0);\
     vr_log = router->vr_logger;\
     if(vr_log != NULL) {\
         log = vr_log->vr_log_buf[mod].buf[lev];\
         vr_get_time(&m_sec, &n_sec);\
         time = (unsigned int) m_sec;\
         vr_sync_fetch_and_add_32u(&buf_hold, 1);\
         idx = vr_sync_fetch_and_add_32u(&vr_log->vr_log_buf[mod].buf_idx[lev], VR_LOG_ENTRY_LEN);\
         idx %= vr_log->vr_log_buf[mod].log_size;\
         length = snprintf(log+idx, VR_LOG_ENTRY_LEN, "%d Level:%s ",time, level_to_name[lev]);\
         idx += length;\
         length = snprintf(log+idx, VR_LOG_ENTRY_LEN, fmt, ##__VA_ARGS__);\
         vr_sync_fetch_and_add_32u(&buf_hold, -1);\
     }\
     }\
}

/*
 * List of available Modules
 */
enum MODULE_MAP
{
    MODULE_FLOW,
    MODULE_INTERFACE,
    MODULE_MIRROR,
    MODULE_NEXTHOP,
    MODULE_QOS,
    MODULE_ROUTE,
    VR_NUM_MODS
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
extern unsigned int log_entries[VR_NUM_MODS];
extern unsigned int log_st_entires;
extern unsigned int buf_hold;

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
    char *buf[VR_NUM_LEVELS];
    unsigned int log_size;
    unsigned int buf_idx[VR_NUM_LEVELS];
};

struct vr_log_buf_st
{
    struct vr_log_buf vr_log_buf[VR_NUM_MODS];
};
extern mod_log_ctrl log_ctrl[VR_NUM_MODS];
#endif
