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
#define VR_LOG_ENTRY_LEN 100

/*
 * Max Number of log Entries
 */
#define VR_LOG_DEFAULT_ENTRIES 2000
#define VR_LOG_ENTRIES 2000

#define VR_LOG_DEFAULT_SIZE (VR_LOG_ENTRY_LEN*VR_LOG_DEFAULT_ENTRIES)

/*
 * Maximum size of buffer that can be sent through SANDESH
 */
#define MAX_READ 3900 

/*
 * For priority level of module
 */
#define LOG_LEVEL_MASK 0x7
/*
 * For log_type of module
 */
#define LOG_CONSOLE_MASK 0x8

/*
 * Macro to check if logging is allowed
 */
#define VR_ALLOW_LOGGING(module, lev) \
    ((log_ctrl[module].level & LOG_LEVEL_MASK) &&\
    (lev <= log_ctrl[module].level))
/*
 * Macro to check log_type of module
 */
#define LOG_TO_CONSOLE(module) \
    (log_ctrl[module].level & LOG_CONSOLE_MASK)

#define SET_MOD_LOG_ENTRIES(module, level, ent) \
    (log_ctrl[module].entries[level] = ent)

/*
 * Macro to set log_type of console to module
 */
#define SET_CONSOLE_LOG(module) \
    (log_ctrl[module].level |= LOG_CONSOLE_MASK)

#define SET_BUFFER_LOG(module) \
    (log_ctrl[module].level &= LOG_LEVEL_MASK)
/*
 * Macro to set level of module
 */
#define SET_MOD_LOG_LEVEL(module, lev) \
    (log_ctrl[module].level = (log_ctrl[module].level&\
                               LOG_CONSOLE_MASK) | lev)

#define VR_LOG_GEN(module, level, fmt, ...) {\
    char *log_fmt = vr_zalloc(VR_LOG_ENTRY_LEN, VR_LOG_REQ_OBJECT);\
    snprintf(log_fmt, VR_LOG_ENTRY_LEN, fmt, ##__VA_ARGS__);\
    VR_LOG(module, level, log_fmt);\
}

extern bool vr_logger_en;
extern unsigned int buffer_hold;

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
    vr_none,
    vr_error,
    vr_warning,
    vr_info,
    vr_debug,
    VR_NUM_LEVELS
};

#define str(x) #x

typedef struct vr_module_log_ctrl
{
    short level;
    unsigned int entries[VR_NUM_LEVELS];
} mod_log_ctrl;

/*
 * Log buffer data structure
 */
struct vr_log_buf
{
    char *buf[VR_NUM_LEVELS];
    unsigned int log_size[VR_NUM_LEVELS];
    unsigned int buf_idx[VR_NUM_LEVELS];
};

struct vr_log_buf_st
{
    struct vr_log_buf vr_log_buf[VR_NUM_MODS];
};
extern mod_log_ctrl log_ctrl[VR_NUM_MODS];

/*
 * Function to write logs to buffer
 */
 extern inline void VR_LOG(int module, int level, char *fmt);
#endif
