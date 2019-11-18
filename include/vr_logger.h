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
#define VR_LOG_DEFAULT_RECORDS 2000

#define VR_LOG_DEFAULT_SIZE (VR_LOG_ENTRY_LEN*VR_LOG_DEFAULT_RECORDS)

#define VR_RECORDS_TO_SIZE(records) (VR_LOG_ENTRY_LEN * records)

/*
 * Maximum size of buffer that can be sent through SANDESH
 */
#define MAX_READ 3900 

/*
 * Macro to check if logging is allowed
 */
#define VR_ALLOW_LOGGING(module, log_level) \
    logger.log_module[module].enable &&\
    log_level <= logger.log_module[module].level
/*
 * Macro to check log_type of module
 */
#define LOG_TO_CONSOLE(module) \
    logger.log_module[module].console

#define SET_MOD_LOG_NUM_RECORDS(module, log_level, records) \
    logger.log_module[module].level_info[log_level].num_records = records

/*
 * Macro to set log_type of console to module
 */
#define SET_CONSOLE_LOG(module) \
    logger.log_module[module].console = 1

#define SET_BUFFER_LOG(module) \
    logger.log_module[module].console = 0

/*
 * Macro to set level of module
 */
#define SET_MOD_LOG_LEVEL(module, log_level) \
    logger.log_module[module].level = log_level;\
    logger.log_module[module].enable = 1;

#define SET_MOD_LOG_LEVEL_NONE(module) \
    logger.log_module[module].enable = 0

#define VR_LOG_GEN(module, level, fmt, ...) {\
    char *log_fmt = vr_zalloc(VR_LOG_ENTRY_LEN, VR_LOG_REQ_OBJECT);\
    snprintf(log_fmt, VR_LOG_ENTRY_LEN, fmt, ##__VA_ARGS__);\
    VR_LOG(module, level, log_fmt);\
}

extern unsigned int buffer_hold;
extern bool vr_logger_en;
/*
 * List of available Modules
 */
enum module_map
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
enum level_map
{
    VR_ERROR,
    VR_WARNING,
    VR_INFO,
    VR_DEBUG,
    VR_NUM_LEVELS
};

#define str(x) #x

/*
 * Logger Data structures
 */

struct vr_log_level_info
{
    unsigned int num_records;
    unsigned int num_records_sysctl; //<-
   // unsigned int mod_param_level_sysctl;
    char *buffer;
    int buf_idx;
};

struct vr_log_module 
{
    struct vr_log_level_info level_info[VR_NUM_LEVELS];
   // unsigned int mod_param_log_sysctl; //<-
    short level;
    bool enable;
    bool console;
};

struct vr_log {
    bool enable;
    struct vr_log_module log_module[VR_NUM_MODS];
};

extern struct vr_log logger;

/*
 * Function to write logs to buffer
 */
 extern inline void VR_LOG(int module, int level, char *fmt);
#endif
