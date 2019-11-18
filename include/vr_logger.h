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
 * MAX size of a Log record
 */
#define VR_LOG_ENTRY_LEN 100

/*
 * Default Number of log record
 */
#define VR_DEFAULT_LOG_RECORDS 2000

#define VR_DEFAULT_LOG_SIZE (VR_LOG_ENTRY_LEN * VR_DEFAULT_LOG_RECORDS)

/*
 * Maximum size of buffer that can be sent through SANDESH
 */
#define VR_LOG_MAX_READ 3900

/*
 * Macro to check if logging is allowed
 */
#define VR_ALLOW_LOGGING(module, log_level) \
    vr_logger.log_module[module].enable &&\
    log_level <= vr_logger.log_module[module].level
/*
 * Macro to check log_type of module
 */
#define LOG_TO_CONSOLE(module) \
    vr_logger.log_module[module].console

/*
 * Macro to set log_type of console to module
 */
#define SET_CONSOLE_LOG(module) \
    vr_logger.log_module[module].console = 1

#define SET_BUFFER_ONLY_LOG(module) \
    vr_logger.log_module[module].console = 0

#define SET_LOG_MODULE_NUM_RECORDS(module, log_level, records) \
    vr_logger.log_module[module].level_info[log_level].num_records = records;\
    vr_logger.log_module[module].level_info[log_level].log_size = (records * VR_LOG_ENTRY_LEN);

/*
 * Macro to set level of module
 */
#define SET_LOG_MODULE_LEVEL(module, log_level) \
    vr_logger.log_module[module].level = log_level;\
    vr_logger.log_module[module].enable = 1;

#define SET_LOG_MODULE_LEVEL_NONE(module) \
    vr_logger.log_module[module].enable = 0

#define VR_LOG_GEN(module, level, fmt, ...) {\
    char *log_fmt = vr_zalloc(VR_LOG_ENTRY_LEN, VR_LOG_REQ_OBJECT);\
    snprintf(log_fmt, VR_LOG_ENTRY_LEN, fmt, ##__VA_ARGS__);\
    vr_log(module, level, log_fmt);\
}

/*
 * List of available Modules
 */
enum module_map
{
    MODULE_NONE,
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
    VR_NONE,
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
    unsigned int log_size;
    char *buffer;
    int buf_idx;
};

struct vr_log_module
{
    struct vr_log_level_info level_info[VR_NUM_LEVELS];
    short level;
    bool enable;
    bool console;
};

struct vr_log {
    struct vr_log_module log_module[VR_NUM_MODS];
};

/*
 * Function to write logs to buffer
 */
extern inline void vr_log(int module, int level, char *fmt, ...);
extern char* prefix_to_string(int prefix_size, uint8_t *prefix);

#endif
