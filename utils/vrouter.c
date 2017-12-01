/*
 *  vrouter.c -- print vrouter information
 *
 *  Copyright (c) 2015 Juniper Networks, Inc. All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <getopt.h>
#include <stdbool.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <net/if.h>

#include "vr_types.h"
#include "nl_util.h"
#include "vr_os.h"
#include "ini_parser.h"
#include "vrouter.h"

#define BUILD_VERSION_STRING    "\"build-version\":"
#define BUILD_USER_STRING       "\"build-user\":"
#define BUILD_HOST_NAME_STRING  "\"build-hostname\":"
#define BUILD_TIME_STRING       "\"build-time\":"

enum opt_vrouter_index {
    INFO_OPT_INDEX,
    HELP_OPT_INDEX,
    GET_LOG_LEVEL_INDEX,
    SET_LOG_LEVEL_INDEX,
    LOG_ENABLE_INDEX,
    LOG_DISABLE_INDEX,
    GET_ENABLED_LOGS_INDEX,
    SET_PERFR_INDEX,
    SET_PERFS_INDEX,
    SET_FROM_VM_MSS_ADJ_INDEX,
    SET_TO_VM_MSS_ADJ_INDEX,
    SET_PERFR1_INDEX,
    SET_PERFR2_INDEX,
    SET_PERFR3_INDEX,
    SET_PERFP_INDEX,
    SET_PERFQ1_INDEX,
    SET_PERFQ2_INDEX,
    SET_PERFQ3_INDEX,
    SET_UDP_COFF_INDEX,
    SET_FLOW_HOLD_LIMIT_INDEX,
    SET_MUDP_INDEX,
    SET_BURST_TOKENS_INDEX,
    SET_BURST_INTERVAL_INDEX,
    SET_BURST_STEP_INDEX,
    SET_PRIORITY_TAGGING_INDEX,
    MAX_OPT_INDEX
};

/* TODO: Change to dynamic handling (8 is current max supported by DPDK) */
#define MAX_LOG_TYPES 8

typedef struct log_types {
    unsigned int size;
    unsigned int types[MAX_LOG_TYPES];
} log_types_t;

typedef struct name_id_pair {
    char *name;
    unsigned int id;
} log_type_name_id_t;

typedef struct name_id_pair log_level_name_id_t;

static struct nl_client *cl;

static int opt[MAX_OPT_INDEX];

static int write_options[] = {
    SET_LOG_LEVEL_INDEX,
    LOG_ENABLE_INDEX,
    LOG_DISABLE_INDEX,
    -1
};

static int read_options[] = {
    INFO_OPT_INDEX,
    GET_LOG_LEVEL_INDEX,
    GET_ENABLED_LOGS_INDEX,
    -1
};

static log_level_name_id_t log_levels[] = {
    {"emergency",   VR_LOG_EMERG},
    {"alert",       VR_LOG_ALERT},
    {"critical",    VR_LOG_CRIT},
    {"error",       VR_LOG_ERR},
    {"warning",     VR_LOG_WARNING},
    {"notice",      VR_LOG_NOTICE},
    {"info",        VR_LOG_INFO},
    {"debug",       VR_LOG_DEBUG},

    {"", 0} /* Must be the last entry */
};

static log_type_name_id_t log_types[] = {
    {"vrouter",     VR_LOGTYPE_VROUTER},
    {"usock",       VR_LOGTYPE_USOCK},
    {"uvhost",      VR_LOGTYPE_UVHOST},
    {"dpcore",      VR_LOGTYPE_DPCORE},

    {"", 0} /* Must be the last entry */
};

static log_types_t log_types_to_enable;
static log_types_t log_types_to_disable;
static unsigned int log_level;

/* Runtime parameters */
static int perfr = -1, perfs = -1, from_vm_mss_adj = -1, to_vm_mss_adj = -1;
static int perfr1 = -1, perfr2 = -1, perfr3 = -1, perfp = -1, perfq1 = -1;
static int perfq2 = -1, perfq3 = -1, udp_coff = -1, flow_hold_limit = -1;
static int mudp = -1, burst_tokens = -1, burst_interval = -1, burst_step = -1;
static unsigned int priority_tagging = 0;

static int platform, vrouter_op = -1;

static bool
vrouter_read_op(void)
{
    int i;

    for (i = 0; read_options[i] != -1; ++i)
        if (opt[read_options[i]])
            return true;

    return false;
}

static bool
vrouter_write_op(void)
{
    int i;

    for (i = 0; write_options[i] != -1; ++i)
        if (opt[write_options[i]])
            return true;

    return false;
}

static unsigned int
log_type_name_to_id(const char *name)
{
    int i;

    for (i = 0; log_types[i].id != 0; ++i) {
        if (strcmp(log_types[i].name, name) == 0)
            return log_types[i].id;
    }

    return 0;
}

static char *
log_type_id_to_name(unsigned int id)
{
    int i;

    for (i = 0; log_types[i].id != 0; ++i) {
        if (log_types[i].id == id)
            return log_types[i].name;
    }

    return NULL;
}

static unsigned int
log_level_name_to_id(const char *name)
{
    int i;

    for (i = 0; log_levels[i].id != 0; ++i) {
        if (strcmp(log_levels[i].name, name) == 0)
            return log_levels[i].id;
    }

    return 0;
}

static char *
log_level_id_to_name(unsigned int id)
{
    int i;

    for (i = 0; log_levels[i].id != 0; ++i) {
        if (log_levels[i].id == id)
            return log_levels[i].name;
    }

    return NULL;
}

void
print_field(char *start, char *end)
{
    while (((*start == ' ') || (*start == '"')) && (start < end))
        start++;

    do {
        printf("%c", *start++);
    } while (*start != '"');

    return;
}

void
print_build_info(char *buildinfo)
{
    char *start, *end;

    end = buildinfo + strlen(buildinfo);

    if (platform != DPDK_PLATFORM)
        printf("vRouter module version      ");
    else
        printf("vRouter/DPDK version        ");

    start = strstr(buildinfo, BUILD_VERSION_STRING);
    if (!start)
        return;

    start += strlen(BUILD_VERSION_STRING);
    if (start >= end)
        return;

    printf(" ");
    print_field(start, end);

    start = strstr(buildinfo, BUILD_USER_STRING);
    if (!start)
        return;

    start += strlen(BUILD_USER_STRING);
    if (start >= end)
        return;

    printf(" (Built by ");
    print_field(start, end);

    start = strstr(buildinfo, BUILD_HOST_NAME_STRING);
    if (!start)
        goto close_string;

    start += strlen(BUILD_HOST_NAME_STRING);
    if (start >= end)
        goto close_string;

    printf("@");
    print_field(start, end);

    printf(" on");
    start = strstr(buildinfo, BUILD_TIME_STRING);
    if (!start)
        goto close_string;

    start += strlen(BUILD_TIME_STRING);
    if (start >= end)
        goto close_string;

    printf(" ");
    print_field(start, end);

close_string:
    printf(")\n\n");
    return;
}

static void
print_vrouter_parameters(vrouter_ops *req)
{
    printf("Startup parameters\n"
        "    Interfaces limit                     %u\n"
        "    VRF tables limit                     %u\n"
        "    NextHops limit                       %u\n"
        "    MPLS Labels limit                    %u\n"
        "    Bridge Table limit                   %u\n"
        "    Bridge Table Overflow limit          %u\n"
        "    Flow Table limit                     %u\n"
        "    Flow Table overflow limit            %u\n"
        "    Mirror entries limit                 %u\n"
        "    Memroy Allocation Checks             %u\n"
        "\n",

        req->vo_interfaces, req->vo_vrfs, req->vo_nexthops,
        req->vo_mpls_labels, req->vo_bridge_entries,
        req->vo_oflow_bridge_entries, req->vo_flow_entries,
        req->vo_oflow_entries, req->vo_mirror_entries,
        req->vo_memory_alloc_checks
    );

    printf("Runtime parameters\n"
        "  Performance tweaks\n"
        "    GRO                                  %d\n"
        "    Segmentation in software             %d\n"
        "  TCP MSS adjust settings\n"
        "    TCP MSS on packets from VM           %d\n"
        "    TCP MSS on packet sent to VM         %d\n"
        "  RPS settings\n"
        "    RPS after pulling inner hdr (perfr1) %d\n"
        "    RPS after GRO on pkt1 (perfr2)       %d\n"
        "    RPS from phys rx handler (perfr3)    %d\n"
        "    Pull inner header (faster version)   %d\n"
        "    CPU to send pkts to, if perfr1 set   %d\n"
        "    CPU to send pkts to, if perfr2 set   %d\n"
        "    CPU to send pkts to, if perfr3 set   %d\n"
        "  Other settings\n"
        "    NIC cksum offload for outer UDP hdr  %d\n"
        "    Flow hold limit:                     %u\n"
        "    MPLS over UDP globally               %d\n"
        "    Used Flow entries                    %u\n"
        "    Used Over Flow entries               %u\n"
        "    Used Bridge entries                  %u\n"
        "    Used Over Flow bridge entries        %u\n"
        "    Burst Total Tokens                   %u\n"
        "    Burst Interval                       %u\n"
        "    Burst Step                           %u\n"
        "    NIC Priority Tagging                 %u\n"
        "\n",

        req->vo_perfr, req->vo_perfs,
        req->vo_from_vm_mss_adj, req->vo_to_vm_mss_adj,
        req->vo_perfr1, req->vo_perfr2, req->vo_perfr3, req->vo_perfp,
        req->vo_perfq1, req->vo_perfq2, req->vo_perfq3,
        req->vo_udp_coff, req->vo_flow_hold_limit, req->vo_mudp,
        req->vo_flow_used_entries, req->vo_flow_used_oentries,
        req->vo_bridge_used_entries, req->vo_bridge_used_oentries,
        req->vo_burst_tokens, req->vo_burst_interval, req->vo_burst_step,
        req->vo_priority_tagging
    );

    return;
}

static void
print_log_level(vrouter_ops *req)
{
    char *str = log_level_id_to_name(req->vo_log_level);

    if (platform != DPDK_PLATFORM)
        return;

    printf("Current log level                        ");
    if (str != NULL)
        printf("%s\n", str);
    else
        printf("UNKNOWN\n");

    return;
}

static void
print_enabled_log_types(vrouter_ops *req)
{
    int i;

    if (platform != DPDK_PLATFORM)
        return;

    printf("Enabled log types                        ");
    if (!req->vo_log_type_enable_size)
        printf("none\n");

    for (i = 0; i < req->vo_log_type_enable_size; ++i) {
        printf("%s ", log_type_id_to_name(req->vo_log_type_enable[i]));
    }

    printf("\n");
    return;
}

static void
_vrouter_ops_process(void *s_req)
{
    vrouter_ops *req = (vrouter_ops *)s_req;

    if (opt[INFO_OPT_INDEX]) {
        if (req->vo_build_info)
            print_build_info(req->vo_build_info);

        print_vrouter_parameters(req);

        print_log_level(req);
        print_enabled_log_types(req);
    } else {
        if (opt[GET_LOG_LEVEL_INDEX])
            print_log_level(req);

        if (opt[GET_ENABLED_LOGS_INDEX])
            print_enabled_log_types(req);
    }

    return;
}

static void
_response_process(void *s)
{
    vr_response_common_process((vr_response *)s, NULL);
    return;
}

static void
vrouter_fill_nl_callbacks()
{
    nl_cb.vrouter_ops_process = _vrouter_ops_process;
    nl_cb.vr_response_process = _response_process;
}

static int
vr_vrouter_op(struct nl_client *cl)
{
    int ret = 0;

    switch (vrouter_op) {
    case SANDESH_OP_GET:
        ret = vr_send_vrouter_get(cl, 0);
        break;

    case SANDESH_OP_ADD:
        if (opt[SET_LOG_LEVEL_INDEX] || opt[LOG_ENABLE_INDEX]) {
            ret = vr_send_vrouter_set_logging(cl, 0, log_level,
                    log_types_to_enable.types, log_types_to_enable.size,
                    log_types_to_disable.types, log_types_to_disable.size);
        } else {
            ret = vr_send_vrouter_set_runtime_opts(cl, 0,
                    perfr, perfs, from_vm_mss_adj, to_vm_mss_adj,
                    perfr1, perfr2, perfr3, perfp, perfq1,
                    perfq2, perfq3, udp_coff, flow_hold_limit,
                    mudp, burst_tokens, burst_interval, burst_step,
                    priority_tagging);
        }
        break;

    default:
        ret = -EINVAL;
        break;
    }

    if (ret < 0)
        return ret;

    return vr_recvmsg(cl, false);
}

static struct option long_options[] = {
    [INFO_OPT_INDEX] = {
        "info", no_argument, &opt[INFO_OPT_INDEX], 1
    },
    [HELP_OPT_INDEX] = {
        "help", no_argument, &opt[HELP_OPT_INDEX], 1
    },
    [GET_LOG_LEVEL_INDEX] = {
        "get-log-level", no_argument, &opt[GET_LOG_LEVEL_INDEX], 1
    },
    [SET_LOG_LEVEL_INDEX] = {
        "set-log-level", required_argument, &opt[SET_LOG_LEVEL_INDEX], 1
    },
    [LOG_ENABLE_INDEX] = {
        "enable-log-type", required_argument, &opt[LOG_ENABLE_INDEX], 1
    },
    [LOG_DISABLE_INDEX] = {
        "disable-log-type", required_argument, &opt[LOG_DISABLE_INDEX], 1
    },
    [GET_ENABLED_LOGS_INDEX] = {
        "get-enabled-log-types", no_argument, &opt[GET_ENABLED_LOGS_INDEX], 1
    },
    [SET_PERFR_INDEX] = {
        "perfr", required_argument, &opt[SET_PERFR_INDEX], 1
    },
    [SET_PERFS_INDEX] = {
        "perfs", required_argument, &opt[SET_PERFS_INDEX], 1
    },
    [SET_FROM_VM_MSS_ADJ_INDEX] = {
        "from_vm_mss_adj", required_argument, &opt[SET_FROM_VM_MSS_ADJ_INDEX], 1
    },
    [SET_TO_VM_MSS_ADJ_INDEX] = {
        "to_vm_mss_adj", required_argument, &opt[SET_TO_VM_MSS_ADJ_INDEX], 1
    },
    [SET_PERFR1_INDEX] = {
        "perfr1", required_argument, &opt[SET_PERFR1_INDEX], 1
    },
    [SET_PERFR2_INDEX] = {
        "perfr2", required_argument, &opt[SET_PERFR2_INDEX], 1
    },
    [SET_PERFR3_INDEX] = {
        "perfr3", required_argument, &opt[SET_PERFR3_INDEX], 1
    },
    [SET_PERFP_INDEX] = {
        "perfp", required_argument, &opt[SET_PERFP_INDEX], 1
    },
    [SET_PERFQ1_INDEX] = {
        "perfq1", required_argument, &opt[SET_PERFQ1_INDEX], 1
    },
    [SET_PERFQ2_INDEX] = {
        "perfq2", required_argument, &opt[SET_PERFQ2_INDEX], 1
    },
    [SET_PERFQ3_INDEX] = {
        "perfq3", required_argument, &opt[SET_PERFQ3_INDEX], 1
    },
    [SET_UDP_COFF_INDEX] = {
        "udp_coff", required_argument, &opt[SET_UDP_COFF_INDEX], 1
    },
    [SET_FLOW_HOLD_LIMIT_INDEX] = {
        "flow_hold_limit", required_argument, &opt[SET_FLOW_HOLD_LIMIT_INDEX], 1
    },
    [SET_MUDP_INDEX] = {
        "mudp", required_argument, &opt[SET_MUDP_INDEX], 1
    },
    [SET_BURST_TOKENS_INDEX] = {
        "burst_tokens", required_argument, &opt[SET_BURST_TOKENS_INDEX], 1
    },
    [SET_BURST_INTERVAL_INDEX] = {
        "burst_interval", required_argument, &opt[SET_BURST_INTERVAL_INDEX], 1
    },
    [SET_BURST_STEP_INDEX] = {
        "burst_step", required_argument, &opt[SET_BURST_STEP_INDEX], 1
    },
    [SET_PRIORITY_TAGGING_INDEX] = {
        "set-priority-tagging", required_argument, &opt[SET_PRIORITY_TAGGING_INDEX], 1
    },
    [MAX_OPT_INDEX] = {NULL, 0, 0, 0}
};

static void
Usage(void)
{
    switch (platform) {
    case DPDK_PLATFORM:
        printf("Usage:\n"
               "vrouter ([--info] [--get-log-level] [--get-enabled-log-types]) |"
               " --help\n"
               "vrouter ([--set-log-level <level>] [--enable-log-type <type>]...\n"
               "         [--disable-log-type <type>]...)\n"
               "vrouter ([--set-mudp <0|1>] [--from_vm_mss_adj <0|1>]...\n"
               "         [--flow_hold_limit <0|1>]...)\n"
               "vrouter ([--burst_tokens <int>>] [--burst_interval<int>]...\n"
               "         [--burst_step<int>]...)\n\n"
               "Options:\n"
               "--info Dumps information about vrouter\n"
               "--get-log-level Prints current log level\n"
               "--get-enabled-log-types Prints enabled log types\n"
               "--set-log-level <level> Sets logging level\n"
               "--enable-log-type <type> Enable given log type\n"
               "--disable-log-type <type> Disable given log type\n"
               "--from_vm_mss_adj <0|1> Turn on|off TCP MSS on packets from VM\n"
               "--flow_hold_limit <0|1> Turn on|off flow hold limit\n"
               "--mudp <0|1> Turn on|off MPLS over UDP globally\n"
               "--burst_tokens <int> total burst tokens \n"
               "--burst_interval <int> timer interval of burst tokens in ms\n"
               "--burst_step <int> burst tokens to add at every interval\n"
               "--help Prints this message\n\n"
               "<type> is one of:\n"
               "    vrouter\n"
               "    usock\n"
               "    uvhost\n"
               "    dpcore\n\n"
               "<level> is one of:\n"
               "    emergency\n"
               "    alert\n"
               "    critical\n"
               "    error\n"
               "    warning\n"
               "    notice\n"
               "    info\n"
               "    debug\n"
               "\n");
        break;

    default:
        printf("Usage:\n"
               "vrouter --info | --help\n"
               "vrouter ([--set-mudp <0|1>] [--from_vm_mss_adj <0|1>]...\n"
               "         [--flow_hold_limit <0|1>]...)\n"
               "vrouter ([--burst_tokens <int>>] [--burst_interval<int>]...\n"
               "         [--burst_step<int>]...)\n\n"
               "--info Dumps information about vrouter\n"
               "--perfr <0|1> Turn on|off GRO\n"
               "--perfs <0|1> Turn on|off segmentation in software\n"
               "--from_vm_mss_adj <0|1> Turn on|off TCP MSS on packets from VM\n"
               "--to_vm_mss_adj <0|1> Turn on|off TCP MSS on packets to VM\n"
               "--perfr1 <0|1> RPS after pulling inner hdr\n"
               "--perfr2 <0|1> RPS after GRO on pkt1\n"
               "--perfr3 <0|1> RPS from phys rx handler\n"
               "--perfp <0|1>  Pull inner hdr (faster version)\n"
               "--perfq1 <cpu> CPU to send pkts to if perfr1 set\n"
               "--perfq2 <cpu> CPU to send pkts to if perfr2 set\n"
               "--perfq3 <cpu> CPU to send pkts to if perfr3 set\n"
               "--udp_coff <0|1> NIC cksum offload for outer UDP hdr\n"
               "--flow_hold_limit <0|1> Turn on|off flow hold limit\n"
               "--mudp <0|1> Turn on|off MPLS over UDP globally\n"
               "--burst_tokens <int> total burst tokens \n"
               "--burst_interval <int> timer interval of burst tokens in ms\n"
               "--burst_step <int> burst tokens to add at every interval\n"
               "--set-priority-tagging <1 | 0> priority tagging on the NIC\n"
               "--help Prints this message\n"
               "\n");
        break;
    }

    exit(1);
}

static bool
log_types_add(log_types_t *types, const char *name)
{
    int i;

    int log_type_id = log_type_name_to_id(name);
    if (log_type_id < 0)
        return false;

    /* Check if already in the table */
    for (i = 0; i < types->size; ++i)
        if (types->types[i] == log_type_id)
            return true;

    /* TODO: Dynamic types' number handling */
    assert(types->size <= MAX_LOG_TYPES);

    types->types[types->size++] = log_type_id;

    return true;
}

static void
log_types_print(log_types_t *types)
{
    int i;

    printf("Types:\n");
    for (i = 0; i < types->size; ++i) {
        printf("%u\n", types->types[i]);
    }
}

static void
assert_platform_for_option(int required_platform, int opt_index)
{
    if (platform != required_platform) {
        printf("Error: %s option not supported on %s platform\n",
                long_options[opt_index].name, get_platform_str());
        Usage();
    }
}

static void
parse_long_opts(int opt_index, char *opt_arg)
{
    bool ret;

    errno = 0;
    switch (opt_index) {
    case INFO_OPT_INDEX:
        vrouter_op = SANDESH_OP_GET;
        break;

    case GET_LOG_LEVEL_INDEX:
        assert_platform_for_option(DPDK_PLATFORM, opt_index);
        vrouter_op = SANDESH_OP_GET;
        break;

    case SET_LOG_LEVEL_INDEX:
        assert_platform_for_option(DPDK_PLATFORM, opt_index);
        vrouter_op = SANDESH_OP_ADD;
        log_level = log_level_name_to_id(opt_arg);
        if (log_level == 0) {
            printf("vrouter: Invalid log level: '%s'\n\n", opt_arg);
            Usage();
        }
        break;

    case LOG_ENABLE_INDEX:
        assert_platform_for_option(DPDK_PLATFORM, opt_index);
        vrouter_op = SANDESH_OP_ADD;
        ret = log_types_add(&log_types_to_enable, opt_arg);
        if (!ret) {
            printf("vrouter: Invalid log type: '%s'\n\n", opt_arg);
            Usage();
        }
        break;

    case LOG_DISABLE_INDEX:
        assert_platform_for_option(DPDK_PLATFORM, opt_index);
        vrouter_op = SANDESH_OP_ADD;
        ret = log_types_add(&log_types_to_disable, opt_arg);
        if (!ret) {
            printf("vrouter: Invalid log type: '%s'\n\n", opt_arg);
            Usage();
        }
        break;

    case GET_ENABLED_LOGS_INDEX:
        assert_platform_for_option(DPDK_PLATFORM, opt_index);
        vrouter_op = SANDESH_OP_GET;
        break;

    case SET_PERFR_INDEX:
        assert_platform_for_option(LINUX_PLATFORM, opt_index);
        vrouter_op = SANDESH_OP_ADD;
        perfr = (int)strtol(opt_arg, NULL, 0);
        if (errno != 0) {
            printf("vrouter: Error parsing perfr: %s: %s (%d)\n", opt_arg,
                    strerror(errno), errno);
            Usage();
        }
        break;

    case SET_PERFS_INDEX:
        assert_platform_for_option(LINUX_PLATFORM, opt_index);
        vrouter_op = SANDESH_OP_ADD;
        perfs = (int)strtol(opt_arg, NULL, 0);
        if (errno != 0) {
            printf("vrouter: Error parsing perfs: %s: %s (%d)\n", opt_arg,
                    strerror(errno), errno);
            Usage();
        }
        break;

    case SET_FROM_VM_MSS_ADJ_INDEX:
        vrouter_op = SANDESH_OP_ADD;
        from_vm_mss_adj = (int)strtol(opt_arg, NULL, 0);
        if (errno != 0) {
            printf("vrouter: Error parsing from_vm_mss_adj: %s: %s (%d)\n", opt_arg,
                    strerror(errno), errno);
            Usage();
        }
        break;

    case SET_TO_VM_MSS_ADJ_INDEX:
        vrouter_op = SANDESH_OP_ADD;
        to_vm_mss_adj = (int)strtol(opt_arg, NULL, 0);
        if (errno != 0) {
            printf("vrouter: Error parsing to_vm_mss_adj: %s: %s (%d)\n", opt_arg,
                    strerror(errno), errno);
            Usage();
        }
        break;

    case SET_PERFR1_INDEX:
        assert_platform_for_option(LINUX_PLATFORM, opt_index);
        vrouter_op = SANDESH_OP_ADD;
        perfr1 = (int)strtol(opt_arg, NULL, 0);
        if (errno != 0) {
            printf("vrouter: Error parsing perfr1: %s: %s (%d)\n", opt_arg,
                    strerror(errno), errno);
            Usage();
        }
        break;

    case SET_PERFR2_INDEX:
        assert_platform_for_option(LINUX_PLATFORM, opt_index);
        vrouter_op = SANDESH_OP_ADD;
        perfr2 = (int)strtol(opt_arg, NULL, 0);
        if (errno != 0) {
            printf("vrouter: Error parsing perfr2: %s: %s (%d)\n", opt_arg,
                    strerror(errno), errno);
            Usage();
        }
        break;

    case SET_PERFR3_INDEX:
        assert_platform_for_option(LINUX_PLATFORM, opt_index);
        vrouter_op = SANDESH_OP_ADD;
        perfr3 = (int)strtol(opt_arg, NULL, 0);
        if (errno != 0) {
            printf("vrouter: Error parsing perfr3: %s: %s (%d)\n", opt_arg,
                    strerror(errno), errno);
            Usage();
        }
        break;

    case SET_PERFP_INDEX:
        assert_platform_for_option(LINUX_PLATFORM, opt_index);
        vrouter_op = SANDESH_OP_ADD;
        perfp = (int)strtol(opt_arg, NULL, 0);
        if (errno != 0) {
            printf("vrouter: Error parsing perfp: %s: %s (%d)\n", opt_arg,
                    strerror(errno), errno);
            Usage();
        }
        break;

    case SET_PERFQ1_INDEX:
        assert_platform_for_option(LINUX_PLATFORM, opt_index);
        vrouter_op = SANDESH_OP_ADD;
        perfq1 = (int)strtol(opt_arg, NULL, 0);
        if (errno != 0) {
            printf("vrouter: Error parsing perfq1: %s: %s (%d)\n", opt_arg,
                    strerror(errno), errno);
            Usage();
        }
        break;

    case SET_PERFQ2_INDEX:
        assert_platform_for_option(LINUX_PLATFORM, opt_index);
        vrouter_op = SANDESH_OP_ADD;
        perfq3 = (int)strtol(opt_arg, NULL, 0);
        if (errno != 0) {
            printf("vrouter: Error parsing perfq2: %s: %s (%d)\n", opt_arg,
                    strerror(errno), errno);
            Usage();
        }
        break;

    case SET_PERFQ3_INDEX:
        assert_platform_for_option(LINUX_PLATFORM, opt_index);
        vrouter_op = SANDESH_OP_ADD;
        perfq3 = (int)strtol(opt_arg, NULL, 0);
        if (errno != 0) {
            printf("vrouter: Error parsing perfq3: %s: %s (%d)\n", opt_arg,
                    strerror(errno), errno);
            Usage();
        }
        break;

    case SET_UDP_COFF_INDEX:
        assert_platform_for_option(LINUX_PLATFORM, opt_index);
        vrouter_op = SANDESH_OP_ADD;
        udp_coff = (int)strtol(opt_arg, NULL, 0);
        if (errno != 0) {
            printf("vrouter: Error parsing udp_coff: %s: %s (%d)\n", opt_arg,
                    strerror(errno), errno);
            Usage();
        }
        break;

    case SET_FLOW_HOLD_LIMIT_INDEX:
        vrouter_op = SANDESH_OP_ADD;
        flow_hold_limit = (int)strtol(opt_arg, NULL, 0);
        if (errno != 0) {
            printf("vrouter: Error parsing flow_hold_limit: %s: %s (%d)\n", opt_arg,
                    strerror(errno), errno);
            Usage();
        }
        break;

    case SET_MUDP_INDEX:
        vrouter_op = SANDESH_OP_ADD;
        mudp = (int)strtol(opt_arg, NULL, 0);
        if (errno != 0) {
            printf("vrouter: Error parsing mudp: %s: %s (%d)\n", opt_arg,
                    strerror(errno), errno);
            Usage();
        }
        break;

    case SET_BURST_TOKENS_INDEX:
        vrouter_op = SANDESH_OP_ADD;
        burst_tokens = (int)strtol(opt_arg, NULL, 0);
        if (errno != 0) {
            printf("vrouter: Error parsing burst_tokens: %s: %s (%d)\n", opt_arg,
                    strerror(errno), errno);
            Usage();
        }
        break;

    case SET_BURST_INTERVAL_INDEX:
        vrouter_op = SANDESH_OP_ADD;
        burst_interval = (int)strtol(opt_arg, NULL, 0);
        if (errno != 0) {
            printf("vrouter: Error parsing burst_interval: %s: %s (%d)\n", opt_arg,
                    strerror(errno), errno);
            Usage();
        }
        break;

    case SET_BURST_STEP_INDEX:
        vrouter_op = SANDESH_OP_ADD;
        burst_step = (int)strtol(opt_arg, NULL, 0);
        if (errno != 0) {
            printf("vrouter: Error parsing burst_step: %s: %s (%d)\n", opt_arg,
                    strerror(errno), errno);
            Usage();
        }
        break;

    case SET_PRIORITY_TAGGING_INDEX:
        vrouter_op = SANDESH_OP_ADD;
        priority_tagging = strtoul(opt_arg, NULL, 0);
        if (errno != 0) {
            printf("vrouter: Error parsing priority tagging configuration");
            Usage();
        }

        break;

    case HELP_OPT_INDEX:
    default:
        Usage();
        break;
    }

    return;
}

static void
validate_options(void)
{
    if (vrouter_read_op() && vrouter_write_op()) {
        printf("vrouter: Can not use both get AND set options together\n");
        Usage();
    }

    return;
}

int
main(int argc, char *argv[])
{
    int ret, opt, option_index;
    vrouter_ops req;

    vrouter_fill_nl_callbacks();

    parse_ini_file();
    platform = get_platform();

    if (argc == 1) {
        Usage();
    }

    while ((opt = getopt_long(argc, argv, "",
                    long_options, &option_index)) >= 0) {
        switch (opt) {
        case 0:
            parse_long_opts(option_index, optarg);
            break;

        case '?':
        default:
            Usage();
            break;
        }
    }


    validate_options();

    cl = vr_get_nl_client(VR_NETLINK_PROTO_DEFAULT);
    if (!cl) {
        exit(1);
    }

    vr_vrouter_op(cl);

    return 0;
}
