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

    printf("vRouter module version      ");

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
    printf(")\n");
    return;
}

static void
print_log_level(vrouter_ops *req)
{
    char *str = log_level_id_to_name(req->vo_log_level);

    if (platform != DPDK_PLATFORM)
        return;

    printf("Current log level            ");
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

    printf("Enabled log types            ");
    if (!req->vo_log_type_enable_size)
        printf("none\n");

    for (i = 0; i < req->vo_log_type_enable_size; ++i) {
        printf("%s ", log_type_id_to_name(req->vo_log_type_enable[i]));
    }

    printf("\n");
    return;
}

void
vrouter_ops_process(void *s_req)
{
    vrouter_ops *req = (vrouter_ops *)s_req;

    if (opt[INFO_OPT_INDEX]) {
        if (req->vo_build_info)
            print_build_info(req->vo_build_info);

        printf("Interfaces limit             %u\n", req->vo_interfaces);
        printf("VRF tables limit             %u\n", req->vo_vrfs);
        printf("NextHops limit               %u\n", req->vo_nexthops);
        printf("MPLS Labels limit            %u\n", req->vo_mpls_labels);
        printf("Bridge Table limit           %u\n", req->vo_bridge_entries);
        printf("Bridge Table Overflow limit  %u\n", req->vo_oflow_bridge_entries);
        printf("Flow Table limit             %u\n", req->vo_flow_entries);
        printf("Flow Table overflow limit    %u\n", req->vo_oflow_entries);
        printf("Mirror entries limit         %u\n", req->vo_mirror_entries);
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

void
vr_response_process(void *s)
{
    vr_response_common_process((vr_response *)s, NULL);
    return;
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
        ret = vr_send_vrouter_set_logging(cl, 0, log_level,
                log_types_to_enable.types, log_types_to_enable.size,
                log_types_to_disable.types, log_types_to_disable.size);
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
               "         [--disable-log-type <type>]...)\n\n"
               "Options:\n"
               "--info Dumps information about vrouter\n"
               "--get-log-level Prints current log level\n"
               "--get-enabled-log-types Prints enabled log types\n"
               "--set-log-level <level> Sets logging level\n"
               "--enable-log-type <type> Enable given log type\n"
               "--disable-log-type <type> Disable given log type\n"
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
               "\n"
               "--info Dumps information about vrouter\n"
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
assert_dpdk_platform_for_option(int opt_index)
{
    if (platform != DPDK_PLATFORM) {
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
        assert_dpdk_platform_for_option(opt_index);
        vrouter_op = SANDESH_OP_GET;
        break;

    case SET_LOG_LEVEL_INDEX:
        assert_dpdk_platform_for_option(opt_index);
        vrouter_op = SANDESH_OP_ADD;
        log_level = log_level_name_to_id(opt_arg);
        if (log_level == 0) {
            printf("vrouter: Invalid log level: '%s'\n\n", opt_arg);
            Usage();
        }
        break;

    case LOG_ENABLE_INDEX:
        assert_dpdk_platform_for_option(opt_index);
        vrouter_op = SANDESH_OP_ADD;
        ret = log_types_add(&log_types_to_enable, opt_arg);
        if (!ret) {
            printf("vrouter: Invalid log type: '%s'\n\n", opt_arg);
            Usage();
        }
        break;

    case LOG_DISABLE_INDEX:
        assert_dpdk_platform_for_option(opt_index);
        vrouter_op = SANDESH_OP_ADD;
        ret = log_types_add(&log_types_to_disable, opt_arg);
        if (!ret) {
            printf("vrouter: Invalid log type: '%s'\n\n", opt_arg);
            Usage();
        }
        break;

    case GET_ENABLED_LOGS_INDEX:
        vrouter_op = SANDESH_OP_GET;
        assert_dpdk_platform_for_option(opt_index);
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
