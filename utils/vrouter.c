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
#if defined(__linux__)
#include <asm/types.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_ether.h>

#include <net/if.h>
#include <netinet/ether.h>
#elif defined(__FreeBSD__)
#include <net/if.h>
#include <net/ethernet.h>
#endif

#include "vr_types.h"
#include "vr_message.h"
#include "vr_genetlink.h"
#include "nl_util.h"
#include "vr_os.h"
#include "ini_parser.h"
#include "vrouter.h"

#define BUILD_VERSION_STRING    "\"build-version\":"
#define BUILD_USER_STRING       "\"build-user\":"
#define BUILD_HOST_NAME_STRING  "\"build-hostname\":"
#define BUILD_TIME_STRING       "\"build-time\":"

enum opt_mpls_index {
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

static bool response_pending = false;

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

static bool
is_read_op_set()
{
   int i;

   for (i = 0; read_options[i] != -1; ++i)
      if (opt[read_options[i]])
         return true;

   return false;
}

static bool
is_write_op_set()
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
print_log_level(unsigned int level)
{
   char *str = log_level_id_to_name(level);

   printf("Current log level: ");
   if (str != NULL)
      printf("%s\n", str);
   else
      printf("UNKNOWN\n");
}

static void
print_enabled_log_types(unsigned int types[], int size)
{
   int i;

   printf("Enabled log types: ");

   for (i = 0; i < size; ++i) {
      printf("%s ", log_type_id_to_name(types[i]));
   }

   if (i == 0)
      printf("none\n");
   else
      printf("\n");
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
   }

   if (opt[GET_LOG_LEVEL_INDEX]) {
      print_log_level(req->vo_log_level);
   }

   if (opt[GET_ENABLED_LOGS_INDEX]) {
      print_enabled_log_types(req->vo_log_type_enable,
            req->vo_log_type_enable_size);
   }

   response_pending = false;
   return;
}

void
vr_response_process(void *s)
{
    vr_response *resp = (vr_response *)s;

    if (resp->resp_code < 0) {
        printf("Error: %s\n", strerror(-resp->resp_code));
    }

    response_pending = false;
    return;
}

static int
send_request(vrouter_ops *req)
{
    int ret, error, attr_len;
    struct nl_response *resp;


    /* nlmsg header */
    ret = nl_build_nlh(cl, cl->cl_genl_family_id, NLM_F_REQUEST);
    if (ret) {
        return ret;
    }

    /* Generic nlmsg header */
    ret = nl_build_genlh(cl, SANDESH_REQUEST, 0);
    if (ret) {
        return ret;
    }

    attr_len = nl_get_attr_hdr_size();

    error = 0;
    ret = sandesh_encode(req, "vrouter_ops", vr_find_sandesh_info,
                         (nl_get_buf_ptr(cl) + attr_len),
                         (nl_get_buf_len(cl) - attr_len), &error);

    if ((ret <= 0) || error) {
        return ret;
    }

    /* Add sandesh attribute */
    nl_build_attr(cl, ret, NL_ATTR_VR_MESSAGE_PROTOCOL);
    nl_update_nlh(cl);

    response_pending = true;
    /* Send the request to kernel */
    ret = nl_sendmsg(cl);
    if (ret <= 0)
       return ret;

    while ((response_pending) && (ret = nl_recvmsg(cl)) > 0) {
        resp = nl_parse_reply(cl);
        if (resp->nl_op == SANDESH_REQUEST) {
            sandesh_decode(resp->nl_data, resp->nl_len, vr_find_sandesh_info,
                    &ret);
        }
    }

    return ret;
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
usage(void)
{
    printf("Usage:\n"
           "vrouter ([--info] | [--get-log-level] | [--get-enabled-log-types] |"
           " --help)\n"
           "vrouter ([--set-log-level <level>] [--enable-log-type <type>]...\n"
           "         [--disable-log-type <type>]...)\n\n"
           "Options:\n"
           "--info  Dumps information about vrouter\n"
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
vrouter_ops_set_log_entries(vrouter_ops *req)
{
    if (log_level > 0)
        req->vo_log_level = log_level;

    if (log_types_to_enable.size) {
        req->vo_log_type_enable_size = log_types_to_enable.size;
        req->vo_log_type_enable = log_types_to_enable.types;
    }

    if (log_types_to_disable.size) {
        req->vo_log_type_disable_size = log_types_to_disable.size;
        req->vo_log_type_disable = log_types_to_disable.types;
    }
}

static void
parse_long_opts(int opt_index, char *opt_arg)
{
    bool ret;

    errno = 0;
    switch (opt_index) {
    case INFO_OPT_INDEX:
        break;

    case GET_LOG_LEVEL_INDEX:
        break;

    case SET_LOG_LEVEL_INDEX:
        log_level = log_level_name_to_id(opt_arg);
        if (log_level == 0) {
            printf("Error: bad log level: '%s'\n\n", opt_arg);
            usage();
        }
        break;

    case LOG_ENABLE_INDEX:
        ret = log_types_add(&log_types_to_enable, opt_arg);
        if (!ret) {
            printf("Error: bad log type: '%s'\n\n", opt_arg);
            usage();
        }
        break;

    case LOG_DISABLE_INDEX:
        ret = log_types_add(&log_types_to_disable, opt_arg);
        if (!ret) {
            printf("Error: bad log type: '%s'\n\n", opt_arg);
            usage();
        }
        break;

    case GET_ENABLED_LOGS_INDEX:
        break;

    case HELP_OPT_INDEX:
    default:
        usage();
        break;
    }

    return;
}

static void
prepare_request(vrouter_ops *req)
{
   bool read, write;
   int ret;

   read = is_read_op_set();
   write = is_write_op_set();

   if (read && write) {
      printf("Error: only get or set type options can be used at a time\n");
      usage();
   }

   memset(req, 0, sizeof(*req));

   if (read) {
      req->h_op = SANDESH_OP_GET;
   } else {
      req->h_op = SANDESH_OP_ADD;
      vrouter_ops_set_log_entries(req);
   }
}

int
main(int argc, char *argv[])
{
    int ret, opt, option_index;
    vrouter_ops req;

    if (argc == 1) {
        usage();
    }

    while ((opt = getopt_long(argc, argv, "",
                    long_options, &option_index)) >= 0) {
        switch (opt) {
        case 0:
            parse_long_opts(option_index, optarg);
            break;

        case '?':
        default:
            usage();
            break;
        }
    }

    cl = nl_register_client();
    if (!cl) {
        exit(1);
    }

    parse_ini_file();

    ret = nl_socket(cl, get_domain(), get_type(), get_protocol());
    if (ret <= 0) {
        exit(1);
    }

    ret = nl_connect(cl, get_ip(), get_port());
    if (ret < 0) {
        exit(1);
    }

    if (vrouter_get_family_id(cl) <= 0) {
        return -1;
    }

    prepare_request(&req);

    ret = send_request(&req);
    if (ret < 0) {
       printf("Error: can not send the request ret=%d\n", ret);
       exit(1);
    }

    return 0;
}
