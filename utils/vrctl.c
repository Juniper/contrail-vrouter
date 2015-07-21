/*
 * vrctl.c - DPDK vRouter control tool
 *
 * Copyright (c) 2015 Semihalf. All rights reserved.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stdbool.h>
#include <getopt.h>
#include <assert.h>

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
#endif
#include <net/ethernet.h>

#include "vr_types.h"
#include "vr_message.h"
#include "vr_genetlink.h"
#include "vr_os.h"
#include "nl_util.h"
#include "ini_parser.h"
#include "vr_dpdk.h"

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

enum opt_index {
    LOG_LEVEL_IND,
    LOG_ENABLE_IND,
    LOG_DISABLE_IND,
    MAX_OPT_IND
};

static struct nl_client *cl;

static int opt[MAX_OPT_IND];
static struct option long_options[] = {
    [LOG_LEVEL_IND] = {
       "log-level", required_argument, &opt[LOG_LEVEL_IND], 1
    },
    [LOG_ENABLE_IND] = {
       "enable-log-type", required_argument, &opt[LOG_ENABLE_IND], 1
    },
    [LOG_DISABLE_IND] = {
       "disable-log-type", required_argument, &opt[LOG_DISABLE_IND], 1
    },
    [MAX_OPT_IND] = {NULL, 0, 0, 0}
};

static log_level_name_id_t log_levels[] = {
    {"emergency",   RTE_LOG_EMERG},
    {"alert",       RTE_LOG_ALERT},
    {"critical",    RTE_LOG_CRIT},
    {"error",       RTE_LOG_ERR},
    {"warning",     RTE_LOG_WARNING},
    {"notice",      RTE_LOG_NOTICE},
    {"info",        RTE_LOG_INFO},
    {"debug",       RTE_LOG_DEBUG},

    {"", 0} /* Must be the last entry */
};

static log_type_name_id_t log_types[] = {
    {"vrouter",     RTE_LOGTYPE_VROUTER},
    {"usock",       RTE_LOGTYPE_USOCK},
    {"uvhost",      RTE_LOGTYPE_UVHOST},
    {"dpcore",      RTE_LOGTYPE_DPCORE},

    {"", 0} /* Must be the last entry */
};

static log_types_t log_types_to_enable;
static log_types_t log_types_to_disable;
static unsigned int log_level;


static int
log_type_name_to_id(const char *name)
{
    int i;

    for (i = 0; log_types[i].id != 0; ++i) {
        if (strcmp(log_types[i].name, name) == 0)
            return log_types[i].id;
    }

    return -1;
}

static int
log_level_name_to_id(const char *name)
{
    int i;

    for (i = 0; log_levels[i].id != 0; ++i) {
        if (strcmp(log_levels[i].name, name) == 0)
            return log_levels[i].id;
    }

    return -1;
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

static vr_ctl_req *
vrctl_create_request()
{
    vr_ctl_req *req = malloc(sizeof(vr_ctl_req));
    if (req == NULL) {
        printf("Error wile allocating memory: %s\n", strerror(errno));
        exit(errno);
    }
    memset(req, 0, sizeof(vr_ctl_req));

    if (log_level >= 0)
        req->ctl_log_level = log_level;

    if (log_types_to_enable.size) {
        req->ctl_log_type_enable_size = log_types_to_enable.size;
        req->ctl_log_type_enable = log_types_to_enable.types;
    }

    if (log_types_to_disable.size) {
        req->ctl_log_type_disable_size = log_types_to_disable.size;
        req->ctl_log_type_disable = log_types_to_disable.types;
    }

    return req;
}

static int
vrctl_send_request(vr_ctl_req *req)
{
    int ret, attr_len, error;
    struct nl_response *resp;

    ret = nl_build_nlh(cl, cl->cl_genl_family_id, NLM_F_REQUEST);
    if (ret)
        return ret;

    ret = nl_build_genlh(cl, SANDESH_REQUEST, 0);
    if (ret)
        return ret;

    attr_len = nl_get_attr_hdr_size();

    error = 0;
    ret = sandesh_encode(req, "vr_ctl_req", vr_find_sandesh_info,
            (nl_get_buf_ptr(cl) + attr_len), (nl_get_buf_len(cl) - attr_len),
            &error);

    if ((ret <= 0) || error) {
        return ret;
    }

    nl_build_attr(cl, ret, NL_ATTR_VR_MESSAGE_PROTOCOL);
    nl_update_nlh(cl);
    ret = nl_sendmsg(cl);
    if (ret <= 0)
        return ret;

    if ((ret = nl_recvmsg(cl)) > 0) {
        resp = nl_parse_reply(cl);
        if (resp->nl_op == SANDESH_REQUEST) {
            sandesh_decode(resp->nl_data, resp->nl_len, vr_find_sandesh_info,
                    &ret);
        }
    }

    if (errno == EAGAIN || errno == EWOULDBLOCK)
        ret = 0;

    return ret;
}

void
vr_response_process(void *sresp)
{
    vr_response *resp = (vr_response *)sresp;

    if (resp->resp_code < 0)
        printf("Error in vRouter operation: %s\n", strerror(-resp->resp_code));

    return;
}

void
usage()
{
    printf("Usage: vrctl <options>\n"
           "\nOptions:\n"
           "--set-log-level <level> Sets logging level\n"
           "--enable-log-type <type> Enable given log type\n"
           "--disable-log-type <type> Disable given log type\n"
           "--help Displays this help message\n\n"
           "<type> is one of:\n"
           "    vrouter\n"
           "    usock\n"
           "    uvhost\n"
           "    dpcore\n"
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
}

static void
parse_long_opts(int ind, char *opt_arg)
{
    bool ret;

    switch(ind) {
    case LOG_LEVEL_IND:
        log_level = log_level_name_to_id(opt_arg);
        if (log_level < 0) {
            printf("Bad log level: '%s'\n\n", opt_arg);
            usage();
        }
        break;

    case LOG_ENABLE_IND:
        ret = log_types_add(&log_types_to_enable, opt_arg);
        if (!ret) {
            printf("Bad log type: '%s'\n\n", opt_arg);
            usage();
        }
        break;

    case LOG_DISABLE_IND:
        ret = log_types_add(&log_types_to_disable, opt_arg);
        if (!ret) {
            printf("Bad log type: '%s'\n\n", opt_arg);
            usage();
        }
        break;

    default:
        usage();
    }
}

int main(int argc, char *argv[])
{
    int ret;
    int opt;
    int ind;

    cl = nl_register_client();
    if (!cl) {
        printf("Error registering a NL client\n");
        exit(1);
    }

    parse_ini_file();

    ret = nl_socket(cl, get_domain(), get_type(), get_protocol());
    if (ret <= 0) {
        printf("Error creating a NL socket\n");
        exit(1);
    }

    ret = nl_connect(cl, get_ip(), get_port());
    if (ret < 0) {
        printf("Error connecting to the vRouter\n");
        exit(1);
    }

    if (vrouter_get_family_id(cl) <= 0) {
        return 0;
    }

    while ((opt = getopt_long(argc, argv, "", long_options, &ind)) >= 0) {
        switch(opt) {
            case 0:
                parse_long_opts(ind, optarg);
                break;

            default:
                usage();
        }

    }

    vr_ctl_req *req = vrctl_create_request();

    ret = vrctl_send_request(req);
    if (ret < 0) {
        printf("Error while sending a request ret=%d\n", ret);
        exit(1);
    }

    free(req);

    return 0;
}
