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

#define BUILD_VERSION_STRING    "\"build-version\":"
#define BUILD_USER_STRING       "\"build-user\":"
#define BUILD_HOST_NAME_STRING  "\"build-hostname\":"
#define BUILD_TIME_STRING       "\"build-time\":"

static struct nl_client *cl;

static int info_set, help_set;
static int vrouter_op = -1;
static bool response_pending = false;

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

void
vrouter_ops_process(void *s_req)
{
   vrouter_ops *req = (vrouter_ops *)s_req;

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

    return;
}

static int
vr_vrouter_op(void)
{
    int ret, error, attr_len;
    struct nl_response *resp;
    struct nlmsghdr *nlh;

    vrouter_ops info_req;

    info_req.h_op = vrouter_op;

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
    ret = sandesh_encode(&info_req, "vrouter_ops", vr_find_sandesh_info,
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
    while ((response_pending) &&
            (ret = nl_recvmsg(cl)) > 0) {
        resp = nl_parse_reply(cl);
        if (resp->nl_op == SANDESH_REQUEST) {
            sandesh_decode(resp->nl_data, resp->nl_len,
                    vr_find_sandesh_info, &ret);
        }
    }


    return 0;
}

enum opt_mpls_index {
    INFO_OPT_INDEX,
    HELP_OPT_INDEX,
    MAX_OPT_INDEX
};

static struct option long_options[] = {
    [INFO_OPT_INDEX]        =       {"info",    no_argument,    &info_set,      1},
    [HELP_OPT_INDEX]        =       {"help",    no_argument,    &help_set,      1},
    [MAX_OPT_INDEX]         =       { NULL,     0,              0,              0},
};

static void
Usage(void)
{
    printf("Usage: vrouter --info\n");
    printf("\n");
    printf("--info  Dumps information about vrouter\n");
    printf("--help  Prints this help message\n");

    exit(1);
}

static void
parse_long_opts(int opt_index, char *opt_arg)
{
    errno = 0;
    switch (opt_index) {
    case INFO_OPT_INDEX:
        vrouter_op = SANDESH_OP_GET;
        break;

    case HELP_OPT_INDEX:
    default:
        Usage();
        break;
    }

    return;
}


int
main(int argc, char *argv[])
{
    int ret, opt, option_index;

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

    if (vrouter_op < 0) {
        Usage();
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

    vr_vrouter_op();

    return 0;
}
