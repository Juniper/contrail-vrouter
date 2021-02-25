/*
 * dpdkinfo.c - CLI dpdkinfo to get info. about bond, lacp, mem etc.
 *
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdbool.h>
#include <getopt.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <net/if.h>

#include "ini_parser.h"
#include "vr_os.h"
#include "vr_types.h"
#include "vr_nexthop.h"
#include "ini_parser.h"
#include "nl_util.h"
#include "ini_parser.h"
#include "vr_packet.h"


static struct nl_client *cl;
static bool dump_pending = false;
static int dump_marker = -1;
/* For supporting multiple CLI clients, Message buffer table id is stored and
 * resend if dump_pending is true */
/* Optional parameter: buffsz -> Send buffer size for the Output buffer(outbuf) 
 * */
static int buff_table_id, buffsz;

static int help_set, ver_set, sock_dir_set;
static unsigned int core = (unsigned)-1;
static unsigned int stats_index = 0;
/* For few  CLI, Inbuf has to send to vrouter for processing(i.e kind of filter
*/
static uint8_t *vr_info_inbuf;

static vr_info_msg_en msginfo;

enum opt_index {
    HELP_OPT_INDEX,
    VER_OPT_INDEX,
    BUFFSZ_OPT_INDEX,
    SOCK_DIR_OPT_INDEX,
    MAX_OPT_INDEX,
};

static struct option long_options[] = {
    [HELP_OPT_INDEX]    =   {"help",    no_argument,        &help_set,      1},
    [VER_OPT_INDEX]    =    {"version",    no_argument,        &ver_set,      1},
    [BUFFSZ_OPT_INDEX]  =   {"buffsz",  required_argument,  &buffsz,        1},
    [SOCK_DIR_OPT_INDEX]  = {"sock-dir", required_argument, &sock_dir_set,  1},
    [MAX_OPT_INDEX]     =   {NULL,    0,                  0,              0},
};

static void
Usage()
{
    printf("Usage: dpdkinfo [--help]\n");
    printf("                 --version|-v           Show version information\n");
    printf("       Optional: --buffsz  <value>      Send output buffer size\n");
    exit(-EINVAL);
}

static void
validate_options(void)
{
    if(!ver_set) {
        Usage();
    }

    return;
}

/*
 * Response messages are sent through character buffer via Sandesh and it has
 * a limitation of sending upto 4K(PAGE_SIZE) for each iteration.
 * */
static void
vrinfo_resp_cb_process(void *s_req)
{
    int ret = 0;
    int platform = get_platform();
    vr_info_req *resp = (vr_info_req *)s_req;

    if(resp != NULL && resp->vdu_proc_info) {
        /* Print the Message buffer(character buffer)
         * sent by vRouter(Server) */
        printf("%s", resp->vdu_proc_info);
    }

    /* For Sandesh DUMP, we should update the marker id and buff_table_id for
     * the next interation. */
    if (resp->h_op == SANDESH_OP_DUMP) {
        dump_marker = resp->vdu_index;
        buff_table_id = resp->vdu_buff_table_id;
    }
}

static void
response_process(void *s)
{
    vr_response_common_process((vr_response *)s, &dump_pending);
}

static void
vrinfo_fill_nl_callbacks()
{
    nl_cb.vr_info_req_process = vrinfo_resp_cb_process;
    nl_cb.vr_response_process = response_process;
}

static void
parse_long_opts(int opt_index, char *opt_arg)
{
    errno = 0;

    switch (opt_index) {
    case VER_OPT_INDEX:
        msginfo = INFO_VER;
        break;
    case SOCK_DIR_OPT_INDEX:
        vr_socket_dir = opt_arg;
        break;
    case BUFFSZ_OPT_INDEX:
        buffsz = (unsigned)strtol(opt_arg, NULL, 0);
        break;
    case HELP_OPT_INDEX:
    default:
        Usage();
    }

    return;
}

/* vr_get_dpdkinfo API send request to vRouter(server) and uses
 * h_op = DUMP for message request.
 *  */
static int
vr_get_vrinfo(struct nl_client *cl)
{
    int ret;
    bool dump = true;

op_retry:
    ret = vr_send_info_dump(cl, 0, dump_marker, buff_table_id, msginfo, buffsz,
            vr_info_inbuf);
    if (ret < 0) {
        return ret;
    }

    ret = vr_recvmsg(cl, dump);
    if (ret <= 0) {
        return ret;
    }

    /* Will loop through till it reaches end of buffer */
    if (dump_pending) {
        goto op_retry;
    }
    return 0;
}

int
main(int argc, char *argv[])
{
    char opt;
    int ret, option_index, log_core = 0, i = 0;

    /* Register callback function for Netlink message */
    vrinfo_fill_nl_callbacks();

    parse_ini_file();

    while (((opt = getopt_long(argc, argv, "h:v:s:",
                        long_options, &option_index)) >= 0)) {
        switch (opt) {
        case 'v':
            ver_set = 1;
            msginfo = INFO_VER;
            parse_long_opts(VER_OPT_INDEX, optarg);
            break;

        case 's':
            sock_dir_set = 1;
            parse_long_opts(SOCK_DIR_OPT_INDEX, optarg);
            break;

        case 0:
            parse_long_opts(option_index, optarg);
            break;

        case 'h':
        default:
            Usage();
        }
    }
    validate_options();

    cl = vr_get_nl_client(VR_NETLINK_PROTO_DEFAULT);
    if (!cl) {
        return -1;
    }

    vr_get_vrinfo(cl);

    return 0;
}
