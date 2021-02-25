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

static int help_set,ver_set, bond_set, lacp_set, mempool_set, stats_set,
    xstats_set, lcore_set, app_set,sock_dir_set;
static unsigned int core = (unsigned)-1;
static unsigned int stats_index = 0;
/* For few  CLI, Inbuf has to send to vrouter for processing(i.e kind of filter
*/
static uint8_t *vr_info_inbuf;

static vr_info_msg_en msginfo;

enum opt_index {
    HELP_OPT_INDEX,
    VER_OPT_INDEX,
    BOND_OPT_INDEX,
    LACP_OPT_INDEX,
    MEMPOOL_OPT_INDEX,
    STATS_OPT_INDEX,
    XSTATS_OPT_INDEX,
    BUFFSZ_OPT_INDEX,
    LCORE_OPT_INDEX,
    APP_OPT_INDEX,
    SOCK_DIR_OPT_INDEX,
    MAX_OPT_INDEX,
};

static struct option long_options[] = {
    [HELP_OPT_INDEX]    =   {"help",    no_argument,        &help_set,      1},
    [VER_OPT_INDEX]    =   {"version",    no_argument,        &ver_set,      1},
    [BOND_OPT_INDEX]    =   {"bond",    no_argument,        &bond_set,      1},
    [LACP_OPT_INDEX]    =   {"lacp",    required_argument,        &lacp_set,      1},
    [MEMPOOL_OPT_INDEX] =   {"mempool", required_argument,        &mempool_set,      1},
    [STATS_OPT_INDEX]    =   {"stats",    required_argument,        &stats_set,      1},
    [XSTATS_OPT_INDEX]    =   {"xstats",  optional_argument,        &xstats_set,      1},
    [LCORE_OPT_INDEX]    =   {"lcore",    no_argument,        &lcore_set,      1},
    [APP_OPT_INDEX]    =   {"app",    no_argument,        &app_set,      1},
    [BUFFSZ_OPT_INDEX]  =   {"buffsz",  required_argument,  &buffsz,        1},
    [SOCK_DIR_OPT_INDEX]  = {"sock-dir", required_argument, &sock_dir_set,  1},
    [MAX_OPT_INDEX]     =   {"NULL",    0,                  0,              0},
};

static void
Usage()
{
    printf("Usage: dpdkinfo [--help]\n");
    printf("                 --version|-v\
                                                      Show DPDK Version\n");
    printf("                 --bond|-b                        Show Master/Slave bond information\n");
    printf("                 --lacp|-l <conf/status/stat/all> Show LACP information from DPDK\n");
    printf("                 --mempool|-m  <all/<mempool-name>>\
                                Show Mempool information\n");
    printf("                 --stats|-n    <eth>\
                                               Show Stats information\n");
    printf("                 --xstats|-x   < =all/ =0(Master)/ =1(Slave(0))/ =2(Slave(1))>\
                                               Show Extended Stats information\n");
    printf("                 --lcore|-c\
                                                        Show Lcore information\n");
    printf("                 --app|-a\
                                                          Show App information\n");
    printf("       Optional: --buffsz  <value>                Send output buffer size\n");
    exit(-EINVAL);
}

static void
validate_options(void)
{
    if(!(ver_set || bond_set || lacp_set|| mempool_set ||
        stats_set || xstats_set || lcore_set || app_set)) {
        Usage();
    }

    return;
}

/*
 * Response messages are sent through character buffer via Sandesh and it has
 * a limitation of sending upto 4K(PAGE_SIZE) for each iteration.
 * */
static void
dpdkinfo_resp_cb_process(void *s_req)
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
dpdkinfo_fill_nl_callbacks()
{
    nl_cb.vr_info_req_process = dpdkinfo_resp_cb_process;
    nl_cb.vr_response_process = response_process;
}

static void
parse_long_opts(int opt_index, char *opt_arg)
{
    errno = 0;

    switch (opt_index) {
	    case VER_OPT_INDEX:
                msginfo = INFO_VER_DPDK;
                vr_info_inbuf = opt_arg;
                break;
            case BOND_OPT_INDEX:
                msginfo = INFO_BOND;
                break;
            case LACP_OPT_INDEX:
                msginfo = INFO_LACP;
                vr_info_inbuf = opt_arg;
                break;
            case MEMPOOL_OPT_INDEX:
                msginfo = INFO_MEMPOOL;
                vr_info_inbuf = opt_arg;
                break;
            case STATS_OPT_INDEX:
                msginfo = INFO_STATS;
                vr_info_inbuf = opt_arg;
                break;
            case XSTATS_OPT_INDEX:
                msginfo = INFO_XSTATS;
                vr_info_inbuf = opt_arg;
                break;
            case LCORE_OPT_INDEX:
                msginfo = INFO_LCORE;
                vr_info_inbuf = opt_arg;
                break;
            case APP_OPT_INDEX:
                msginfo = INFO_APP;
                vr_info_inbuf = opt_arg;
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
vr_get_dpdkinfo(struct nl_client *cl)
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
    int platform = 0;

    /* Register callback function for Netlink message */
    dpdkinfo_fill_nl_callbacks();

    parse_ini_file();

    while (((opt = getopt_long(argc, argv, "h:v:b:l:m:s:n:x:c:a:",
                        long_options, &option_index)) >= 0)) {
        switch (opt) {
        case 'v':
            ver_set = 1;
            msginfo = INFO_VER_DPDK;
            parse_long_opts(VER_OPT_INDEX, optarg);
            break;
        case 'b':
            bond_set = 1;
            msginfo = INFO_BOND;
            parse_long_opts(BOND_OPT_INDEX, optarg);
            break;

        case 'l':
            lacp_set = 1;
            msginfo = INFO_LACP;
            parse_long_opts(LACP_OPT_INDEX, optarg);
            break;
        case 'm':
            mempool_set = 1;
            msginfo = INFO_MEMPOOL;
            parse_long_opts(MEMPOOL_OPT_INDEX, optarg);
            break;

        case 'n':
            stats_set = 1;
            msginfo = INFO_STATS;
            parse_long_opts(STATS_OPT_INDEX, optarg);
            break;

        case 'x':
            xstats_set = 1;
            msginfo = INFO_XSTATS;
            parse_long_opts(XSTATS_OPT_INDEX, optarg);
            break;

        case 'c':
            lcore_set = 1;
            msginfo = INFO_LCORE;
            parse_long_opts(LCORE_OPT_INDEX, optarg);
            break;

        case 's':
            sock_dir_set = 1;
            parse_long_opts(SOCK_DIR_OPT_INDEX, optarg);
            break;
        
	case 'a':
            app_set = 1;
            msginfo = INFO_APP;
            parse_long_opts(APP_OPT_INDEX, optarg);
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

    platform = get_platform();
    if (platform != DPDK_PLATFORM) {
        Usage();
    }
    cl = vr_get_nl_client(VR_NETLINK_PROTO_DEFAULT);
    if (!cl) {
        return -1;
    }

    vr_get_dpdkinfo(cl);

    return 0;
}

