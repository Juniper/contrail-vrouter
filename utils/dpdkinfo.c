/*
 * dpdkutils.c - Utilities of DPDK like get Mempool info, bond members info etc.
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
//#include "vr_dpdk.h"

static struct nl_client *cl;
static int help_set, core_set, offload_set, log_set, clear_set, sock_dir_set;
static unsigned int core = (unsigned)-1;
static unsigned int stats_index = 0;

static void
dpdkutils_req_process(void *s_req)
{
    int ret = 0;
    int platform = get_platform();
    printf("Response called \n");
    vr_util_info_req *resp = (vr_util_info_req *)s_req;
    if(resp != NULL && resp->vdu_proc_info) {
        printf("%s", resp->vdu_proc_info);
    
    }

}

static void
dpdkutils_fill_nl_callbacks()
{
    nl_cb.vr_util_info_req_process = dpdkutils_req_process; 
}
#if 0
pkt_drop_log_nlutils_callbacks()
{
    /* Registering callback for packet drop log in netlink process*/
    nl_cb.vr_pkt_drop_log_req_process = pkt_drop_log_req_process;
}
static int vr_get_pkt_drop_log(struct nl_client *cl,int core,int stats_index) {
    int ret = 0;

    vr_pkt_drop_log_request(cl, 0, core, stats_index);
    if(ret < 0)
        return ret;

    ret = vr_recvmsg(cl, false);
    if(ret <= 0)
        return ret;

    return 0;
}

static void
drop_stats_req_process(void *s_req)
{
    vr_drop_stats_req *stats = (vr_drop_stats_req *)s_req;
    int platform = get_platform();

    if(stats->h_op == SANDESH_OP_RESET)
    {
        printf("\nDropstats counters cleared successfully on all cores \n\n");
        return;
    }

    if (core == (unsigned)-2)
        printf("Statistics for NIC offloads\n\n");
    else if (core != (unsigned)-1)
        printf("Statistics for core %u\n\n", core);

    vr_print_drop_stats(stats, core);
    return;
}

static void
dropstats_fill_nl_callbacks()
{
    nl_cb.vr_drop_stats_req_process = drop_stats_req_process;
}


static int
vr_clear_drop_stats(struct nl_client *cl)
{
    int ret = vr_drop_stats_reset(cl);
    if (ret < 0)
        return ret;

    return 0;
}

enum opt_index {
    HELP_OPT_INDEX,
    CORE_OPT_INDEX,
    OFFL_OPT_INDEX,
    LOG_OPT_INDEX,
    CLEAR_OPT_INDEX,
    SOCK_DIR_OPT_INDEX,
    MAX_OPT_INDEX,
};

static struct option long_options[] = {
    [HELP_OPT_INDEX]    =   {"help",    no_argument,        &help_set,      1},
    [CORE_OPT_INDEX]    =   {"core",    required_argument,  &core_set,      1},
    [OFFL_OPT_INDEX]    =   {"offload", no_argument,        &offload_set,   1},
    [LOG_OPT_INDEX]     =   {"log",     required_argument,  &log_set,       1},
    [CLEAR_OPT_INDEX]   =   {"clear",   no_argument,        &clear_set,     1},
    [SOCK_DIR_OPT_INDEX]  = {"sock-dir", required_argument, &sock_dir_set,  1},
    [MAX_OPT_INDEX]     =   {"NULL",    0,                  0,              0},
};

static void
Usage()
{
    printf("Usage: dropstats [--help]\n");
    printf("Usage: dropstats [--core|-c] <core number> %s\n\n",
            get_offload_enabled()?"[--offload|-o]":"");
    printf("--core <core number>\t Show statistics for a specified CPU core\n");
    printf("--sock-dir <netlink socket dir>\n");
    if (get_offload_enabled()) {
        printf("--offload\t\t Show statistics for pkts offloaded on NIC\n");
        printf("\t\t\t (offload stats included if no flags given)\n");
    }
    printf("--log <core number>\t Show Packet drops log for a specified core.. \
		Core number starts from 1...n. If core number specified as zero, \
		it will log for all cores \n");
    printf("--clear\t To clear stats counters on all cores\n");
    exit(-EINVAL);
}

static void
parse_long_opts(int opt_index, char *opt_arg)
{
    errno = 0;

    switch (opt_index) {
    case CORE_OPT_INDEX:
        core = (unsigned)strtol(opt_arg, NULL, 0);
        if (errno) {
            printf("Error parsing core %s: %s (%d)\n", opt_arg,
                    strerror(errno), errno);
            Usage();
        }
        break;
    case OFFL_OPT_INDEX:
        if (!get_offload_enabled()) {
            printf("Error: hardware offloads not enabled\n");
            Usage();
        }
        core = -2;
        break;
    case LOG_OPT_INDEX:
	core = (unsigned)strtol(opt_arg, NULL, 0);
	if (errno) {
		printf("Error parsing log %s: %s (%d)\n", opt_arg,
			strerror(errno), errno);
		Usage();
	}
	break;
    case CLEAR_OPT_INDEX:
        break;
    case SOCK_DIR_OPT_INDEX:
        vr_socket_dir = opt_arg;
        break;
    case HELP_OPT_INDEX:
    default:
        Usage();
    }

    return;
}
#endif

static int
vr_get_dpdkutils(struct nl_client *cl)
{
    int ret;
    ret = vr_send_dpdkutils_get(cl, 0);
    if (ret < 0)
        return ret;

    ret = vr_recvmsg(cl, false);
    if (ret <= 0)
        return ret;

    return 0;
}

int
main(int argc, char *argv[])
{
    char opt;
    int ret, option_index, log_core = 0, i = 0;

    dpdkutils_fill_nl_callbacks();

   // parse_ini_file();
/*
    while (((opt = getopt_long(argc, argv, "h:c:o:l:s:",
                        long_options, &option_index)) >= 0)) {
        switch (opt) {
        case 'c':
            core_set = 1;
            parse_long_opts(CORE_OPT_INDEX, optarg);
            break;

        case 'o':
            offload_set = 1;
            parse_long_opts(OFFL_OPT_INDEX, optarg);
            break;

        case 'l':
            log_set = 1;
            parse_long_opts(LOG_OPT_INDEX, optarg);
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
*/
#if 0
    if (sock_dir_set) {
        set_platform_vtest();
    }
    if (!cl)
        return -1;
    
    if ((option_index == LOG_OPT_INDEX) || (log_set == 1))
    {
        log_core = atoi(argv[2]);

        /* Register nl allback function for pkt drop log buffer*/
        pkt_drop_log_nlutils_callbacks();

        vr_get_pkt_drop_log(cl,log_core,stats_index);
        return 0;
    }

    if (option_index == CLEAR_OPT_INDEX)
    {
        vr_clear_drop_stats(cl);

        ret = vr_recvmsg(cl, false);
        if (ret <= 0)
            return ret;
    }
    else
        vr_get_drop_stats(cl);
#endif
    cl = vr_get_nl_client(VR_NETLINK_PROTO_DEFAULT);
    vr_get_dpdkutils(cl);

    return 0;
}
