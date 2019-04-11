/*
 * dropstats.c - drop statistics
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
static int help_set, core_set, offload_set, log_set, clear_set;
static unsigned int core = (unsigned)-1;
static unsigned int stats_index = 0;
static int vr_get_pkt_drop_log(struct nl_client *cl,int core,int stats_index);

static void pkt_drop_log_req_process(void *s_req) {

    static int log_all_cores = 0, last_buffer_stats = 0, last_buffer_entry = 0;
    vr_pkt_drop_log_req *stats = (vr_pkt_drop_log_req *)s_req;

    /* Below check ensures that pkt drop log sysctl enabled during runtime*/
    if(stats->vdl_pkt_droplog_sysctl_en == 1)
    {
        /* Below check ensures that drop stats support is enabled at load time*/
        if(stats->vdl_pkt_droplog_en == 1)
        {
            /* Print the drop stats log*/
            vr_print_pkt_drop_log(stats);

            /* Since sandesh message doesn't support passing data more than 4KB,
             * So the message request sent in serial manner.
             * If the configured size  more than VR_PKT_DROPLOG_MAX_ALLOW_BUFSZ,
             * then index is maintained at utils side
             * and request data based on index
             * */
            if(stats->vdl_pkt_droplog_max_bufsz > VR_PKT_DROPLOG_MAX_ALLOW_BUFSZ)
            {
                /* If stats->index reached MAX size, it will not be processed.
                 * stats->vdl_log_idx is used for printing serial numbers on
                 * the console */
                if(stats->vdl_log_idx < (stats->vdl_pkt_droplog_max_bufsz -
                            VR_PKT_DROPLOG_MAX_ALLOW_BUFSZ))
                {
                    /* Request packet drop buffer for next iteration by
                     * incrementing with MAX_ALLOWED_BUFFER  */
                    stats_index  = stats->vdl_log_idx +
                        VR_PKT_DROPLOG_MAX_ALLOW_BUFSZ;
                    vr_get_pkt_drop_log(cl, stats->vdl_core, stats_index);
                }
                /* Below condition will process last iteration buffer,
                 * If modulus is non-zero */
                else if( stats->vdl_pkt_droplog_max_bufsz %
                        VR_PKT_DROPLOG_MAX_ALLOW_BUFSZ != 0)
                {
                    /* Below condition to be processed only once per core */
                    if( ! last_buffer_entry)
                    {
                        stats_index  = stats->vdl_log_idx +
                            VR_PKT_DROPLOG_MAX_ALLOW_BUFSZ;
                        last_buffer_entry = 1;
                        vr_get_pkt_drop_log(cl, stats->vdl_core, stats_index);
                    }
                    else
                    {
                        /* Resetting index and last buffer entry because all
                         * processing done for this particular core*/
                        last_buffer_entry = 0;
                        stats_index = 0;
                    }
                }
                else
                    stats_index = 0;
            }
            /* When packet drop log is requested for all cores, below
             * condition would be enabled*/
            if(stats->vdl_core ==0 || log_all_cores == 1)
            {
                /* Increment the core value*/
                core++;

                if(core < stats->vdl_max_num_cores){
                    log_all_cores = 1;
                    vr_get_pkt_drop_log(cl,core+1,stats_index);
                }
                else
                {
                    log_all_cores = 0;
                }

            }
        }
        else
        {
            printf("\n\nPkt drop stats log support is not enabled or misconfigured \
                    in vrouter module parameters. Configured value is %d\n",
                    stats->vdl_pkt_droplog_en);
            printf("You can enable by providing \"options vrouter \
                    vr_pkt_droplog_buf_en=1\" in /etc/modprobe.d/vrouter.conf\n");
        }
    }
    else
    {
        printf("\n\nPacket Drop Log sysctl is not enabled or misconfigured, \
                Configured value is %d\n",stats->vdl_pkt_droplog_sysctl_en);
        printf("You can enable it by passing \"echo 1 > \
                /proc/sys/net/vrouter/pkt_drop_log_enable\"\n");
    }
    return;
}

static void
dropstats_log_nlutils_callbacks()
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
vr_get_drop_stats(struct nl_client *cl)
{
    int ret;

    /*
     * Implementation of getting per-core drop statistics is based on this
     * little trick to avoid making changes in how agent makes requests for
     * statistics. From vRouter's and agent's point of view, request for
     * stats for 0th core means a request for stats summed up for all the
     * cores. So cores are enumerated starting with 1.
     * Meanwhile, from user's point of view they are enumerated starting
     * with 0 (e.g. dropstats --core 0 means 'drop statistics for the very
     * first (0th) core'). This is how Linux enumerates CPUs, so it should
     * be more intuitive for the user.
     *
     * Agent is not aware of possibility of asking for per-core stats. Its
     * requests have vds_core implicitly set to 0. So we need to make a
     * conversion between those enumerating systems. The dropstats utility
     * increments by 1 the core number user asked for. Then it is
     * decremented back in vRouter.
     *
     * vRouter will return only the offloaded dropstats if the "core"
     * is passed in as -2.  This allows returning of only dropstats offloaded
     * on NIC using this same mechanism.  If all CPUs are requested, the
     * offloaded dropstats are included.
     */
    ret = vr_send_drop_stats_get(cl, 0, core + 1);
    if (ret < 0)
        return ret;

    ret = vr_recvmsg(cl, false);
    if (ret <= 0)
        return ret;

    return 0;
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
    MAX_OPT_INDEX,
};

static struct option long_options[] = {
    [HELP_OPT_INDEX]    =   {"help",    no_argument,        &help_set,      1},
    [CORE_OPT_INDEX]    =   {"core",    required_argument,  &core_set,      1},
    [OFFL_OPT_INDEX]    =   {"offload", no_argument,        &offload_set,   1},
    [LOG_OPT_INDEX]     =   {"log",     required_argument,  &log_set,       1},
    [CLEAR_OPT_INDEX]   =   {"clear",   no_argument,        &clear_set,     1},
    [MAX_OPT_INDEX]     =   {"NULL",    0,                  0,              0},
};

static void
Usage()
{
    printf("Usage: dropstats [--help]\n");
    printf("Usage: dropstats [--core|-c] <core number> %s\n\n",
            get_offload_enabled()?"[--offload|-o]":"");
    printf("--core <core number>\t Show statistics for a specified CPU core\n");
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
    case HELP_OPT_INDEX:
    default:
        Usage();
    }

    return;
}

int
main(int argc, char *argv[])
{
    char opt;
    int ret, option_index, log_core = 0, i = 0;

    dropstats_fill_nl_callbacks();

    parse_ini_file();

    while (((opt = getopt_long(argc, argv, "h:c:o:l:",
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

            log_core = atoi(argv[2]);

            /* Register nl allback function for dropstats log buffer*/
            dropstats_log_nlutils_callbacks();

            /* Register with nlclient(socket message) for dropstats log buffer*/
            cl = vr_get_nl_client(VR_NETLINK_PROTO_DEFAULT);
            if(!cl)
                return -1;

            vr_get_pkt_drop_log(cl,log_core,stats_index);
            return 0;

        case 0:
            parse_long_opts(option_index, optarg);
            break;

        case 'h':
        default:
            Usage();
        }
    }

    cl = vr_get_nl_client(VR_NETLINK_PROTO_DEFAULT);
    if (!cl)
        return -1;

    if (option_index == CLEAR_OPT_INDEX)
    {
        vr_clear_drop_stats(cl);

        ret = vr_recvmsg(cl, false);
        if (ret <= 0)
            return ret;
    }
    else
        vr_get_drop_stats(cl);

    return 0;
}
