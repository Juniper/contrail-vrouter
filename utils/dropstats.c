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
static int help_set, core_set, log_set;
static unsigned int core = (unsigned)-1;
static unsigned int stats_index = 0;
static int vr_get_drop_stats_log(struct nl_client *cl,int core,int stats_index);

static void
drop_stats_req_process(void *s_req)
{
    vr_drop_stats_req *stats = (vr_drop_stats_req *)s_req;

    vr_print_drop_stats(stats, core);


    return;
}
#if (VR_DROP_STATS_LOG_BUFFER_INFRA ==STD_ON)
static void drop_stats_log_req_process(void *s_req) {
    
    static int log_all_cores = 0,last_buffer_stats=0,last_buffer_entry=0;
    vr_drop_stats_log_req *stats = (vr_drop_stats_log_req *)s_req;

    /* Below check ensures that drop stats support is enabled at load time*/
    if(stats->vds_drop_stats_support == 1)
    {
        /* Print the drop stats log*/
        vr_print_drop_stats_log(stats);
        
        /* Since sandesh message doesn't support passing data more than 4KB, So the message request sent in serial manner
         * If the configured size is more than VR_DROP_STATS_MAX_ALLOWED_BUFFER_SIZE, then index is maintained at utils side 
         * and request data based on index
         * */
        if(stats->vds_drop_stats_max_log_buffer_size > VR_DROP_STATS_MAX_ALLOWED_BUFFER_SIZE)
        {
            /* If stats->index reached MAX size, it will not be processed.
             * stats->vds_stats_index is used for printing serial numbers on the console */

            if(stats->vds_stats_index < (stats->vds_drop_stats_max_log_buffer_size - VR_DROP_STATS_MAX_ALLOWED_BUFFER_SIZE))
            {
                /* stats_index variable sent */
                stats_index  = stats->vds_stats_index + VR_DROP_STATS_MAX_ALLOWED_BUFFER_SIZE;
                vr_get_drop_stats_log(cl,stats->vds_core,stats_index);
            }
            else if( stats->vds_drop_stats_max_log_buffer_size % VR_DROP_STATS_MAX_ALLOWED_BUFFER_SIZE != 0)
            {
                if( ! last_buffer_entry)
                {
                    stats_index  = stats->vds_stats_index + VR_DROP_STATS_MAX_ALLOWED_BUFFER_SIZE;
                    last_buffer_entry = 1;
                    vr_get_drop_stats_log(cl,stats->vds_core,stats_index);
                }
                else
                {
                    last_buffer_entry = 0;
                    stats_index = 0;
                }
            }
            else
                stats_index = 0;
        }

        if(stats->vds_core ==0 || log_all_cores == 1)
        {
            core++;
            if(core < stats->vds_max_num_cores){
                log_all_cores = 1;
                vr_get_drop_stats_log(cl,core+1,stats_index);
            }
            else
            {
                log_all_cores = 0;
            }

        }
    }
    else
    {
        printf("\n\nDrop stats log support is not enabled or misconfigured. Configured value is %d\n",stats->vds_drop_stats_support);
        printf("You can enable by providing \"options vrouter vr_config_drop_stats_log_buffer_enable=1\" in /etc/modprobe.d/vrouter.conf\n");
    }
    return;
}

static void
dropstats_log_nlutils_callbacks()
{
    nl_cb.vr_drop_stats_log_req_process = drop_stats_log_req_process;
}

static int vr_get_drop_stats_log(struct nl_client *cl,int core,int stats_index) {
    int ret;

    vr_drop_stats_log_request(cl, 0, core, stats_index);
    if(ret <0)
        return ret;

    ret = vr_recvmsg(cl, false);
    if(ret <= 0)
        return ret;

    return 0;
}
#endif

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
     */
    ret = vr_send_drop_stats_get(cl, 0, core + 1);
    if (ret < 0)
        return ret;

    ret = vr_recvmsg(cl, false);
    if (ret <= 0)
        return ret;

    return 0;
}

enum opt_index {
    HELP_OPT_INDEX,
    CORE_OPT_INDEX,
#if (VR_DROP_STATS_LOG_BUFFER_INFRA ==STD_ON)
    LOG_OPT_INDEX,
#endif
    MAX_OPT_INDEX,
};

static struct option long_options[] = {
    [HELP_OPT_INDEX]    =   {"help",    no_argument,        &help_set,      1},
    [CORE_OPT_INDEX]    =   {"core",    required_argument,  &core_set,      1},
#if (VR_DROP_STATS_LOG_BUFFER_INFRA ==STD_ON)
    [LOG_OPT_INDEX]     =   {"log",     required_argument,  &log_set,       1},
#endif
    [MAX_OPT_INDEX]     =   {NULL,    0,                  0,              0},
};

static void
Usage()
{
    printf("Usage: dropstats [--help]\n");
    printf("Usage: dropstats [--core|-c] <core number>\n\n");
    printf("--core <core number>\t Show statistics for a specified CPU core\n");
#if (VR_DROP_STATS_LOG_BUFFER_INFRA ==STD_ON)
    printf("--log <core number>\t Show Packet drops log for a specified core.. Core number starts from 1...n. If core number specified as zero, it will log for all cores \n");
#endif
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
#if (VR_DROP_STATS_LOG_BUFFER_INFRA ==STD_ON)
    case LOG_OPT_INDEX:
        core = (unsigned)strtol(opt_arg, NULL, 0);
        if (errno) {
            printf("Error parsing log %s: %s (%d)\n", opt_arg,
                    strerror(errno), errno);
            Usage();
        }
        break;
#endif

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
    int ret, option_index,log_core=0,i=0;

    dropstats_fill_nl_callbacks();
    
    while (((opt = getopt_long(argc, argv, "h:c:l:",
                        long_options, &option_index)) >= 0)) {
      
        switch (opt) {
        
            case 'c':
                core_set = 1;
                parse_long_opts(CORE_OPT_INDEX, optarg);
                break;
#if (VR_DROP_STATS_LOG_BUFFER_INFRA ==STD_ON)
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
               
                vr_get_drop_stats_log(cl,log_core,stats_index);
                return 0;
#endif
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

    vr_get_drop_stats(cl);

    return 0;
}
