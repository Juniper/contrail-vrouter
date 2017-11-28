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

static struct nl_client *cl;
static int help_set, core_set;
static unsigned int core = (unsigned)-1;

static void
drop_stats_req_process(void *s_req)
{
    vr_drop_stats_req *stats = (vr_drop_stats_req *)s_req;

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
    MAX_OPT_INDEX,
};

static struct option long_options[] = {
    [HELP_OPT_INDEX]    =   {"help",    no_argument,        &help_set,      1},
    [CORE_OPT_INDEX]    =   {"core",    required_argument,  &core_set,      1},
    [MAX_OPT_INDEX]     =   {NULL,    0,                  0,              0},
};

static void
Usage()
{
    printf("Usage: dropstats [--help]\n");
    printf("Usage: dropstats [--core|-c] <core number>\n\n");
    printf("--core <core number>\t Show statistics for a specified CPU core\n");
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
    int ret, option_index;

    dropstats_fill_nl_callbacks();

    while (((opt = getopt_long(argc, argv, "h:c:",
                        long_options, &option_index)) >= 0)) {
        switch (opt) {
        case 'c':
            core_set = 1;
            parse_long_opts(CORE_OPT_INDEX, optarg);
            break;

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
