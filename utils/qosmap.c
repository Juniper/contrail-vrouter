/*
 * qosmap.c -- utility to set and get qos mappings
 *
 * Copyright (c) 2016, Juniper Networks, Inc.
 * All rights reserved
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdbool.h>

#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/mman.h>
#if defined(__linux__)
#include <asm/types.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_ether.h>
#endif

#include <net/if.h>
#if defined(__linux__)
#include <netinet/ether.h>
#endif

#include "vr_types.h"
#include "vr_qos.h"
#include "vr_flow.h"
#include "vr_mirror.h"
#include "vr_genetlink.h"
#include "nl_util.h"
#include "vr_os.h"
#include "ini_parser.h"
#include "vr_packet.h"

static bool dump_pending = false;
static int marker = -1;

unsigned int help_set, dump_fc_set, dump_qos_set;
unsigned int get_fc_set, set_fc_set, fc_set;
unsigned int get_qos_set, set_qos_set, delete_qos_set;
unsigned int dscp_set, mpls_qos_set, dotonep_set, queue_set;

uint8_t dotonep, dscp, mpls_qos, fc, queue;
unsigned int qos_index;

struct nl_client *cl;

void
vr_fc_map_req_process(void *s)
{
    unsigned int i;
    vr_fc_map_req *req = (vr_fc_map_req *)s;

    if (marker == -1) {
        printf("Forwarding Class Map %d\n", req->fmr_rid);
        printf(" FC            DSCP  EXP  .1p    Queue\n");
    }

    for (i = 0; i < req->fmr_id_size; i++) {
        printf("%3u        %8u  %3u  %3u %8u\n",
                req->fmr_id[i], req->fmr_dscp[i], req->fmr_mpls_qos[i],
                req->fmr_dotonep[i], req->fmr_queue_id[i]);
    }

    if (i > 0) {
        marker = (unsigned int)(req->fmr_id[i - 1]);
    }

    return;
}

void
vr_qos_map_req_process(void *s)
{
    unsigned int i;
    vr_qos_map_req *req = (vr_qos_map_req *)s;

    printf("QOS Map %d/%d\n", req->qmr_rid, req->qmr_id);
    if (req->qmr_dscp_size) {
        printf("    DSCP              FC\n");
        for (i = 0; i < req->qmr_dscp_size; i++) {
            if (req->qmr_dscp_fc_id[i])
                printf("%8u        %8u\n", req->qmr_dscp[i],
                        req->qmr_dscp_fc_id[i]);
        }
        printf("\n");
    }

    if (req->qmr_mpls_qos_size) {
        printf("     EXP              FC\n");
        for (i = 0; i < req->qmr_mpls_qos_size; i++) {
            if (req->qmr_mpls_qos_fc_id[i])
                printf("%8u        %8u\n", req->qmr_mpls_qos[i],
                        req->qmr_mpls_qos_fc_id[i]);
        }
        printf("\n");
    }

    if (req->qmr_dotonep_size) {
        printf(" DOTONEP              FC\n");
        for (i = 0; i < req->qmr_dotonep_size; i++) {
            if (req->qmr_dotonep_fc_id[i])
                printf("%8u        %8u\n", req->qmr_dotonep[i],
                        req->qmr_dotonep_fc_id[i]);
        }
        printf("\n");
    }

    printf("\n");
    marker = req->qmr_id;
    return;
}

void
vr_response_process(void *s)
{
    vr_response_common_process((vr_response *)s, &dump_pending);
    return;
}

static int
qos_map_op(void)
{
    int ret;
    unsigned int num_dscp, num_mpls_qos, num_dotonep;
    bool dump = false;

op_retry:
    num_dscp = num_mpls_qos = num_dotonep = 0;

    if (get_fc_set) {
        ret = vr_send_fc_map_get(cl, 0, qos_index);
    } else if (set_fc_set) {
        ret = vr_send_fc_map_add(cl, 0, (int16_t *)&qos_index, 1,
                &dscp, &mpls_qos, &dotonep, &queue);
    } else if (dump_fc_set) {
        dump = true;
        ret = vr_send_fc_map_dump(cl, 0, marker);
    } else if (get_qos_set) {
        ret = vr_send_qos_map_get(cl, 0, qos_index);
    } else if (set_qos_set) {
        if (dscp_set)
            num_dscp = 1;
        if (mpls_qos_set)
            num_mpls_qos = 1;
        if (dotonep_set)
            num_dotonep = 1;

        ret = vr_send_qos_map_add(cl, 0, qos_index,
                &dscp, num_dscp, &fc,
                &mpls_qos, num_mpls_qos, &fc,
                &dotonep, num_dotonep, &fc);
    } else if (dump_qos_set) {
        ret = vr_send_qos_map_dump(cl, 0, marker);
        dump = true;
    } else if (delete_qos_set) {
        ret = vr_send_qos_map_delete(cl, 0, qos_index);
    } else {
        ret = -EINVAL;
    }


    if (ret < 0)
        return ret;

    ret = vr_recvmsg(cl, dump);
    if (ret <= 0)
        return ret;

    if (dump_pending)
        goto op_retry;

    return ret;
}

enum opt_qos_index {
    DELETE_QOS_MAP_OPT_INDEX,
    DUMP_FC_OPT_INDEX,
    DUMP_QOS_MAP_OPT_INDEX,
    DOTONEP_OPT_INDEX,
    DSCP_OPT_INDEX,
    MPLS_QOS_OPT_INDEX,
    FC_OPT_INDEX,
    GET_FC_OPT_INDEX,
    GET_QOS_MAP_OPT_INDEX,
    QUEUE_ID_OPT_INDEX,
    SET_FC_OPT_INDEX,
    SET_QOS_MAP_OPT_INDEX,
    HELP_OPT_INDEX,
    MAX_OPT_INDEX
};

static struct option long_options[] = {
    [DELETE_QOS_MAP_OPT_INDEX]  = {"delete-qos",    required_argument,  &delete_qos_set,    1},
    [DUMP_FC_OPT_INDEX]         = {"dump-fc",       no_argument,        &dump_fc_set,       1},
    [DUMP_QOS_MAP_OPT_INDEX]    = {"dump-qos",      no_argument,        &dump_qos_set,      1},
    [DOTONEP_OPT_INDEX]         = {"dotonep",       required_argument,  &dotonep_set,       1},
    [DSCP_OPT_INDEX]            = {"dscp",          required_argument,  &dscp_set,          1},
    [MPLS_QOS_OPT_INDEX]        = {"mpls_qos",      required_argument,  &mpls_qos_set,      1},
    [FC_OPT_INDEX]              = {"fc",            required_argument,  &fc_set,            1},
    [GET_FC_OPT_INDEX]          = {"get-fc",        required_argument,  &get_fc_set,        1},
    [GET_QOS_MAP_OPT_INDEX]     = {"get-qos",       required_argument,  &get_qos_set,       1},
    [QUEUE_ID_OPT_INDEX]        = {"queue",         required_argument,  &queue_set,         1},
    [SET_FC_OPT_INDEX]          = {"set-fc",        required_argument,  &set_fc_set,        1},
    [SET_QOS_MAP_OPT_INDEX]     = {"set-qos",       required_argument,  &set_qos_set,       1},
    [HELP_OPT_INDEX]            = {"help",          no_argument,        &help_set,          1},
    [MAX_OPT_INDEX]             = { NULL,           0,                  0,                  0}
};


static void
Usage(void)
{
    printf("qosmap --get-fc <fc-id>\n");
    printf("       --set-fc <fc-id> <--dscp | --mpls_qos | --dotonep | --queue> <value>\n");
    printf("       --get-qos <index>\n");
    printf("       --set-qos <index> <--dscp | --mpls_qos | --dotonep> <value> --fc <fc-id>\n");
    printf("       --dump-fc\n");
    printf("       --dump-qos\n");
    printf("       --delete-qos <index>\n");

    exit(EINVAL);

    return;
}

static void
validate_options(void)
{
    unsigned int set = dotonep_set + mpls_qos_set + dscp_set + queue_set;
    unsigned int op_set = get_fc_set + get_qos_set + set_fc_set +
        set_qos_set + dump_fc_set + dump_qos_set + delete_qos_set;

    if (op_set != 1) {
        goto exit_options;
    }

    if (get_fc_set) {
        if (fc_set || set) {
            printf("Invalid arguments for --get-fc\n");
            goto exit_options;
        }
    } else if (get_qos_set) {
        if (fc_set || set) {
            printf("Invalid arguments to --get-qos\n");
            goto exit_options;
        }
    } else if (set_fc_set) {
        if (fc_set || (set != 4)) {
            printf("Invalid options to --set-fc\n");
            goto exit_options;
        }
    } else if (set_qos_set) {
        if (set != 1 || !fc_set) {
            printf("Invalid options to --set-qos\n");
            goto exit_options;
        }
    } else if (dump_fc_set || dump_qos_set || delete_qos_set) {
        if (set) {
            printf("Invalid options\n");
            goto exit_options;
        }
    }

    return;

exit_options:
    Usage();
    return;
}

static void
parse_long_opts(int opt_index, char *opt_arg)
{
    errno = 0;

    switch (opt_index) {
    case DOTONEP_OPT_INDEX:
        dotonep = strtoul(opt_arg, NULL, 0);
        break;

    case DSCP_OPT_INDEX:
        dscp = strtoul(opt_arg, NULL, 0);
        break;

    case DUMP_FC_OPT_INDEX:
    case DUMP_QOS_MAP_OPT_INDEX:
        break;

    case MPLS_QOS_OPT_INDEX:
        mpls_qos = strtoul(opt_arg, NULL, 0);
        break;

    case FC_OPT_INDEX:
        fc = strtoul(opt_arg, NULL, 0);
        break;

    case QUEUE_ID_OPT_INDEX:
        queue = strtoul(opt_arg, NULL, 0);
        break;

    case GET_QOS_MAP_OPT_INDEX:
    case GET_FC_OPT_INDEX:
    case SET_FC_OPT_INDEX:
    case SET_QOS_MAP_OPT_INDEX:
    case DELETE_QOS_MAP_OPT_INDEX:
        qos_index = strtoul(opt_arg, NULL, 0);
        break;

    case HELP_OPT_INDEX:
    default:
        Usage();
        break;
    }

    if (errno) {
        perror("parse_long_opts");
        Usage();
    }

    return;
}


int
main(int argc, char *argv[])
{
    char opt;
    int ret, option_index;

    while ((opt = getopt_long(argc, argv, "", long_options,
                    &option_index)) >= 0) {
        switch (opt) {
        case 0:
            parse_long_opts(option_index, optarg);
            break;

        default:
            Usage();
        }
    }

    validate_options();

    cl = vr_get_nl_client(VR_NETLINK_PROTO_DEFAULT);
    if (!cl)
        exit(1);

    ret = qos_map_op();
    if (ret) {
        return ret;
    }

    return 0;
}
