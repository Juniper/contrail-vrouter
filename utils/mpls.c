/*
 *  mpls.c
 *
 *  Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <stdbool.h>

#include <sys/types.h>

#include <net/if.h>

#include "vr_types.h"
#include "vr_mpls.h"
#include "nl_util.h"
#include "vr_os.h"

static struct nl_client *cl;
static bool dump_pending = false;
static int dump_marker = -1;

static int create_set, delete_set, dump_set;
static int get_set, nh_set, label_set;
static int help_set, cmd_set;
static int mpls_label, mpls_op = -1, mpls_nh;

static void
mpls_req_process(void *s_req)
{
   vr_mpls_req *req = (vr_mpls_req *)s_req;

   printf("%8d    %6d\n", req->mr_label, req->mr_nhid);
   if (mpls_op == SANDESH_OP_DUMP)
       dump_marker = req->mr_label;

   return;
}

static void
response_process(void *s)
{
    vr_response_common_process((vr_response *)s, &dump_pending);
    return;
}

static void
mpls_fill_nl_callbacks()
{
    nl_cb.vr_response_process = response_process;
    nl_cb.vr_mpls_req_process = mpls_req_process;
}

static int
vr_mpls_op(struct nl_client *cl)
{
    int ret;
    bool dump = false;

op_retry:
    switch (mpls_op) {
    case SANDESH_OP_ADD:
        ret = vr_send_mpls_add(cl, 0, mpls_label, mpls_nh);
        break;

    case SANDESH_OP_DEL:
        ret = vr_send_mpls_delete(cl, 0, mpls_label);
        break;

    case SANDESH_OP_DUMP:
        dump = true;
        ret = vr_send_mpls_dump(cl, 0, dump_marker);
        break;

    case SANDESH_OP_GET:
        ret = vr_send_mpls_get(cl, 0, mpls_label);
        break;

    default:
        ret = -EINVAL;
        break;
    }


    if (ret < 0)
        return ret;

    ret = vr_recvmsg(cl, dump);
    if (ret <= 0)
        return ret;

    if (dump_pending)
        goto op_retry;

    return 0;
}

enum opt_mpls_index {
    COMMAND_OPT_INDEX,
    CREATE_OPT_INDEX,
    DELETE_OPT_INDEX,
    DUMP_OPT_INDEX,
    GET_OPT_INDEX,
    HELP_OPT_INDEX,
    NEXTHOP_OPT_INDEX,
    MAX_OPT_INDEX
};

static struct option long_options[] = {
    [COMMAND_OPT_INDEX]     =       {"cmd",     no_argument,        &cmd_set,       1},
    [CREATE_OPT_INDEX]      =       {"create",  required_argument,  &create_set,    1},
    [DELETE_OPT_INDEX]      =       {"delete",  required_argument,  &delete_set,    1},
    [DUMP_OPT_INDEX]        =       {"dump",    no_argument,        &dump_set,      1},
    [GET_OPT_INDEX]         =       {"get",     required_argument,  &get_set,       1},
    [HELP_OPT_INDEX]        =       {"help",    no_argument,        &help_set,      1},
    [NEXTHOP_OPT_INDEX]     =       {"nh",      required_argument,  &nh_set,        1},
    [MAX_OPT_INDEX]         =       { NULL,     0,                  0,              0},
};

static void
usage_internal()
{
    printf("Usage:      mpls --create <label> --nh <nh index>\n");
    printf("            mpls --delete <label>\n");
    printf("\n");
    printf("--create    Create an entry for <label> in incoming label map\n");
    printf("            with nexthop set to <nh index>\n");
    printf("--delete    Delete the entry corresponding to <label>\n");

    exit(1);
}

static void
Usage(void)
{
    printf("Usage:  mpls --dump\n");
    printf("        mpls --get <label>\n");
    printf("        mpls --help\n");
    printf("\n");
    printf("--dump  Dumps the mpls incoming label map\n");
    printf("--get   Dumps the entry corresponding to label <label>\n");
    printf("        in the label map\n");
    printf("--help  Prints this help message\n");

    exit(1);
}

static void
parse_long_opts(int opt_index, char *opt_arg)
{
    errno = 0;
    switch (opt_index) {
    case COMMAND_OPT_INDEX:
        usage_internal();
        break;

    case CREATE_OPT_INDEX:
        mpls_op = SANDESH_OP_ADD;
        mpls_label = strtoul(opt_arg, NULL, 0);
        if (errno)
            usage_internal();
        break;

    case DELETE_OPT_INDEX:
        mpls_op = SANDESH_OP_DEL;
        mpls_label = strtoul(opt_arg, NULL, 0);
        if (errno)
            usage_internal();
        break;

    case DUMP_OPT_INDEX:
        mpls_op = SANDESH_OP_DUMP;
        break;

    case GET_OPT_INDEX:
        mpls_op = SANDESH_OP_GET;
        mpls_label = strtoul(opt_arg, NULL, 0);
        if (errno)
            Usage();
        break;

    case HELP_OPT_INDEX:
        Usage();
        break;

    case NEXTHOP_OPT_INDEX:
        mpls_nh = strtoul(opt_arg, NULL, 0);
        if (errno)
            usage_internal();
        break;

    default:
        Usage();
        break;
    }

    return;
}


static void
validate_options(void)
{
    int sum_op = create_set + delete_set + dump_set + get_set;

    if (sum_op > 1 || mpls_op < 0)
        Usage();

    if (create_set)
        if (!nh_set)
            usage_internal();

    if (label_set)
        if (!create_set || !delete_set || !get_set)
            usage_internal();

    return;
}

int main(int argc, char *argv[])
{
    int ret;
    int opt;
    int option_index;

    mpls_fill_nl_callbacks();

    while ((opt = getopt_long(argc, argv, "bcdgn:l:",
                    long_options, &option_index)) >= 0) {
            switch (opt) {
            case 'c':
                if (mpls_op >= 0)
                    Usage();
                create_set = 1;
                mpls_op = SANDESH_OP_ADD;
                break;

            case 'd':
                if (mpls_op >= 0)
                    Usage();
                delete_set = 1;
                mpls_op = SANDESH_OP_DEL;
                break;

            case 'g':
                if (mpls_op >= 0)
                    Usage();
                get_set = 1;
                mpls_op = SANDESH_OP_GET;
                break;

            case 'b':
                if (mpls_op >= 0)
                    Usage();
                dump_set = 1;
                mpls_op = SANDESH_OP_DUMP;
                break;

            case 'n':
                mpls_nh = atoi(optarg);
                nh_set = 1;
                break;

            case 'l':
                mpls_label = atoi(optarg);
                label_set = 1;
                break;

            case 0:
                parse_long_opts(option_index, optarg);
                break;

            case '?':
            default:
                Usage();
                break;
        }
    }

    validate_options();

    if (mpls_op == SANDESH_OP_DUMP || mpls_op == SANDESH_OP_GET) {
        printf("MPLS Input Label Map\n\n");
        printf("   Label    NextHop\n");
        printf("-------------------\n");
    }

    cl = vr_get_nl_client(VR_NETLINK_PROTO_DEFAULT);
    if (!cl) {
        exit(1);
    }

    vr_mpls_op(cl);

    return 0;
}
