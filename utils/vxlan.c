/*
 *  vxlan.c
 *
 *  Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
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
#include <net/if.h>

#include "vr_os.h"
#include "vr_types.h"
#include "vr_vxlan.h"
#include "nl_util.h"

static struct nl_client *cl;
static bool dump_pending = false;
unsigned int dump_marker= 0;

static int vxlan_vnid;
static int vxlan_nh;

static int create_set, delete_set, dump_set;
static int get_set, nh_set, vnid_set;
static int help_set, cmd_set;
static int vxlan_op = -1;

static void
vxlan_req_process(void *s_req)
{
   vr_vxlan_req *req = (vr_vxlan_req *)s_req;

   printf("%7d    %d\n", req->vxlanr_vnid,
           req->vxlanr_nhid);

   dump_marker = req->vxlanr_vnid;
   return;
}

static void
response_process(void *s)
{
    vr_response_common_process((vr_response *)s, &dump_pending);
    return;
}

static void
vxlan_fill_nl_callbacks()
{
    nl_cb.vr_vxlan_req_process = vxlan_req_process;
    nl_cb.vr_response_process = response_process;
}

static int
vr_vxlan_op(struct nl_client *cl)
{
    int ret;
    bool dump = false;

op_retry:
    switch (vxlan_op) {
    case SANDESH_OP_ADD:
        ret = vr_send_vxlan_add(cl, 0, vxlan_vnid, vxlan_nh);
        break;

    case SANDESH_OP_DEL:
        ret = vr_send_vxlan_delete(cl, 0, vxlan_vnid);
        break;

    case SANDESH_OP_DUMP:
        dump = true;
        ret = vr_send_vxlan_dump(cl, 0, dump_marker);
        break;

    case SANDESH_OP_GET:
        ret = vr_send_vxlan_get(cl, 0, vxlan_vnid);
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

enum opt_vxlan_index {
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
    printf("Usage:      vxlan --create <vnid> --nh <nh index>\n");
    printf("            vxlan --delete <vnid>\n");
    printf("\n");
    printf("--create    Create an entry for <vnid> in the vxlan table\n");
    printf("            with nexthop set to <nh index>\n");
    printf("--delete    Delete the entry corresponding to <vnid>\n");

    exit(1);
}

static void
Usage(void)
{
    printf("Usage:  vxlan --dump\n");
    printf("        vxlan --get <vnid>\n");
    printf("        vxlan --help\n");
    printf("\n");
    printf("--dump  Dumps the vxlan table\n");
    printf("--get   Dumps the entry corresponding to <vnid>\n");
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
        vxlan_op = SANDESH_OP_ADD;
        vxlan_vnid = strtoul(opt_arg, NULL, 0);
        if (errno)
            usage_internal();
        break;

    case DELETE_OPT_INDEX:
        vxlan_op = SANDESH_OP_DEL;
        vxlan_vnid = strtoul(opt_arg, NULL, 0);
        if (errno)
            usage_internal();
        break;

    case DUMP_OPT_INDEX:
        vxlan_op = SANDESH_OP_DUMP;
        break;

    case GET_OPT_INDEX:
        vxlan_op = SANDESH_OP_GET;
        vxlan_vnid = strtoul(opt_arg, NULL, 0);
        if (errno)
            Usage();
        break;

    case HELP_OPT_INDEX:
        Usage();
        break;

    case NEXTHOP_OPT_INDEX:
        vxlan_nh = strtoul(opt_arg, NULL, 0);
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

    if (sum_op > 1 || vxlan_op < 0)
        Usage();

    if (create_set)
        if (!nh_set)
            usage_internal();

    if (vnid_set)
        if (!create_set || !delete_set || !get_set)
            usage_internal();

    return;
}

int main(int argc, char *argv[])
{
    int ret, opt, option_index;

    vxlan_fill_nl_callbacks();

    while ((opt = getopt_long(argc, argv, "bcdgn:l:",
                    long_options, &option_index)) >= 0) {
            switch (opt) {
            case 'c':
                if (vxlan_op >= 0)
                    Usage();

                vxlan_op = SANDESH_OP_ADD;
                create_set = 1;
                break;

            case 'd':
                if (vxlan_op >= 0)
                    Usage();

                vxlan_op = SANDESH_OP_DEL;
                delete_set = 1;
                break;

            case 'g':
                if (vxlan_op >= 0)
                    Usage();

                vxlan_op = SANDESH_OP_GET;
                get_set = 1;
                break;

            case 'b':
                if (vxlan_op >= 0)
                    Usage();

                vxlan_op = SANDESH_OP_DUMP;
                dump_set = 1;
                break;

            case 'n':
                vxlan_nh = atoi(optarg);
                nh_set = 1;
                break;

            case 'l':
                vxlan_vnid = strtoul(optarg, NULL, 10);
                vnid_set = 1;
                break;

            case 0:
                parse_long_opts(option_index, optarg);
                break;

            case '?':
            default:
                Usage();
        }
    }

    validate_options();

    if ((vxlan_op == SANDESH_OP_DUMP) ||
            (vxlan_op == SANDESH_OP_GET)) {
        printf("VXLAN Table\n\n");
        printf(" VNID    NextHop\n");
        printf("----------------\n");
    }

    cl = vr_get_nl_client(VR_NETLINK_PROTO_DEFAULT);
    if (!cl) {
        exit(1);
    }

    vr_vxlan_op(cl);

    return 0;
}
