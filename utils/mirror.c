/*
 *  mirror.c
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
#include <sys/socket.h>

#include <net/if.h>

#include "vr_os.h"
#include "vr_types.h"
#include "vr_mirror.h"
#include "nl_util.h"

static struct nl_client *cl;
static bool dump_pending = false;
static int dump_marker = -1;

static int create_set, delete_set, dump_set;
static int get_set, nh_set, mirror_set;
static int dynamic_set, help_set, cmd_set, vni_set;
static int mirror_op = -1, mirror_nh;
static int mirror_index = -1, mirror_flags, vni_id = -1;

static void
mirror_req_process(void *s_req)
{
    vr_mirror_req *req = (vr_mirror_req *)s_req;
    char flags[12];


    memset(flags, 0, sizeof(flags));
    if (req->mirr_flags & VR_MIRROR_FLAG_DYNAMIC)
        strcat(flags, "D");

    if (req->mirr_flags & VR_MIRROR_FLAG_HW_ASSISTED)
        strcat(flags, "Hw");

    printf("%5d    %7d", req->mirr_index, req->mirr_nhid);
    printf("    %4s", flags);
    if (req->mirr_vni != -1)
        printf("    %7d", req->mirr_vni);

    printf("    %4d", req->mirr_vlan);
    printf("\n");

    if (mirror_op == SANDESH_OP_DUMP)
        dump_marker = req->mirr_index;

    return;
}

static void
response_process(void *s)
{
    vr_response_common_process((vr_response *)s, &dump_pending);
    return;
}

static void
mirror_fill_nl_callbacks()
{
    nl_cb.vr_mirror_req_process = mirror_req_process;
    nl_cb.vr_response_process = response_process;
}

static int
vr_mirror_op(struct nl_client *cl)
{
    int ret = 0;
    bool dump = false;

op_retry:
    switch (mirror_op) {
    case SANDESH_OP_ADD:
        ret = vr_send_mirror_add(cl, 0, mirror_index,
                mirror_nh, mirror_flags, vni_id);
        break;

    case SANDESH_OP_DEL:
        ret = vr_send_mirror_delete(cl, 0, mirror_index);
        break;

    case SANDESH_OP_DUMP:
        dump = true;
        ret = vr_send_mirror_dump(cl, 0, dump_marker);
        break;

    case SANDESH_OP_GET:
        ret = vr_send_mirror_get(cl, 0, mirror_index);
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

enum opt_mirror_index {
    COMMAND_OPT_INDEX,
    CREATE_OPT_INDEX,
    DELETE_OPT_INDEX,
    DUMP_OPT_INDEX,
    GET_OPT_INDEX,
    HELP_OPT_INDEX,
    NEXTHOP_OPT_INDEX,
    DYNAMIC_OPT_INDEX,
    VNI_OPT_INDEX,
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
    [DYNAMIC_OPT_INDEX]     =       {"dyn",     no_argument,        &dynamic_set,   1},
    [VNI_OPT_INDEX]         =       {"vni",     required_argument,  &vni_set,       1},
    [MAX_OPT_INDEX]         =       { NULL,     0,                  0,              0},
};

static void
usage_internal()
{
    printf("Usage:      mirror --create <index> --nh <nh index> --vni <vxlan id> --dyn\n");
    printf("            mirror --delete <index>\n");
    printf("\n");
    printf("--create    Create a mirror entry for <index> with nexthop set to <nh index>\n");
    printf("--delete    Delete the entry corresponding to <index>\n");

    exit(1);
}

static void
Usage(void)
{
    printf("Usage:  mirror --dump\n");
    printf("        mirror --get <index>\n");
    printf("        mirror --help\n");
    printf("\n");
    printf("--dump  Dumps the mirror table\n");
    printf("--get   Dumps the mirror entry corresponding to index <index>\n");
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
        mirror_op = SANDESH_OP_ADD;
        mirror_index = strtoul(opt_arg, NULL, 0);
        if (errno)
            usage_internal();
        break;

    case DELETE_OPT_INDEX:
        mirror_op = SANDESH_OP_DEL;
        mirror_index = strtoul(opt_arg, NULL, 0);
        if (errno)
            usage_internal();
        break;

    case DUMP_OPT_INDEX:
        mirror_op = SANDESH_OP_DUMP;
        break;

    case GET_OPT_INDEX:
        mirror_op = SANDESH_OP_GET;
        mirror_index = strtoul(opt_arg, NULL, 0);
        if (errno)
            Usage();
        break;

    case HELP_OPT_INDEX:
        Usage();
        break;

    case NEXTHOP_OPT_INDEX:
        mirror_nh = strtoul(opt_arg, NULL, 0);
        if (errno)
            usage_internal();
        break;

    case DYNAMIC_OPT_INDEX:
        mirror_flags = VR_MIRROR_FLAG_DYNAMIC;
        break;

    case VNI_OPT_INDEX:
        vni_id = strtoul(opt_arg, NULL, 0);
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

    if (sum_op > 1 || mirror_op < 0)
        Usage();

    if (create_set)
        if (!nh_set)
            usage_internal();

    if (mirror_set)
        if (!create_set || !delete_set || !get_set)
            usage_internal();

    return;
}

int main(int argc, char *argv[])
{
    int ret, opt, option_index;

    mirror_fill_nl_callbacks();

    while ((opt = getopt_long(argc, argv, "bcdgn:m:",
                    long_options, &option_index)) >= 0) {
            switch (opt) {
            case 'c':
                if (mirror_op >= 0)
                    Usage();

                create_set = 1;
                mirror_op = SANDESH_OP_ADD;
                break;

            case 'd':
                if (mirror_op >= 0)
                    Usage();

                delete_set = 1;
                mirror_op = SANDESH_OP_DEL;
                break;

            case 'g':
                if (mirror_op >= 0)
                    Usage();

                get_set = 1;
                mirror_op = SANDESH_OP_GET;
                break;

            case 'b':
                if (mirror_op >= 0)
                    Usage();

                dump_set = 1;
                mirror_op = SANDESH_OP_DUMP;
                break;

            case 'n':
                mirror_nh = atoi(optarg);
                nh_set = 1;
                break;

            case 'm':
                mirror_index = atoi(optarg);
                mirror_set = 1;
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

    if ((mirror_op == SANDESH_OP_DUMP) ||
            (mirror_op == SANDESH_OP_GET)) {
        printf("Mirror Table\n\n");
        printf("Flags:D=Dynamic Mirroring, Hw=NIC Assisted Mirroring \n\n");
        printf("Index    NextHop    Flags       VNI    Vlan\n");
        printf("------------------------------------------------\n");
    }

    cl = vr_get_nl_client(VR_NETLINK_PROTO_DEFAULT);
    if (!cl) {
        exit(1);
    }

    vr_mirror_op(cl);

    return 0;
}
