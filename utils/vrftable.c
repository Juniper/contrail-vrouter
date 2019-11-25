/*
 *  vrftable.c
 *
 *  Copyright (c) 2019 Juniper Networks, Inc. All rights reserved.
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
#include "vr_vrf_table.h"
#include "nl_util.h"
#include "ini_parser.h"

static struct nl_client *cl;
static bool dump_pending = false;
static int dump_marker = -1;

static int create_set, delete_set, dump_set, sock_dir_set;
static int get_set, hbsl_set, hbsr_set, vrf_set;
static int help_set, cmd_set;
static int vrf_op = -1;
static int vrf_index = -1, vrf_flags, hbsl_idx, hbsr_idx;

static void
vrf_req_process(void *s_req)
{
    vr_vrf_req *req = (vr_vrf_req *)s_req;
    char flags[24];
    char vif_l_idx_str[24];
    char vif_r_idx_str[24];

    memset(flags, 0, sizeof(flags));
    if (req->vrf_flags & VRF_FLAG_VALID)
        strcat(flags, "V");

    if (req->vrf_flags & VRF_FLAG_HBF_L_VALID) {
        strcat(flags, "Hl");
        sprintf(vif_l_idx_str, "%d", req->vrf_hbfl_vif_idx);
    } else {
        sprintf(vif_l_idx_str, "-");
    }

    if (req->vrf_flags & VRF_FLAG_HBF_R_VALID) {
        strcat(flags, "Hr");
        sprintf(vif_r_idx_str, "%d", req->vrf_hbfr_vif_idx);
    } else {
        sprintf(vif_r_idx_str, "-");
    }

    printf("%5d    %4s", req->vrf_idx, flags);
    printf("    %7s    %4s", vif_l_idx_str, vif_r_idx_str);

    printf("\n");

    if (vrf_op == SANDESH_OP_DUMP)
        dump_marker = req->vrf_marker;

    return;
}

static void
response_process(void *s)
{
    vr_response_common_process((vr_response *)s, &dump_pending);
    return;
}

static void
vrf_fill_nl_callbacks()
{
    nl_cb.vr_vrf_req_process = vrf_req_process;
    nl_cb.vr_response_process = response_process;
}

static int
vr_vrf_op(struct nl_client *cl)
{
    int ret = 0;
    bool dump = false;

op_retry:
    switch (vrf_op) {
    case SANDESH_OP_ADD:
        ret = vr_send_vrf_add(cl, 0, vrf_index,
                hbsl_idx, hbsr_idx, VRF_FLAG_VALID|VRF_FLAG_HBF_L_VALID|VRF_FLAG_HBF_R_VALID);
        break;

    case SANDESH_OP_DEL:
        ret = vr_send_vrf_delete(cl, 0, vrf_index);
        break;

    case SANDESH_OP_DUMP:
        dump = true;
        ret = vr_send_vrf_dump(cl, 0, dump_marker);
        break;

    case SANDESH_OP_GET:
        ret = vr_send_vrf_get(cl, 0, vrf_index);
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

enum opt_vrf_index {
    COMMAND_OPT_INDEX,
    CREATE_OPT_INDEX,
    DELETE_OPT_INDEX,
    DUMP_OPT_INDEX,
    GET_OPT_INDEX,
    HELP_OPT_INDEX,
    HBSL_OPT_INDEX,
    HBSR_OPT_INDEX,
    SOCK_DIR_OPT_INDEX,
    MAX_OPT_INDEX
};

static struct option long_options[] = {
    [COMMAND_OPT_INDEX]     =       {"cmd",     no_argument,        &cmd_set,       1},
    [CREATE_OPT_INDEX]      =       {"create",  required_argument,  &create_set,    1},
    [DELETE_OPT_INDEX]      =       {"delete",  required_argument,  &delete_set,    1},
    [DUMP_OPT_INDEX]        =       {"dump",    no_argument,        &dump_set,      1},
    [GET_OPT_INDEX]         =       {"get",     required_argument,  &get_set,       1},
    [HELP_OPT_INDEX]        =       {"help",    no_argument,        &help_set,      1},
    [HBSL_OPT_INDEX]        =       {"hbs-l",   required_argument,  &hbsl_set,      1},
    [HBSR_OPT_INDEX]        =       {"hbs-r",   required_argument,  &hbsr_set,      1},
    [SOCK_DIR_OPT_INDEX]    =       {"sock-dir", required_argument, &sock_dir_set,  1},
    [MAX_OPT_INDEX]         =       { NULL,     0,                  0,              0},
};

static void
usage_internal()
{
    printf("Usage:      vrftable --create <vrf_idx> --hbs-l <vif index> --hbs-r <vif idx>\n");
    printf("            vrftable --delete <vrf_idx>\n");
    printf("\n");
    printf("--create    Create a vrf entry for <vrf_idx> with hbs left and hbs right vif index\n");
    printf("--delete    Delete the entry corresponding to <index>\n");

    exit(1);
}

static void
Usage(void)
{
    printf("Usage:  vrftable --dump\n");
    printf("        vrftable --get <index>\n");
    printf("        vrftable --help\n");
    printf("\n");
    printf("--dump  Dumps the vrf table\n");
    printf("--get   Dumps the vrf entry corresponding to index <index>\n");
    printf("--sock-dir  <netlink sock dir>\n");
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
        vrf_op = SANDESH_OP_ADD;
        vrf_index = strtoul(opt_arg, NULL, 0);
        if (errno)
            usage_internal();
        break;

    case DELETE_OPT_INDEX:
        vrf_op = SANDESH_OP_DEL;
        vrf_index = strtoul(opt_arg, NULL, 0);
        if (errno)
            usage_internal();
        break;

    case DUMP_OPT_INDEX:
        vrf_op = SANDESH_OP_DUMP;
        break;

    case GET_OPT_INDEX:
        vrf_op = SANDESH_OP_GET;
        vrf_index = strtoul(opt_arg, NULL, 0);
        if (errno)
            Usage();
        break;

    case HELP_OPT_INDEX:
        Usage();
        break;

    case HBSL_OPT_INDEX:
        hbsl_idx = strtoul(opt_arg, NULL, 0);
        if (errno)
            usage_internal();
        break;

    case HBSR_OPT_INDEX:
        hbsr_idx = strtoul(opt_arg, NULL, 0);
        if (errno)
            usage_internal();
        break;

    case SOCK_DIR_OPT_INDEX:
        vr_socket_dir = opt_arg;
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

    if (sum_op > 1 || vrf_op < 0)
        Usage();

    if (create_set)
        if (!hbsl_set || !hbsr_set)
            usage_internal();

    if (vrf_set)
        if (!create_set || !delete_set || !get_set)
            usage_internal();

    return;
}

int main(int argc, char *argv[])
{
    int ret, opt, option_index;

    vrf_fill_nl_callbacks();

    while ((opt = getopt_long(argc, argv, "bcdgl:r:v:s:",
                    long_options, &option_index)) >= 0) {
            switch (opt) {
            case 'c':
                if (vrf_op >= 0)
                    Usage();

                create_set = 1;
                vrf_op = SANDESH_OP_ADD;
                break;

            case 'd':
                if (vrf_op >= 0)
                    Usage();

                delete_set = 1;
                vrf_op = SANDESH_OP_DEL;
                break;

            case 'g':
                if (vrf_op >= 0)
                    Usage();

                get_set = 1;
                vrf_op = SANDESH_OP_GET;
                break;

            case 'b':
                if (vrf_op >= 0)
                    Usage();

                dump_set = 1;
                vrf_op = SANDESH_OP_DUMP;
                break;

            case 'l':
                hbsl_idx = atoi(optarg);
                hbsl_set = 1;
                break;

            case 'r':
                hbsr_idx = atoi(optarg);
                hbsr_set = 1;
                break;

            case 'v':
                vrf_index = atoi(optarg);
                vrf_set = 1;
                break;

            case 's':
                sock_dir_set = 1;
                parse_long_opts(SOCK_DIR_OPT_INDEX, optarg);
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

    if ((vrf_op == SANDESH_OP_DUMP) ||
            (vrf_op == SANDESH_OP_GET)) {
        printf("VRF Table\n\n");
        printf("Flags: V=Valid, Hl=HBS Left Valid, Hr=HBS Right Valid\n\n");
        printf("   Vrf   Flags      HBS-L   HBS-R\n");
        printf("------------------------------------------------\n");
    }

    if (sock_dir_set) {
        set_platform_vtest();
    }

    cl = vr_get_nl_client(VR_NETLINK_PROTO_DEFAULT);
    if (!cl) {
        exit(1);
    }

    vr_vrf_op(cl);

    return 0;
}
