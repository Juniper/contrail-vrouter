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
#include <malloc.h>
#include <getopt.h>
#include <stdbool.h>

#include <asm/types.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <asm/types.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_ether.h>

#include <net/if.h>
#include <netinet/ether.h>

#include "vr_types.h"
#include "vr_message.h"
#include "vr_mpls.h"
#include "vr_genetlink.h"
#include "nl_util.h"
#include "ini_parser.h"

static struct nl_client *cl;
static bool dump_pending = false;
static bool response_pending = true;
static int dump_marker = -1;

static int create_set, delete_set, dump_set;
static int get_set, nh_set, label_set;
static int help_set, cmd_set;
static int mpls_label, mpls_op = -1, mpls_nh;

void
vr_mpls_req_process(void *s_req)
{
   vr_mpls_req *req = (vr_mpls_req *)s_req;

   printf("%8d    %6d\n", (req->mr_label & 0xFFFF), (req->mr_nhid & 0xFFFF));
   if (mpls_op == SANDESH_OP_DUMP)
       dump_marker = req->mr_label;

   response_pending = false;
}

void
vr_response_process(void *s)
{
    vr_response *resp = (vr_response *)s;
    response_pending = false;
    if (resp->resp_code < 0) {
        printf("Error: %s\n", strerror(-resp->resp_code));
    } else {
        if (mpls_op == SANDESH_OP_DUMP) {
            if (resp->resp_code > 0)
                response_pending = true;

            if (resp->resp_code & VR_MESSAGE_DUMP_INCOMPLETE) {
                dump_pending = true;
                response_pending = true;
            } else {
                dump_pending = false;
            }
        }
    }
}

static int 
vr_mpls_op(void)
{
    vr_mpls_req mpls_req;
    int ret, error, attr_len;
    struct nl_response *resp;
    struct nlmsghdr *nlh;

op_retry:
    mpls_req.h_op = mpls_op;

    switch (mpls_op) {
    case SANDESH_OP_DUMP:
        mpls_req.mr_marker = dump_marker;
        break;

    case SANDESH_OP_ADD:
        mpls_req.mr_nhid = mpls_nh;
        /* no break */
        /* fall through */
    default:
        mpls_req.mr_label = mpls_label;
        break;
    }


    /* nlmsg header */
    ret = nl_build_nlh(cl, cl->cl_genl_family_id, NLM_F_REQUEST);
    if (ret) {
        return ret;
    }

    /* Generic nlmsg header */
    ret = nl_build_genlh(cl, SANDESH_REQUEST, 0);
    if (ret) {
        return ret;
    }

    attr_len = nl_get_attr_hdr_size();
     
    error = 0;
    ret = sandesh_encode(&mpls_req, "vr_mpls_req", vr_find_sandesh_info, 
                             (nl_get_buf_ptr(cl) + attr_len),
                             (nl_get_buf_len(cl) - attr_len), &error);

    if ((ret <= 0) || error) {
        return ret;
    }

    /* Add sandesh attribute */
    nl_build_attr(cl, ret, NL_ATTR_VR_MESSAGE_PROTOCOL);
    nl_update_nlh(cl);

    response_pending = true;
    /* Send the request to kernel */
    ret = nl_sendmsg(cl);
    while (response_pending) {
        if ((ret = nl_recvmsg(cl)) > 0) {
            resp = nl_parse_reply(cl);
            if (resp->nl_op == SANDESH_REQUEST) {
                sandesh_decode(resp->nl_data, resp->nl_len,
                               vr_find_sandesh_info, &ret);
            }
        }

        nlh = (struct nlmsghdr *)cl->cl_buf;
        if (!nlh->nlmsg_flags)
            break;
    }

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
        mpls_op = SANDESH_OP_DELETE;
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
    uint32_t nh_id;
    int32_t label;

    nh_id = 0;
    label = -1;
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
                mpls_op = SANDESH_OP_DELETE;
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
                nh_id = atoi(optarg);
                nh_set = 1;
                break;

            case 'l':
                label = atoi(optarg);
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

    cl = nl_register_client();
    if (!cl) {
        exit(1);
    }

    parse_ini_file();

    ret = nl_socket(cl, get_domain(), get_type(), get_protocol());
    if (ret <= 0) {
        exit(1);
    }

    ret = nl_connect(cl, get_ip(), get_port());
    if (ret < 0) {
        exit(1);
    }

    if (vrouter_get_family_id(cl) <= 0) {
        return -1;
    }

    vr_mpls_op();

    return 0;
}
