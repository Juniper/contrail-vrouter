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
#if defined(__linux__)
#include <asm/types.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_ether.h>

#include <net/if.h>
#include <netinet/ether.h>
#elif defined(__FreeBSD__)
#include <net/if.h>
#include <net/ethernet.h>
#endif

#include "vr_types.h"
#include "vr_message.h"
#include "vr_mirror.h"
#include "vr_genetlink.h"
#include "nl_util.h"
#include "vr_os.h"
#include "ini_parser.h"

static struct nl_client *cl;
static bool dump_pending = false;
static bool response_pending = true;
static int dump_marker = -1;

static int create_set, delete_set, dump_set;
static int get_set, nh_set, mirror_set;
static int pcap_set, help_set, cmd_set;
static int mirror_op = -1, mirror_nh;
static int mirror_index = -1, mirror_flags;

void
vr_mirror_req_process(void *s_req)
{
   vr_mirror_req *req = (vr_mirror_req *)s_req;
   char flags[12];


   memset(flags, 0, sizeof(flags));
   if (req->mirr_flags & VR_MIRROR_PCAP)
       strcat(flags, "P");
   if (req->mirr_flags & VR_MIRROR_FLAG_MARKED_DELETE)
       strcat(flags, "Md");

   printf("%5d    %7d", req->mirr_index, req->mirr_nhid);
   printf("    %4s", flags);
   printf("    %10u\n", req->mirr_users);

   if (mirror_op == SANDESH_OP_DUMP)
       dump_marker = req->mirr_index;

   response_pending = false;
   return;
}

void
vr_response_process(void *s)
{
    vr_response *resp = (vr_response *)s;
    response_pending = false;
    if (resp->resp_code < 0) {
        printf("Error: %s\n", strerror(-resp->resp_code));
    } else {
        if (mirror_op == SANDESH_OP_DUMP) {
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

    return;
}

static int
vr_mirror_op(void)
{
    vr_mirror_req mirror_req;
    int ret, error, attr_len;
    struct nl_response *resp;
    struct nlmsghdr *nlh;

op_retry:
    mirror_req.h_op = mirror_op;
    mirror_req.mirr_index = mirror_index;

    switch (mirror_op) {
    case SANDESH_OP_ADD:
        mirror_req.mirr_nhid = mirror_nh;
        mirror_req.mirr_flags = mirror_flags;
        break;

    case SANDESH_OP_DUMP:
        mirror_req.mirr_marker = dump_marker;
        break;

    default:
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
    ret = sandesh_encode(&mirror_req, "vr_mirror_req", vr_find_sandesh_info,
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

enum opt_mirror_index {
    COMMAND_OPT_INDEX,
    CREATE_OPT_INDEX,
    DELETE_OPT_INDEX,
    DUMP_OPT_INDEX,
    GET_OPT_INDEX,
    HELP_OPT_INDEX,
    NEXTHOP_OPT_INDEX,
    PCAP_OPT_INDEX,
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
    [PCAP_OPT_INDEX]        =       {"pcap",    no_argument,        &pcap_set,      1},
    [MAX_OPT_INDEX]         =       { NULL,     0,                  0,              0},
};

static void
usage_internal()
{
    printf("Usage:      mirror --create <index> --nh <nh index> <--pcap>\n");
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
        mirror_op = SANDESH_OP_DELETE;
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

    case PCAP_OPT_INDEX:
        mirror_flags = VR_MIRROR_PCAP;
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
                mirror_op = SANDESH_OP_DELETE;
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
        printf("Index    NextHop    Flags    References\n");
        printf("---------------------------------------\n");
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

    vr_mirror_op();

    return 0;
}
