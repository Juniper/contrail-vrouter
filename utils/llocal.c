/*
 *  llocal.c
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

#include "vr_os.h"

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
#include "vr_genetlink.h"
#include "nl_util.h"
#include "ini_parser.h"
#include "vrouter.h"
#include "vr_packet.h"
#include "vr_llocal.h"

static struct nl_client *cl;
static bool dump_pending = false;
static bool response_pending = true;
unsigned int dump_marker= 0;
static int cmd_set, dump_set, proto_set, help_set, proto, op = -1;

void
vr_link_local_ports_req_process(void *s_req)
{
    int i;
    vr_link_local_ports_req *req = (vr_link_local_ports_req *)s_req;

   printf("%d\n", ntohs(req->vllp_port));
   dump_marker = req->vllp_marker;

   if (op != SANDESH_OP_DUMP)
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
        if (op == SANDESH_OP_DUMP) {
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
vr_llocal_op(void)
{
    vr_link_local_ports_req req;
    int ret, error, attr_len;
    struct nl_response *resp;
    struct nlmsghdr *nlh;

op_retry:
    bzero(&req, sizeof(req));
    req.h_op = op;

    switch (op) {

    case SANDESH_OP_DUMP:
        req.vllp_marker = dump_marker;
        req.vllp_rid = 0;
        if (proto == 1)
            req.vllp_proto = htons(VR_IP_PROTO_TCP); 
        else
            req.vllp_proto = htons(VR_IP_PROTO_UDP); 
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
    ret = sandesh_encode(&req, "vr_link_local_ports_req", vr_find_sandesh_info,
                             (nl_get_buf_ptr(cl) + attr_len),
                             (nl_get_buf_len(cl) - attr_len), &error);

    if ((ret < 0) || error) {
        errno = error;
        perror("Error");
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
            } else if (resp->nl_type == NL_MSG_TYPE_DONE) {
                response_pending = false;
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

enum opt_vxlan_index {
    COMMAND_OPT_INDEX,
    DUMP_OPT_INDEX,
    PROTO_OPT_INDEX,
    HELP_OPT_INDEX,
    MAX_OPT_INDEX
};

static struct option long_options[] = {
    [COMMAND_OPT_INDEX]     =       {"cmd",     no_argument,        &cmd_set,       1},
    [DUMP_OPT_INDEX]        =       {"dump",    no_argument,        &dump_set,      1},
    [PROTO_OPT_INDEX]       =       {"proto",   required_argument,  &proto_set,     1},
    [HELP_OPT_INDEX]        =       {"help",    no_argument,        &help_set,      1},
    [MAX_OPT_INDEX]         =       { NULL,     0,                  0,              0},
};

static void
usage(void)
{
    printf("Usage:  llocal --dump\n");
    printf("            --proto <1 | 2> \n");
    printf("            1 - For TCP 2 - For UDP\n");
    exit(1);
}

static void
usage_internal()
{
    usage();
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

    case DUMP_OPT_INDEX:
        op = SANDESH_OP_DUMP;
        break;

    case PROTO_OPT_INDEX:
        proto = strtoul(opt_arg, NULL, 0);
        if (errno)
            usage();

        if (proto != 1 && proto != 2)
            usage();

        break;

    case HELP_OPT_INDEX:
        usage();
        break;

    default:
        usage();
        break;
    }

    return;
}


static void
validate_options(void)
{
    if (!dump_set)
        usage();

    if (dump_set && !proto_set)
        usage();

    return;
}

int main(int argc, char *argv[])
{
    int ret, opt, option_index, ind;


    while ((opt = getopt_long(argc, argv, "",
                                        long_options, &ind)) >= 0) {
        switch(opt) {
            case 0:
                parse_long_opts(ind, optarg);
                break;

            default:
                usage();
        }

    }

    validate_options();

    if (op == SANDESH_OP_DUMP) {
        if (proto == 1)
            printf("Link Local TCP Ports Table\n\n");
        else
            printf("Link Local UDP Ports Table\n\n");
        printf("--------------------\n");
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

    vr_llocal_op();

    return 0;
}
