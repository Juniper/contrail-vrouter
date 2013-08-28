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

static struct nl_client *cl;
static bool dump_pending = false;
static int dump_marker = -1;
static int op;

void
vr_mpls_req_process(void *s_req)
{
   vr_mpls_req *req = (vr_mpls_req *)s_req;

   printf("Mpls Label : %d\n", (req->mr_label & 0xFFFF));
   printf("     Nhid  : %d\n", (req->mr_nhid & 0xFFFF));

   if (op == 4)
       dump_marker = req->mr_label;

}

void
vr_response_process(void *s)
{
   vr_response *resp = (vr_response *)s;
    if (resp->resp_code < 0) {
        printf("Error %s in kernel operation\n", strerror(-resp->resp_code));
    } else {
        if (op == 4) {
            if (resp->resp_code & VR_MESSAGE_DUMP_INCOMPLETE)
                dump_pending = true;
            else
                dump_pending = false;
        }
    }
}

int 
vr_mpls_op(int opt, uint32_t label, uint32_t nh_id)
{
    vr_mpls_req mpls_req;
    int ret, error, attr_len;
    struct nl_response *resp;

op_retry:

    if (opt == 1) {
        mpls_req.h_op = SANDESH_OP_ADD;
        mpls_req.mr_nhid = nh_id;
    } else if (opt == 2) {
        mpls_req.h_op = SANDESH_OP_DELETE;
    } else if (opt == 3) {
        mpls_req.h_op = SANDESH_OP_GET;
    } else if (opt == 4) {
        mpls_req.h_op = SANDESH_OP_DUMP;
        mpls_req.mr_marker = dump_marker;
    }

    mpls_req.mr_label = label;

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

    /* Send the request to kernel */
    ret = nl_sendmsg(cl);
    while ((ret = nl_recvmsg(cl)) > 0) {
        resp = nl_parse_reply(cl);
        if (resp->nl_op == SANDESH_REQUEST) {
            sandesh_decode(resp->nl_data, resp->nl_len, vr_find_sandesh_info, &ret);
        }
    }

    if (dump_pending)
        goto op_retry;

    return 0;
}

void
usage()
{
    printf("Usage: b - bulk dump\n"
           "       c - create\n"
           "       d - delete\n"
           "       g - get\n"
           "       n - <nhop_id>\n"
           "       l - <label>\n");
                      

}

int main(int argc, char *argv[])
{
    int ret;
    int opt;
    uint32_t nh_id;
    int32_t label;

    cl = nl_register_client();
    if (!cl) {
        exit(1);
    }

    ret = nl_socket(cl, NETLINK_GENERIC);    
    if (ret <= 0) {
       exit(1);
    }

    if (vrouter_get_family_id(cl) <= 0) {
        return -1;
    }

    nh_id = 0;
    label = -1;
    while ((opt = getopt(argc, argv, "bcdgn:l:")) != -1) {
            switch (opt) {
            case 'c':
                op = 1;
                break;
            case 'd':
                op = 2;
                break;
            case 'g':
                op = 3;
                break;
            case 'b':
                op = 4;
                break;
            case 'n':
                nh_id = atoi(optarg);
                break;
            case 'l':
                label = atoi(optarg);
                break;
            case '?':
            default:
                usage();
                exit(0);
        }
    }

    if (opt == 0 ) {
        usage();
        exit(1);
    }

    if (op != 4 && label == -1) {
        usage();
        exit(1);
    }

    if (op == 1 && nh_id == 0) {
        usage();
        exit(1);
    }


    vr_mpls_op(op, label, nh_id);

    return 0;
}
