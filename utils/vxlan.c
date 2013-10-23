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
#include "vr_vxlan.h"
#include "vr_genetlink.h"
#include "nl_util.h"

static struct nl_client *cl;
static bool dump_pending = false;
static int op;
unsigned int dump_marker= 0;

void
vr_vxlan_req_process(void *s_req)
{
   vr_vxlan_req *req = (vr_vxlan_req *)s_req;

   printf("vnid : %d\n", (req->vxlanr_vnid & 0xFFFF));
   printf("Nhid : %d\n\n", (req->vxlanr_nhid & 0xFFFF));
   dump_marker = req->vxlanr_vnid;

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
vr_vxlan_op(int opt, uint32_t vnid, uint32_t nh_id)
{
    vr_vxlan_req vxlan_req;
    int ret, error, attr_len;
    struct nl_response *resp;

op_retry:

    vxlan_req.vxlanr_vnid = vnid;
    if (opt == 1) {
        vxlan_req.h_op = SANDESH_OP_ADD;
        vxlan_req.vxlanr_nhid = nh_id;
    } else if (opt == 2) {
        vxlan_req.h_op = SANDESH_OP_DELETE;
    } else if (opt == 3) {
        vxlan_req.h_op = SANDESH_OP_GET;
    } else if (opt == 4) {
        vxlan_req.h_op = SANDESH_OP_DUMP;
        vxlan_req.vxlanr_vnid = dump_marker;
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
    ret = sandesh_encode(&vxlan_req, "vr_vxlan_req", vr_find_sandesh_info, 
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
           "       l - <vnid>\n");
                      

}

int main(int argc, char *argv[])
{
    int ret;
    int opt;
    uint32_t nh_id;
    uint32_t vnid;

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

    nh_id = 99999;
    vnid = 99999;
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
                vnid = 0;
                break;
            case 'n':
                nh_id = atoi(optarg);
                break;
            case 'l':
                vnid = strtoul(optarg, NULL, 10);
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

    if (op != 4 && vnid == 99999) {
        usage();
        exit(1);
    }

    if (op == 1 && nh_id == 99999) {
        usage();
        exit(1);
    }


    vr_vxlan_op(op, vnid, nh_id);

    return 0;
}
