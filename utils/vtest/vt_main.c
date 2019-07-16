/*
 * vt_main.c -- test main function
 *
 * Copyright (c) 2015, Juniper Networks, Inc.
 * All rights reserved
 */

#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>

#include <libxml/xmlmemory.h>
#include <libxml/parser.h>

#include <vtest.h>
#include <vt_main.h>
#include <vt_message.h>
#include <vt_process_xml.h>

#include <vr_dpdk_usocket.h>

#include <net/if.h>
#include <nl_util.h>
#include <vr_defs.h>
#include <ini_parser.h>

#ifndef _WIN32
#include <vt_packet.h>
#endif

/* vTest command-line options. */
enum vr_opt_index {
#define HELP_OPT                "help"
    HELP_OPT_INDEX,
#define SOCKET_DIR_OPT          "vr_socket_dir"
    SOCKET_DIR_OPT_INDEX,
#define NETLINK_PORT_OPT        "vr_netlink_port"
    NETLINK_PORT_OPT_INDEX,
#define SEND_SANDESH_REQ        "send_sandesh_req"
    SEND_SANDESH_REQ_INDEX,
#define RECV_SANDESH_RESP       "recv_sandesh_resp"
    RECV_SANDESH_RESP_INDEX,
#define SEND_RECV_PKT           "send_recv_pkt"
    SEND_RECV_PKT_INDEX,
    MAX_OPT_INDEX
};

extern struct received_vrouter received_msg;
extern struct return_vrouter return_msg;

extern void vt_fill_nl_callbacks();

struct vtest_module vt_modules[] = {
    {   .vt_name        =   "test_name",
        .vt_node        =   vt_test_name,
    },
    {
        .vt_name        =   "message",
        .vt_node        =   vt_message,
    },
    {
        .vt_name        =   "packet",
        .vt_node        =   vt_packet,
    },
};

const size_t VTEST_NUM_MODULES = ARRAYSIZE(vt_modules);

static void
vt_dealloc_test(struct vtest *test) {
    int i = 0;
    struct received_mem_handle *handles = test->messages.received_vrouter_msg->mem_handles;

    vt_safe_free(test->vtest_name);
    vt_safe_free(test->vtest_error_module);

    for (i = 0; i <= test->message_ptr_num; ++i) {
        vt_safe_free(test->messages.data[i].mem);
    }


    for(i = 0; i <= test->messages.received_vrouter_msg->ptr_num; ++i) {
        handles[i].free_mem(handles[i].mem);
        vt_safe_free(handles[i].mem);
    }

    return;
}

static int
vt_init(struct vtest *test)
{

    (test->messages).data = calloc(sizeof(struct message_element), VT_MESSAGES_MAX);
    if(test->messages.data == NULL) {
        return E_MAIN_ERR_ALLOC;
    }
    memset(&received_msg, 0, sizeof(received_msg));
    memset(&return_msg, 0, sizeof(return_msg));

    test->messages.received_vrouter_msg = &received_msg;
    test->messages.return_vrouter_msg = &return_msg;
    test->message_ptr_num = -1;
    test->message_ptr_start = -1;
    test->flow_count = 1;

    received_msg.ptr_num = test->message_ptr_num;
    return_msg.ptr_num = test->message_ptr_num;

    test->vtest_name = calloc(VT_MAX_TEST_NAME_LEN, 1);
    if (!test->vtest_name) {
        return E_MAIN_ERR_ALLOC;
    }

    test->vtest_error_module = calloc(VT_MAX_TEST_MODULE_NAME_LEN, 1);
    if (!test->vtest_error_module) {
        return E_MAIN_ERR_ALLOC;
    }

    return E_MAIN_OK;

}

static void
vt_Usage(void)
{
    printf(
        "Usage: "VT_PROG_NAME" [options]\n"
        "    <xml file> [deprecated]\n"
        "    --"HELP_OPT"       This help\n"
        "\n"
        "    --"SEND_SANDESH_REQ" <xml file>\n"
        "    --"RECV_SANDESH_RESP" <xml file>\n"
        "    --"SEND_RECV_PKT" <xml file>\n"
        "    --"SOCKET_DIR_OPT" DIR        Socket directory to use\n"
        "    --"NETLINK_PORT_OPT" PORT     Netlink TCP port to use\n"
        );

    exit(1);
}

static void
parse_long_opts(int opt_flow_index, char *optarg, vtest_cli_opt_t *cli_opt)
{
    errno = 0;

    switch (opt_flow_index) {
    case SOCKET_DIR_OPT_INDEX:
        vr_socket_dir = optarg;
        break;

    case NETLINK_PORT_OPT_INDEX:
        vr_netlink_port = (unsigned int)strtoul(optarg, NULL, 0);
        if (errno != 0) {
            vr_netlink_port = VR_DEF_NETLINK_PORT;
        }
        break;

    case SEND_SANDESH_REQ_INDEX:
        if (strlen(optarg) >= VT_MAX_FILENAME) {
            printf("Filename size exceeded limit of 128\n");
        } else {
            cli_opt->cli_cmd = VTEST_CLI_CMD_SANDESH_REQ;
            strcpy(cli_opt->req_file, optarg);
        }
        break;
    case RECV_SANDESH_RESP_INDEX:
        if (strlen(optarg) >= VT_MAX_FILENAME) {
            printf("Filename size exceeded limit of 128\n");
        } else {
            cli_opt->cli_cmd = VTEST_CLI_CMD_SANDESH_REQ;
            strcpy(cli_opt->resp_file, optarg);
        }
        break;
    case SEND_RECV_PKT_INDEX:
        if (strlen(optarg) >= VT_MAX_FILENAME) {
            printf("Filename size exceeded limit of 128\n");
        } else {
            cli_opt->cli_cmd = VTEST_CLI_CMD_PACKET_REQ;
            strcpy(cli_opt->req_file, optarg);
        }
        break;

    case HELP_OPT_INDEX:
    default:
        vt_Usage();
    }
}

static struct option long_options[] = {
    [HELP_OPT_INDEX]                =   {HELP_OPT,              no_argument,
                                                    NULL,                   0},
    [SEND_SANDESH_REQ_INDEX]        =   {SEND_SANDESH_REQ,      required_argument,
                                                    NULL,                   0},
    [RECV_SANDESH_RESP_INDEX]       =   {RECV_SANDESH_RESP,     required_argument,
                                                    NULL,                   0},
    [SEND_RECV_PKT_INDEX]           =   {SEND_RECV_PKT,         required_argument,
                                                    NULL,                   0},
    [SOCKET_DIR_OPT_INDEX]          =   {SOCKET_DIR_OPT,        required_argument,
                                                    NULL,                   0},
    [NETLINK_PORT_OPT_INDEX]        =   {NETLINK_PORT_OPT,      required_argument,
                                                    NULL,                   0},
    [MAX_OPT_INDEX]                 =   {NULL,                  0,
                                                    NULL,                   0},
};

int
main(int argc, char *argv[])
{
    int ret, opt, option_index;
    unsigned int i;

    struct stat stat_buf;
    struct vtest vtest;

    memset(&vtest, 0, sizeof(struct vtest));

    vt_fill_nl_callbacks();

    while ((opt = getopt_long(argc, argv, "", long_options, &option_index))
            >= 0) {
        switch (opt) {
        case 0:
            parse_long_opts(option_index, optarg, &vtest.cli_opt);
            break;

        case '?':
        default:
            fprintf(stderr, "Invalid option %s\n", argv[optind - 1]);
            vt_Usage();
        }
    }

    /* Backward compatiblity stuff */
    if ((vtest.cli_opt.cli_cmd != VTEST_CLI_CMD_SANDESH_REQ) &&
        (vtest.cli_opt.cli_cmd != VTEST_CLI_CMD_PACKET_REQ) &&
        (strcmp((argv[argc-1] + strlen(argv[argc-1]) - 3),
                "xml") == 0)) {
         vtest.cli_opt.cli_cmd = VTEST_CLI_CMD_SINGLE_TEST_FILE;
         strcpy(vtest.cli_opt.req_file, argv[argc-1]); 
    }

    ret = stat(vtest.cli_opt.req_file, &stat_buf);
    if (ret) {
        fprintf(stderr, "%s: File not found: %s\n", __func__, vtest.cli_opt.req_file);
        return E_MAIN_ERR_XML;
    }
    ret = vt_init(&vtest);
    if (ret != E_MAIN_OK) {
        return ret;
    }

    set_platform_vtest();
    vtest.vrouter_cl = vr_get_nl_client(VR_NETLINK_PROTO_DEFAULT);
    if (!vtest.vrouter_cl) {
        fprintf(stderr, "Error registering NetLink client: %s (%d)\n",
                strerror(errno), errno);
        return E_MAIN_ERR_SOCK;
    }

    for (i = 0; i < VTEST_NUM_MODULES; i++) {
        if (vt_modules[i].vt_init) {
            ret = vt_modules[i].vt_init();
            if (ret != E_MAIN_OK) {
                fprintf(stderr, "%s: %s init failed\n", VT_PROG_NAME,
                        vt_modules[i].vt_name);
                return E_MAIN_ERR;
            }
        }
    }

    vt_parse_file(vtest.cli_opt.req_file, &vtest);

    nl_free_client(vtest.vrouter_cl);
    vt_dealloc_test(&vtest);

    if (vtest.vtest_return == E_MAIN_TEST_FAIL) {
        return EXIT_FAILURE;//E_MAIN_TEST_FAIL;

    } else if (vtest.vtest_return == E_MAIN_TEST_PASS) {
        return EXIT_SUCCESS;//E_MAIN_TEST_PASS;

    } else {
        return 2;
    }

    return EXIT_SUCCESS;
}

