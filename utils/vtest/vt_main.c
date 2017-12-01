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
    MAX_OPT_INDEX
};

extern struct expect_vrouter expect_msg;
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
#ifndef _WIN32
    {
        .vt_name        =   "packet",
        .vt_node        =   vt_packet,
    },
#endif
};

const size_t VTEST_NUM_MODULES = ARRAYSIZE(vt_modules);

static void
vt_dealloc_test(struct vtest *test) {

    vt_safe_free(test->vtest_name);
    vt_safe_free(test->vtest_error_module);
    int i = 0;

    for (i = 0; i <= test->message_ptr_num; ++i) {
        vt_safe_free(test->messages.data[i].mem);
    }

    for(i = 0; i <= test->messages.expect_vrouter_msg->expected_ptr_num; ++i) {
        vt_safe_free(test->messages.expect_vrouter_msg->mem_expected_msg[i]);
    }

    return;
}

static int
vt_init(struct vtest *test)
{

    memset(test, 0, sizeof(struct vtest));
    memset(&expect_msg, 0, sizeof(expect_msg));
    memset(&return_msg, 0, sizeof(return_msg));

    test->messages.expect_vrouter_msg = &expect_msg;
    test->messages.return_vrouter_msg = &return_msg;
    test->message_ptr_num = -1;

    expect_msg.expected_ptr_num = test->message_ptr_num;
    return_msg.returned_ptr_num = test->message_ptr_num;

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
        "Usage: "VT_PROG_NAME" [options] <XML-file with test definition>\n"
        "    --"HELP_OPT"       This help\n"
        "\n"
        "    --"SOCKET_DIR_OPT" DIR        Socket directory to use\n"
        "    --"NETLINK_PORT_OPT" PORT     Netlink TCP port to use\n"
        );

    exit(1);
}

static void
parse_long_opts(int opt_flow_index, char *optarg)
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

    case HELP_OPT_INDEX:
    default:
        vt_Usage();
    }
}

static struct option long_options[] = {
    [HELP_OPT_INDEX]                =   {HELP_OPT,              no_argument,
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
    char *xml_file;

    struct stat stat_buf;
    struct vtest vtest;

    vt_fill_nl_callbacks();

    while ((opt = getopt_long(argc, argv, "", long_options, &option_index))
            >= 0) {
        switch (opt) {
        case 0:
            parse_long_opts(option_index, optarg);
            break;

        case '?':
        default:
            fprintf(stderr, "Invalid option %s\n", argv[optind - 1]);
            vt_Usage();
        }
    }
    if (optind >= argc) {
        vt_Usage();
    }
    xml_file = argv[optind];

    ret = stat(xml_file, &stat_buf);
    if (ret) {
        fprintf(stderr, "%s: File not found: %s\n", __func__, xml_file);
        return E_MAIN_ERR_XML;
    }
    ret = vt_init(&vtest);
    if (ret != E_MAIN_OK) {
        return ret;
    }

    vtest.vrouter_cl = vr_get_nl_client(VR_NETLINK_PROTO_TEST);
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

    vt_parse_file(xml_file, &vtest);

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

