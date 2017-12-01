/*
 * vtest.h --
 *
 * Copyright (c) 2015, Juniper Networks, Inc.
 * All rights reserved
 */
#ifndef __VTEST_H__
#define __VTEST_H__

#include <linux/un.h>
#include <linux/limits.h>
#include <limits.h>

#include <stdint.h>
#include <stdbool.h>

#define VT_PROG_NAME                "vtest"
#define VT_MAX_TEST_NAME_LEN        128
#define VT_MAX_TEST_MODULE_NAME_LEN 128

#define VT_PACKET_MAX_TX_CLIENT     (1024 * 4)
#define VT_MESSAGES_MAX             (1024 * 4)


struct packet_interface {
   unsigned short vif_id;
   //Todo send a message for map interface id to name interface
   //Socket name is created with vif_name parameter.
   char un_socket[UNIX_PATH_MAX];
};

struct packet {
    char pcap_file[PATH_MAX];
    char pcap_ref_file[PATH_MAX];
    char pcap_dest_file[PATH_MAX];
    size_t rx_client_num;
};

struct expect_vrouter {
    void *mem_expected_msg[VT_MESSAGES_MAX];
    int expected_ptr_num;
};

struct return_vrouter {
    int return_val[VT_MESSAGES_MAX];
    int returned_ptr_num;
};

struct message_xml {
    int return_value;
    bool is_element_return;
    bool is_element_expect;
    uint64_t* element_expect_ptr;
};

struct message_element {
    uint64_t* mem;
    char *type;
    /* Value from vr_recvmsg()*/
    int recv_ret_value;
    int return_from_expected;
    struct message_xml xml_data;
};

struct message {
    struct message_element data[VT_MESSAGES_MAX];
    /* Following pointers are for reponse and process callbacks from vRouter
     * Cause, we are using global variables. */
    struct expect_vrouter *expect_vrouter_msg;
    struct return_vrouter *return_vrouter_msg;
};

struct vtest {
    int vtest_iteration;
    int vtest_return;
    bool vtest_break;
    bool packet_test;
    char *vtest_name;
    char *vtest_error_module;
    struct message messages;
    int message_ptr_num;
    struct packet_interface packet_tx;
    struct packet_interface packet_rx[VT_PACKET_MAX_TX_CLIENT];
    struct packet packet;
    /* vRouter socket -> for message sending */
    struct nl_client *vrouter_cl;
    char *file_name;
};

struct vtest_module {
    char *vt_name;
    int (*vt_node)(xmlNodePtr, struct vtest *);
    int (*vt_init)(void);
};

extern const size_t VTEST_NUM_MODULES;

extern int vt_message(xmlNodePtr, struct vtest *);
extern int vt_packet(xmlNodePtr, struct vtest *);
extern int vt_test_name(xmlNodePtr, struct vtest *);

#endif /* __VTEST_H__ */
