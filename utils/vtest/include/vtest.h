/*
 * vtest.h --
 *
 * Copyright (c) 2015, Juniper Networks, Inc.
 * All rights reserved
 */
#ifndef __VTEST_H__
#define __VTEST_H__

#include <linux/un.h>
#include <limits.h>

#define VT_PROG_NAME                "vtest"
#define VT_MAX_TEST_NAME_LEN        128
#define VT_MAX_TEST_MODULE_NAME_LEN 128

#define VT_PACKET_MAX_TX_CLIENT (256)



struct packet_interface {
   unsigned short vif_id;
   char un_socket[UNIX_PATH_MAX];
};

struct packet {
    char pcap_file[PATH_MAX];
    char pcap_ref_file[PATH_MAX];
    size_t rx_client_num;
};

struct vtest {
    int vtest_return;
    int vtest_iteration;
    bool vtest_break;
    bool packet_test;
    unsigned char *vtest_name;
    unsigned char *vtest_error_module;
    struct packet_interface packet_tx;
    struct packet_interface packet_rx[VT_PACKET_MAX_TX_CLIENT];
    struct packet packet;
};

struct vtest_module {
    unsigned char *vt_name;
    int (*vt_node)(xmlNodePtr, struct vtest *);
    int (*vt_init)(void);
};

extern int vt_message(xmlNodePtr, struct vtest *);
extern int vt_packet(xmlNodePtr, struct vtest *);

#endif /* __VTEST_H__ */
