/*
 * vt_message.c -- the messaging module
 *
 * Copyright (c) 2015, Juniper Networks, Inc.
 * All rights reserved
 */
#include <string.h>
#include <stdbool.h>
#include <limits.h>

#include <libxml/xmlmemory.h>
#include <libxml/parser.h>

#include <vtest.h>
#include <vt_gen_message_modules.h>



#include "../../include/nl_util.h"

#define RETURN  "message.return"
#define EXPECT  "message.expect"
#define MESSAGE "message"

extern struct vt_message_module vt_message_modules[];
extern unsigned int vt_message_modules_num;

extern struct nl_client *cl;


void *
vt_expect_node(xmlNodePtr node, struct vtest *test)
{
    unsigned int i;
    bool result;
    /* TODO */
    void *buf = NULL;

    node = node->xmlChildrenNode;
    while (node) {
       for (i = 0; i < vt_message_modules_num; i++) {
            if (!strncmp(node->name, vt_message_modules[i].vmm_name,
                        strlen(vt_message_modules[i].vmm_name))) {
                result = vt_message_modules[i].vmm_expect(node, test, buf);
                if (!result) {
                    vt_error(EXPECT, test, -EINVAL);
                    break;
                }
            }
       }
    }

    return NULL;
}

void *
vt_return_node(xmlNodePtr node, struct vtest *test)
{
    int exp_ret;

   if (!node || !node->children || !node->children->content ) {
        return NULL;
   }

    exp_ret = strtoul(node->children->content, NULL, 0);
    if (exp_ret != test->vtest_return) {
        printf("Expected return %d. Actual return %d\n",
                exp_ret, test->vtest_return);
        vt_error(RETURN, test, -EINVAL);
        return NULL;
    }

    return NULL;
}

int
vt_packet(xmlNodePtr node, struct vtest *test)
{
/*
 * TODO: Rewrite this part to functions/callbacks
 * */
    xmlNodePtr l_node_interface = NULL;
    node = node->xmlChildrenNode;

    while (node) {

        if (node->type == XML_TEXT_NODE) {
            node = node->next;
            continue;
        }
        if (!strncmp(node->name, "pcap_file", strlen(node->name))) {
            if (node->children && node->children->content) {
                if (node->children && node->children->content) {
                    strncpy(test->packet.pcap_file, node->children->content, PATH_MAX);

                }
            }

        } else if (!strncmp(node->name, "pcap_reference_file", strlen(node->name))) {
            if (node->children && node->children->content) {
                strncpy(test->packet.pcap_ref_file, node->children->content, PATH_MAX);

            }
        } else if (!strncmp(node->name, "tx_interface", strlen(node->name))) {

            l_node_interface = node;
            l_node_interface = l_node_interface->xmlChildrenNode;

            while (l_node_interface) {
                if (l_node_interface->type != XML_ELEMENT_NODE) {
                    l_node_interface = l_node_interface->next;
                    continue;
                }
                if (l_node_interface->children && l_node_interface->children->content) {

                    test->packet_tx.vif_id = strtoul(l_node_interface->children->content, NULL, 0);
                    break;
                }
                l_node_interface = l_node_interface->next;

            }
        } else if (!strncmp(node->name, "rx_interface", strlen(node->name))) {
            l_node_interface = node;
            l_node_interface = l_node_interface->xmlChildrenNode;

            while (l_node_interface) {
                if (l_node_interface->type != XML_ELEMENT_NODE) {
                    l_node_interface = l_node_interface->next;
                    continue;
                }
                if (l_node_interface->children && l_node_interface->children->content) {

                    test->packet_rx[test->packet.rx_client_num].vif_id = strtoul(l_node_interface->children->content, NULL, 0);
                    test->packet.rx_client_num += 1;
                    break;
                }
                l_node_interface = l_node_interface->next;
            }
        }
        node = node->next;

    }
    test->packet_test = 1;

    return 0;
}


int
vt_message(xmlNodePtr node, struct vtest *test)
{
    int ret = 0;
    unsigned int i;
    struct nl_parse_reply *resppp = NULL;
    void *buf;
    node = node->xmlChildrenNode;
    while (node) {
        for (i = 0; i < vt_message_modules_num; i++) {
            if (!strncmp(node->name, vt_message_modules[i].vmm_name,
                        strlen(vt_message_modules[i].vmm_name))) {
                buf = vt_message_modules[i].vmm_node(node, test);
                if (!buf && vt_message_modules[i].vmm_size) {
                    return -ENOMEM;
                }
                if (buf) {
                    ret = vr_sendmsg(cl, buf, vt_message_modules[i].vmm_name);
                    ret = vr_recvmsg(cl, false);
                    //TODO needs add correct response
                    if (ret <= 0) {
                        test->vtest_return = -99;
                    }
                }
                break;
            }
        }

        if (test->vtest_break || !strncmp(node->name, "return", strlen(node->name)))
            return 0;

        node = node->next;
    }

    return -1;
}

