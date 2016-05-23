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
#include <vt_message.h>

#include <vt_gen_message_modules.h>
#include <vr_types.h>
#include <vt_gen_lib.h>

#include <vr_message.h>
#include <vr_packet.h>
#include <vr_interface.h>

#include <net/if.h>
#include <nl_util.h>

extern struct vt_message_module vt_message_modules[];
extern unsigned int vt_message_modules_num;

int
vt_expect_node(xmlNodePtr node, struct vtest *test)
{
    unsigned int i;
    bool result;

    if (!test || !node){
        return E_MESSAGE_ERR_FARG ;
    }
    void *buf = test->messages.expect_vrouter_msg->mem_expected_msg[test->messages.expect_vrouter_msg->expected_ptr_num];

    if (!buf) {
        return E_MESSAGE_ERR;
    }
    node = node->xmlChildrenNode;
    while (node) {
        for (i = 0; i < vt_message_modules_num; i++) {
            if (!strncmp(node->name, vt_message_modules[i].vmm_name,
                        strlen(vt_message_modules[i].vmm_name))) {
                result = vt_message_modules[i].vmm_expect(node, test, buf);
                test->messages.data[test->message_ptr_num].return_from_expected = result;
                break;
            }
        }
        node = node->next;
    }

    return E_MESSAGE_OK;
}

void *
vt_return_node(xmlNodePtr node, struct vtest *test)
{

    if (!node || !node->children || !node->children->content ) {
        return NULL;
    }
    test->messages.data[test->message_ptr_num].xml_data.return_value =
        (strtoul(node->children->content, NULL, 0));
    test->messages.data[test->message_ptr_num].xml_data.is_element_return = true;

    return NULL;
}


int
search_message_modules_by_name(const char *vmm_name) {

    // -1 = not found
    int ret = -1;
    size_t i = 0;

    if (!vmm_name) {
        return -2;
    }

    for (i = 0; i < vt_message_modules_num; i++) {
        if (!strncmp(vmm_name, vt_message_modules[i].vmm_name,
                    strlen(vt_message_modules[i].vmm_name) + 1)) {
            return (int)i;
        }
    }
    return ret;
}


int
vt_message(xmlNodePtr node, struct vtest *test)
{
    void *buf;
    node = node->xmlChildrenNode;
    int message_modules_element_key = -1;

    if (!node || !test) {
        return E_MESSAGE_ERR_FARG;
    }

    while (node) {

        if (node->type != XML_ELEMENT_NODE) {
            node = node->next;
            continue;
        }

        //Save the pointer to the expected node if presents in XML,
        //Because we need first send a message, after it, we can call vt_expect node
        if (!strncmp(node->name, "expect", sizeof("expect"))) {
            test->messages.data[test->message_ptr_num].xml_data.is_element_expect = true;
            test->messages.data[test->message_ptr_num].xml_data.element_expect_ptr = (uint64_t *) node;
            node = node->next;
            continue;
        }

        message_modules_element_key = search_message_modules_by_name(node->name);
        if (!(message_modules_element_key >= 0)) {
            return E_MESSAGE_ERR_MESSAGE_MODULES;
        }

        buf = vt_message_modules[message_modules_element_key].vmm_node(node, test);
        if (!buf && vt_message_modules[message_modules_element_key].vmm_size) {
            return E_MESSAGE_ERR_UNK;

        } else if (buf) {
            test->message_ptr_num++;
            test->messages.data[test->message_ptr_num].mem = buf;
            test->messages.data[test->message_ptr_num].type =
                (vt_message_modules[message_modules_element_key].vmm_name);
        }

        node = node->next;
    }

    return E_MESSAGE_OK;

}

