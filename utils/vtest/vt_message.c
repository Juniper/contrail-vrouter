/*
 * vt_message.c -- the messaging module
 *
 * Copyright (c) 2015, Juniper Networks, Inc.
 * All rights reserved
 */
#include <string.h>
#include <stdbool.h>

#include <libxml/xmlmemory.h>
#include <libxml/parser.h>

#include <vtest.h>
#include <vt_gen_message_modules.h>

#define RETURN  "message.return"
#define EXPECT  "message.expect"
#define MESSAGE "message"

extern struct vt_message_module vt_message_modules[];
extern unsigned int vt_message_modules_num;

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

    exp_ret = strtoul(node->content, NULL, 0);
    if (exp_ret != test->vtest_return) {
        printf("Expected return %d. Actual return %d\n",
                exp_ret, test->vtest_return);
        vt_error(RETURN, test, -EINVAL);
        return NULL;
    }

    return NULL;
}

int
vt_message(xmlNodePtr node, struct vtest *test)
{
    int ret = 0;
    unsigned int i;

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
            }
        }

        if (test->vtest_break)
            return 0;

        node = node->next;
    }

    return -1;
}

