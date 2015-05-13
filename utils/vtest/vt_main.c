/*
 * vt_main.c -- test main function
 *
 * Copyright (c) 2015, Juniper Networks, Inc.
 * All rights reserved
 */

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

static int vt_test_name(xmlNodePtr, struct vtest *);

struct vtest_module vt_modules[] = {
    {   .vt_name        =   "test_name",
        .vt_node        =   vt_test_name,
    },
    {
        .vt_name        =   "message",
        .vt_node        =   vt_message,
    },
};

#define VTEST_NUM_MODULES   sizeof(vt_modules) / sizeof(vt_modules[0])

void
vt_error(unsigned char *module, struct vtest *test, int ret)
{
    test->vtest_return = ret;
    test->vtest_break = true;
    test->vtest_error_module = malloc(strlen(module) + 1);
    if (!test->vtest_error_module) {
        printf("(Unrelated)Internal metadata allocation failure\n");
        return;
    }
    strcpy(test->vtest_error_module, module);

    return;
}

static int
vt_test_name(xmlNodePtr node, struct vtest *test)
{
    xmlNodePtr child;

    child = node->xmlChildrenNode;
    if (!child || !child->content || !strlen(child->content))
        return;

    printf("Running \"%s\"\n", (char *)child->content);

    return 0;
}

static int
vt_process_node(xmlNodePtr node, struct vtest *test)
{
    int ret = 0;
    unsigned int i;

    struct vtest_module *vt;

    for (i = 0; i < VTEST_NUM_MODULES; i++) {
        if (!strncmp((char *)node->name, vt_modules[i].vt_name,
                    strlen(vt_modules[i].vt_name))) {
            ret = vt_modules[i].vt_node(node, test);
            if (ret)
                return ret;
        }
    }

    if (i == VTEST_NUM_MODULES) {
        printf("Unrecognized node %s in xml\n", node->name);
        return EINVAL;
    }

    return 0;
}
        
static int
vt_tree_traverse(xmlNodePtr node, struct vtest *test)
{
    int ret;
    xmlNodePtr child;

    while (node) {
        if (node->type == XML_ELEMENT_NODE) {
            ret = vt_process_node(node, test);
            if (ret)
                return ret;
        }

        node = node->next;
    }

    return;
}

static int
vt_parse_file(char *file, struct vtest *test)
{
    xmlDocPtr doc;
    xmlNodePtr node;

    doc = xmlParseFile(file);
    if (!doc) {
        printf("xmlParseFile %s failed\n", file);
        return EINVAL;
    }

    node = xmlDocGetRootElement(doc);
    if (!node) {
        printf("NULL Root Element\n");
        return EINVAL;
    }

    vt_tree_traverse(node->xmlChildrenNode, test);

    return 0;
}

static int
vt_init(struct vtest *test)
{
    int error;

    memset(test, 0, sizeof(*test));

    test->vtest_return = 0;
    test->vtest_iteration = 0;
    test->vtest_break = 0;
    test->vtest_name = calloc(VT_MAX_TEST_NAME_LEN, 1);
    if (!test->vtest_name) {
        error = ENOMEM;
        goto error;
    }

    test->vtest_error_module = calloc(VT_MAX_TEST_MODULE_NAME_LEN, 1);
    if (!test->vtest_error_module) {
        error = ENOMEM;
        goto error;
    }

    return 0;

error:
    if (test->vtest_name) {
        free(test->vtest_name);
        test->vtest_name = NULL;
    }

    if (test->vtest_error_module) {
        free(test->vtest_error_module);
        test->vtest_error_module = NULL;
    }

    return error;
}

static void
vt_Usage(void)
{
    printf("Usage: %s <test xml description file>\n",
            VT_PROG_NAME);
    return;
}

int
main(int argc, char *argv[])
{
    int ret;
    unsigned int i;
    char *xml_file;

    struct stat stat_buf;
    struct vtest vtest;

    if (argc != 2) {
        vt_Usage();
        return EINVAL;
    }

    xml_file = argv[1];
    ret = stat(xml_file, &stat_buf);
    if (ret) {
        perror(xml_file);
        return errno;
    }

    vt_init(&vtest);

    for (i = 0; i < VTEST_NUM_MODULES; i++) {
        if (vt_modules[i].vt_init) {
            ret = vt_modules[i].vt_init();
            if (ret) {
                printf("%s: %s init failed\n", VT_PROG_NAME,
                        vt_modules[i].vt_name);
                return ret;
            }
        }
    }

    vt_parse_file(xml_file, &vtest);

    return 0;
}
