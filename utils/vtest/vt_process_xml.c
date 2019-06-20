
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>

#include <libxml/xmlmemory.h>
#include <libxml/parser.h>

#include <vtest.h>
#include <vt_main.h>
#include <vt_message.h>
#include <vt_process_xml.h>

#include <net/if.h>
#include <nl_util.h>

#ifndef _WIN32
#include <vt_packet.h>
#endif

extern struct vtest_module vt_modules[];
#define SKIP_TEST_PFX "SKIP"

int
vt_test_name(xmlNodePtr node, struct vtest *test)
{
    xmlNodePtr child;
    if (!node ||!test) {
        return E_PROCESS_XML_ERR_FARG;
    }

    child = node->xmlChildrenNode;
    if (!child || !child->content || !strlen(child->content)) {
        return E_MAIN_ERR_FARG;
    }

    if (strncmp(child->content, SKIP_TEST_PFX,
        sizeof(SKIP_TEST_PFX) - 1) == 0) {
        printf("Skipping %s...\n", (char *)child->content +
            sizeof(SKIP_TEST_PFX) + 1);
        return E_MAIN_SKIP;
    } else {
        printf("Running %s...\n", (char *)child->content);
    }

    return E_PROCESS_XML_OK;
}

static int
vt_search_vt_modules_by_name(char *vt_name) {

    // -1 = not found
    int ret = -1;
    size_t i = 0;
    if (!vt_name) {
        return -2;
    }

    for (i = 0; i < VTEST_NUM_MODULES; i++) {
        if (!strncmp(vt_name, vt_modules[i].vt_name,
                    strlen(vt_modules[i].vt_name) + 1)) {
            return i;
        }
    }
    return ret;
}

static int
vt_check_return_val(struct vtest *test) {

    bool has_returned;
    int xml_return_val = 0;
    int returned_msg_val = 0;

    if (!test || !test->messages.return_vrouter_msg) {
        return E_PROCESS_XML_ERR_FARG;
    }

    has_returned = test->messages.return_vrouter_msg->has_returned;
    xml_return_val = test->messages.data[test->message_ptr_num].xml_data.return_value;
    returned_msg_val = test->messages.return_vrouter_msg->return_val[test->messages.return_vrouter_msg->ptr_num];

    if (has_returned && xml_return_val == returned_msg_val) {
        return E_PROCESS_XML_OK;
    }

    test->vtest_return = E_MAIN_TEST_FAIL;

    return E_PROCESS_XML_ERR;
}

static int
vt_send_vRouter_msg(struct vtest *test) {

    return (vr_sendmsg(test->vrouter_cl, test->messages.data[test->message_ptr_num].mem,
                test->messages.data[test->message_ptr_num].type));
}

static int
vt_recv_vRouter_msg( struct vtest *test) {

    int ret = 0;
    if (!test) {
        return E_PROCESS_XML_ERR_FARG;
    }
    test->messages.return_vrouter_msg->has_returned = false;
    ret = vr_recvmsg(test->vrouter_cl, false);
    test->messages.data[test->message_ptr_num].recv_ret_value = ret;
    return ret;
}

static int inline
vt_post_process_message_expect(struct vtest *test) {

    if (test->messages.data[test->message_ptr_num].xml_data.is_element_expect) {
        vt_expect_node((xmlNodePtr)test->messages.data[test->message_ptr_num].xml_data.element_expect_ptr, test);
        if (test->messages.data[test->message_ptr_num].return_from_expected != true) {
            fprintf(stderr, "Message has different value then expected value.\n");
            test->vtest_return = E_MAIN_TEST_FAIL;
            return E_MAIN_ERR;
        }
    }
    return E_PROCESS_XML_OK;

}

static void
vt_post_process_write_response_xml(struct vtest *test)
{
    sandesh_info_t *sinfo = NULL;
    int resp_index = test->messages.received_vrouter_msg->ptr_num;
    int err = 0;
    ThriftXMLProtocol xml_proto;
    ThriftFileTransport file_transport;

    if ((test->cli_opt.resp_file[0] == '\0') || (resp_index < 0)) {
        return;
    }

    sinfo = vr_find_sandesh_info(test->messages.data[test->message_ptr_num].type);
    if (!sinfo) {
        fprintf(stderr, "Failed to find sandesh info for %s\n",
                test->messages.data[test->message_ptr_num].type);
        return;
    }

    fprintf(stdout, "Found sandesh info for %s\n", 
            test->messages.data[test->message_ptr_num].type);

    fprintf(stdout, "Write response to xml file %s\n", test->cli_opt.resp_file);
    if (thrift_file_transport_init(&file_transport,
                                   test->cli_opt.resp_file) < 0) {
        fprintf(stderr, "Failed to open file %s\n", test->cli_opt.resp_file);
        return;
    }
    thrift_protocol_init((ThriftProtocol *)&xml_proto, T_PROTOCOL_XML,
                         (ThriftTransport *)&file_transport);
    sinfo->write((void *)test->messages.received_vrouter_msg->\
                 mem_handles[resp_index].mem, (ThriftProtocol *)&xml_proto, &err);
    if (err != 0) {
        fprintf(stderr, "Sandesh write returned error %d\n", err);
    }
    thrift_file_transport_close(&file_transport);
}

static int inline
vt_post_process_message(struct vtest *test) {

    int ret = 0;
    int tot_cnt = 0;

    test->vtest_return = E_MAIN_TEST_PASS;
    tot_cnt = test->message_ptr_num - test->message_ptr_start;
    /* reset the current pointer */
    test->message_ptr_num = test->message_ptr_start;
    /*advance the start pointer */
    test->message_ptr_start += tot_cnt;
    tot_cnt++;

    while (tot_cnt != 0) {
        if (test->messages.data[test->message_ptr_num].mem) {
            ret = vt_send_vRouter_msg(test);
            if (!(ret > 0)) {
                fprintf(stderr, "Send message, failed\n");
                return E_PROCESS_XML_ERR_MSG_SEND;
            }

            ret = vt_recv_vRouter_msg(test);
            if (!(ret > 0)) {
                fprintf(stderr, "Receive message, failed\n");
                return E_PROCESS_XML_ERR_MSG_RECV;
            }

            ret =  vt_check_return_val(test);
            if (ret != E_PROCESS_XML_OK) {
                fprintf(stderr, "Message has different return value, failed\n");
                return E_PROCESS_XML_ERR;
            }

            /* If expect element is in <message> file. */
            ret = vt_post_process_message_expect(test);
            if (ret != E_PROCESS_XML_OK) {
                fprintf(stderr, "Expected message has different value then returned, failed\n");

                return ret;
            }
            /* Write the response in XML file */
            vt_post_process_write_response_xml(test);
        }
        tot_cnt--;
        test->message_ptr_num++;
    }

    test->message_ptr_num = test->message_ptr_start;
    return E_MAIN_OK;
}

static int inline
vt_post_process_packet(struct vtest *test) {

    int ret = 0;

    ret = run_pcap_test(test);
    if (ret == EXIT_FAILURE) {
        test->vtest_return = E_MAIN_TEST_FAIL;
        return E_PROCESS_XML_ERR;
    } else if (ret == EXIT_SUCCESS) {
        test->vtest_return = E_MAIN_TEST_PASS;
        return E_PROCESS_XML_OK;
    }

    return E_PROCESS_XML_OK;
}

static int
vt_post_process_node(xmlNodePtr node, struct vtest *test) {

    int ret = 0;

    if (!test || !node) {
        return E_PROCESS_XML_ERR_FARG;
    }

    if (!strncmp((char *) node->name, "message", sizeof("message"))) {
        ret = vt_post_process_message(test);

    }

#ifndef _WIN32
    if(!strncmp((char *) node->name, "packet", sizeof("packet"))) {
        ret = vt_post_process_packet(test);
    }
#endif

    return ret;
}

static int
vt_process_node(xmlNodePtr node, struct vtest *test)
{
    unsigned int i;
    int ret = 0;

    if (!node || !test) {
        return E_PROCESS_XML_ERR_FARG;
    }

    /* control block is processed already */
    if (!strncmp((char *) node->name, "control", sizeof("control"))) {
        return E_PROCESS_XML_OK;
    }
    for (i = 0; i < VTEST_NUM_MODULES; i++) {
        if (!strncmp((char *)node->name, vt_modules[i].vt_name,
                    strlen(vt_modules[i].vt_name) + 1)) {
            ret = vt_modules[i].vt_node(node, test);

            if (ret == E_MAIN_SKIP)
                return ret;

            if (ret != E_MESSAGE_OK) {
                fprintf(stderr, "%s(): Error processing node %s\n",
                    __func__, node->name);
                return ret;
            }

            ret = vt_post_process_node(node, test);
            if (ret != E_PROCESS_XML_OK) {
                fprintf(stderr, "%s(): Error post-processing node %s\n",
                    __func__, node->name);
                return ret;
            }

            return E_PROCESS_XML_OK;
        }
    }

    if (i == VTEST_NUM_MODULES) {
        fprintf(stderr, "Unrecognized node %s in XML\n", node->name);
        return E_PROCESS_XML_ERR;
    }

    return E_PROCESS_XML_ERR;
}

static int
vt_tree_traverse(xmlNodePtr node, struct vtest *test)
{
    int ret = 0;

    if (!node || !test) {
        return E_PROCESS_XML_ERR_FARG;
    }

    while (node) {
        if (node->type == XML_ELEMENT_NODE) {
            ret = vt_process_node(node, test);
            if (ret == E_MAIN_SKIP) {
                return ret;
            }

            if (ret != E_PROCESS_XML_OK) {
                fprintf(stderr ,"%s(): Tree traverse error %d\n",
                    __func__, ret);

                return ret;
            }
            else {
                test->vtest_break = 0;
            }
        }
        node = node->next;
    }

    return E_PROCESS_XML_ERR;
}

static int
vt_traverse_control_node(xmlNodePtr node, struct vtest *test)
{
    int ret = E_MAIN_SKIP;

    if (!node || !test) {
        return E_PROCESS_XML_ERR_FARG;
    }

    while (node) {
        if (node->type == XML_ELEMENT_NODE) {
            if (!strncmp((char *) node->name, "control", sizeof("control"))) {
                xmlNodePtr child_node = node->xmlChildrenNode;
                while (child_node) {
                    if (!strncmp((char *) child_node->name, "flow_count",
                            sizeof("flow_count"))) {
                        if (child_node->children &&
                                    child_node->children->content) {
                            test->flow_count =
                                strtoul(child_node->children->content, NULL, 0);
                            ret = E_MAIN_OK;
                        }
                    }
                    child_node = child_node->next;
                }
            }


        }
        node = node->next;
    }
    return ret;
}

int
vt_parse_file(char *file, struct vtest *test)
{
    xmlDocPtr doc = NULL;
    xmlNodePtr node = NULL;
    int ret;


    doc = xmlParseFile(file);
    if (!doc) {
        fprintf(stderr ,"%s(): Error parsing XML file %s\n", __func__, file);
        return E_PROCESS_XML_ERR;
    }
    test->file_name = file;

    node = xmlDocGetRootElement(doc);
    if (!node) {
        fprintf(stderr ,"%s(): Error getting root element\n", __func__);
        return E_PROCESS_XML_ERR;
    }

    ret = vt_traverse_control_node(node->xmlChildrenNode, test);
    ret = vt_tree_traverse(node->xmlChildrenNode, test);

    xmlFreeDoc(doc);

    return ret;
}
