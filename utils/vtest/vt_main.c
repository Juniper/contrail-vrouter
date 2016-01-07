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


#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <libxml/xmlmemory.h>
#include <libxml/parser.h>
#include <linux/un.h>

#include <vtest.h>

#include "vhost/uvhost.h"
#include "vhost/util.h"
#include <pcap/pcap.h>

#include "nl_util.h"

struct nl_client *cl;

static int vt_test_name(xmlNodePtr, struct vtest *);

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
    unsigned int i;

    struct vtest_module *vt;

    for (i = 0; i < VTEST_NUM_MODULES; i++) {
        if (!strncmp((char *)node->name, vt_modules[i].vt_name,
                    strlen(vt_modules[i].vt_name))) {
            return vt_modules[i].vt_node(node, test);
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
    test->packet_test = 0;
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
/*
 * Code below is only for demonstration purpose. I am waiting for review process
 * This code is copied from vhost_net, when review process will be done.
 * I will have more information to decide "how it rewrite".
 * Thank you.
 */
int
run_pcap_test(struct vtest *test) {

    Vhost_Client *vhost_client_send = NULL;
    Vhost_Client *vhost_client_recv = NULL;

    char pcap_dest[PATH_MAX] = {0};
    char unix_socket_file_buf[UNIX_PATH_MAX] = {0};
    int uvhost_state_tx = 0;
    int uvhost_state_rx = 0;

    snprintf(pcap_dest, UNIX_PATH_MAX, "/tmp/dest_%u.pcap", (unsigned)(time(NULL)));

    /*TODO  For now, we are substituting socket name from vif (in future should be from name)  */
    snprintf(unix_socket_file_buf, UNIX_PATH_MAX, "/var/run/vrouter/uvh_vif_%d", test->packet_tx.vif_id);
    uvhost_state_rx = uvhost_run_vhost_client(&vhost_client_send, unix_socket_file_buf, CLIENT_TYPE_TX);
    memset(unix_socket_file_buf, 0, sizeof(char) * UNIX_PATH_MAX);

    /*TODO  For now, we are substituting socket name from vif (in future should be from name)  */
    /*TODO * Dont forget about multicast packet rx_client_num */
    snprintf(unix_socket_file_buf, UNIX_PATH_MAX, "/var/run/vrouter/uvh_vif_%d", test->packet_rx[0].vif_id);
    uvhost_state_tx = uvhost_run_vhost_client(&vhost_client_recv, unix_socket_file_buf, CLIENT_TYPE_RX);

    if (!vhost_client_recv || !vhost_client_send || uvhost_state_tx != EXIT_SUCCESS || uvhost_state_rx != EXIT_SUCCESS) {
        return -99;
    }

    int return_val_tx = EXIT_SUCCESS;
    int return_val_rx = EXIT_SUCCESS;

    //Data structures for loading data from a pcap file
    char errbuf[128] = {0};
    pcap_t *p = pcap_open_offline(test->packet.pcap_file, errbuf);
    struct pcap_pkthdr *pkt_header = NULL;
    const u_char *pkt_data = NULL;

    //Data structures for creating a pcap file
    pcap_t *pd = pcap_open_dead(DLT_EN10MB, 1 << 16);
    pcap_dumper_t *dumper = pcap_dump_open(pd, pcap_dest);
    struct  pcap_pkthdr pcap_hdr;
    memset(&pcap_hdr, 0, sizeof(struct pcap_pkthdr));

    struct timeval tv_before, tv_after;
    memset(&tv_before, 0, sizeof(struct timeval));
    memset(&tv_after, 0, sizeof(struct timeval));

    gettimeofday(&tv_before, NULL);

    uint64_t data_dest_buf = 0;
    size_t data_len_recv = 0;

    struct uvhost_app_handler *vhost_tx_handler_data = &vhost_client_send->client.vhost_net_app_handler;
    struct uvhost_app_handler *vhost_rx_handler_data = &vhost_client_recv->client.vhost_net_app_handler;

    poll_func_handler *tx_callback = &vhost_client_send->client.vhost_net_app_handler.poll_func_handler;
    poll_func_handler *rx_callback = &vhost_client_recv->client.vhost_net_app_handler.poll_func_handler;

    while(1) {
        //Now we can send next data
        if (return_val_tx == EXIT_SUCCESS && return_val_rx != EXIT_SUCCESS + 40) {
            if (pcap_next_ex(p, &pkt_header, &pkt_data) == -2) {
                break;
            }
            return_val_tx = (*tx_callback)((*vhost_tx_handler_data).context, (u_char *)pkt_data, (size_t *)&(pkt_header->len));
        }
        return_val_rx = (*rx_callback)((*vhost_rx_handler_data).context, &data_dest_buf, &data_len_recv);
        //If everything is correct e.g. we have space in a ring...
        //We can save packet to pcap
        if (return_val_rx == EXIT_SUCCESS ) {
            pcap_hdr.caplen = data_len_recv;
            pcap_hdr.len = pcap_hdr.caplen;
            //printf("pcap_hdr.caplen %u, pcap_hdr.len %u\n", pcap_hdr.caplen, pcap_hdr.len);
            pcap_dump((u_char*) dumper, &pcap_hdr, (u_char *) data_dest_buf);
            gettimeofday(&tv_after, NULL);
            //printf("tv_after  tv_usec %ld  tv_sec %ld | tv_before tv_usec %ld tv_sec %ld | \n", tv_after.tv_usec, tv_after.tv_sec, tv_before.tv_usec, tv_before.tv_sec);
            pcap_hdr.ts.tv_usec = tv_after.tv_usec - tv_before.tv_usec;
            pcap_hdr.ts.tv_sec = tv_after.tv_sec - tv_before.tv_sec;
        }
    }

    pcap_close(pd);
    pcap_dump_close(dumper);
    uvhost_delete_Vhost_Client(vhost_client_recv);
    uvhost_delete_Vhost_Client(vhost_client_send);

    //pcap compare part
    char *pcap_reference = test->packet.pcap_ref_file;
    char *pcap_processed = pcap_dest;

    //Data structures for loading data from a pcap file
    char errbuf_1[128] = {0};
    pcap_t *p_1 = pcap_open_offline(pcap_reference, errbuf);
    struct pcap_pkthdr *pkt_header_1 = NULL;
    const u_char *pkt_data_1 = NULL;
    int end_pcap_1 = 0;

    //Data structures for loading data from a pcap file
    char errbuf_2[128] = {0};
    pcap_t *p_2 = pcap_open_offline(pcap_processed, errbuf);
    struct pcap_pkthdr *pkt_header_2 = NULL;
    const u_char *pkt_data_2 = NULL;
    int end_pcap_2 = 0;

    while(true) {

        if(pcap_next_ex(p_1, &pkt_header_1, &pkt_data_1) == -2) {
            end_pcap_1 = 1;

        }
        if(pcap_next_ex(p_2, &pkt_header_2, &pkt_data_2) == -2) {
            end_pcap_2 = 1;

        }

        if (end_pcap_1 != end_pcap_2) {
            return EXIT_FAILURE;
        } else if (end_pcap_1 && end_pcap_2) {
            return EXIT_SUCCESS;
        }

        if (pkt_header_1->len == pkt_header_2->len ) {
            if (memcmp((u_char *)pkt_data_1, (u_char *)pkt_data_2, pkt_header_1->len)) {
                return EXIT_FAILURE;
            }

        } else {
            return EXIT_FAILURE;

        }

    }

    return EXIT_SUCCESS;
}


int
main(int argc, char *argv[])
{
    int ret;
    unsigned int i;
    char *xml_file;
    unsigned int sock_proto = VR_NETLINK_PROTO_DEFAULT;

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

    cl = vr_get_nl_client(sock_proto);
    if (!cl) {
        fprintf(stderr, "Error registering NetLink client: %s (%d)\n",
                strerror(errno), errno);
        exit(-ENOMEM);
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
    nl_free(cl);

    if (vtest.packet_test) {
        ret = run_pcap_test(&vtest);
        if (ret == EXIT_FAILURE) {
            fprintf(stderr, "Pcaps are not same or  \n");
            return ret;

        } else if (ret == EXIT_SUCCESS) {
            fprintf(stdout, "Pcaps are same.\n");
            return ret;
        } else if (ret == -99) {
            fprintf(stderr, "Cannot run run_pcap_test.\n");
            return ret;

        }

    }
    return EXIT_SUCCESS;
}

