
#include <string.h>
#include <stdbool.h>
#include <limits.h>
#include <time.h>
#include <unistd.h>

#include <libxml/xmlmemory.h>
#include <libxml/parser.h>

#include <vtest.h>
#include "include/vt_packet.h"
#include <vt_main.h>
#include <vt_gen_message_modules.h>
#include <vr_types.h>
#include <vt_gen_lib.h>

#include <vr_message.h>
#include <vr_packet.h>
#include <vr_interface.h>

#include "vt_packet.h"

/**
 * vt_file_name_assign - assign relative file name by concatinating
 * test file directory and relative PCAP file name.
 */
void
vt_fname_assign(struct vtest *test, char *fname, char *rel_name)
{
    size_t i, l;

    if (rel_name[0] == '/') {
        strncpy(fname, rel_name, PATH_MAX - 1);
    } else {
        /* Copy current test directory. */
        l = strlen(test->file_name);
        if (l > PATH_MAX)
            l = PATH_MAX;
        for (i = l; i > 0; i--) {
            if (test->file_name[i] == '/')
                break;
        }
        strncpy(fname, test->file_name, i);
        fname[i] = '/'; fname[i + 1] = '\0';

        /* Append relative file name. */
        strncat(fname, rel_name, PATH_MAX - i - 1);
    }

    return;
}

/*
 * Parse XML structure and set structures packet and packet interface (vtest.h)
 */
int
vt_packet(xmlNodePtr node, struct vtest *test)
{
    xmlNodePtr l_node_interface = NULL;
    node = node->xmlChildrenNode;

    while (node) {

        if (node->type == XML_TEXT_NODE) {
            node = node->next;
            continue;
        }
        if (!strncmp(node->name, "pcap_input_file", strlen(node->name))) {
            if (node->children && node->children->content) {
                if (node->children && node->children->content) {
                    vt_fname_assign(test,
                        test->packet.pcap_file, node->children->content);
                }
            }

        } else if (!strncmp(node->name, "pcap_expected_file", strlen(node->name))) {
            if (node->children && node->children->content) {
                vt_fname_assign(test,
                    test->packet.pcap_ref_file, node->children->content);
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

                    (test->packet_tx.vif_id =
                     strtoul(l_node_interface->children->content, NULL, 0));
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
                    (test->packet_rx[test->packet.rx_client_num].vif_id =
                     strtoul(l_node_interface->children->content, NULL, 0));
                    //for multicast purpose 1:M, multicast is not implemented
                    test->packet.rx_client_num += 1;
                    break;
                }
                l_node_interface = l_node_interface->next;
            }
        }
        node = node->next;

    }

    test->packet_test = 1;
    return E_PACKET_OK;
}

int
pcap_compare(char *pcap_file_1, char *pcap_file_2) {

    struct pcap_pkthdr *pkt_header_1 = NULL;
    const u_char *pkt_data_1 = NULL;
    int end_pcap_1 = 0;

    char errbuf_1[PCAP_ERRBUF_SIZE] = {0};

    struct pcap_pkthdr *pkt_header_2 = NULL;
    const u_char *pkt_data_2 = NULL;
    int end_pcap_2 = 0;
    char errbuf_2[PCAP_ERRBUF_SIZE] = {0};

    printf("Comparing reference file with %s...\n", pcap_file_2);
    pcap_t *p_1 = pcap_open_offline(pcap_file_1, errbuf_1);
    if (!p_1) {
        fprintf(stderr, "%s(): Error opening pcap reference file: %s\n",
            __func__, errbuf_1);
        return E_PACKET_PCAP_SETUP_TEST_ERR;
    }

    pcap_t *p_2 = pcap_open_offline(pcap_file_2, errbuf_2);
    if (!p_2) {
        fprintf(stderr, "%s(): Error opening pcap destination file: %s\n",
            __func__, errbuf_2);
        return E_PACKET_PCAP_SETUP_TEST_ERR;
    }

    while(true) {

        if (pcap_next_ex(p_1, &pkt_header_1, &pkt_data_1) < 0) {
            end_pcap_1 = true;
        }

        if (pcap_next_ex(p_2, &pkt_header_2, &pkt_data_2) < 0 ) {
            end_pcap_2 = true;
        }

        if (end_pcap_1 != end_pcap_2) {
            fprintf(stderr, "%s(): Error comparing pcap files: different number of packets\n",
                __func__);
            return E_PACKET_PCAP_FAIL_ERR;

        } else if (end_pcap_1 && end_pcap_2) {
            return E_PACKET_PCAP_OK;
        }
        if (pkt_header_1->len == pkt_header_2->len) {
            if (memcmp((u_char *) pkt_data_1, (u_char *) pkt_data_2, pkt_header_1->len)) {
                fprintf(stderr, "%s(): Error comparing pcap files: packet data is different\n",
                    __func__);
                return E_PACKET_PCAP_FAIL_ERR;
            }

        } else {
            fprintf(stderr, "%s(): Error comparing pcap files: packet len is different\n",
                __func__);
            return E_PACKET_PCAP_FAIL_ERR;
        }

    }

    return E_PACKET_PCAP_OK;
}

static int inline
clean_vtest_struct_packet(struct vtest *test){

    if (!test) {
        return E_PACKET_FARG_ERR;
    }

    memset(&test->packet, 0, sizeof(struct packet));

    return E_PACKET_OK;
}

int
run_pcap_test(struct vtest *test) {

    int ret = 0;
    if (!test) {
        return E_PACKET_FARG_ERR;
    }

    ret = tx_rx_pcap_test(test);

    if (ret != E_PACKET_OK) {
        test->vtest_return = E_MAIN_TEST_FAIL;
    } else if (strlen(test->packet.pcap_ref_file)) {
        ret = pcap_compare(test->packet.pcap_ref_file, test->packet.pcap_dest_file);

        if (ret != E_PACKET_PCAP_OK) {
            test->vtest_return = E_MAIN_TEST_FAIL;
        } else {
            test->vtest_return = E_MAIN_TEST_PASS;
        }
    }

    clean_vtest_struct_packet(test);

    return ret;
}


/* TODO Multicast, return parameter */
int
tx_rx_pcap_test(struct vtest *test) {

    if (!test) {
        return E_PACKET_FARG_ERR;
    }

    typedef enum {
        S_SEND,
        S_RECV,
        S_RECV_ERR,
        S_RECV_TIMEOUT
    } TX_RX_AUTOMATA_STATE;

    /* Path variable */

    char pcap_dest[PATH_MAX] = {0};

    snprintf(pcap_dest, PATH_MAX, "/tmp/dest_%u.pcap", (unsigned)(time(NULL)));
    strncpy(test->packet.pcap_dest_file, pcap_dest, strlen(pcap_dest));


    char src_vif_ctrl_sock[UNIX_PATH_MAX] = {0};
    char dst_vif_ctrl_sock[UNIX_PATH_MAX] = {0};


    snprintf(src_vif_ctrl_sock, UNIX_PATH_MAX, "/var/run/vrouter/uvh_vif_%d", test->packet_tx.vif_id);
    snprintf(dst_vif_ctrl_sock, UNIX_PATH_MAX, "/var/run/vrouter/uvh_vif_%d", test->packet_rx[0].vif_id);


    struct tx_rx_handler tx_rx_handler;

    vhost_net_state rx_state = E_VHOST_NET_OK;
    vhost_net_state tx_state = E_VHOST_NET_OK;

    memset(&tx_rx_handler, 0, sizeof(struct tx_rx_handler));

    tx_state = init_vhost_net(&tx_rx_handler.send_data, src_vif_ctrl_sock);
    rx_state = init_vhost_net(&tx_rx_handler.recv_data, dst_vif_ctrl_sock);

    if (tx_state != E_VHOST_NET_OK || rx_state != E_VHOST_NET_OK) {
        return E_PACKET_ERR;
    }

    memset(&tx_rx_handler.errbuf, 0, sizeof(char) * PCAP_ERRBUF_SIZE);
    tx_rx_handler.p =  pcap_open_offline(test->packet.pcap_file, tx_rx_handler.errbuf);
    if (!tx_rx_handler.p) {
        fprintf(stderr, "%s(): Error opening pcap offline: %s\n",
            __func__, tx_rx_handler.errbuf);
        return E_PACKET_PCAP_SETUP_TEST_ERR;
    }

    tx_rx_handler.pd = pcap_open_dead(DLT_EN10MB, 1 << 16);
    if (!tx_rx_handler.pd) {
        fprintf(stderr, "%s(): Error opening pcap dead\n", __func__);
        return E_PACKET_PCAP_SETUP_TEST_ERR;
    }

    tx_rx_handler.dumper = pcap_dump_open(tx_rx_handler.pd, pcap_dest);
    if (!tx_rx_handler.dumper) {
        fprintf(stderr, "%s(): Error opening pcap dump: %s\n",
            __func__, pcap_geterr(tx_rx_handler.pd));
        return E_PACKET_PCAP_SETUP_TEST_ERR;
    }

    gettimeofday(&tx_rx_handler.tv_before, NULL);

    int return_val_tx = 0;
    int return_val_rx = 0;

    TX_RX_AUTOMATA_STATE tx_rx_state = S_SEND;

    unsigned int read_try = 0 ;

    //TODO: Burst
    // We need to be sure, that vRouter has empty desc for writing packets. -> sleep(1);
    sleep(1);

    while(1) {

        //Now we can send next data
        if (tx_rx_state == S_SEND) {
            if (pcap_next_ex(tx_rx_handler.p, &tx_rx_handler.pkt_header, &tx_rx_handler.pkt_data) == -2) {
                break;
            }

            return_val_tx = (tx_rx_handler.send_data->tx(
                        tx_rx_handler.send_data->context,
                        (u_char *)tx_rx_handler.pkt_data,
                        (size_t *) &(tx_rx_handler.pkt_header->len)));
            tx_rx_state = S_RECV;

        } else if (tx_rx_state == S_RECV || tx_rx_state == S_RECV_TIMEOUT) {
            return_val_rx = (tx_rx_handler.recv_data->rx(
                        tx_rx_handler.recv_data->context,
                        &tx_rx_handler.data_dest_buf,
                        &tx_rx_handler.data_len_recv));

            //If everything is correct e.g. we have space in a ring...
            //We can save packet to pcap
            if (return_val_rx == E_VHOST_NET_OK) {

                tx_rx_handler.pcap_hdr.caplen = tx_rx_handler.data_len_recv;
                tx_rx_handler.pcap_hdr.len = tx_rx_handler.pcap_hdr.caplen;
                (pcap_dump(
                           (u_char*) tx_rx_handler.dumper,
                           &tx_rx_handler.pcap_hdr,
                           (u_char *) tx_rx_handler.data_dest_buf));
                gettimeofday(&tx_rx_handler.tv_after, NULL);
                tx_rx_handler.pcap_hdr.ts.tv_usec = tx_rx_handler.tv_after.tv_usec - tx_rx_handler.tv_before.tv_usec;
                tx_rx_handler.pcap_hdr.ts.tv_sec = tx_rx_handler.tv_after.tv_sec - tx_rx_handler.tv_before.tv_sec;

                tx_rx_state = S_SEND;
                read_try = 0;
                continue;

            } else {
                if (tx_rx_state == S_RECV_TIMEOUT && ((++read_try) > 51200)) {
                    tx_rx_state = S_SEND;
                } else {
                    tx_rx_state = S_RECV_ERR;
                }
            }
        } else {
            if (tx_rx_state == S_RECV_ERR) {
                tx_rx_state = S_RECV_TIMEOUT;
            }
        }
    }

    pcap_close(tx_rx_handler.pd);
    pcap_dump_close(tx_rx_handler.dumper);
    deinit_vhost_net(tx_rx_handler.send_data);
    deinit_vhost_net(tx_rx_handler.recv_data);

    return E_PACKET_OK;
}


