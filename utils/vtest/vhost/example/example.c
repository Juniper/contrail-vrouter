#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <pcap/pcap.h>

#include "../src/vhost_net.h"


/* The EXAMPLE with sending and receiving a PCAP file trough vRouter*/

typedef enum {
    S_SEND,
    S_RECV,
    S_RECV_ERR,
    S_RECV_TIMEOUT
} TX_RX_AUTOMATA_STATE;

struct tx_rx_handler {
    //Data structure for
    vhost_net *send_data;
    vhost_net *recv_data;
    //Data structures for loading data from a pcap file
    char errbuf[128];
    pcap_t *p;
    struct pcap_pkthdr *pkt_header;
    const u_char *pkt_data;
    //Data structures for creating a pcap file
    pcap_t *pd;
    pcap_dumper_t *dumper;
    struct pcap_pkthdr pcap_hdr;
    struct timeval tv_before;
    struct timeval tv_after;
    uint64_t data_dest_buf[10000];
    size_t data_len_recv;
};


int
main (int argc, char **argv) {

    struct tx_rx_handler tx_rx_handler;

    memset(&tx_rx_handler, 0, sizeof(struct tx_rx_handler));
    init_vhost_net(&tx_rx_handler.send_data, "/var/run/vrouter/uvh_vif_1", 1);
    init_vhost_net(&tx_rx_handler.recv_data, "/var/run/vrouter/uvh_vif_2", 1);

    memset(&tx_rx_handler.errbuf, 0, sizeof(char) * 128);
    tx_rx_handler.p =  pcap_open_offline("deadbeef.pcap",tx_rx_handler.errbuf);

    tx_rx_handler.pd = pcap_open_dead(DLT_EN10MB, 1 << 16);
    tx_rx_handler.dumper = pcap_dump_open(tx_rx_handler.pd, "destination.pcap");
    gettimeofday(&tx_rx_handler.tv_before, NULL);

    int return_val_rx = 0;

    unsigned int read_try = 0;

    TX_RX_AUTOMATA_STATE tx_rx_state = S_SEND;
    sleep(1);

    while(1) {

        //Now we can send next data
        if (tx_rx_state == S_SEND) {
            if ((pcap_next_ex(
                   tx_rx_handler.p,
                   &tx_rx_handler.pkt_header,
                   &tx_rx_handler.pkt_data) == -2)) {
                break;
            }

            (tx_rx_handler.send_data->tx(
              tx_rx_handler.send_data->context,
              ( u_char *)tx_rx_handler.pkt_data,
              (size_t *) &(tx_rx_handler.pkt_header->len)));

            tx_rx_state = S_RECV;

        } else if (tx_rx_state == S_RECV || tx_rx_state == S_RECV_TIMEOUT) {

            return_val_rx =
                (tx_rx_handler.recv_data->rx(
                  tx_rx_handler.recv_data->context,
                  &tx_rx_handler.data_dest_buf,
                  &tx_rx_handler.data_len_recv));

            //If everything is correct e.g. we have space in a ring...
            //We can save packet to pcap
            if (return_val_rx == EXIT_SUCCESS ) {

                tx_rx_handler.pcap_hdr.caplen = tx_rx_handler.data_len_recv;
                tx_rx_handler.pcap_hdr.len = tx_rx_handler.pcap_hdr.caplen;
                (pcap_dump(
                        (u_char*) tx_rx_handler.dumper,
                        &tx_rx_handler.pcap_hdr,
                        (u_char *) tx_rx_handler.data_dest_buf));

                gettimeofday(&tx_rx_handler.tv_after, NULL);
                tx_rx_handler.pcap_hdr.ts.tv_usec =
                    (tx_rx_handler.tv_after.tv_usec - tx_rx_handler.tv_before.tv_usec);
                tx_rx_handler.pcap_hdr.ts.tv_sec =
                    (tx_rx_handler.tv_after.tv_sec - tx_rx_handler.tv_before.tv_sec);

                tx_rx_state = S_SEND;
                read_try = 0;
                continue;
            } else {
                if (tx_rx_state == S_RECV_TIMEOUT && ((++read_try) > 512)) {
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

    return EXIT_SUCCESS;
}
