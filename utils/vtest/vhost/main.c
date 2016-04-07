#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <pcap/pcap.h>

#include "vhost_net.h"


#define WAITING_FOR_VROUTER_uS 1000

/* The EXAMPLE with sending and receiving a PCAP file trough vRouter*/


typedef enum {
    S_START = 0,
    S_LOAD_PACKET,
    S_LOAD_PACKET_ERR,
    S_SAVE_PACKET,
    S_SEND,
    S_RECV,
    S_RECV_ERR,
    S_END,
    AUTOMATA_END
} tx_rx_automata;


tx_rx_automata
set_tx_rx_automata_state( tx_rx_automata *current_state, tx_rx_automata *previous_state) {

    tx_rx_automata temp_current_state = *current_state;

    if (*current_state == S_START) {
        *current_state = S_LOAD_PACKET;

    } else if (*current_state == S_LOAD_PACKET) {
        *current_state = S_SEND;

    } else if (*current_state == S_LOAD_PACKET_ERR) {
        *current_state = S_RECV;

    } else if (*previous_state == S_RECV && *current_state == S_RECV_ERR) {
        *current_state = S_LOAD_PACKET;
    } else if (*previous_state == S_LOAD_PACKET_ERR && *current_state == S_RECV) {
        *current_state = S_SAVE_PACKET;
        return *current_state;

    } else if (*current_state == S_RECV) {
        *current_state = S_SAVE_PACKET;

    } else if (*current_state == S_SAVE_PACKET) {
        *current_state = S_LOAD_PACKET;

    } else if (*current_state == S_SEND) {
        *current_state = S_RECV;

    }
    *previous_state = temp_current_state;

    return *current_state;
}

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
    uint64_t data_dest_buf[1600];
    size_t data_len_recv;
    //Automata state;
    tx_rx_automata current_state;
    tx_rx_automata previous_state;
    int timeout;
};


typedef int (*tx_rx_automata_handler)(struct tx_rx_handler *);


int
S_START_FUNC(struct tx_rx_handler *tx_rx_struct) {

    return set_tx_rx_automata_state(&tx_rx_struct->current_state, &tx_rx_struct->previous_state);
}

int
S_LOAD_PACKET_FUNC(struct tx_rx_handler *tx_rx_struct) {

    int ret_pcap_next = 0;
    tx_rx_struct->timeout = 0;

    ret_pcap_next = pcap_next_ex(tx_rx_struct->p, &tx_rx_struct->pkt_header, &tx_rx_struct->pkt_data);

    if (ret_pcap_next <= 0) {
        tx_rx_struct->previous_state = tx_rx_struct->current_state;
        tx_rx_struct->current_state = S_LOAD_PACKET_ERR;
        usleep(500000);
    }

    return set_tx_rx_automata_state(&tx_rx_struct->current_state, &tx_rx_struct->previous_state);
}

int
S_SAVE_PACKET_FUNC(struct tx_rx_handler *tx_rx_struct) {

    tx_rx_struct->pcap_hdr.caplen = tx_rx_struct->data_len_recv;
    tx_rx_struct->pcap_hdr.len = tx_rx_struct->pcap_hdr.caplen;
    pcap_dump((u_char*) tx_rx_struct->dumper, &tx_rx_struct->pcap_hdr, (u_char *) tx_rx_struct->data_dest_buf);
    gettimeofday(&tx_rx_struct->tv_after, NULL);
    tx_rx_struct->pcap_hdr.ts.tv_usec = tx_rx_struct->tv_after.tv_usec - tx_rx_struct->tv_before.tv_usec;
    tx_rx_struct->pcap_hdr.ts.tv_sec = tx_rx_struct->tv_after.tv_sec - tx_rx_struct->tv_before.tv_sec;

    if (tx_rx_struct->previous_state == S_LOAD_PACKET_ERR) {
        tx_rx_struct->previous_state = S_LOAD_PACKET_ERR;
        tx_rx_struct->current_state = S_END;
    }


    return set_tx_rx_automata_state(&tx_rx_struct->current_state, &tx_rx_struct->previous_state);
}

int
S_SEND_FUNC(struct tx_rx_handler *tx_rx_struct) {

    int send_packet_ret_val;

    send_packet_ret_val = tx_rx_struct->send_data->tx(tx_rx_struct->send_data->context, (u_char *)tx_rx_struct->pkt_data, (size_t *) &(tx_rx_struct->pkt_header->len));

    /*TODO Burst, also  Pcap writing process is slow */
    usleep(200);
    return set_tx_rx_automata_state(&tx_rx_struct->current_state, &tx_rx_struct->previous_state);
}

int
S_RECV_FUNC(struct tx_rx_handler *tx_rx_struct) {

    int recv_packet_ret_val;
    recv_packet_ret_val = tx_rx_struct->recv_data->rx(tx_rx_struct->recv_data->context, &tx_rx_struct->data_dest_buf, &tx_rx_struct->data_len_recv);

    if (recv_packet_ret_val != E_VHOST_NET_OK) {

        if (tx_rx_struct->previous_state == S_LOAD_PACKET_ERR) {
            tx_rx_struct->previous_state = tx_rx_struct->current_state;
            tx_rx_struct->current_state = S_END;
        } else {
            tx_rx_struct->previous_state = tx_rx_struct->current_state;
            tx_rx_struct->current_state = S_RECV_ERR;
        }
    } else {
        if (tx_rx_struct->previous_state == S_LOAD_PACKET_ERR) {
            tx_rx_struct->previous_state = S_LOAD_PACKET_ERR;
            tx_rx_struct->current_state = S_RECV;
        }
    }

    return set_tx_rx_automata_state(&tx_rx_struct->current_state, &tx_rx_struct->previous_state);
}



int
main (int argc, char **argv) {

    struct tx_rx_handler tx_rx_handler;

    memset(&tx_rx_handler, 0, sizeof(struct tx_rx_handler));

    tx_rx_handler.current_state = S_START;
    tx_rx_handler.previous_state = S_START;


    tx_rx_automata_handler tx_rx_func[AUTOMATA_END] = {NULL};

    tx_rx_func[S_START] = &S_START_FUNC;
    tx_rx_func[S_LOAD_PACKET] = &S_LOAD_PACKET_FUNC;
    tx_rx_func[S_SAVE_PACKET] = &S_SAVE_PACKET_FUNC;
    tx_rx_func[S_SEND] = &S_SEND_FUNC;
    tx_rx_func[S_RECV] = &S_RECV_FUNC;

    tx_rx_func[S_END] = NULL;
    init_vhost_net(&tx_rx_handler.send_data, "/var/run/vrouter/uvh_vif_vm1");
    init_vhost_net(&tx_rx_handler.recv_data, "/var/run/vrouter/uvh_vif_vm2");

    memset(&tx_rx_handler.errbuf, 0, sizeof(char) * 128);
    tx_rx_handler.p =  pcap_open_offline("deadbeef.pcap",tx_rx_handler.errbuf);

    tx_rx_handler.pd = pcap_open_dead(DLT_EN10MB, 1 << 16);
    tx_rx_handler.dumper = pcap_dump_open(tx_rx_handler.pd, "destination.pcap");
   gettimeofday(&tx_rx_handler.tv_before, NULL);

   int next_automata_state = S_START;

    while((next_automata_state = (*tx_rx_func[next_automata_state])(&tx_rx_handler))
            && next_automata_state != S_END)
    ;

    pcap_close(tx_rx_handler.pd);
    pcap_dump_close(tx_rx_handler.dumper);
    deinit_vhost_net(tx_rx_handler.send_data);
    deinit_vhost_net(tx_rx_handler.recv_data);

    return EXIT_SUCCESS;
}
