
#ifndef __PACKET_H__
#define __PACKET_H__

#include <stdlib.h>
#include <stdlib.h>
#include <limits.h>
#include <pcap/pcap.h>
#include <linux/un.h>

#include <vtest.h>
#include "../vhost/src/vhost_net.h"

#define READ_TRY_MAX 1U << 31

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

/*TODO MULTICAST */

struct tx_rx_handler {
    //vhost_net data structure
    vhost_net *send_data;
    char send_virtio_control_sock_path[UNIX_PATH_MAX];
    vhost_net *recv_data;
    char recv_virtio_control_sock_path[UNIX_PATH_MAX];
    //Data structures for loading data from a pcap file
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *p;
    struct pcap_pkthdr *pkt_header;
    const u_char *pkt_data;
    //Data structures for creating a pcap file
    char pcap_dest[PATH_MAX];
    pcap_t *pd;
    pcap_dumper_t *dumper;
    struct pcap_pkthdr pcap_hdr;
    struct timeval tv_before;
    struct timeval tv_after;
    uint64_t data_dest_buf[10000];
    size_t data_len_recv;
    //Automata state;
    tx_rx_automata current_state;
    tx_rx_automata previous_state;
};

typedef enum {

    E_PACKET_OK = EXIT_SUCCESS,
    E_PACKET_FARG_ERR,
    E_PACKET_PCAP_OK,
    E_PACKET_PCAP_FAIL_ERR,
    E_PACKET_PCAP_SETUP_TEST_ERR,
    E_PACKET_ERR,

} VT_PACKET_RET_VAL;

typedef int (*tx_rx_automata_handler)(struct tx_rx_handler *);


int run_pcap_test(struct vtest *);
int tx_rx_pcap_test(struct vtest *test);


#endif

