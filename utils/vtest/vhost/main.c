#include <stdio.h>
#include <stdlib.h>

#include "uvhost.h"
#include "util.h"
#include <string.h>
#include <pcap/pcap.h>


/* Below is only EXAMPLE*
 * How to call function etc...
 *
 * TODO: library -> probably need different architecture
 *                  need rewrite some return value
 *                  fix some header files
 *
 *       Pcap_comparator -> which types of comparator we need.
 *
 */
int main (int argc, char **argv) {

    // init client
    // send or receive
    //
    Vhost_Client *vhost_client_send = NULL;
    Vhost_Client *vhost_client_recv = NULL;

    uvhost_run_vhost_client(&vhost_client_send, "/var/run/vrouter/uvh_vif_vm1", CLIENT_TYPE_TX);
    uvhost_run_vhost_client(&vhost_client_recv, "/var/run/vrouter/uvh_vif_vm2", CLIENT_TYPE_RX);

    int return_val_tx = EXIT_SUCCESS;
    int return_val_rx = EXIT_SUCCESS;

    //Data structures for loading data from a pcap file

    char errbuf[128] = {0};
    pcap_t *p = pcap_open_offline("deadbeef.pcap",errbuf);
    struct pcap_pkthdr *pkt_header = NULL;
    const u_char *pkt_data = NULL;

    //Data structures for creating a pcap file
    pcap_t *pd = pcap_open_dead(DLT_EN10MB, 1 << 16);
    pcap_dumper_t *dumper = pcap_dump_open(pd, "destination.pcap");
    struct  pcap_pkthdr pcap_hdr;
    memset(&pcap_hdr, 0, sizeof(struct pcap_pkthdr));

    struct timeval tv_before, tv_after;
    memset(&tv_before, 0, sizeof(struct timeval));
    memset(&tv_after, 0, sizeof(struct timeval));

    gettimeofday(&tv_before, NULL);

    uint64_t data_dest_buf = 0;
    size_t data_len_recv = 0;

    struct uvhost_app_handler  *vhost_tx_handler_data = &vhost_client_send->client.vhost_net_app_handler;
    struct uvhost_app_handler  *vhost_rx_handler_data = &vhost_client_recv->client.vhost_net_app_handler;



    poll_func_handler *tx_callback = &vhost_client_send->client.vhost_net_app_handler.poll_func_handler;
    poll_func_handler *rx_callback = &vhost_client_recv->client.vhost_net_app_handler.poll_func_handler;

    while(1) {

        //Now we can send next data
        if (return_val_tx == EXIT_SUCCESS && return_val_rx != EXIT_SUCCESS + 40) {
           if (pcap_next_ex(p, &pkt_header, &pkt_data) == -2) {
                break;
           }

        return_val_tx = (*tx_callback)((*vhost_tx_handler_data).context, ( u_char *)pkt_data, (size_t *) &(pkt_header->len));
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

    return EXIT_SUCCESS;
}
