/*
 * win_packet_splitting.h -- IP fragmentation and TCP segmentation functions
 *
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */
#ifndef __WIN_PACKET_SPLITTING_H__
#define __WIN_PACKET_SPLITTING_H__

#include "vr_packet.h"
#include "win_packet.h"

PWIN_MULTI_PACKET split_packet_if_needed(struct vr_packet *pkt);

// exposed for tests - begin
struct SplittingContext {
    struct vr_packet *pkt;
    PWIN_PACKET original_pkt;
    PWIN_MULTI_PACKET split_pkt;
    int mtu;

    // Original packet.
    unsigned char* outer_headers;
    struct vr_ip* outer_ip_header;
    struct vr_ip* inner_ip_header;

    // If we're performing TCP segmentation instead of
    // IP fragmentation. In this case, we assume that TCP headers
    // belong to inner headers and the payload is the TCP payload.
    bool is_tcp_segmentation;

    // Size for outer and inner headers is the same in original packet and
    // in all new packets (fragments).
    int outer_headers_size;
    int inner_headers_size;
    int inner_eth_header_size;

    // Offset of the inner TCP header (only when segmenting)
    int tcp_header_offset;

    // Payload offset in original packet (excluding all headers).
    int inner_payload_offset;

    // Payload size of original packet (excluding all headers).
    int total_payload_size;

    // 'More fragments' flag from original inner IP header.
    bool inner_ip_mf;

    // Fragment offset from original inner IP header.
    unsigned short inner_ip_frag_offset_in_bytes;

    // Maximum size of payload in inner fragmented IP packet. It takes into
    // account size of all headers (inner and outer) and MTU. Additionally
    // maximum_inner_payload_length % 8 == 0 as required in fragment offset
    // definition.
    int maximum_inner_payload_length;
};

void fix_packet_length_in_inner_ip_header_of_split_packet(struct SplittingContext*, struct vr_ip*, bool);
// exposed for tests - end

#endif //__WIN_PACKET_SPLITTING_H__
