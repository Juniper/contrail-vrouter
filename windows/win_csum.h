/*
 * win_csum.h -- Checksum calculation functions
 *
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */
#ifndef __WIN_CSUM_H__
#define __WIN_CSUM_H__

#include "vr_os.h"
#include "vr_packet.h"

__attribute__packed__open__
struct tcp_pseudo_header {
    unsigned int source_address;
    unsigned int destination_address;
    unsigned char reserved;
    unsigned char protocol;
    unsigned short tcp_length;
} __attribute__packed__close__;

uint16_t calc_csum(uint8_t* ptr, size_t size);
void csum_replace2(uint16_t *csum, uint16_t old_val, uint16_t new_val);

void init_tcp_pseudo_header(
    struct vr_ip* ip_hdr,
    struct tcp_pseudo_header* tcp_pseudo_hdr);
void fill_partial_csum_of_tcp_packet(
    struct vr_ip* ip_header,
    struct vr_tcp* tcp_header);
void fill_csum_of_tcp_packet_provided_that_partial_csum_is_computed(
    uint8_t* ip_packet);

void fill_csum_of_ip_header(struct vr_ip* iph);

#endif //__WIN_CSUM_H__
