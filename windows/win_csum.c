/*
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */
#include "vr_packet.h"
#include "win_csum.h"

uint16_t
trim_csum(uint32_t csum)
{
    while (csum & 0xffff0000)
        csum = (csum >> 16) + (csum & 0x0000ffff);

    return (uint16_t)csum;
}

uint16_t
calc_csum(uint8_t* ptr, size_t size)
{
    uint32_t csum = 0;
    for (int i = 0; i < size; i++)
    {
        if (i & 1)
            csum += ptr[i];
        else
            csum += ptr[i] << 8;
    }

    return trim_csum(csum);
}

static unsigned short
get_ip_payload_length(struct vr_ip* ip_hdr)
{
    return ntohs(ip_hdr->ip_len) - ip_hdr->ip_hl * 4;
}

void
init_tcp_pseudo_header(
    struct vr_ip* ip_hdr,
    struct tcp_pseudo_header* tcp_pseudo_hdr)
{
    tcp_pseudo_hdr->source_address = ip_hdr->ip_saddr;
    tcp_pseudo_hdr->destination_address = ip_hdr->ip_daddr;
    tcp_pseudo_hdr->reserved = 0;
    tcp_pseudo_hdr->protocol = ip_hdr->ip_proto;
    tcp_pseudo_hdr->tcp_length = htons(get_ip_payload_length(ip_hdr));
}

void
fill_partial_csum_of_tcp_packet(
    struct vr_ip* ip_header,
    struct vr_tcp* tcp_header)
{
    struct tcp_pseudo_header tcp_pseudo_header;
    init_tcp_pseudo_header(ip_header, &tcp_pseudo_header);
    uint16_t tcp_pseudo_hdr_csum = calc_csum(
        (uint8_t*)&tcp_pseudo_header, sizeof(tcp_pseudo_header));
    tcp_header->tcp_csum = htons(tcp_pseudo_hdr_csum);
}

void
fill_csum_of_tcp_packet_provided_that_partial_csum_is_computed(
    uint8_t* ip_packet)
{
    struct vr_ip *iph = (struct vr_ip*) ip_packet;
    unsigned tcp_offset = iph->ip_hl * 4;
    uint16_t tcp_packet_length = ntohs(iph->ip_len) - tcp_offset;
    uint8_t* tcp_packet = ip_packet + tcp_offset;
    uint16_t csum = calc_csum(tcp_packet, tcp_packet_length);
    struct vr_tcp* tcph = (struct vr_tcp*) tcp_packet;
    tcph->tcp_csum = htons(~(trim_csum(csum)));
}

// TODO: This is duplicated from vr_proto_ip.c because compilation and linking in tests.
static unsigned short
vr_ip_csum(struct vr_ip *ip)
{
    int sum = 0;
    unsigned short *ptr = (unsigned short *)ip;
    unsigned short answer = 0;
    unsigned short *w = ptr;
    int len = ip->ip_hl * 4;
    int nleft = len;

    ip->ip_csum = 0;

    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    /* mop up an odd byte, if necessary */
    if (nleft == 1) {
        *(unsigned char *)(&answer) = *(unsigned char *)w;
        sum += answer;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    answer = ~sum;

    return answer;
}

void
fill_csum_of_ip_header(struct vr_ip* iph)
{
    iph->ip_csum = vr_ip_csum(iph);
}
