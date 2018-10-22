/*
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */
#include "vr_interface.h"
#include "vr_packet.h"
#include "vr_mpls.h"
#include "vrouter.h"

#include "win_memory.h"
#include "win_packet.h"
#include "win_packet_raw.h"
#include "win_packet_impl.h"
#include "windows_nbl.h"
#include "win_csum.h"

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

static void
initialize_splitting_context(
    struct SplittingContext *pctx,
    struct vr_packet *pkt)
{
    RtlZeroMemory(pctx, sizeof(*pctx));
    pctx->pkt = pkt;
    pctx->mtu = pkt->vp_if->vif_mtu;

    pctx->original_pkt = GetWinPacketFromVrPacket(pkt);
}

static inline bool
is_splitting_needed(struct SplittingContext *pctx)
{
    PWIN_PACKET_RAW rawPkt = WinPacketToRawPacket(pctx->original_pkt);
    return vr_pkt_type_is_overlay(pctx->pkt->vp_type) &&
        WinPacketRawDataLength(rawPkt) > pctx->mtu;
}

static inline unsigned char *
get_next_header_after_ip(struct vr_ip *ip)
{
    return (unsigned char *)ip + ip->ip_hl * 4;
}

static void
extract_outer_headers_from_original_packet(
    struct SplittingContext *pctx)
{
    pctx->outer_headers = pkt_data(pctx->pkt);
    pctx->outer_ip_header = (struct vr_ip*)(pctx->outer_headers
        + sizeof(struct vr_eth));

    struct vr_ip* outer_iph = pctx->outer_ip_header;
    pctx->outer_headers_size = sizeof(struct vr_eth) + outer_iph->ip_hl * 4;
    if (outer_iph->ip_proto == VR_IP_PROTO_GRE) {
        pctx->outer_headers_size += VR_GRE_BASIC_HDR_LEN + VR_MPLS_HDR_LEN;
    } else if (outer_iph->ip_proto == VR_IP_PROTO_UDP) {
        pctx->outer_headers_size += sizeof(struct vr_udp);
        struct vr_udp *outer_udph = (struct vr_udp *)get_next_header_after_ip(outer_iph);
        if (vr_vxlan_udp_port(ntohs(outer_udph->udp_dport))) {
            pctx->outer_headers_size += sizeof(struct vr_vxlan);
        } else {
            pctx->outer_headers_size += VR_MPLS_HDR_LEN;
        }
    }
}

static inline bool
more_fragments(struct vr_ip* ip)
{
    return ntohs(ip->ip_frag_off) & VR_IP_MF ? true : false;
}

static inline unsigned short
fragment_offset_in_bytes(struct vr_ip* ip)
{
    return (ntohs(ip->ip_frag_off) & VR_IP_FRAG_OFFSET_MASK) * 8;
}

static void
extract_inner_ip_fragmentation_flags_and_offset_from_original_packet(
    struct SplittingContext* pctx)
{
    pctx->inner_ip_mf = more_fragments(pctx->inner_ip_header);
    pctx->inner_ip_frag_offset_in_bytes
        = fragment_offset_in_bytes(pctx->inner_ip_header);
}

static void
extract_inner_ip_payload_offset_and_size_from_original_packet(
    struct SplittingContext* pctx)
{
    pctx->inner_payload_offset = pctx->outer_headers_size
        + pctx->inner_headers_size;
    pctx->total_payload_size = sizeof(struct vr_eth)
        + ntohs(pctx->outer_ip_header->ip_len) - pctx->inner_payload_offset;
}

static void
extract_inner_tcp_header_from_original_packet(struct SplittingContext* pctx)
{
    struct vr_tcp *tcp = (struct vr_tcp*)(pctx->inner_ip_header + 1);
    pctx->inner_headers_size += VR_TCP_OFFSET(tcp->tcp_offset_r_flags) * 4;
    pctx->tcp_header_offset = (unsigned char*)(tcp) - pctx->outer_headers;
}

static void
check_if_tcp_segmentation_is_needed(struct SplittingContext* pctx)
{
    if (pctx->inner_ip_header->ip_proto == VR_IP_PROTO_TCP) {
        pctx->is_tcp_segmentation = true;
        extract_inner_tcp_header_from_original_packet(pctx);
    } else {
        pctx->is_tcp_segmentation = false;
    }
}

static void
extract_inner_headers_size_and_offset_from_original_packet(
    struct SplittingContext* pctx)
{
    unsigned short inner_iph_offset = pkt_get_inner_network_header_off(pctx->pkt);
    pctx->inner_ip_header = (struct vr_ip*)pkt_data_at_offset(pctx->pkt, inner_iph_offset);

    unsigned char *inner_headers = pctx->outer_headers + pctx->outer_headers_size;
    pctx->inner_eth_header_size = (unsigned char*)pctx->inner_ip_header - inner_headers;

    pctx->inner_headers_size = pctx->inner_eth_header_size
        + pctx->inner_ip_header->ip_hl * 4;
}

static void
extract_inner_headers_from_original_packet(struct SplittingContext* pctx)
{
    extract_inner_headers_size_and_offset_from_original_packet(pctx);
    check_if_tcp_segmentation_is_needed(pctx);
    extract_inner_ip_fragmentation_flags_and_offset_from_original_packet(pctx);
    extract_inner_ip_payload_offset_and_size_from_original_packet(pctx);
}

static void
extract_headers_from_original_packet(struct SplittingContext* pctx)
{
    extract_outer_headers_from_original_packet(pctx);
    extract_inner_headers_from_original_packet(pctx);
}

static bool
fix_split_packet_metadata(struct SplittingContext* pctx)
{
    PWIN_PACKET_RAW originalRawPacket = WinPacketToRawPacket(pctx->original_pkt);
    PWIN_PACKET_RAW splitRawPacket = WinMultiPacketToRawPacket(pctx->split_pkt);

    if (WinPacketRawCopyOutOfBandData(splitRawPacket, originalRawPacket) == FALSE) {
        return false;
    }

    WinPacketRawSetParentOf(splitRawPacket, originalRawPacket);
    WinPacketRawIncrementChildCountOf(originalRawPacket);

    return true;
}

static void
calculate_maximum_inner_payload_length_for_new_packets(
    struct SplittingContext* pctx)
{
    // Note: fragment offset in IP header actually means amount of 8-byte
    // blocks. It means that 'payload size' % 8 == 0 for each packet with
    // 'more fragments' flag set to true. It means that
    // maximum_inner_payload_length has to be aligned down to 8-byte boundary.
    int free_space_for_inner_payload = pctx->mtu - pctx->inner_payload_offset;
    if (pctx->is_tcp_segmentation) {
        pctx->maximum_inner_payload_length = win_pgso_size(pctx->pkt);
    } else {
        pctx->maximum_inner_payload_length = free_space_for_inner_payload & ~7;
    }
}

static void
split_original_packet(struct SplittingContext* pctx)
{
    calculate_maximum_inner_payload_length_for_new_packets(pctx);

    PWIN_PACKET_RAW originalPkt = WinPacketToRawPacket(pctx->original_pkt);
    PWIN_PACKET_RAW splitRawPkt = WinPacketRawAllocateMultiFragment(
        originalPkt, pctx->inner_payload_offset, pctx->maximum_inner_payload_length);

    if (splitRawPkt == NULL) {
        return;
    }

    pctx->split_pkt = (PWIN_MULTI_PACKET)splitRawPkt;
    WinPacketRawAssertAllHeadersAreInFirstMDL(splitRawPkt, pctx->inner_payload_offset);

    if (!fix_split_packet_metadata(pctx)) {
        WinPacketRawFreeMultiFragmentWithoutFwdContext(splitRawPkt);
        pctx->split_pkt = NULL;
    }
}

static void
set_fragment_offset(struct vr_ip* ip, unsigned short offset_in_bytes)
{
    ASSERTMSG(
        "set_fragment_offset: offset_in_bytes is not divisible by 8",
        offset_in_bytes % 8 == 0);
    ip->ip_frag_off &= htons(~VR_IP_FRAG_OFFSET_MASK);
    ip->ip_frag_off |= htons(offset_in_bytes / 8);
}

static void
fix_packet_length_in_inner_ip_header_of_split_packet(
    struct SplittingContext* pctx,
    struct vr_ip* fragment_inner_ip_header,
    bool more_new_packets)
{
    unsigned short inner_ip_packet_length =
        pctx->inner_headers_size - pctx->inner_eth_header_size;

    if (more_new_packets) {
        inner_ip_packet_length += pctx->maximum_inner_payload_length;
    } else {
        inner_ip_packet_length += pctx->total_payload_size
            % pctx->maximum_inner_payload_length;
    }

    fragment_inner_ip_header->ip_len = htons(inner_ip_packet_length);
}

static void
fix_csum_in_ip_header(struct vr_ip* iph)
{
    iph->ip_csum = vr_ip_csum(iph);
}

static void
fix_headers_of_inner_split_packet(
    struct SplittingContext* pctx,
    unsigned char* headers,
    bool more_new_packets,
    unsigned short* byte_offset_for_next_inner_ip_header)
{
    struct vr_ip* fragment_inner_ip_header = (struct vr_ip*)(headers
        + pctx->outer_headers_size + pctx->inner_eth_header_size);

    if (!pctx->is_tcp_segmentation) {
        // Fix 'more fragments' in inner IP header.
        if (more_new_packets || pctx->inner_ip_mf) {
            fragment_inner_ip_header->ip_frag_off |= htons(VR_IP_MF);
        }

        // Fix 'fragment offset' in inner IP header.
        set_fragment_offset(fragment_inner_ip_header,
            *byte_offset_for_next_inner_ip_header);
        *byte_offset_for_next_inner_ip_header
            += pctx->maximum_inner_payload_length;
    }

    fix_packet_length_in_inner_ip_header_of_split_packet(
        pctx, fragment_inner_ip_header, more_new_packets);
    fix_csum_in_ip_header(fragment_inner_ip_header);
}

static void
fix_headers_of_outer_split_packet(
    struct SplittingContext* pctx,
    unsigned char* headers)
{
    struct vr_ip* fragment_inner_ip_header = (struct vr_ip*)(headers
        + pctx->outer_headers_size + pctx->inner_eth_header_size);
    struct vr_ip* fragment_outer_ip_header = (struct vr_ip*)(headers
            + sizeof(struct vr_eth));

    // Fix packet length in outer IP header.
    unsigned short outer_ip_len = pctx->outer_headers_size - sizeof(struct vr_eth) +
        ntohs(fragment_inner_ip_header->ip_len) + pctx->inner_eth_header_size;
    fragment_outer_ip_header->ip_len = htons(outer_ip_len);

    // Fix packet length in outer UDP header.
    if (fragment_outer_ip_header->ip_proto == VR_IP_PROTO_UDP) {
        struct vr_udp* outer_udp_header =
            (struct vr_udp*)get_next_header_after_ip(fragment_outer_ip_header);

        outer_udp_header->udp_length = htons(outer_ip_len -
            fragment_outer_ip_header->ip_hl * 4);
    }

    fix_csum_in_ip_header(fragment_outer_ip_header);
}

static void
remove_split_nbl(struct SplittingContext* pctx)
{
    PWIN_PACKET_RAW originalRawPacket = WinPacketToRawPacket(pctx->original_pkt);
    PWIN_PACKET_RAW splitRawPacket = WinMultiPacketToRawPacket(pctx->split_pkt);

    WinPacketRawFreeMultiFragment(splitRawPacket);
    pctx->split_pkt = NULL;

    WinPacketRawDecrementChildCountOf(originalRawPacket);
}

static bool
fill_csum_of_inner_tcp_packet_provided_that_partial_csum_is_computed(
    PWIN_SUB_PACKET SubPacket,
    unsigned inner_ip_offset_in_nb)
{
    ULONG packetDataSize = WinSubPacketRawDataLength(SubPacket);
    PVOID packetDataBuff = WinRawAllocate(packetDataSize);

    uint8_t* packetData = WinSubPacketRawGetDataBuffer(
        SubPacket, packetDataBuff, packetDataSize);

    if (packetData == NULL)
        return false;

    fill_csum_of_tcp_packet_provided_that_partial_csum_is_computed(
        packetData + inner_ip_offset_in_nb);

    if (packetDataBuff)
        ExFreePool(packetDataBuff);

    return true;
}

static void
fill_partial_csum_of_inner_tcp_packet(
    struct SplittingContext* pctx,
    struct vr_tcp* inner_tcp_header,
    unsigned char* headers)
{
    struct vr_ip* inner_ip_header = (struct vr_ip*)(headers +
        ((uint8_t *)pctx->inner_ip_header - (uint8_t *)pctx->outer_headers));
    fill_partial_csum_of_tcp_packet(inner_ip_header, inner_tcp_header);
}

static void
fill_checksum_of_inner_tcp_packet(
    struct SplittingContext* pctx,
    PWIN_SUB_PACKET SubPacket,
    unsigned char* headers)
{
    struct vr_tcp* inner_tcp_header =
        (struct vr_tcp*) (headers + pctx->tcp_header_offset);

    fill_partial_csum_of_inner_tcp_packet(pctx, inner_tcp_header, headers);
    fill_csum_of_inner_tcp_packet_provided_that_partial_csum_is_computed(
        SubPacket, (uint8_t*)pctx->inner_ip_header
        - (uint8_t*)pctx->outer_headers);
}

static void
fix_headers_of_inner_tcp_packet(
    struct SplittingContext* pctx,
    PWIN_SUB_PACKET SubPacket,
    unsigned char *headers,
    unsigned int byte_offset_for_next_inner_tcp_header,
    bool more_new_packets)
{
    struct vr_tcp* inner_tcp_header =
        (struct vr_tcp*) (headers + pctx->tcp_header_offset);
    inner_tcp_header->tcp_seq = htonl(byte_offset_for_next_inner_tcp_header);

    uint16_t flags = ntohs(inner_tcp_header->tcp_offset_r_flags);

    if (more_new_packets) {
        flags &= ~VR_TCP_FLAG_FIN & ~VR_TCP_FLAG_PSH;
    }

    inner_tcp_header->tcp_offset_r_flags = htons(flags);

    fill_checksum_of_inner_tcp_packet(pctx, SubPacket, headers);
}

static unsigned int
get_initial_segment_offset_for_inner_tcp_header(
    struct SplittingContext* pctx)
{
    struct vr_tcp* inner_tcp_header =
        (struct vr_tcp*) (pctx->outer_headers + pctx->tcp_header_offset);
    return ntohl(inner_tcp_header->tcp_seq);
}

static void
fix_headers_of_new_packets(struct SplittingContext* pctx)
{
    PWIN_PACKET_RAW originalRawPacket = WinPacketToRawPacket(pctx->original_pkt);
    PWIN_PACKET_RAW splitRawPacket = WinMultiPacketToRawPacket(pctx->split_pkt);

    PWIN_SUB_PACKET curSubPkt;
    PWIN_SUB_PACKET nextSubPkt;

    // Disable checksum calculation offloading, so it doesn't interefere
    // with our checksum calculation.
    WinPacketRawClearChecksumInfo(splitRawPacket);

    unsigned short byte_offset_for_next_inner_ip_header
        = pctx->inner_ip_frag_offset_in_bytes;

    unsigned int segment_offset_for_next_inner_tcp_header = 0;
    if (pctx->is_tcp_segmentation) {
        segment_offset_for_next_inner_tcp_header
            = get_initial_segment_offset_for_inner_tcp_header(pctx);
    }

    for (curSubPkt = WinPacketRawGetFirstSubPacket(splitRawPacket);
            curSubPkt != NULL;
            curSubPkt = nextSubPkt) {
        nextSubPkt = WinSubPacketRawGetNext(curSubPkt);

        WinPacketRawCopyHeadersToSubPacket(curSubPkt, originalRawPacket, pctx->inner_payload_offset);

        unsigned char* headers = WinSubPacketRawGetDataPtr(curSubPkt);
        if (headers == NULL) {
            remove_split_nbl(pctx);
            return;
        }

        bool more_new_packets = (nextSubPkt != NULL);
        fix_headers_of_inner_split_packet(
            pctx,
            headers,
            more_new_packets,
            &byte_offset_for_next_inner_ip_header);
        if (pctx->is_tcp_segmentation) {
            fix_headers_of_inner_tcp_packet(
                pctx,
                curSubPkt,
                headers,
                segment_offset_for_next_inner_tcp_header,
                more_new_packets);
            segment_offset_for_next_inner_tcp_header
                += pctx->maximum_inner_payload_length;
        }
        fix_headers_of_outer_split_packet(pctx, headers);
    }
}

PWIN_MULTI_PACKET
split_packet_if_needed(struct vr_packet *pkt)
{
    struct SplittingContext ctx;
    initialize_splitting_context(&ctx, pkt);

    if (!is_splitting_needed(&ctx)) {
        return (PWIN_MULTI_PACKET)WinPacketToRawPacket(ctx.original_pkt);
    }

    extract_headers_from_original_packet(&ctx);
    split_original_packet(&ctx);

    if (ctx.split_pkt != NULL) {
        fix_headers_of_new_packets(&ctx);
    }

    return ctx.split_pkt;
}
