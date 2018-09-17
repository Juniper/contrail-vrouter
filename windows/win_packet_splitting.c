/*
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */
#include "precomp.h"

#include "vr_interface.h"
#include "vr_packet.h"
#include "vr_windows.h"
#include "vr_mpls.h"
#include "vrouter.h"

#include "win_packet.h"
#include "win_packet_raw.h"
#include "win_packet_impl.h"
#include "windows_devices.h"
#include "windows_nbl.h"
#include "win_csum.h"

struct SplittingContext {
    struct vr_packet *pkt;
    PNET_BUFFER_LIST original_nbl;
    PNET_BUFFER_LIST split_nbl;
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

    PWIN_PACKET winPacket = GetWinPacketFromVrPacket(pkt);
    PWIN_PACKET_RAW winPacketRaw = WinPacketToRawPacket(winPacket);
    pctx->original_nbl = WinPacketRawToNBL(winPacketRaw);
}

static inline bool
is_splitting_needed(struct SplittingContext *pctx)
{
    return vr_pkt_type_is_overlay(pctx->pkt->vp_type)
        && NET_BUFFER_DATA_LENGTH(pctx->original_nbl->FirstNetBuffer)
        > pctx->mtu;
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
    pctx->split_nbl->SourceHandle = VrSwitchObject->NdisFilterHandle;

    if (CreateForwardingContext(pctx->split_nbl) != NDIS_STATUS_SUCCESS) {
        return false;
    }

    NDIS_STATUS status
        = VrSwitchObject->NdisSwitchHandlers.CopyNetBufferListInfo(
        VrSwitchObject->NdisSwitchContext, pctx->split_nbl,
        pctx->original_nbl, 0);
    if (status != NDIS_STATUS_SUCCESS) {
        FreeForwardingContext(pctx->split_nbl);
        return false;
    }

    pctx->split_nbl->ParentNetBufferList = pctx->original_nbl;
    InterlockedIncrement(&pctx->original_nbl->ChildRefCount);
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

PNET_BUFFER_LIST
split_original_nbl(struct SplittingContext* pctx)
{
    return NdisAllocateFragmentNetBufferList(
        pctx->original_nbl,
        VrNBLPool,
        VrNBPool,
        pctx->inner_payload_offset,
        pctx->maximum_inner_payload_length,
        pctx->inner_payload_offset,
        0,
        0
    );
}

static void
split_original_packet(struct SplittingContext* pctx)
{
    calculate_maximum_inner_payload_length_for_new_packets(pctx);

    pctx->split_nbl = split_original_nbl(pctx);
    if (pctx->split_nbl == NULL) {
        return;
    }

    ASSERTMSG(
        "split_original_packet: It is expected that all headers are in first MDL",
        pctx->split_nbl->FirstNetBuffer != NULL &&
        MmGetMdlByteCount(pctx->split_nbl->FirstNetBuffer->CurrentMdl)
        - pctx->split_nbl->FirstNetBuffer->CurrentMdlOffset
        == pctx->inner_payload_offset);

    if (!fix_split_packet_metadata(pctx)) {
        NdisFreeFragmentNetBufferList(pctx->split_nbl,
            pctx->inner_payload_offset, 0);
        pctx->split_nbl = NULL;
    }
}

static void
copy_original_headers_to_net_buffer(
    struct SplittingContext* pctx,
    PNET_BUFFER nb)
{
    unsigned long bytes_copied = 0;
    NDIS_STATUS status = NdisCopyFromNetBufferToNetBuffer(
        nb,
        0,
        pctx->inner_payload_offset,
        pctx->original_nbl->FirstNetBuffer,
        0,
        &bytes_copied
    );

    // Failure may occur only due to error in fragmentation logic.
    // New resources are not allocated in NdisCopyFromNetBufferToNetBuffer.
    ASSERTMSG(
        "copy_original headers_to_net_buffer: NdisCopyFromNetBufferToNetBuffer"
        " failed",
        status == NDIS_STATUS_SUCCESS
        && bytes_copied == pctx->inner_payload_offset);
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

static unsigned char*
get_split_packet_headers(PNET_BUFFER nb)
{
    return (unsigned char*) MmGetSystemAddressForMdlSafe(
        nb->CurrentMdl, LowPagePriority | MdlMappingNoExecute)
        + nb->CurrentMdlOffset;
}

static void
remove_split_nbl(struct SplittingContext* pctx)
{
    FreeForwardingContext(pctx->split_nbl);
    NdisFreeFragmentNetBufferList(pctx->split_nbl,
        pctx->inner_payload_offset, 0);
    pctx->split_nbl = NULL;
    InterlockedDecrement(&pctx->original_nbl->ChildRefCount);
}

static bool
fill_csum_of_inner_tcp_packet_provided_that_partial_csum_is_computed(
    PNET_BUFFER nb,
    unsigned inner_ip_offset_in_nb,
    struct vr_tcp* inner_tcp_header)
{
    uint32_t csum;
    uint16_t size;
    uint8_t type;

    void* packet_data_buffer = ExAllocatePoolWithTag(
        NonPagedPoolNx, NET_BUFFER_DATA_LENGTH(nb), VrAllocationTag);
    uint8_t* packet_data = NdisGetDataBuffer(
        nb, NET_BUFFER_DATA_LENGTH(nb), packet_data_buffer, 1, 0);

    if (packet_data == NULL)
        return false;

    struct vr_ip *hdr = (struct vr_ip*) &packet_data[inner_ip_offset_in_nb];
    unsigned inner_tcp_offset_in_nb = inner_ip_offset_in_nb + hdr->ip_hl * 4;
    size = ntohs(hdr->ip_len) - 4 * hdr->ip_hl;

    type = hdr->ip_proto;

    uint8_t* payload = &packet_data[inner_tcp_offset_in_nb];
    csum = calc_csum(payload, size);
    inner_tcp_header->tcp_csum = htons(~(trim_csum(csum)));

    if (packet_data_buffer)
        ExFreePool(packet_data_buffer);

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
    PNET_BUFFER cur_nb,
    unsigned char* headers)
{
    struct vr_tcp* inner_tcp_header =
        (struct vr_tcp*) (headers + pctx->tcp_header_offset);

    fill_partial_csum_of_inner_tcp_packet(pctx, inner_tcp_header, headers);
    fill_csum_of_inner_tcp_packet_provided_that_partial_csum_is_computed(
        cur_nb, (uint8_t*)pctx->inner_ip_header
        - (uint8_t*)pctx->outer_headers,
        inner_tcp_header);
}

static void
fix_headers_of_inner_tcp_packet(
    struct SplittingContext* pctx,
    PNET_BUFFER cur_nb,
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

    fill_checksum_of_inner_tcp_packet(pctx, cur_nb, headers);
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
disable_csum_calculation_offloading_for_outer_split_packets(
    struct SplittingContext* pctx)
{
    NET_BUFFER_LIST_INFO(pctx->split_nbl, TcpIpChecksumNetBufferListInfo)
        = 0;
}

static void
fix_headers_of_new_packets(struct SplittingContext* pctx)
{
    PNET_BUFFER cur_nb;
    PNET_BUFFER next_nb;

    // Disable checksum calculation offloading, so it doesn't interefere
    // with our checksum calculation.
    disable_csum_calculation_offloading_for_outer_split_packets(pctx);

    unsigned short byte_offset_for_next_inner_ip_header
        = pctx->inner_ip_frag_offset_in_bytes;

    unsigned int segment_offset_for_next_inner_tcp_header = 0;
    if (pctx->is_tcp_segmentation) {
        segment_offset_for_next_inner_tcp_header
            = get_initial_segment_offset_for_inner_tcp_header(pctx);
    }

    for (cur_nb = pctx->split_nbl->FirstNetBuffer;
            cur_nb != NULL;
            cur_nb = next_nb) {
        next_nb = cur_nb->Next;

        copy_original_headers_to_net_buffer(pctx, cur_nb);

        unsigned char* headers = get_split_packet_headers(cur_nb);
        if (headers == NULL) {
            remove_split_nbl(pctx);
            return;
        }

        bool more_new_packets = (next_nb != NULL);
        fix_headers_of_inner_split_packet(
            pctx,
            headers,
            more_new_packets,
            &byte_offset_for_next_inner_ip_header);
        if (pctx->is_tcp_segmentation) {
            fix_headers_of_inner_tcp_packet(
                pctx,
                cur_nb,
                headers,
                segment_offset_for_next_inner_tcp_header,
                more_new_packets);
            segment_offset_for_next_inner_tcp_header
                += pctx->maximum_inner_payload_length;
        }
        fix_headers_of_outer_split_packet(pctx, headers);
    }
}

PNET_BUFFER_LIST
split_packet_if_needed(struct vr_packet *pkt)
{
    struct SplittingContext ctx;
    initialize_splitting_context(&ctx, pkt);

    if (!is_splitting_needed(&ctx)) {
        return ctx.original_nbl;
    }

    extract_headers_from_original_packet(&ctx);
    split_original_packet(&ctx);

    if (ctx.split_nbl != NULL) {
        fix_headers_of_new_packets(&ctx);
    }

    return ctx.split_nbl;
}
