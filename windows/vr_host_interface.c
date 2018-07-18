/*
 * Copyright (c) 2017 Juniper Networks, Inc. All rights reserved.
 */
#include "precomp.h"

#include "vr_interface.h"
#include "vr_packet.h"
#include "vr_windows.h"
#include "vrouter.h"

#include "win_packet.h"
#include "windows_devices.h"
#include "windows_nbl.h"

static NDIS_MUTEX win_if_mutex;

void
win_if_lock(void)
{
    NDIS_WAIT_FOR_MUTEX(&win_if_mutex);
}

void
win_if_unlock(void)
{
    NDIS_RELEASE_MUTEX(&win_if_mutex);
}

static int
win_if_add(struct vr_interface* vif)
{
    if (vif->vif_type == VIF_TYPE_STATS)
        return 0;

    if (vif->vif_name[0] == '\0')
        return -ENODEV;

    // Unlike FreeBSD/Linux, we don't have to register handlers here

    return 0;
}

static int
win_if_add_tap(struct vr_interface* vif)
{
    UNREFERENCED_PARAMETER(vif);
    // NOOP - no bridges on Windows
    return 0;
}

static int
win_if_del(struct vr_interface *vif)
{
    UNREFERENCED_PARAMETER(vif);
    return 0;
}

static int
win_if_del_tap(struct vr_interface *vif)
{
    UNREFERENCED_PARAMETER(vif);
    // NOOP - no bridges on Windows; most *_drv_del function which call if_del_tap
    // also call if_del
    return 0;
}

static uint16_t
trim_csum(uint32_t csum)
{
    while (csum & 0xffff0000)
        csum = (csum >> 16) + (csum & 0x0000ffff);

    return (uint16_t)csum;
}

static uint16_t
calc_csum(uint8_t* ptr, size_t size)
{
    uint32_t csum = 0;
    // Checksum based on payload
    for (int i = 0; i < size; i++)
    {
        if (i & 1)
            csum += ptr[i];
        else
            csum += ptr[i] << 8;
    }

    return trim_csum(csum);
}

static void
fix_ip_csum_at_offset(struct vr_packet *pkt, unsigned offset)
{
    struct vr_ip *iph;

    ASSERT(0 < offset);

    iph = (struct vr_ip *)pkt_data_at_offset(pkt, offset);
    iph->ip_csum = vr_ip_csum(iph);
}

static void
zero_ip_csum_at_offset(struct vr_packet *pkt, unsigned offset)
{
    struct vr_ip *iph;

    ASSERT(0 < offset);

    iph = (struct vr_ip *)pkt_data_at_offset(pkt, offset);
    iph->ip_csum = 0;
}

static bool fix_csum(struct vr_packet *pkt, unsigned offset)
{
    uint32_t csum;
    uint16_t size;
    uint8_t type;

    PWIN_PACKET winPacket = GetWinPacketFromVrPacket(pkt);
    PNET_BUFFER_LIST nbl = WinPacketToNBL(winPacket);
    PNET_BUFFER nb = NET_BUFFER_LIST_FIRST_NB(nbl);

    void* packet_data_buffer = ExAllocatePoolWithTag(NonPagedPoolNx, NET_BUFFER_DATA_LENGTH(nb), VrAllocationTag);

    // Copy the packet. This function will not fail if ExAllocatePoolWithTag succeeded
    // So no need to clean it up
    // If ExAllocatePoolWithTag failed (packet_data_buffer== NULL),
    // this function will work okay if the data is contigous.
    uint8_t* packet_data = NdisGetDataBuffer(nb, NET_BUFFER_DATA_LENGTH(nb), packet_data_buffer, 1, 0);

    if (packet_data == NULL)
        // No need for free
        return false;

    if (pkt->vp_type == VP_TYPE_IP6 || pkt->vp_type == VP_TYPE_IP6OIP) {
        struct vr_ip6 *hdr = (struct vr_ip6*) (packet_data + offset);
        offset += sizeof(struct vr_ip6);
        size = ntohs(hdr->PayloadLength);

        type = hdr->NextHeader;
    } else {
        struct vr_ip *hdr = (struct vr_ip*) &packet_data[offset];
        offset += hdr->ip_hl * 4;
        size = ntohs(hdr->ip_len) - 4 * hdr->ip_hl;

        type = hdr->ip_proto;
    }

    uint8_t* payload = &packet_data[offset];
    csum = calc_csum((uint8_t*) payload, size);

    // This time it's the "real" packet. Header being contiguous is guaranteed, but nothing else
    if (type == VR_IP_PROTO_UDP) {
        struct vr_udp* udp = (struct vr_udp*) pkt_data_at_offset(pkt, offset);
        udp->udp_csum = htons(~(trim_csum(csum)));
    } else if (type == VR_IP_PROTO_TCP) {
        struct vr_tcp* tcp = (struct vr_tcp*) pkt_data_at_offset(pkt, offset);
        tcp->tcp_csum = htons(~(trim_csum(csum)));
    }

    if (packet_data_buffer)
        ExFreePool(packet_data_buffer);

    return true;
}

static void
fix_tunneled_csum(struct vr_packet *pkt)
{
    PWIN_PACKET winPacket = GetWinPacketFromVrPacket(pkt);
    PNET_BUFFER_LIST nbl = WinPacketToNBL(winPacket);
    NDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO settings;
    settings.Value = NET_BUFFER_LIST_INFO(nbl, TcpIpChecksumNetBufferListInfo);

    if (settings.Transmit.IpHeaderChecksum) {
        // Zero the outer checksum, it'll be offloaded
        zero_ip_csum_at_offset(pkt, sizeof(struct vr_eth));
        // Fix the inner checksum, it will not be offloaded
        fix_ip_csum_at_offset(pkt, pkt->vp_inner_network_h);
    } else {
        // Fix the outer checksum
        fix_ip_csum_at_offset(pkt, sizeof(struct vr_eth));
        // Inner checksum is OK
    }

    if (settings.Transmit.TcpChecksum) {
        // Calculate the header/data csum and turn off HW acceleration
        if (fix_csum(pkt, pkt->vp_inner_network_h)) {
            settings.Transmit.TcpChecksum = 0;
            settings.Transmit.TcpHeaderOffset = 0;
            NET_BUFFER_LIST_INFO(nbl, TcpIpChecksumNetBufferListInfo) = settings.Value;
        }
        // else try to offload it even though it's tunneled.
    }

    if (settings.Transmit.UdpChecksum) {
        // Calculate the header/data csum and turn off HW acceleration
        if (fix_csum(pkt, pkt->vp_inner_network_h)) {
            settings.Transmit.UdpChecksum = 0;
            NET_BUFFER_LIST_INFO(nbl, TcpIpChecksumNetBufferListInfo) = settings.Value;
        }
        // else try to offload it even though it's tunneled.
    }
}

// If computation of IP checksum is about to be offloaded, its value
// should be set to zero (because initial checksum's value is taken into
// account when computing the checksum). However, dp-core doesn't care about
// this specific case (e.g. vr_incremental_diff/vr_ip_incremental_csum are
// called to incrementally "improve" checksum).
static void
fix_ip_v4_csum_to_be_offloaded(struct vr_packet *pkt) {
    PWIN_PACKET winPacket = GetWinPacketFromVrPacket(pkt);
    PNET_BUFFER_LIST nbl = WinPacketToNBL(winPacket);
    NDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO settings;
    settings.Value = NET_BUFFER_LIST_INFO(nbl, TcpIpChecksumNetBufferListInfo);

    if (settings.Transmit.IpHeaderChecksum) {
        zero_ip_csum_at_offset(pkt, sizeof(struct vr_eth));
    }
}

/////////////////////////////////////////////////////////////////////
// IP FRAGMENTATION POC

struct POC_FragmentationContext {
    struct vr_packet *pkt;
    PNET_BUFFER_LIST original_nbl;
    PNET_BUFFER_LIST fragmented_nbl;
    int mtu;

    // Original packet.
    unsigned char* outer_headers;
    struct vr_ip* outer_ip_header;
    struct vr_ip* inner_ip_header;

    // Size for outer and inner headers is the same in original packet and
    // in all new packets (fragments).
    int outer_headers_size;
    int inner_headers_size;

    // Payload offset in original packet (excluding all headers).
    int inner_payload_offset;

    // Payload size of original packet (excluding all headers).
    int total_payload_size;

    // 'More fragments' flag from original inner IP header.
    bool inner_ip_mf;

    // Fragment offset from original inner IP header.
    unsigned short inner_ip_byte_offset;

    // Free space for payload in inner fragmented IP packet. It takes into
    // account size of all headers (inner and outer) and MTU.
    int free_space_for_inner_payload;

    // Maximum size of payload in inner fragmented IP packet. It takes into
    // account size of all headers (inner and outer) and MTU. Additionally
    // maximum_inner_payload_length % 8 == 0 as required in fragment offset
    // definition.
    int maximum_inner_payload_length;
};

#define MAX_HEADERS_SIZE 1000
#define MPLS_HEADER_SIZE 4
#define VXLAN_HEADER_SIZE 8
#define VXLAN_DST_PORT 4789

void POC_InitializeContext(
        struct POC_FragmentationContext* pctx,
        struct vr_packet *pkt) {
    RtlZeroMemory(pctx, sizeof(struct POC_FragmentationContext));
    pctx->pkt = pkt;
    pctx->mtu = pkt->vp_if->vif_mtu;

    PWIN_PACKET winPacket = GetWinPacketFromVrPacket(pkt);
    // TODO will be needed once code refactoring is merged
    // PWIN_PACKET_RAW winPacketRaw = WinPacketToRawPacket(winPacket);
    // pctx->original_nbl = WinPacketRawToNBL(winPacketRaw);
    // pctx->original_nbl = WinPacketToNBL(winPacketRaw);
    pctx->original_nbl = WinPacketToNBL(winPacket);
}

bool POC_IsFragmentationNeeded(struct POC_FragmentationContext* pctx) {
    return vr_pkt_type_is_overlay(pctx->pkt->vp_type)
        && pctx->original_nbl->FirstNetBuffer->DataLength > pctx->mtu;
}

void POC_ExtractOuterHeadersFromOriginalPacket(struct POC_FragmentationContext* pctx) {
    pctx->outer_headers = pctx->pkt->vp_head + pctx->pkt->vp_data;
    pctx->outer_ip_header = (struct vr_ip*)(pctx->outer_headers
        + sizeof(struct vr_eth));

    pctx->outer_headers_size = sizeof(struct vr_eth) + sizeof(struct vr_ip);
    if (pctx->outer_ip_header->ip_proto == VR_IP_PROTO_GRE) {
        pctx->outer_headers_size += sizeof(struct vr_gre) + MPLS_HEADER_SIZE ;
    } else if (pctx->outer_ip_header->ip_proto == VR_IP_PROTO_UDP) {
        pctx->outer_headers_size += sizeof(struct vr_udp);
        struct vr_udp* outer_udp_header = (struct vr_udp*)(
            pctx->outer_headers + sizeof(struct vr_eth) + sizeof(struct vr_ip));
        if (ntohs(outer_udp_header->udp_dport) == VXLAN_DST_PORT) {
            pctx->outer_headers_size += VXLAN_HEADER_SIZE;
        } else {
            pctx->outer_headers_size += MPLS_HEADER_SIZE;
        }
    }
}

void POC_ExtractInnerHeadersFromOriginalPacket(
        struct POC_FragmentationContext* pctx) {
    pctx->inner_ip_header = (struct vr_ip*)(pctx->outer_headers
        + pctx->outer_headers_size + sizeof(struct vr_eth));

    // Determine inner header size: eth, ip.
    // What about IPv6? We don't care in POC.
    // We also assume that IP header has constant size (which is not true).
    pctx->inner_headers_size = sizeof(struct vr_eth) + sizeof(struct vr_ip);
    pctx->inner_payload_offset = pctx->outer_headers_size
        + pctx->inner_headers_size;
    pctx->total_payload_size = sizeof(struct vr_eth)
        + ntohs(pctx->outer_ip_header->ip_len) - pctx->inner_payload_offset;

    // Extract inner fragmentation flags and offset.
    pctx->inner_ip_mf = ntohs(pctx->inner_ip_header->ip_frag_off)
        & VR_IP_MF;
    pctx->inner_ip_byte_offset = (ntohs(pctx->inner_ip_header->ip_frag_off)
        & VR_IP_FRAG_OFFSET_MASK) * 8;
}

void POC_SplitOriginalPacket(struct POC_FragmentationContext* pctx) {
    // Note: fragment offset in IP header actually means amount of 8-byte
    // blocks. It means that 'payload size' % 8 == 0 for each packet with
    // 'more fragments' flag set to true.
    pctx->free_space_for_inner_payload = pctx->mtu - pctx->inner_payload_offset;
    pctx->maximum_inner_payload_length
        = pctx->free_space_for_inner_payload & ~7;

    PNET_BUFFER_LIST fragmented_nbl = NdisAllocateFragmentNetBufferList(
        pctx->original_nbl,
        VrNBLPool,
        VrNBPool,
        pctx->inner_payload_offset,
        pctx->maximum_inner_payload_length,
        pctx->inner_payload_offset,
        0,
        0
    );

    pctx->fragmented_nbl->ParentNetBufferList = pctx->original_nbl;
    InterlockedIncrement(&pctx->original_nbl->ChildRefCount);
}

bool POC_CopyHeadersToNetBuffer(
        struct POC_FragmentationContext* pctx,
        PNET_BUFFER nb) {
    unsigned long bytes_copied = 0;
    NDIS_STATUS status = NdisCopyFromNetBufferToNetBuffer(
        nb,
        0,
        pctx->inner_payload_offset,
        pctx->original_nbl->FirstNetBuffer,
        0,
        &bytes_copied
    );

    if (status != NDIS_STATUS_SUCCESS
            || bytes_copied != pctx->inner_payload_offset) {
        return false;
        // Failure.
        // Can't recover.
    }
    return true;
}

void POC_FixHeadersOfInnerFragmentedPacket(
        struct POC_FragmentationContext* pctx,
        unsigned char* headers,
        bool more_new_packets,
        unsigned short* byte_offset_for_next_inner_ip_header) {
    struct vr_ip* fragment_inner_ip_header = (struct vr_ip*)(headers
        + pctx->outer_headers_size + sizeof(struct vr_eth));

    // Fix 'more fragments' in inner IP header.
    if (more_new_packets || pctx->inner_ip_mf) {
        fragment_inner_ip_header->ip_frag_off |= htons(VR_IP_MF);
    }

    // Fix 'fragment offset' in inner IP header.
    fragment_inner_ip_header->ip_frag_off &= htons(~VR_IP_FRAG_OFFSET_MASK);
    fragment_inner_ip_header->ip_frag_off
        += htons(*byte_offset_for_next_inner_ip_header / 8);
    *byte_offset_for_next_inner_ip_header
        += pctx->maximum_inner_payload_length;

    // Fix packet length in inner IP header.
    fragment_inner_ip_header->ip_len = htons(sizeof(struct vr_ip)
        + (more_new_packets ? pctx->maximum_inner_payload_length
        : pctx->total_payload_size % pctx->maximum_inner_payload_length));

    // Fix checksum in inner IP header.
    unsigned short inner_csum = vr_ip_csum(fragment_inner_ip_header);
    fragment_inner_ip_header->ip_csum = htons(inner_csum);
}

void POC_FixHeadersOfOuterFragmentedPacket(
        struct POC_FragmentationContext* pctx,
        unsigned char* headers) {
    struct vr_ip* fragment_inner_ip_header = (struct vr_ip*)(headers
        + pctx->outer_headers_size + sizeof(struct vr_eth));
    struct vr_ip* fragment_outer_ip_header = (struct vr_ip*)(headers
            + sizeof(struct vr_eth));

    // Fix packet length in outer IP header.
    fragment_outer_ip_header->ip_len = htons(pctx->outer_headers_size
        + ntohs(fragment_inner_ip_header->ip_len));

    // Fix checksum in outer IP header.
    unsigned short outer_csum = vr_ip_csum(fragment_outer_ip_header);
    fragment_outer_ip_header->ip_csum = htons(outer_csum);
}

void POC_FixHeadersOfFragmentedPackets(struct POC_FragmentationContext* pctx) {
    PNET_BUFFER cur_nb;
    PNET_BUFFER next_nb;

    // TODO: use header_storage
    // char header_storage[MAX_HEADERS_SIZE];

    unsigned short byte_offset_for_next_inner_ip_header
        = pctx->inner_ip_byte_offset;
    for (cur_nb = pctx->fragmented_nbl->FirstNetBuffer;
            cur_nb != NULL;
            cur_nb = next_nb) {
        next_nb = cur_nb->Next;

        if(!POC_CopyHeadersToNetBuffer(pctx, cur_nb)) {
            // Big failure. Can't recover.
        }

        unsigned char* headers = NdisGetDataBuffer(
            cur_nb, pctx->inner_payload_offset, NULL /*header_storage*/, 1, 1);
        if (headers == NULL) {
            // Failure.
            // It actually means that new NB doesn't have all headers
            // in consistent block of memory.
            // Can be handled with header_storage (TODO).
        }

        POC_FixHeadersOfInnerFragmentedPacket(
            pctx,
            headers,
            next_nb != NULL,
            &byte_offset_for_next_inner_ip_header);
        POC_FixHeadersOfOuterFragmentedPacket(pctx, headers);

        // TODO
        //if (headers != header_storage) {
        //    copy to cur_nb from header_storage
        //}
    }
}

PNET_BUFFER_LIST POC_Fragment(struct vr_packet *pkt) {
    struct POC_FragmentationContext ctx;
    POC_InitializeContext(&ctx, pkt);
    if(!POC_IsFragmentationNeeded(&ctx)) {
        return ctx.original_nbl;
    }
    POC_ExtractOuterHeadersFromOriginalPacket(&ctx);
    POC_ExtractInnerHeadersFromOriginalPacket(&ctx);
    POC_SplitOriginalPacket(&ctx);
    POC_FixHeadersOfFragmentedPackets(&ctx);

    return ctx.fragmented_nbl;
}

/////////////////////////////////////////////////////////////////////

static int
__win_if_tx(struct vr_interface *vif, struct vr_packet *pkt)
{
    if (vr_pkt_type_is_overlay(pkt->vp_type))
        fix_tunneled_csum(pkt);
    else if(pkt->vp_type == VP_TYPE_IP) {
        // There's no checksum in IPv6 header.
        fix_ip_v4_csum_to_be_offloaded(pkt);
    }

    PWIN_PACKET winPacket = GetWinPacketFromVrPacket(pkt);
    PNET_BUFFER_LIST nbl = WinPacketToNBL(winPacket);

    NDIS_SWITCH_PORT_DESTINATION newDestination = { 0 };

    newDestination.PortId = vif->vif_port;
    newDestination.NicIndex = vif->vif_nic;
    DbgPrint("Adding target, PID: %u, NID: %u\r\n", newDestination.PortId, newDestination.NicIndex);

    VrSwitchObject->NdisSwitchHandlers.AddNetBufferListDestination(VrSwitchObject->NdisSwitchContext, nbl, &newDestination);

    PNDIS_SWITCH_FORWARDING_DETAIL_NET_BUFFER_LIST_INFO fwd = NET_BUFFER_LIST_SWITCH_FORWARDING_DETAIL(nbl);
    fwd->IsPacketDataSafe = TRUE;

    NdisAdvanceNetBufferListDataStart(nbl, pkt->vp_data, TRUE, NULL);

    nbl = POC_Fragment(pkt);

    ExFreePool(pkt);

    ASSERTMSG("Trying to pass non-leaf NBL to NdisFSendNetBufferLists", nbl->ChildRefCount == 0);

    NdisFSendNetBufferLists(VrSwitchObject->NdisFilterHandle,
        nbl,
        NDIS_DEFAULT_PORT_NUMBER,
        0);

    return 0;
}

static int
win_if_tx(struct vr_interface *vif, struct vr_packet* pkt)
{
    DbgPrint("%s: Got pkt\n", __func__);
    if (vif == NULL) {
        win_free_packet(pkt);
        return 0; // Sent into /dev/null
    }

    if (vif->vif_type == VIF_TYPE_AGENT)
        return pkt0_if_tx(vif, pkt);
    else
        return __win_if_tx(vif, pkt);
}

static int
win_if_rx(struct vr_interface *vif, struct vr_packet* pkt)
{
    DbgPrint("%s: Got pkt\n", __func__);

    // Since we are operating from virtual switch's PoV and not from OS's PoV, RXing is the same as TXing
    // On Linux, we receive the packet as an OS, but in Windows we are a switch to we simply push the packet to OS's networking stack
    // See vhost_tx for reference (it calls hif_ops->hif_rx)

    win_if_tx(vif, pkt);

    return 0;
}

static int
win_if_get_settings(struct vr_interface *vif, struct vr_interface_settings *settings)
{
    UNREFERENCED_PARAMETER(vif);
    UNREFERENCED_PARAMETER(settings);

    /* TODO: Implement */
    DbgPrint("%s(): dummy implementation called\n", __func__);

    return -EINVAL;
}

static unsigned int
win_if_get_mtu(struct vr_interface *vif)
{
    UNREFERENCED_PARAMETER(vif);

    /* TODO: Implement */
    DbgPrint("%s(): dummy implementation called\n", __func__);

    return vif->vif_mtu;
}

static unsigned short
win_if_get_encap(struct vr_interface *vif)
{
    UNREFERENCED_PARAMETER(vif);

    /* TODO: Implement */
    DbgPrint("%s(): dummy implementation called\n", __func__);

    return VIF_ENCAP_TYPE_ETHER;
}

static struct vr_host_interface_ops win_host_interface_ops = {
    .hif_lock           = win_if_lock,
    .hif_unlock         = win_if_unlock,
    .hif_add            = win_if_add,
    .hif_del            = win_if_del,
    .hif_add_tap        = win_if_add_tap,
    .hif_del_tap        = win_if_del_tap,
    .hif_tx             = win_if_tx,
    .hif_rx             = win_if_rx,
    .hif_get_settings   = win_if_get_settings,
    .hif_get_mtu        = win_if_get_mtu,
    .hif_get_encap      = win_if_get_encap,
    .hif_stats_update   = NULL,
};

void
vr_host_vif_init(struct vrouter *router)
{
    UNREFERENCED_PARAMETER(router);
}

void
vr_host_interface_exit(void)
{
    /* Noop */
}

void
vhost_xconnect(void)
{
    struct vrouter *vrouter = vrouter_get(0);
    struct vr_interface *host_if;

    if (vrouter->vr_host_if != NULL) {
        host_if = vrouter->vr_host_if;
        vif_set_xconnect(host_if);

        if (host_if->vif_bridge != NULL)
            vif_set_xconnect(host_if->vif_bridge);
    }
}

void
vhost_remove_xconnect(void)
{
    struct vrouter *vrouter = vrouter_get(0);
    struct vr_interface *host_if;

    if (vrouter->vr_host_if != NULL) {
        host_if = vrouter->vr_host_if;
        vif_remove_xconnect(host_if);

        if (host_if->vif_bridge != NULL)
            vif_remove_xconnect(host_if->vif_bridge);
    }
}

struct vr_host_interface_ops *
vr_host_interface_init(void)
{
    NDIS_INIT_MUTEX(&win_if_mutex);

    return &win_host_interface_ops;
}
