#include "win_tx_postprocess.h"

#include <basetsd.h>
#include <vr_packet.h>

#include "win_callbacks.h"
#include "win_assert.h"
#include "win_csum.h"
#include "win_memory.h"
#include "win_packet_impl.h"
#include "win_packet_raw.h"
#include "win_packet_splitting.h"
#include "win_packet.h"

#include "win_packetdump.h"

static void
fix_ip_csum_at_offset(struct vr_packet *pkt, unsigned offset)
{
    struct vr_ip *iph;

    WinAssert(0 < offset);

    iph = (struct vr_ip *)(pkt_data(pkt) + offset);
    fill_csum_of_ip_header(iph);
}

static void
zero_ip_csum_at_offset(struct vr_packet *pkt, unsigned offset)
{
    struct vr_ip *iph;

    WinAssert(0 < offset);

    iph = (struct vr_ip *)(pkt_data(pkt) + offset);
    iph->ip_csum = 0;
}

static bool
fix_csum(struct vr_packet *pkt, unsigned offset)
{
    uint32_t csum;
    uint16_t size;
    uint8_t type;

    PWIN_PACKET winPacket = GetWinPacketFromVrPacket(pkt);
    PWIN_PACKET_RAW winPacketRaw = WinPacketToRawPacket(winPacket);

    ULONG packet_data_size = WinPacketRawDataLength(winPacketRaw);
    void *packet_data_buffer = WinRawAllocate(packet_data_size);

    // If the data is in contiguous block but the WinRawAllocate
    // function failed this function will still work ok.
    uint8_t* packet_data = WinPacketRawGetDataBuffer(winPacketRaw, packet_data_buffer, packet_data_size);

    if (packet_data == NULL) {
        if (packet_data_buffer != NULL) {
            WinRawFree(packet_data_buffer);
        }
        return false;
    }

    if (pkt->vp_type == VP_TYPE_IP6 || pkt->vp_type == VP_TYPE_IP6OIP) {
        struct vr_ip6 *hdr = (struct vr_ip6*) (packet_data + offset);
        offset += sizeof(struct vr_ip6);
        size = ntohs(hdr->ip6_plen);

        type = hdr->ip6_nxt;
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
        struct vr_udp* udp = (struct vr_udp*) win_data_at_offset(pkt, offset);
        udp->udp_csum = csum;
    } else if (type == VR_IP_PROTO_TCP) {
        struct vr_tcp* tcp = (struct vr_tcp*) win_data_at_offset(pkt, offset);
        tcp->tcp_csum = csum;
    }

    if (packet_data_buffer) {
        WinRawFree(packet_data_buffer);
    }

    return true;
}

static void
fix_tunneled_csum(struct vr_packet *pkt)
{
    PWIN_PACKET winPacket = GetWinPacketFromVrPacket(pkt);
    PWIN_PACKET_RAW winPacketRaw = WinPacketToRawPacket(winPacket);

    if (WinPacketRawShouldIpChecksumBeOffloaded(winPacketRaw)) {
        // Zero the outer checksum, it'll be offloaded
        zero_ip_csum_at_offset(pkt, sizeof(struct vr_eth));
        // Fix the inner checksum, it will not be offloaded
        fix_ip_csum_at_offset(pkt, pkt->vp_inner_network_h);
    } else {
        // Fix the outer checksum
        fix_ip_csum_at_offset(pkt, sizeof(struct vr_eth));
        // Inner checksum is OK
    }

    if (WinPacketRawShouldTcpChecksumBeOffloaded(winPacketRaw)) {
        // Calculate the header/data csum and turn off HW acceleration
        if (fix_csum(pkt, pkt->vp_inner_network_h)) {
            WinPacketRawClearTcpChecksumOffloading(winPacketRaw);
        }
        // else try to offload it even though it's tunneled.
    }

    if (WinPacketRawShouldUdpChecksumBeOffloaded(winPacketRaw)) {
        // Calculate the header/data csum and turn off HW acceleration
        if (fix_csum(pkt, pkt->vp_inner_network_h)) {
            WinPacketRawClearUdpChecksumOffloading(winPacketRaw);
        }
        // else try to offload it even though it's tunneled.
    }
}

static void
fix_ip_v4_csum(struct vr_packet *pkt)
{
    PWIN_PACKET winPacket = GetWinPacketFromVrPacket(pkt);
    PWIN_PACKET_RAW winPacketRaw = WinPacketToRawPacket(winPacket);

    if (pkt->vp_data != 0) {
        // This packet came to us in a tunnel (which is now unwrapped),
        // therefore .Receive is now the active field of the settings union
        // (although we don't look at it as it refers to the outer headers anyway).
        // We assume all the checksums are valid, so we need to explicitly disable
        // offloading (so the .Receive field isn't erroneously reinterpreted as .Transmit)
        WinPacketRawClearChecksumOffloading(winPacketRaw);
    } else {
        // This packet comes from a container or the agent,
        // therefore we should look at settings.Transmit.
        //
        // WinPacketRawGetMSS(winPacketRaw) != 0 condition (below) handles
        // a situation when LSO is enabled. In such a case checksum should be
        // zeroed because it's going to be computed by NIC.
        // According to
        // https://docs.microsoft.com/en-us/windows-hardware/drivers/network/offloading-checksum-tasks :
        // "Turning off Address Checksum Offloads when Large Send Offload (LSO)
        // is enabled does not prevent the miniport driver from computing and
        // inserting checksums in the packets generated by the LSO feature."
        if (WinPacketRawShouldIpChecksumBeOffloaded(winPacketRaw)
            || WinPacketRawGetMSS(winPacketRaw) != 0) {
            // If computation of IP checksum is about to be offloaded, its value
            // should be set to zero (because initial checksum's value is taken into
            // account when computing the checksum). However, dp-core doesn't care about
            // this specific case (e.g. vr_incremental_diff/vr_ip_incremental_csum are
            // called to incrementally "improve" checksum).
            zero_ip_csum_at_offset(pkt, sizeof(struct vr_eth));
        } else {
            // No offloading requested - checksum should be valid.
        }
    }
}

PWIN_MULTI_PACKET
WinTxPostprocess(struct vr_packet *VrPacket)
{
    PacketToFileWriter(VrPacket, "before_postprocess");

    if (vr_pkt_type_is_overlay(VrPacket->vp_type)) {
        fix_tunneled_csum(VrPacket);
    } else if (VrPacket->vp_type == VP_TYPE_IP) {
        // There's no checksum in IPv6 header.
        fix_ip_v4_csum(VrPacket);
    }

    PWIN_PACKET winPacket = GetWinPacketFromVrPacket(VrPacket);
    PWIN_PACKET_RAW winPacketRaw = WinPacketToRawPacket(winPacket);
    PWIN_MULTI_PACKET multiPacket = (PWIN_MULTI_PACKET)winPacketRaw;

    PWIN_MULTI_PACKET fragmentedPacket = split_packet_if_needed(VrPacket);
    if (fragmentedPacket != NULL) {
        multiPacket = fragmentedPacket;
    }

    return multiPacket;
}
