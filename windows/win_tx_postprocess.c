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

static void
fix_ip_csum_at_offset(struct vr_packet *pkt, unsigned offset)
{
    struct vr_ip *iph;

    WinAssert(0 < offset);

    iph = (struct vr_ip *)(pkt_data(pkt) + offset);
    iph->ip_csum = vr_ip_csum(iph);
}

static void
zero_ip_csum_at_offset(struct vr_packet *pkt, unsigned offset)
{
    struct vr_ip *iph;

    WinAssert(0 < offset);

    iph = (struct vr_ip *)(pkt_data(pkt) + offset);
    iph->ip_csum = 0;
}

static bool fix_csum(struct vr_packet *pkt, unsigned offset)
{
    uint32_t csum;
    uint16_t size;
    uint8_t type;

    PWIN_PACKET winPacket = GetWinPacketFromVrPacket(pkt);
    PWIN_PACKET_RAW winPacketRaw = WinPacketToRawPacket(winPacket);

    ULONG packet_data_size = WinPacketRawDataLength(winPacketRaw);
    void *packet_data_buffer = WinRawAllocate(packet_data_size);

    // Copy the packet. This function will not fail if ExAllocatePoolWithTag succeeded
    // So no need to clean it up
    // If ExAllocatePoolWithTag failed (packet_data_buffer== NULL),
    // this function will work okay if the data is contigous.
    uint8_t* packet_data = WinPacketRawGetDataBuffer(winPacketRaw, packet_data_buffer, packet_data_size);

    if (packet_data == NULL)
        // No need for free
        return false;

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
        udp->udp_csum = htons(~(trim_csum(csum)));
    } else if (type == VR_IP_PROTO_TCP) {
        struct vr_tcp* tcp = (struct vr_tcp*) win_data_at_offset(pkt, offset);
        tcp->tcp_csum = htons(~(trim_csum(csum)));
    }

    if (packet_data_buffer)
        WinRawFree(packet_data_buffer);

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
            WinPacketRawClearTcpChecksumFlags(winPacketRaw);
        }
        // else try to offload it even though it's tunneled.
    }

    if (WinPacketRawShouldUdpChecksumBeOffloaded(winPacketRaw)) {
        // Calculate the header/data csum and turn off HW acceleration
        if (fix_csum(pkt, pkt->vp_inner_network_h)) {
            WinPacketRawClearUdpChecksumFlags(winPacketRaw);
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
        WinPacketRawClearChecksumInfo(winPacketRaw);
    } else {
        // This packet comes from a container or the agent,
        // therefore we should look at settings.Transmit.
        if (WinPacketRawShouldIpChecksumBeOffloaded(winPacketRaw)) {
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
    if (vr_pkt_type_is_overlay(VrPacket->vp_type)) {
        fix_tunneled_csum(VrPacket);
    } else if (VrPacket->vp_type == VP_TYPE_IP) {
        // There's no checksum in IPv6 header.
        fix_ip_v4_csum(VrPacket);
    }

    PWIN_PACKET winPacket = GetWinPacketFromVrPacket(VrPacket);
    PWIN_PACKET_RAW winPacketRaw = WinPacketToRawPacket(winPacket);
    PWIN_MULTI_PACKET multiPacket = (PWIN_MULTI_PACKET)winPacketRaw;

    // TODO: Make compilable
    #if 0
    PWIN_MULTI_PACKET fragmentedPacket = split_packet_if_needed(VrPacket);
    if (fragmentedPacket != NULL) {
        multiPacket = fragmentedPacket;
    }
    #endif

    return multiPacket;
}
