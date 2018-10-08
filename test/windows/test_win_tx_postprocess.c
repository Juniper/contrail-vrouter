/*
 * test_win_tx_postprocess.c
 *
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>

#include <fake_win_packet.h>
#include <vr_packet.h>
#include <win_packet.h>
#include <win_packet_raw.h>
#include <win_tx_postprocess.h>

// TODO: Reuse; copy-pasted from test_win_pclone.c
static struct vr_packet *
AllocateVrPacketNonOwned(VOID)
{
    PVR_PACKET_WRAPPER pkt = test_calloc(1, sizeof(*pkt));
    pkt->WinPacket = Fake_WinPacketAllocateNonOwned();
    return &pkt->VrPacket;
}

// TODO: Reuse; copy-pasted from test_win_pclone.c
static VOID
FreeVrPacket(struct vr_packet * vrPkt)
{
    win_pfree(vrPkt, 0);
}

static int
Test_win_tx_pp_SetUp(void **state)
{
    return 0;
}

static int
Test_win_tx_pp_TearDown(void **state)
{
    return 0;
}

static void
Test_win_tx_pp_ArpPacket(void **state)
{
    PVR_PACKET_WRAPPER wrapper = test_calloc(1, sizeof(*wrapper));

    struct vr_packet *packet = &wrapper->VrPacket;
    packet->vp_type = VP_TYPE_ARP;

    PWIN_PACKET_RAW expected = NULL;
    PWIN_PACKET_RAW result = WinTxPostprocess(packet);
    assert_ptr_equal(result, expected);

    test_free(wrapper);
}

static void
Test_win_tx_pp_SmallIpUdpOverTunnelPacket(void **state)
{
    // NOTE: Assumption. Checksum is to be offloaded.

    uint8_t buffer[4096] = { 0 };
    uint8_t payload[] = {0x1, 0x2, 0x3, 0x4};

    struct vr_eth *outerEthHeader = (struct vr_eth *)(buffer);
    // TODO: Fill outer ethernet header.

    struct vr_ip *outerIpHeader = (struct vr_ip *)(outerEthHeader + 1);
    // TODO: Fill outer IP header.

    struct vr_gre *greHeader = (struct vr_gre *)(outerIpHeader + 1);
    // TODO: Fill GRE header.

    uint32_t *mplsHeader = (uint32_t *)(greHeader + 1);
    // TODO: Fill MPLS header.

    struct vr_eth *innerEthHeader = (struct vr_eth *)(mplsHeader + 1);
    {
        uint8_t smac[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x03};
        uint8_t dmac[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x04};

        VR_MAC_COPY(innerEthHeader->eth_dmac, dmac);
        VR_MAC_COPY(innerEthHeader->eth_smac, smac);
        innerEthHeader->eth_proto = htons(VR_ETH_PROTO_IP);
    }

    struct vr_ip *innerIpHeader = (struct vr_ip *)(innerEthHeader + 1);
    {
        innerIpHeader->ip_hl = 5;
        innerIpHeader->ip_version = 4;
        innerIpHeader->ip_tos = 0; // TODO: Fill accordingly
        innerIpHeader->ip_len = htons(32); // TODO: Fill accordingly
        innerIpHeader->ip_id = htons(0x5351); // TODO: Fill accordingly
        innerIpHeader->ip_frag_off = 0; // TODO: Fill accordingly
        innerIpHeader->ip_ttl = 128; // TODO: Fill accordingly
        innerIpHeader->ip_proto = VR_IP_PROTO_UDP;
        innerIpHeader->ip_csum = 0;
        // TODO: Byte ordering in ip_saddr and ip_daddr is wrong
        innerIpHeader->ip_saddr = htons(0x0a000003);
        innerIpHeader->ip_daddr = htons(0x0a000004);
    }

    struct vr_udp *innerUdpHeader = (struct vr_udp *)(innerIpHeader + 1);
    {
        innerUdpHeader->udp_sport = 11111;
        innerUdpHeader->udp_dport = 22222;
        innerUdpHeader->udp_length = sizeof(*innerUdpHeader) + ARRAYSIZE(payload);
        innerUdpHeader->udp_csum = 0;
    }

    intptr_t a = (intptr_t)(buffer);
    intptr_t b = (intptr_t)(innerUdpHeader + 1);
    ptrdiff_t d = b - a;
    assert_int_equal(d, 84);

    // NOTE: In this test case, IP/UDP offload requested
    // TODO: Fill vr_packet fields and bind buffers with the vrPacket.
    struct vr_packet *vrPacket = AllocateVrPacketNonOwned();
    vrPacket->vp_head = buffer;
    vrPacket->vp_if = NULL;
    vrPacket->vp_nh = NULL;
    vrPacket->vp_data = 0; // TODO: Fill
    vrPacket->vp_tail = 0; // TODO: Fill
    vrPacket->vp_len = 0; // TODO: Fill
    vrPacket->vp_end = 0; // TODO: Fill
    vrPacket->vp_network_h = 0; // TODO: Fill
    vrPacket->vp_flags = VP_FLAG_FLOW_SET;
    vrPacket->vp_inner_network_h = 0; // TODO: Fill
    vrPacket->vp_cpu = 0;
    vrPacket->vp_type = VP_TYPE_IPOIP;
    vrPacket->vp_ttl = 64;
    vrPacket->vp_queue = 0;
    vrPacket->vp_priority = VP_PRIORITY_INVALID;
    vrPacket->vp_notused = 0;

    PWIN_PACKET_RAW result = WinTxPostprocess(vrPacket);

    // NOTE: Output contract = IP checksum offload requested
    // NOTE: Output contract = UDP checksum offload not requested
    assert_ptr_not_equal(result, NULL);
    assert_int_equal(outerIpHeader->ip_csum, 0);
    assert_int_equal(innerIpHeader->ip_csum, 0xd375);
    assert_int_equal(innerUdpHeader->udp_csum, 0x0534);

    FreeVrPacket(vrPacket);
}

#define win_tx_pp_(p, f) cmocka_unit_test_setup_teardown(p##f, p##SetUp, p##TearDown)
#define win_tx_pp(f) win_tx_pp_(Test_win_tx_pp_, f)

int main(void) {
    const struct CMUnitTest tests[] = {
        win_tx_pp(ArpPacket),
        win_tx_pp(SmallIpUdpOverTunnelPacket),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
