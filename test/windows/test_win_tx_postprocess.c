/*
 * test_win_tx_postprocess.c
 *
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */

#include <stdbool.h>

bool TcpOverMplsOverUdp();
bool UdpOverMplsOverUdp();
bool SmallIpUdpOverTunnelPacket();
bool ArpPacket();

int main(void) {

    int result = 0;

    result |= TcpOverMplsOverUdp();
    result |= UdpOverMplsOverUdp();
    result |= SmallIpUdpOverTunnelPacket();
    result |= ArpPacket();

    return result;
}
