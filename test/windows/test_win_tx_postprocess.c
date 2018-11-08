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

    bool result = true;

    result = TcpOverMplsOverUdp() && result;
    result = UdpOverMplsOverUdp() && result;
    result = SmallIpUdpOverTunnelPacket() && result;
    result = ArpPacket() && result;

    return result;
}
