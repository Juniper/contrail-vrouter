/*
 * vr_packet_test.c
 *
 * Copyright (c) 2019 Juniper Networks, Inc. All rights reserved.
 */

#include <assert.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <setjmp.h>
#include <cmocka.h>

#include "common_test.h"
#include "vr_packet.h"

#define TCPH_MAX 60
#define MSS_VAL 1300

uint8_t tcphe[TCPH_MAX];
struct vr_tcp *tcph;

static void test_SetUp(void **state) {
    memset(tcphe, 0, TCPH_MAX);
    size_t i = sizeof(struct vr_tcp);
    tcph = (struct vr_tcp*) &tcphe[0];
    tcph->tcp_flag_syn = true;
    tcphe[i++] = VR_TCP_OPT_MSS;
    tcphe[i++] = VR_TCP_OLEN_MSS;
    tcphe[i++] = (MSS_VAL >> 8) & 0xff;
    tcphe[i++] = MSS_VAL & 0xff;
    tcph->tcp_doff = i / 4;
}

static void test_TearDown(void **state) {
    free(*state);
}

static void test_vr_adjust_tcp_mss_not_changed(void **state) {
    uint16_t eth_mtu =  sizeof(struct vr_tcp) + MSS_VAL*2;
    uint16_t len_overhead = 0;
    uint16_t old_mss = 16;
    uint16_t new_mss = 5;

    uint16_t max_mss = eth_mtu - (len_overhead + sizeof(struct vr_tcp));
    assert_true(max_mss >= MSS_VAL);

    assert_false(__vr_adjust_tcp_mss(tcph, len_overhead, eth_mtu,
                                     &old_mss, &new_mss));
    assert_int_equal(old_mss, 16);
    assert_int_equal(new_mss, 5);
}

static void test_vr_adjust_tcp_mss_changed(void **state) {
    uint16_t eth_mtu = sizeof(struct vr_tcp) + 1000;
    uint16_t len_overhead = 100;
    uint16_t old_mss = 0;
    uint16_t new_mss = 0;

    uint16_t max_mss = eth_mtu - (len_overhead + sizeof(struct vr_tcp));
    assert_true(max_mss < MSS_VAL);

    assert_true(__vr_adjust_tcp_mss(tcph, len_overhead, eth_mtu,
                                    &old_mss, &new_mss));
    assert_int_equal(old_mss, MSS_VAL);
    assert_int_equal(new_mss, max_mss);
}

#define VrPacket_UnitTest_(p, f) unit_test_setup_teardown(p##f, p##SetUp, p##TearDown)
#define VrPacket_UnitTest(f) VrPacket_UnitTest_(test_, f)

int main(void) {
    const UnitTest tests[] = {
        VrPacket_UnitTest(vr_adjust_tcp_mss_not_changed),
        VrPacket_UnitTest(vr_adjust_tcp_mss_changed),
    };
    return run_tests(tests);
}
