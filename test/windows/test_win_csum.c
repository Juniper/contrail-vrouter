/*
 * test_win_csum.c
 *
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>

#include "vr_packet.h"
#include "win_csum.h"

uint8_t* network_packet = NULL;

uint8_t*
create_tcp_ip_packet(uint16_t payload_length)
{
    uint16_t packet_length = sizeof(struct vr_ip)
        + sizeof(struct vr_tcp) + payload_length;
    uint8_t* network_packet = malloc(packet_length);

    if (network_packet == NULL) {
        return NULL;
    }

    memset(network_packet, 0, packet_length);
    struct vr_ip* iph = (struct vr_ip*) network_packet;
    struct vr_tcp* tcph = (struct vr_tcp*) (network_packet
        + sizeof(struct vr_ip));

    iph->ip_saddr = 0x01020304;
    iph->ip_daddr = 0x05060708;
    iph->ip_proto = 0x02;
    iph->ip_len = htons(packet_length);
    iph->ip_hl = sizeof(*iph) / 4;
    iph->ip_id = 0xABAB;
    iph->ip_frag_off = 0xEFEF;
    iph->ip_ttl = 0x10;

    tcph->tcp_sport = htons(0x0123);
    tcph->tcp_sport = htons(0x0456);
    tcph->tcp_seq = htonl(0x0246);
    tcph->tcp_ack = htonl(0x0210);
    tcph->tcp_win = htons(0x1000);

    uint8_t* payload = network_packet + sizeof(struct vr_ip)
        + sizeof(struct vr_tcp);
    memset(payload, 0xAB, payload_length);

    return network_packet;
}

int
Test_TearDown(void** state)
{
    if (network_packet != NULL) {
        free(network_packet);
        network_packet = NULL;
    }
    return 0;
}

void
Test_ReturnsCorrectCsum1(void **state)
{
    char some_bytes[] = {0x1, 0x2, 0x3, 0x4};
    uint16_t csum = calc_csum(some_bytes, 4);
    uint16_t good_csum = ~0x0604;
    assert_int_equal(csum, good_csum);
}

void
Test_ReturnsCorrectCsum2(void **state)
{
    char some_bytes[] = {0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0x0};
    uint16_t csum = calc_csum(some_bytes, 6);
    uint16_t good_csum = ~0x1;
    assert_int_equal(csum, good_csum);
}

void
Test_csum_replace2(void **state)
{
    uint16_t csum = ~0x0406;
    csum_replace2(&csum, 0x0304, 0x0506);
    uint16_t good_csum = ~0x0608;
    assert_int_equal(csum, good_csum);
}

void
Test_CalculatesCorrectPartialTCPCsum(void **state)
{
    uint16_t payload_length = 10;
    uint8_t* packet = create_tcp_ip_packet(payload_length);
    assert_non_null(packet);
    struct vr_ip* iph = (struct vr_ip*) packet;
    struct vr_tcp* tcph = (struct vr_tcp*) (packet + iph->ip_hl * 4);

    fill_partial_csum_of_tcp_packet(iph, tcph);
    uint16_t good_csum = 0x3014;
    assert_int_equal(tcph->tcp_csum, good_csum);
}

void
Test_CalculatesCorrectTCPCsum(void **state)
{
    uint16_t payload_length = 10;
    uint8_t* packet = create_tcp_ip_packet(payload_length);
    assert_non_null(packet);
    struct vr_ip* iph = (struct vr_ip*) packet;
    struct vr_tcp* tcph = (struct vr_tcp*) (packet + iph->ip_hl * 4);

    fill_partial_csum_of_tcp_packet(iph, tcph);
    fill_csum_of_tcp_packet_provided_that_partial_csum_is_computed(packet);
    uint16_t good_csum = 0xc978;
    assert_int_equal(tcph->tcp_csum, good_csum);
}

#define win_csum_UnitTest_(p, f) cmocka_unit_test_teardown(p##f, p##TearDown)
#define win_csum_UnitTest(f) win_csum_UnitTest_(Test_, f)

int main(void) {
    const struct CMUnitTest tests[] = {
        win_csum_UnitTest(ReturnsCorrectCsum1),
        win_csum_UnitTest(ReturnsCorrectCsum2),
        win_csum_UnitTest(csum_replace2),
        win_csum_UnitTest(CalculatesCorrectPartialTCPCsum),
        win_csum_UnitTest(CalculatesCorrectTCPCsum),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
