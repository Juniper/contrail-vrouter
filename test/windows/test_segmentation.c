/*
 * test_segmentation.c
 *
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>

#include "win_packet_splitting.h"

void
Test_segmentation_ProperlySplitsNonMultiples(void **state)
{
    struct SplittingContext pctx;
    struct vr_ip ip_header;

    pctx.inner_eth_header_size = 14;
    pctx.inner_headers_size = 54;
    pctx.maximum_inner_payload_length = 1300;
    pctx.total_payload_size = 5000;

    fix_packet_length_in_inner_ip_header_of_split_packet(&pctx, &ip_header, true);
    assert_int_equal(ip_header.ip_len, htons(1340));
    fix_packet_length_in_inner_ip_header_of_split_packet(&pctx, &ip_header, false);
    assert_int_equal(ip_header.ip_len, htons(1140));
}

void
Test_segmentation_ProperlySplitsMultiples(void **state)
{
    struct SplittingContext pctx;
    struct vr_ip ip_header;

    pctx.inner_eth_header_size = 14;
    pctx.inner_headers_size = 54;
    pctx.maximum_inner_payload_length = 1300;
    pctx.total_payload_size = 3900;

    fix_packet_length_in_inner_ip_header_of_split_packet(&pctx, &ip_header, true);
    assert_int_equal(ip_header.ip_len, htons(1340));
    fix_packet_length_in_inner_ip_header_of_split_packet(&pctx, &ip_header, false);
    assert_int_equal(ip_header.ip_len, htons(1340));
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(Test_segmentation_ProperlySplitsMultiples),
        cmocka_unit_test(Test_segmentation_ProperlySplitsNonMultiples),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
