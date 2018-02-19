/*
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */

#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>
#include <vr_packet.h>

static void test_example(void **state) {
    struct vr_ip iph;
    iph.ip_proto = VR_IP_PROTO_ICMP;
    assert_true(vr_ip_proto_pull(&iph));
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_example),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
