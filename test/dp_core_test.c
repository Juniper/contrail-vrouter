#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "vr_types.h"
#include "vr_os.h"
#include "vr_packet.h"
#include "vr_message.h"
#include "vr_interface.h"

#include "host/vr_host.h"
#include "host/vr_host_packet.h"
#include "host/vr_host_interface.h"

extern int vrouter_host_init(unsigned int);
extern unsigned int vr_num_cpus;
extern unsigned int vr_bridge_entries;
extern unsigned int vr_bridge_oentries;
extern unsigned int vr_flow_entries;
extern unsigned int vr_oflow_entries;


unsigned int allocated = 0;

void *alloc_for_test(unsigned int size, unsigned int obj) {
    void *ptr;

    ptr = malloc(size);
    allocated++;

    return ptr;
}

void free_for_test(void *ptr, unsigned int obj) {
    free(ptr);
    allocated--;
}

int fake_response_cb(void *ptr1, unsigned int i, void *ptr2) {
    return 1;
}

void drop_stats_memory_test(void **state) {
    vr_drop_stats_req req = {
        .h_op = SANDESH_OP_GET,
        .vds_rid = 0
    };

    /* process request */
    vr_drop_stats_req_process(&req);

    /* currently one response queued */
    assert_int_equal(allocated, 2);

    /* dequeue it, and check the alloctions */
    vr_message_process_response(fake_response_cb, NULL);
    assert_int_equal(allocated, 0);
}

static void setup(void **state) {
    vrouter_host->hos_malloc = alloc_for_test;
    vrouter_host->hos_zalloc = alloc_for_test;
    vrouter_host->hos_free = free_for_test;
}

static void teardown(void **state) {
    free(*state);
}

int main(void) {
    int ret;


    /*
     * Initialise the tables to small values, in the test they
     * are likely to fail with huge values
     */
    vr_bridge_entries = 1024;
    vr_bridge_oentries = 64;
    vr_flow_entries = 1024;
    vr_oflow_entries = 64;

    /* test suite */
    const UnitTest tests[] = {
        unit_test_setup_teardown(drop_stats_memory_test, setup, teardown),
    };

    vr_diet_message_proto_init();

    /* init the vrouter */
    ret = vrouter_host_init(VR_MPROTO_SANDESH);
    if (ret)
        return ret;


    /* let's run the test suite */
    ret = run_tests(tests);

    return ret;
}
