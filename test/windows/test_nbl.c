/*
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */

#include "test_helpers.h"

#include "vr_packet.h"
#include "windows_nbl.h"
#include "ndis.h"

#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>

static void test_FreeCloneNetBufferListNonRecursive(void **state) {
    PNET_BUFFER_LIST parentNbl = AllocateMockNetBufferList(VrNBLPool);

    PNET_BUFFER_LIST child = CloneNetBufferList(parentNbl);
    assert_non_null(child);
    FreeClonedNetBufferListPreservingParent(child);

    FreeNetBufferList(parentNbl);
}

static void test_CloneNetBufferList(void **state) {
    PNET_BUFFER_LIST parentNbl = AllocateMockNetBufferList(VrNBLPool);

    PNET_BUFFER_LIST child1 = CloneNetBufferList(parentNbl);
    assert_non_null(child1);

    PNET_BUFFER_LIST child2 = CloneNetBufferList(parentNbl);
    assert_non_null(child2);

    FreeNetBufferList(child1);
    FreeNetBufferList(child2);

    // Cmocka should check that parentNbl was freed.
}

static void test_CloneNonOwnedNetBufferList(void **state) {
    // Simulate NBL not created by us.
    PNET_BUFFER_LIST parentNbl = AllocateMockNetBufferList(NULL);

    PNET_BUFFER_LIST child = CloneNetBufferList(parentNbl);
    assert_non_null(child);

    FreeNetBufferList(child);

    assert_true(parentNbl->TestIsCompleted);

    test_free(parentNbl->Context);
    test_free(parentNbl);
}

static void test_pclone(void **state) {
    struct vr_packet *pkt1 = AllocateMockNetBufferListWithVrPacket();

    struct vr_packet *pkt2 = windows_host.hos_pclone(pkt1);
    assert_non_null(pkt2);

    struct vr_packet *pkt3 = windows_host.hos_pclone(pkt1);
    assert_non_null(pkt3);

    PNET_BUFFER_LIST nbl1 = (PNET_BUFFER_LIST)(pkt1->vp_net_buffer_list);
    PNET_BUFFER_LIST nbl2 = (PNET_BUFFER_LIST)(pkt2->vp_net_buffer_list);
    PNET_BUFFER_LIST nbl3 = (PNET_BUFFER_LIST)(pkt3->vp_net_buffer_list);

    // vr_packets should point to leaves
    assert_false(nbl1->ChildRefCount);
    assert_false(nbl2->ChildRefCount);
    assert_false(nbl3->ChildRefCount);

    assert_ptr_not_equal(nbl1, nbl2);
    assert_ptr_not_equal(nbl2, nbl3);
    assert_ptr_not_equal(nbl1, nbl3);

    windows_host.hos_pfree(pkt1, 42);
    windows_host.hos_pfree(pkt2, 42);
    windows_host.hos_pfree(pkt3, 42);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_FreeCloneNetBufferListNonRecursive),
        cmocka_unit_test(test_CloneNetBufferList),
        cmocka_unit_test(test_CloneNonOwnedNetBufferList),
        cmocka_unit_test(test_pclone)
    };

    InitializeVrSwitchObject();

    return cmocka_run_group_tests(tests, NULL, NULL);
}
