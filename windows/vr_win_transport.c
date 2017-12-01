/*
 * Copyright (c) 2017 Juniper Networks, Inc. All rights reserved.
 */
#include <precomp.h>

#include "vr_message.h"
#include "vr_sandesh.h"

static ULONG WIN_TRANSPORT_TAG = 'ARTV';

static char *
win_trans_alloc(unsigned int size)
{
    char *buffer;
    size_t allocation_size;

    allocation_size = NLMSG_ALIGN(size) + NETLINK_HEADER_LEN;
    buffer = ExAllocatePoolWithTag(NonPagedPoolNx, allocation_size, WIN_TRANSPORT_TAG);
    if (buffer == NULL)
        return NULL;

    return buffer + NETLINK_HEADER_LEN;
}

static void
win_trans_free(char *buf)
{
    ASSERT(buf != NULL);
    ExFreePool(buf - NETLINK_HEADER_LEN);
}

static struct vr_mtransport win_transport = {
    .mtrans_alloc   =   win_trans_alloc,
    .mtrans_free    =   win_trans_free,
};

void
vr_transport_exit(void)
{
    vr_message_transport_unregister(&win_transport);
}

int
vr_transport_init(void)
{
    int ret;

    ret = vr_message_transport_register(&win_transport);
    if (ret) {
        DbgPrint("%s: error on transport register = %d\n", __func__, ret);
        return ret;
    }

    return 0;
}

NTSTATUS
vr_message_init(void)
{
    int ret = vr_sandesh_init();
    if (ret) {
        DbgPrint("%s: vr_sandesh_init() failed with return %d\n", __func__, ret);
        return NDIS_STATUS_FAILURE;
    }

    ret = vr_transport_init();
    if (ret) {
        DbgPrint("%s: vr_transport_init() failed with return %d", __func__, ret);
        vr_sandesh_exit();
        return NDIS_STATUS_FAILURE;
    }

    return NDIS_STATUS_SUCCESS;
}

void
vr_message_exit(void)
{
    vr_transport_exit();
    vr_sandesh_exit();
}
