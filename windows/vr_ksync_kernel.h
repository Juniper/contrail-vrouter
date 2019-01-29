/*
 * vr_ksync_kernel.h - defines interface into vRouter Ksync
 *                     message parsing module
 *
 * Copyright (c) 2019 Juniper Networks, Inc. All rights reserved.
 */
#ifndef _VR_KSYNC_KERNEL_H_
#define _VR_KSYNC_KERNEL_H_

#include "ksync/ksync_device_context.h"

NTSTATUS KsyncHandleWrite(PKSYNC_DEVICE_CONTEXT ctx,
                          uint8_t *buffer,
                          size_t buffer_size);

#endif // _VR_KSYNC_KERNEL_H_