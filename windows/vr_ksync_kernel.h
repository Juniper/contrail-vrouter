/*
 * vr_ksync_kernel.h -- ksync functions that need to be redefined to
 *                      be appropriate for unit testing in user space
 * 
 * Copyright (c) 2019 Juniper Networks, Inc. All rights reserved.
 */
#ifndef _VR_KSYNC_KERNEL_H_
#define _VR_KSYNC_KERNEL_H_

#include "ksync_device_context.h"

NTSTATUS KsyncHandleWrite(PKSYNC_DEVICE_CONTEXT ctx,
                          uint8_t *buffer,
                          size_t buffer_size);

#endif // _VR_KSYNC_KERNEL_H_