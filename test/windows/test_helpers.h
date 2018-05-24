/*
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */

#pragma once

#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>
#include "vr_packet.h"
#include "windows_nbl.h"
#include <ndis.h>

PNET_BUFFER_LIST AllocateMockNetBufferList(NDIS_HANDLE NBLPool);
struct vr_packet *AllocateMockNetBufferListWithVrPacket(void);
void InitializeVrSwitchObject(void);
