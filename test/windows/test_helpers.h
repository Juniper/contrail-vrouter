/*
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */

#pragma once

#include "vr_packet.h"

#include <ndis.h>

PNET_BUFFER_LIST AllocateMockNetBufferList(NDIS_HANDLE NBLPool);
struct vr_packet *AllocateMockNetBufferListWithVrPacket(void);
void InitializeVrSwitchObject(void);
