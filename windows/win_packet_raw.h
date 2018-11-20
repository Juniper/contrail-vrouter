/*
 * win_packet_raw.h -- wrapper interface for Windows packet subsystem
 *
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */
#ifndef __WIN_PACKET_RAW_H__
#define __WIN_PACKET_RAW_H__

#include "vr_os.h"
#include <ndis.h>

typedef struct _WIN_PACKET_LIST WIN_PACKET_LIST, *PWIN_PACKET_LIST;
typedef struct _WIN_SUB_PACKET WIN_SUB_PACKET, *PWIN_SUB_PACKET;
typedef struct _WIN_PACKET_RAW WIN_PACKET_RAW, *PWIN_PACKET_RAW;

PWIN_PACKET_RAW WinPacketRawGetParentOf(PWIN_PACKET_RAW Packet);
VOID WinPacketRawSetParentOf(PWIN_PACKET_RAW Packet, PWIN_PACKET_RAW Parent);

LONG WinPacketRawGetChildCountOf(PWIN_PACKET_RAW Packet);
LONG WinPacketRawIncrementChildCountOf(PWIN_PACKET_RAW Packet);
LONG WinPacketRawDecrementChildCountOf(PWIN_PACKET_RAW Packet);

BOOLEAN WinPacketRawShouldIpChecksumBeOffloaded(PWIN_PACKET_RAW Packet);
BOOLEAN WinPacketRawShouldTcpChecksumBeOffloaded(PWIN_PACKET_RAW Packet);
VOID WinPacketRawClearTcpChecksumOffloading(PWIN_PACKET_RAW Packet);
BOOLEAN WinPacketRawShouldUdpChecksumBeOffloaded(PWIN_PACKET_RAW Packet);
VOID WinPacketRawClearUdpChecksumOffloading(PWIN_PACKET_RAW Packet);
VOID WinPacketRawClearChecksumOffloading(PWIN_PACKET_RAW Packet);

ULONG WinSubPacketRawDataLength(PWIN_SUB_PACKET SubPacket);
ULONG WinPacketRawDataLength(PWIN_PACKET_RAW Packet);
PVOID WinSubPacketRawGetDataBuffer(PWIN_SUB_PACKET SubPacket, PVOID Buffer, ULONG BufferSize);
PVOID WinPacketRawGetDataBuffer(PWIN_PACKET_RAW Packet, PVOID Buffer, ULONG BufferSize);

PVOID WinPacketRawDataAtOffset(PWIN_PACKET_RAW Packet, UINT16 Offset);
ULONG WinPacketRawGetMSS(PWIN_PACKET_RAW Packet);
VOID WinPacketRawClearSegmentationOffloading(PWIN_PACKET_RAW Packet);

BOOLEAN WinPacketRawIsOwned(PWIN_PACKET_RAW Packet);
BOOLEAN WinPacketRawIsMultiFragment(PWIN_PACKET_RAW Packet);
VOID WinPacketRawComplete(PWIN_PACKET_RAW Packet);
VOID WinPacketRawFreeCreated(PWIN_PACKET_RAW Packet);

BOOLEAN WinPacketRawCopyOutOfBandData(PWIN_PACKET_RAW Child, PWIN_PACKET_RAW Original);
PWIN_PACKET_RAW WinPacketRawAllocateClone(PWIN_PACKET_RAW Packet);
VOID WinPacketRawFreeClone(PWIN_PACKET_RAW Packet);
PWIN_PACKET_RAW WinPacketRawAllocateMultiFragment(
    PWIN_PACKET_RAW OriginalPkt, ULONG HeadersSize, ULONG MaxFragmentLen);
VOID WinPacketRawFreeMultiFragment(PWIN_PACKET_RAW Packet);
VOID WinPacketRawFreeMultiFragmentWithoutFwdContext(PWIN_PACKET_RAW Packet);
VOID WinPacketRawAssertAllHeadersAreInFirstMDL(PWIN_PACKET_RAW Packet, ULONG HeadersSize);
VOID WinPacketRawCopyHeadersToSubPacket(
    PWIN_SUB_PACKET SubPkt, PWIN_PACKET_RAW OriginalPkt, ULONG HeadersSize);
PVOID WinSubPacketRawGetDataPtr(PWIN_SUB_PACKET SubPacket);

PWIN_PACKET_LIST WinPacketListRawAllocateElement();
VOID WinPacketListRawFreeElement(PWIN_PACKET_LIST Element);

PWIN_SUB_PACKET WinPacketRawGetFirstSubPacket(PWIN_PACKET_RAW Packet);
VOID WinPacketRawSetFirstSubPacket(PWIN_PACKET_RAW Packet, PWIN_SUB_PACKET SubPacket);

PWIN_SUB_PACKET WinSubPacketRawGetNext(PWIN_SUB_PACKET SubPacket);
VOID WinSubPacketRawSetNext(PWIN_SUB_PACKET SubPacket, PWIN_SUB_PACKET Next);

// TODO: Remove this declaration and change the definition to `static inline`
// when callback layer is independent of NDIS
PNET_BUFFER_LIST WinPacketRawToNBL(PWIN_PACKET_RAW Packet);
PWIN_PACKET_RAW WinPacketRawFromNBL(PNET_BUFFER_LIST NetBufferList);

#endif /* __WIN_PACKET_RAW_H__ */
