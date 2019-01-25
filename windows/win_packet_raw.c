/*
 * win_packet_raw.c -- wrapper interface for Windows packet subsystem
 *
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */
#include "win_packet_raw.h"
#include "win_packet.h"
#include "windows_nbl.h"

#include <ndis.h>

static CONST ULONG PacketListAllocationTag = 'ELPW';

static inline PNET_BUFFER
WinSubPacketRawToNB(PWIN_SUB_PACKET SubPacket)
{
    return (PNET_BUFFER)SubPacket;
}

static inline PWIN_SUB_PACKET
WinSubPacketRawFromNB(PNET_BUFFER NetBuffer)
{
    return (PWIN_SUB_PACKET)NetBuffer;
}

PWIN_PACKET_RAW
WinPacketRawGetParentOf(PWIN_PACKET_RAW Packet)
{
    PNET_BUFFER_LIST childNbl = WinPacketRawToNBL(Packet);
    PNET_BUFFER_LIST parentNbl = childNbl->ParentNetBufferList;

    return WinPacketRawFromNBL(parentNbl);
}

VOID
WinPacketRawSetParentOf(PWIN_PACKET_RAW Packet, PWIN_PACKET_RAW Parent)
{
    PNET_BUFFER_LIST parentNbl = WinPacketRawToNBL(Parent);
    PNET_BUFFER_LIST childNbl = WinPacketRawToNBL(Packet);

    childNbl->ParentNetBufferList = parentNbl;
}

LONG
WinPacketRawGetChildCountOf(PWIN_PACKET_RAW Packet)
{
    PNET_BUFFER_LIST nbl = WinPacketRawToNBL(Packet);
    return nbl->ChildRefCount;
}

LONG
WinPacketRawIncrementChildCountOf(PWIN_PACKET_RAW Packet)
{
    PNET_BUFFER_LIST nbl = WinPacketRawToNBL(Packet);
    return InterlockedIncrement(&nbl->ChildRefCount);
}

LONG
WinPacketRawDecrementChildCountOf(PWIN_PACKET_RAW Packet)
{
    PNET_BUFFER_LIST nbl = WinPacketRawToNBL(Packet);
    return InterlockedDecrement(&nbl->ChildRefCount);
}

BOOLEAN
WinPacketRawShouldIpChecksumBeOffloaded(PWIN_PACKET_RAW Packet)
{
    PNET_BUFFER_LIST nbl = WinPacketRawToNBL(Packet);

    NDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO settings;
    settings.Value = NET_BUFFER_LIST_INFO(nbl, TcpIpChecksumNetBufferListInfo);

    return settings.Transmit.IpHeaderChecksum;
}

BOOLEAN
WinPacketRawShouldTcpChecksumBeOffloaded(PWIN_PACKET_RAW Packet)
{
    PNET_BUFFER_LIST nbl = WinPacketRawToNBL(Packet);

    NDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO settings;
    settings.Value = NET_BUFFER_LIST_INFO(nbl, TcpIpChecksumNetBufferListInfo);

    return settings.Transmit.TcpChecksum;
}

VOID
WinPacketRawClearTcpChecksumOffloading(PWIN_PACKET_RAW Packet)
{
    PNET_BUFFER_LIST nbl = WinPacketRawToNBL(Packet);

    NDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO settings;
    settings.Value = NET_BUFFER_LIST_INFO(nbl, TcpIpChecksumNetBufferListInfo);
    settings.Transmit.TcpChecksum = 0;
    settings.Transmit.TcpHeaderOffset = 0;

    NET_BUFFER_LIST_INFO(nbl, TcpIpChecksumNetBufferListInfo) = settings.Value;
}

BOOLEAN
WinPacketRawShouldUdpChecksumBeOffloaded(PWIN_PACKET_RAW Packet)
{
    PNET_BUFFER_LIST nbl = WinPacketRawToNBL(Packet);

    NDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO settings;
    settings.Value = NET_BUFFER_LIST_INFO(nbl, TcpIpChecksumNetBufferListInfo);

    return settings.Transmit.UdpChecksum;
}

VOID
WinPacketRawClearUdpChecksumOffloading(PWIN_PACKET_RAW Packet)
{
    PNET_BUFFER_LIST nbl = WinPacketRawToNBL(Packet);

    NDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO settings;
    settings.Value = NET_BUFFER_LIST_INFO(nbl, TcpIpChecksumNetBufferListInfo);
    settings.Transmit.UdpChecksum = 0;

    NET_BUFFER_LIST_INFO(nbl, TcpIpChecksumNetBufferListInfo) = settings.Value;
}

VOID
WinPacketRawClearChecksumOffloading(PWIN_PACKET_RAW Packet)
{
    PNET_BUFFER_LIST nbl = WinPacketRawToNBL(Packet);
    NET_BUFFER_LIST_INFO(nbl, TcpIpChecksumNetBufferListInfo) = 0;
}

ULONG
WinSubPacketRawDataLength(PWIN_SUB_PACKET SubPacket)
{
    PNET_BUFFER nb = WinSubPacketRawToNB(SubPacket);
    return NET_BUFFER_DATA_LENGTH(nb);
}

ULONG
WinPacketRawDataLength(PWIN_PACKET_RAW Packet)
{
    PNET_BUFFER_LIST nbl = WinPacketRawToNBL(Packet);
    ASSERT(nbl->Next == NULL);

    PNET_BUFFER nb = NET_BUFFER_LIST_FIRST_NB(nbl);
    ASSERT(nb->Next == NULL);

    return NET_BUFFER_DATA_LENGTH(nb);
}

PVOID
WinSubPacketRawGetDataBuffer(PWIN_SUB_PACKET SubPacket, PVOID Buffer, ULONG BufferSize)
{
    PNET_BUFFER nb = WinSubPacketRawToNB(SubPacket);

    CONST UINT alignMultiple = 1;
    CONST UINT alignOffset = 0;

    return NdisGetDataBuffer(nb, BufferSize, Buffer, alignMultiple, alignOffset);
}

PVOID
WinPacketRawGetDataBuffer(PWIN_PACKET_RAW Packet, PVOID Buffer, ULONG BufferSize)
{
    PNET_BUFFER_LIST nbl = WinPacketRawToNBL(Packet);
    ASSERT(nbl->Next == NULL);

    PNET_BUFFER nb = NET_BUFFER_LIST_FIRST_NB(nbl);
    ASSERT(nb->Next == NULL);

    PWIN_SUB_PACKET subPacket = WinSubPacketRawFromNB(nb);
    return WinSubPacketRawGetDataBuffer(subPacket, Buffer, BufferSize);
}

ULONG
WinPacketRawGetMSS(PWIN_PACKET_RAW Packet)
{
    PNET_BUFFER_LIST nbl = WinPacketRawToNBL(Packet);

    NDIS_TCP_LARGE_SEND_OFFLOAD_NET_BUFFER_LIST_INFO lso_info;
    lso_info.Value = NET_BUFFER_LIST_INFO(nbl, TcpLargeSendNetBufferListInfo);

    return lso_info.LsoV2Transmit.MSS;
}

VOID
WinPacketRawClearSegmentationOffloading(PWIN_PACKET_RAW Packet)
{
    PNET_BUFFER_LIST nbl = WinPacketRawToNBL(Packet);

    NDIS_TCP_LARGE_SEND_OFFLOAD_NET_BUFFER_LIST_INFO lso_info;
    lso_info.Value = 0;
    NET_BUFFER_LIST_INFO(nbl, TcpLargeSendNetBufferListInfo) = lso_info.Value;
}

PVOID
WinPacketRawDataAtOffset(PWIN_PACKET_RAW Packet, UINT16 Offset)
{
    // THIS FUNCTION IS NOT SECURE
    // DP-CORE assumes all headers will be contigous, ie. pointers
    // of type (struct vr_headertype*), when pointing to the beginning
    // of the header, will be valid for it's entiriety

    // TODO: Extract most of the logic into WIN_PACKET layer.

    PNET_BUFFER_LIST nbl = WinPacketRawToNBL(Packet);
    PNET_BUFFER nb = NET_BUFFER_LIST_FIRST_NB(nbl);
    PMDL current_mdl = NET_BUFFER_CURRENT_MDL(nb);
    unsigned length = MmGetMdlByteCount(current_mdl) - NET_BUFFER_CURRENT_MDL_OFFSET(nb);
    while (length < Offset) {
        /* Get the pointer to the beginning of data represented in current MDL. */
        Offset -= length;

        current_mdl = current_mdl->Next;
        if (current_mdl == NULL)
            return NULL;

        length = MmGetMdlByteCount(current_mdl);
    }

    void* ret = MmGetSystemAddressForMdlSafe(current_mdl,
        LowPagePriority | MdlMappingNoExecute);
    if (ret == NULL)
        return NULL;

    return (uint8_t*) ret + Offset;
}

BOOLEAN
WinPacketRawIsOwned(PWIN_PACKET_RAW Packet)
{
    PNET_BUFFER_LIST nbl = WinPacketRawToNBL(Packet);
    return nbl->NdisPoolHandle == VrNBLPool;
}

BOOLEAN
WinPacketRawIsMultiFragment(PWIN_PACKET_RAW Packet)
{
    PNET_BUFFER_LIST nbl = WinPacketRawToNBL(Packet);
    return nbl->FirstNetBuffer && nbl->FirstNetBuffer->Next;
}

VOID
WinPacketRawComplete(PWIN_PACKET_RAW Packet)
{
    PNET_BUFFER_LIST nbl = WinPacketRawToNBL(Packet);

    ASSERT(nbl != NULL);

    /* Flag SINGLE_SOURCE is used, because of singular NBLS */
    NdisFSendNetBufferListsComplete(VrSwitchObject->NdisFilterHandle,
        nbl, NDIS_SEND_COMPLETE_FLAGS_SWITCH_SINGLE_SOURCE);
}

VOID
WinPacketRawFreeCreated(PWIN_PACKET_RAW Packet)
{
    PNET_BUFFER_LIST nbl = WinPacketRawToNBL(Packet);

    ASSERT(nbl != NULL);
    ASSERTMSG("A non-singular NBL made it's way into the process",
        nbl->Next == NULL);

    FreeForwardingContext(nbl);

    CONST MM_PAGE_PRIORITY priority = LowPagePriority | MdlMappingNoExecute;
    PNET_BUFFER nb = NET_BUFFER_LIST_FIRST_NB(nbl);
    PMDL mdlNext = NULL;

    /* Free MDLs associated with NET_BUFFERS */
    for (; nb != NULL; nb = NET_BUFFER_NEXT_NB(nb)) {
        for (PMDL mdl = NET_BUFFER_FIRST_MDL(nb); mdl != NULL; mdl = mdlNext) {
            mdlNext = mdl->Next;

            PVOID data = MmGetSystemAddressForMdlSafe(mdl, priority);
            NdisFreeMdl(mdl);

            if (data != NULL) {
                ExFreePool(data);
            }
        }
    }

    NdisFreeNetBufferList(nbl);
}

BOOLEAN
WinPacketRawCopyOutOfBandData(PWIN_PACKET_RAW Child, PWIN_PACKET_RAW Original)
{
    PNET_BUFFER_LIST originalNbl = WinPacketRawToNBL(Original);
    PNET_BUFFER_LIST childNbl = WinPacketRawToNBL(Child);

    childNbl->SourceHandle = VrSwitchObject->NdisFilterHandle;

    if (CreateForwardingContext(childNbl) != NDIS_STATUS_SUCCESS) {
        return FALSE;
    }

    NDIS_SWITCH_COPY_NET_BUFFER_LIST_INFO_HANDLER copyFunction =
        VrSwitchObject->NdisSwitchHandlers.CopyNetBufferListInfo;

    CONST UINT32 flags = 0;

    NDIS_STATUS status = copyFunction(
        VrSwitchObject->NdisSwitchContext, childNbl, originalNbl, flags);

    if (status != NDIS_STATUS_SUCCESS) {
        FreeForwardingContext(childNbl);
        return FALSE;
    }

    return TRUE;
}

PWIN_PACKET_RAW
WinPacketRawAllocateClone(PWIN_PACKET_RAW Packet)
{
    PNET_BUFFER_LIST originalNbl = WinPacketRawToNBL(Packet);

    PNET_BUFFER_LIST clonedNbl = NdisAllocateCloneNetBufferList(
        originalNbl, VrNBLPool, NULL, 0);

    if (clonedNbl == NULL) {
        return NULL;
    }

    PWIN_PACKET_RAW clonedPkt = WinPacketRawFromNBL(clonedNbl);

    if (WinPacketRawCopyOutOfBandData(clonedPkt, Packet) == FALSE) {
        NdisFreeCloneNetBufferList(clonedNbl, 0);
        return NULL;
    }

    return clonedPkt;
}

VOID
WinPacketRawFreeClone(PWIN_PACKET_RAW Packet)
{
    PNET_BUFFER_LIST nbl = WinPacketRawToNBL(Packet);

    FreeForwardingContext(nbl);
    NdisFreeCloneNetBufferList(nbl, 0);
}

PWIN_PACKET_RAW
WinPacketRawAllocateMultiFragment(
    PWIN_PACKET_RAW OriginalPkt, ULONG HeadersSize, ULONG MaxFragmentLen)
{
    PNET_BUFFER_LIST originalNbl = WinPacketRawToNBL(OriginalPkt);

    PNET_BUFFER_LIST splitNbl = NdisAllocateFragmentNetBufferList(
        originalNbl, VrNBLPool, VrNBPool, HeadersSize,
        MaxFragmentLen, HeadersSize, 0, 0);

    return WinPacketRawFromNBL(splitNbl);
}

VOID
WinPacketRawFreeMultiFragmentWithoutFwdContext(PWIN_PACKET_RAW Packet)
{
    PNET_BUFFER_LIST nbl = WinPacketRawToNBL(Packet);

    CONST ULONG mdlLen = MmGetMdlByteCount(nbl->FirstNetBuffer->CurrentMdl);
    CONST ULONG dataOffset = nbl->FirstNetBuffer->CurrentMdlOffset;
    CONST ULONG dataLength = mdlLen - dataOffset;

    NdisFreeFragmentNetBufferList(nbl, dataLength, 0);
}

VOID
WinPacketRawFreeMultiFragment(PWIN_PACKET_RAW Packet)
{
    PNET_BUFFER_LIST nbl = WinPacketRawToNBL(Packet);

    FreeForwardingContext(nbl);
    WinPacketRawFreeMultiFragmentWithoutFwdContext(Packet);
}

VOID
WinPacketRawAssertAllHeadersAreInFirstMDL(
    PWIN_PACKET_RAW Packet, ULONG HeadersSize)
{
    PNET_BUFFER_LIST nbl = WinPacketRawToNBL(Packet);
    ULONG mdlDataSize = MmGetMdlByteCount(nbl->FirstNetBuffer->CurrentMdl) -
        nbl->FirstNetBuffer->CurrentMdlOffset;

    ASSERTMSG("It is expected that all headers are in first MDL",
        mdlDataSize == HeadersSize);
}

PWIN_PACKET_LIST
WinPacketListRawAllocateElement()
{
    PWIN_PACKET_LIST element = ExAllocatePoolWithTag(
        NonPagedPoolNx, sizeof(*element), PacketListAllocationTag);

    if (element == NULL) {
        return NULL;
    }

    RtlZeroMemory(element, sizeof(*element));
    return element;
}

VOID
WinPacketListRawFreeElement(PWIN_PACKET_LIST Element)
{
    ExFreePool(Element);
}

PWIN_SUB_PACKET
WinPacketRawGetFirstSubPacket(PWIN_PACKET_RAW Packet)
{
    PNET_BUFFER_LIST nbl = WinPacketRawToNBL(Packet);
    PNET_BUFFER nb = NET_BUFFER_LIST_FIRST_NB(nbl);

    return WinSubPacketRawFromNB(nb);
}

VOID
WinPacketRawSetFirstSubPacket(PWIN_PACKET_RAW Packet, PWIN_SUB_PACKET SubPacket)
{
    PNET_BUFFER_LIST nbl = WinPacketRawToNBL(Packet);
    PNET_BUFFER nb = WinSubPacketRawToNB(SubPacket);

    NET_BUFFER_LIST_FIRST_NB(nbl) = nb;
}

PWIN_SUB_PACKET
WinSubPacketRawGetNext(PWIN_SUB_PACKET SubPacket)
{
    PNET_BUFFER currentNb = WinSubPacketRawToNB(SubPacket);
    PNET_BUFFER nextNb = NET_BUFFER_NEXT_NB(currentNb);

    return WinSubPacketRawFromNB(nextNb);
}

VOID
WinSubPacketRawSetNext(PWIN_SUB_PACKET SubPacket, PWIN_SUB_PACKET Next)
{
    PNET_BUFFER currentNb = WinSubPacketRawToNB(SubPacket);
    PNET_BUFFER nextNb = WinSubPacketRawToNB(Next);

    NET_BUFFER_NEXT_NB(currentNb) = nextNb;
}

VOID
WinPacketRawCopyHeadersToSubPacket(
    PWIN_SUB_PACKET SubPkt, PWIN_PACKET_RAW OriginalPkt, ULONG HeadersSize)
{
    PNET_BUFFER nb = WinSubPacketRawToNB(SubPkt);
    PNET_BUFFER_LIST nbl = WinPacketRawToNBL(OriginalPkt);

    ULONG bytesCopied = 0;
    CONST ULONG srcOffset = 0;
    CONST ULONG dstOffset = 0;

    NDIS_STATUS status = NdisCopyFromNetBufferToNetBuffer(nb, dstOffset,
        HeadersSize, nbl->FirstNetBuffer, srcOffset, &bytesCopied);

    // Failure may occur only due to error in fragmentation logic.
    // New resources are not allocated in NdisCopyFromNetBufferToNetBuffer.
    ASSERTMSG("NdisCopyFromNetBufferToNetBuffer failed",
        status == NDIS_STATUS_SUCCESS && bytesCopied == HeadersSize);
}

PVOID
WinSubPacketRawGetDataPtr(PWIN_SUB_PACKET SubPacket)
{
    PNET_BUFFER nb = WinSubPacketRawToNB(SubPacket);

    CONST MM_PAGE_PRIORITY priority = LowPagePriority | MdlMappingNoExecute;
    PUCHAR bufferPtr = MmGetSystemAddressForMdlSafe(nb->CurrentMdl, priority);

    return bufferPtr + nb->CurrentMdlOffset;
}

PNET_BUFFER_LIST
WinPacketRawToNBL(PWIN_PACKET_RAW Packet)
{
    return (PNET_BUFFER_LIST)Packet;
}

PWIN_PACKET_RAW
WinPacketRawFromNBL(PNET_BUFFER_LIST NetBufferList)
{
    return (PWIN_PACKET_RAW)NetBufferList;
}
