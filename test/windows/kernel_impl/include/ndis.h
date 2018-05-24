/*
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */

#pragma once

#include "wdm.h"
#include "ntstrsafe.h"

#include <winsock2.h>
#include <windows.h>
#include <in6addr.h>

// fake types

#define NDIS_STATUS_SUCCESS 0
#define NDIS_STATUS_FAILURE 1

#define NDIS_PROTOCOL_ID_DEFAULT 0
#define NDIS_OBJECT_TYPE_DEFAULT 0
#define NDIS_DEFAULT_PORT_NUMBER 0

#define NDIS_OBJECT_TYPE_DEVICE_OBJECT_ATTRIBUTES 0
#define NDIS_DEVICE_OBJECT_ATTRIBUTES_REVISION_1 0
#define NDIS_SIZEOF_DEVICE_OBJECT_ATTRIBUTES_REVISION_1 0
#define NDIS_OBJECT_TYPE_FILTER_DRIVER_CHARACTERISTICS 0
#define NDIS_SIZEOF_FILTER_DRIVER_CHARACTERISTICS_REVISION_2 0
#define NDIS_FILTER_CHARACTERISTICS_REVISION_2 0
#define NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1 0
#define NDIS_SIZEOF_NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1 0

// NdisFSendNetBufferLists flags (stubs)
#define NDIS_SEND_FLAGS_DISPATCH_LEVEL 0
#define NDIS_SEND_FLAGS_CHECK_FOR_LOOPBACK 0
#define NDIS_SEND_FLAGS_SWITCH_SINGLE_SOURCE 0
#define NDIS_SEND_FLAGS_SWITCH_DESTINATION_GROUP 0
#define NDIS_TEST_SEND_FLAG(_Flags, _Flag) ((_Flags) & (_Flag))

// NdisFSendNetBufferListsComplete flags (stubs)
#define NDIS_SEND_COMPLETE_FLAGS_DISPATCH_LEVEL 0
#define NDIS_SEND_COMPLETE_FLAGS_SWITCH_SINGLE_SOURCE 0

#define NDIS_INIT_MUTEX(x)
#define NDIS_RELEASE_MUTEX(x)
#define NDIS_WAIT_FOR_MUTEX(x)
#define NET_BUFFER_FIRST_MDL(_nb) NULL
#define NET_BUFFER_NEXT_NB(_nb) (nb->Next)
#define NET_BUFFER_CURRENT_MDL(_nb) (_nb->CurrentMdl)
#define NET_BUFFER_CURRENT_MDL_OFFSET(_nb) (_nb->CurrentMdlOffset)
#define NET_BUFFER_DATA_OFFSET(_NB) 0
#define NET_BUFFER_DATA_LENGTH(x) 0
#define NET_BUFFER_LIST_FIRST_NB(_nbl) (_nbl->FirstNetBuffer)
#define NET_BUFFER_LIST_NEXT_NBL(_nbl) (_nbl->Next)
#define NET_BUFFER_LIST_SWITCH_FORWARDING_DETAIL(x) NULL

#define NDIS_SWITCH_NIC_AT_ARRAY_INDEX(_NicArray_, _Index_) NULL

#define NdisQueryMdl(_Mdl, _VirtualAddress, _Length, _Priority)

typedef int NDIS_MUTEX;
typedef int NDIS_SWITCH_CONTEXT;
typedef int NDIS_EVENT;
typedef int NDIS_STATUS;
typedef int NDIS_PORT_NUMBER;
typedef int NDIS_SWITCH_PORT_ID;
typedef int NDIS_SWITCH_NIC_INDEX;

typedef void *PNDIS_RW_LOCK_EX;
typedef void *PNDIS_FILTER_ATTACH_PARAMETERS;
typedef void *PNDIS_FILTER_PAUSE_PARAMETERS;
typedef void *PNDIS_FILTER_RESTART_PARAMETERS;
typedef void *PNDIS_OID_REQUEST;

// real types

#define NDIS_FILTER_MAJOR_VERSION 6
#define NDIS_FILTER_MINOR_VERSION 4

typedef struct _LOCK_STATE_EX {
  KIRQL OldIrql;
  UCHAR LockState;
  UCHAR Flags;
} LOCK_STATE_EX, *PLOCK_STATE_EX;

#define NET_BUFFER_LIST_INFO(_NBL, _Id)             ((_NBL)->NetBufferListInfo[(_Id)])

struct _NET_BUFFER_LIST;
typedef struct _NET_BUFFER_LIST NET_BUFFER_LIST, *PNET_BUFFER_LIST;
typedef UNICODE_STRING NDIS_STRING, *PNDIS_STRING;
typedef PVOID NDIS_HANDLE, *PNDIS_HANDLE;

struct _NET_BUFFER;
typedef struct _NET_BUFFER NET_BUFFER, *PNET_BUFFER;
struct _NET_BUFFER {
  union {
    struct {
      PNET_BUFFER Next;
      PMDL        CurrentMdl;
      ULONG       CurrentMdlOffset;
      union {
        ULONG  DataLength;
        SIZE_T stDataLength;
      };
      PMDL        MdlChain;
      ULONG       DataOffset;
    };
    // SLIST_HEADER      Link;
    // NET_BUFFER_HEADER NetBufferHeader;
  };
  USHORT                ChecksumBias;
  USHORT                Reserved;
  NDIS_HANDLE           NdisPoolHandle;
  PVOID                 NdisReserved[2];
  PVOID                 ProtocolReserved[6];
  PVOID                 MiniportReserved[4];
  // NDIS_PHYSICAL_ADDRESS DataPhysicalAddress;
  // union {
  //   PNET_BUFFER_SHARED_MEMORY SharedMemoryInfo;
  //   PSCATTER_GATHER_LIST      ScatterGatherList;
  // };
};

typedef struct _NET_BUFFER_LIST_CONTEXT {
    struct NET_BUFFER_LIST_CONTEXT *Next;
    USHORT                          Size;
    USHORT                          Offset;
    UCHAR                           ContextData[];
} NET_BUFFER_LIST_CONTEXT, *PNET_BUFFER_LIST_CONTEXT;

typedef enum _NDIS_NET_BUFFER_LIST_INFO {
    TcpIpChecksumNetBufferListInfo,
    TcpOffloadBytesTransferred                    = TcpIpChecksumNetBufferListInfo,
    IPsecOffloadV1NetBufferListInfo,
    IPsecOffloadV2NetBufferListInfo               = IPsecOffloadV1NetBufferListInfo,
    TcpLargeSendNetBufferListInfo,
    TcpReceiveNoPush                              = TcpLargeSendNetBufferListInfo,
    ClassificationHandleNetBufferListInfo,
    Ieee8021QNetBufferListInfo,
    NetBufferListCancelId,
    MediaSpecificInformation,
    NetBufferListFrameType,
    NetBufferListProtocolId                       = NetBufferListFrameType,
    NetBufferListHashValue,
    NetBufferListHashInfo,
    WfpNetBufferListInfo,
    IPsecOffloadV2TunnelNetBufferListInfo,
    IPsecOffloadV2HeaderNetBufferListInfo,
    NetBufferListCorrelationId,
    NetBufferListFilteringInfo,
    MediaSpecificInformationEx,
    NblOriginalInterfaceIfIndex,
    NblReAuthWfpFlowContext                       = NblOriginalInterfaceIfIndex,
    TcpReceiveBytesTransferred,
    SwitchForwardingReserved,
    SwitchForwardingDetail,
    VirtualSubnetInfo,
    IMReserved,
    TcpRecvSegCoalesceInfo,
    RscTcpTimestampDelta,
    TcpSendOffloadsSupplementalNetBufferListInfo  = RscTcpTimestampDelta,
    MaxNetBufferListInfo
} NDIS_NET_BUFFER_LIST_INFO, *PNDIS_NET_BUFFER_LIST_INFO;

typedef struct _NDIS_OBJECT_HEADER {
    UCHAR  Type;
    UCHAR  Revision;
    USHORT Size;
} NDIS_OBJECT_HEADER, *PNDIS_OBJECT_HEADER;

typedef struct _NDIS_DEVICE_OBJECT_ATTRIBUTES {
    NDIS_OBJECT_HEADER Header;
    PNDIS_STRING       DeviceName;
    PNDIS_STRING       SymbolicName;
    PDRIVER_DISPATCH   *MajorFunctions;
    ULONG              ExtensionSize;
    PCUNICODE_STRING   DefaultSDDLString;
    LPCGUID            DeviceClassGuid;
} NDIS_DEVICE_OBJECT_ATTRIBUTES, *PNDIS_DEVICE_OBJECT_ATTRIBUTES;

typedef struct _NDIS_SWITCH_NIC_ARRAY {
  NDIS_OBJECT_HEADER Header;
  ULONG              Flags;
  USHORT             FirstElementOffset;
  ULONG              NumElements;
  ULONG              ElementSize;
} NDIS_SWITCH_NIC_ARRAY, *PNDIS_SWITCH_NIC_ARRAY;

typedef void FILTER_SEND_NET_BUFFER_LISTS(
    NDIS_HANDLE FilterModuleContext,
    PNET_BUFFER_LIST NetBufferList,
    NDIS_PORT_NUMBER PortNumber,
    ULONG SendFlags
);

typedef void FILTER_SEND_NET_BUFFER_LISTS_COMPLETE(
    NDIS_HANDLE FilterModuleContext,
    PNET_BUFFER_LIST NetBufferList,
    ULONG SendCompleteFlags
);

typedef NDIS_STATUS FILTER_ATTACH(
    NDIS_HANDLE NdisFilterHandle,
    NDIS_HANDLE FilterDriverContext,
    PNDIS_FILTER_ATTACH_PARAMETERS AttachParameters
);

typedef void FILTER_DETACH(
    NDIS_HANDLE FilterModuleContext
);

typedef NDIS_STATUS FILTER_RESTART(
    NDIS_HANDLE FilterModuleContext,
    PNDIS_FILTER_RESTART_PARAMETERS RestartParameters
);

typedef NDIS_STATUS FILTER_PAUSE(
    NDIS_HANDLE FilterModuleContext,
    PNDIS_FILTER_PAUSE_PARAMETERS PauseParameters
);

typedef void FILTER_SEND_NET_BUFFER_LISTS(
    NDIS_HANDLE FilterModuleContext,
    PNET_BUFFER_LIST NetBufferList,
    NDIS_PORT_NUMBER PortNumber,
    ULONG SendFlags
);

typedef void FILTER_SEND_NET_BUFFER_LISTS_COMPLETE(
    NDIS_HANDLE FilterModuleContext,
    PNET_BUFFER_LIST NetBufferList,
    ULONG SendCompleteFlags
);

typedef NDIS_STATUS FILTER_OID_REQUEST(
    NDIS_HANDLE FilterModuleContext,
    PNDIS_OID_REQUEST OidRequest
);

typedef void FILTER_OID_REQUEST_COMPLETE(
    NDIS_HANDLE FilterModuleContext,
    PNDIS_OID_REQUEST OidRequest,
    NDIS_STATUS Status
);

typedef void FILTER_CANCEL_OID_REQUEST(
    NDIS_HANDLE FilterModuleContext,
    PVOID RequestId
);

typedef FILTER_ATTACH *FILTER_ATTACH_HANDLER;
typedef FILTER_DETACH *FILTER_DETACH_HANDLER;
typedef FILTER_RESTART *FILTER_RESTART_HANDLER;
typedef FILTER_PAUSE *FILTER_PAUSE_HANDLER;
typedef FILTER_SEND_NET_BUFFER_LISTS *FILTER_SEND_NET_BUFFER_LISTS_HANDLER;
typedef FILTER_SEND_NET_BUFFER_LISTS_COMPLETE *FILTER_SEND_NET_BUFFER_LISTS_COMPLETE_HANDLER;
typedef FILTER_OID_REQUEST *FILTER_OID_REQUEST_HANDLER;
typedef FILTER_OID_REQUEST_COMPLETE *FILTER_OID_REQUEST_COMPLETE_HANDLER;
typedef FILTER_CANCEL_OID_REQUEST *FILTER_CANCEL_OID_REQUEST_HANDLER;

typedef struct _NDIS_FILTER_DRIVER_CHARACTERISTICS {
    NDIS_OBJECT_HEADER                              Header;
    UCHAR                                           MajorNdisVersion;
    UCHAR                                           MinorNdisVersion;
    UCHAR                                           MajorDriverVersion;
    UCHAR                                           MinorDriverVersion;
    ULONG                                           Flags;
    NDIS_STRING                                     FriendlyName;
    NDIS_STRING                                     UniqueName;
    NDIS_STRING                                     ServiceName;
//    SET_OPTIONS_HANDLER                             SetOptionsHandler;
//    FILTER_SET_FILTER_MODULE_OPTIONS_HANDLER        SetFilterModuleOptionsHandler;
    FILTER_ATTACH_HANDLER                           AttachHandler;
    FILTER_DETACH_HANDLER                           DetachHandler;
    FILTER_RESTART_HANDLER                          RestartHandler;
    FILTER_PAUSE_HANDLER                            PauseHandler;
    FILTER_SEND_NET_BUFFER_LISTS_HANDLER            SendNetBufferListsHandler;
    FILTER_SEND_NET_BUFFER_LISTS_COMPLETE_HANDLER   SendNetBufferListsCompleteHandler;
//    FILTER_CANCEL_SEND_HANDLER                      CancelSendNetBufferListsHandler;
//    FILTER_RECEIVE_NET_BUFFER_LISTS_HANDLER         ReceiveNetBufferListsHandler;
//    FILTER_RETURN_NET_BUFFER_LISTS_HANDLER          ReturnNetBufferListsHandler;
    FILTER_OID_REQUEST_HANDLER                      OidRequestHandler;
    FILTER_OID_REQUEST_COMPLETE_HANDLER             OidRequestCompleteHandler;
    FILTER_CANCEL_OID_REQUEST_HANDLER               CancelOidRequestHandler;
/*    FILTER_DEVICE_PNP_EVENT_NOTIFY_HANDLER          DevicePnPEventNotifyHandler;
    FILTER_NET_PNP_EVENT_HANDLER                    NetPnPEventHandler;
    FILTER_STATUS_HANDLER                           StatusHandler;
#if (NDIS_SUPPORT_NDIS61)
    FILTER_DIRECT_OID_REQUEST_HANDLER               DirectOidRequestHandler;
    FILTER_DIRECT_OID_REQUEST_COMPLETE_HANDLER      DirectOidRequestCompleteHandler;
    FILTER_CANCEL_DIRECT_OID_REQUEST_HANDLER        CancelDirectOidRequestHandler;
#endif
#if (NDIS_SUPPORT_NDIS680)
    FILTER_SYNCHRONOUS_OID_REQUEST_HANDLER          SynchronousOidRequestHandler;
    FILTER_SYNCHRONOUS_OID_REQUEST_COMPLETE_HANDLER SynchronousOidRequestHandlerComplete;
#endif */
} NDIS_FILTER_DRIVER_CHARACTERISTICS, *PNDIS_FILTER_DRIVER_CHARACTERISTICS;

typedef struct _NET_BUFFER_LIST_POOL_PARAMETERS {
    NDIS_OBJECT_HEADER Header;
    UCHAR              ProtocolId;
    BOOLEAN            fAllocateNetBuffer;
    USHORT             ContextSize;
    ULONG              PoolTag;
    ULONG              DataSize;
} NET_BUFFER_LIST_POOL_PARAMETERS, *PNET_BUFFER_LIST_POOL_PARAMETERS;

typedef struct _NDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO {
    union {
        struct {
            ULONG IsIPv4  :1;
            ULONG IsIPv6  :1;
            ULONG TcpChecksum  :1;
            ULONG UdpChecksum  :1;
            ULONG IpHeaderChecksum  :1;
            ULONG Reserved  :11;
            ULONG TcpHeaderOffset  :10;
        } Transmit;
        struct {
            ULONG TcpChecksumFailed  :1;
            ULONG UdpChecksumFailed  :1;
            ULONG IpChecksumFailed  :1;
            ULONG TcpChecksumSucceeded  :1;
            ULONG UdpChecksumSucceeded  :1;
            ULONG IpChecksumSucceeded  :1;
            ULONG Loopback  :1;
            ULONG TcpChecksumValueInvalid  :1;
            ULONG IpChecksumValueInvalid  :1;
        } Receive;
        PVOID Value;
    };
} NDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO, *PNDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO;

typedef struct _NET_BUFFER_LIST_DATA {
    PNET_BUFFER_LIST Next;
    PNET_BUFFER      FirstNetBuffer;
} NET_BUFFER_LIST_DATA, *PNET_BUFFER_LIST_DATA;

// typedef struct _NET_BUFFER_LIST_HEADER {
//     NET_BUFFER_LIST_DATA NetBufferListData;
//     SLIST_HEADER         Link;
// } NET_BUFFER_LIST_HEADER, *PNET_BUFFER_LIST_HEADER;

struct _NET_BUFFER_LIST {
    union {
        struct {
            PNET_BUFFER_LIST Next;
            PNET_BUFFER      FirstNetBuffer;
        };
        // SLIST_HEADER           Link;
        // NET_BUFFER_LIST_HEADER NetBufferListHeader;
    };
    PNET_BUFFER_LIST_CONTEXT Context;
    PNET_BUFFER_LIST         ParentNetBufferList;
    NDIS_HANDLE              NdisPoolHandle;
    PVOID                    NdisReserved[2];
    PVOID                    ProtocolReserved[4];
    PVOID                    MiniportReserved[2];
    PVOID                    Scratch;
    NDIS_HANDLE              SourceHandle;
    ULONG                    NblFlags;
    LONG                     ChildRefCount;
    ULONG                    Flags;
    NDIS_STATUS              Status;
    PVOID                    NetBufferListInfo[MaxNetBufferListInfo];

    // Flags for testing:
    BOOLEAN                  TestIsCompleted;
};

typedef struct _NDIS_SWITCH_PORT_DESTINATION {
    NDIS_SWITCH_PORT_ID   PortId;
    NDIS_SWITCH_NIC_INDEX NicIndex;
    USHORT                IsExcluded  :1;
    UINT32                PreserveVLAN  :1;
    UINT32                PreservePriority  :1;
    USHORT                Reserved  :13;
} NDIS_SWITCH_PORT_DESTINATION, *PNDIS_SWITCH_PORT_DESTINATION;

typedef NDIS_STATUS NDIS_SWITCH_ADD_NET_BUFFER_LIST_DESTINATION(
    NDIS_SWITCH_CONTEXT NdisSwitchContext,
    PNET_BUFFER_LIST NetBufferList,
    PNDIS_SWITCH_PORT_DESTINATION Destination
);

typedef NDIS_SWITCH_ADD_NET_BUFFER_LIST_DESTINATION *NDIS_SWITCH_ADD_NET_BUFFER_LIST_DESTINATION_HANDLER;

typedef union _NDIS_SWITCH_FORWARDING_DETAIL_NET_BUFFER_LIST_INFO {
    UINT64 AsUINT64;
    struct {
        UINT32 NumAvailableDestinations  :16;
        UINT32 SourcePortId  :16;
        UINT32 SourceNicIndex  :8;
        UINT32 NativeForwardingRequired  :1;
        UINT32 Reserved1  :1;
        UINT32 IsPacketDataSafe  :1;
        UINT32 SafePacketDataSize  :12;
        UINT32 Reserved2  :9;
    };
} NDIS_SWITCH_FORWARDING_DETAIL_NET_BUFFER_LIST_INFO, *PNDIS_SWITCH_FORWARDING_DETAIL_NET_BUFFER_LIST_INFO;

// stubs:
typedef struct {
    PWCH   String;
    USHORT Length;
} NDIS_SWITCH_NIC_NAME;
typedef int NDIS_SWITCH_PORT_ID, NDIS_SWITCH_NIC_INDEX, NDIS_SWITCH_NIC_TYPE;
#define NdisSwitchNicTypeExternal 0
#define NdisSwitchNicTypeInternal 0
#define NdisSwitchNicTypeEmulated 0
#define NdisSwitchNicTypeSynthetic 0

typedef struct _NDIS_SWITCH_NIC_PARAMETERS {
//   NDIS_OBJECT_HEADER           Header;
//   ULONG                        Flags;
  NDIS_SWITCH_NIC_NAME         NicName;
//   NDIS_SWITCH_NIC_FRIENDLYNAME NicFriendlyName;
  NDIS_SWITCH_PORT_ID          PortId;
  NDIS_SWITCH_NIC_INDEX        NicIndex;
  NDIS_SWITCH_NIC_TYPE         NicType;
//   NDIS_SWITCH_NIC_STATE        NicState;
//   NDIS_VM_NAME                 VmName;
//   NDIS_VM_FRIENDLYNAME         VmFriendlyName;
  GUID                         NetCfgInstanceId;
//   ULONG                        MTU;
//   USHORT                       NumaNodeId;
//   UCHAR                        PermanentMacAddress[NDIS_MAX_PHYS_ADDRESS_LENGTH];
//   UCHAR                        VMMacAddress[NDIS_MAX_PHYS_ADDRESS_LENGTH];
//   UCHAR                        CurrentMacAddress[NDIS_MAX_PHYS_ADDRESS_LENGTH];
//   BOOLEAN                      VFAssigned;
//   ULONG64                      NdisReserved[2];
} NDIS_SWITCH_NIC_PARAMETERS, *PNDIS_SWITCH_NIC_PARAMETERS;

typedef void NET_BUFFER_FREE_MDL_HANDLER(
    PMDL Mdl
);

typedef VOID (NDIS_IO_WORKITEM_FUNCTION)(
    PVOID                        WorkItemContext,
    NDIS_HANDLE                  NdisIoWorkItemHandle
    );
typedef NDIS_IO_WORKITEM_FUNCTION (*NDIS_IO_WORKITEM_ROUTINE);

PVOID NdisGetDataBuffer(
    PNET_BUFFER NetBuffer,
    ULONG       BytesNeeded,
    PVOID       Storage,
    UINT        AlignMultiple,
    UINT        AlignOffset
);

PMDL NdisAllocateMdl(
  NDIS_HANDLE NdisHandle,
  PVOID       VirtualAddress,
  UINT        Length
);

PNET_BUFFER_LIST NdisAllocateNetBufferAndNetBufferList(
  NDIS_HANDLE           PoolHandle,
  USHORT                ContextSize,
  USHORT                ContextBackFill,
  PMDL                  MdlChain,
  ULONG                 DataOffset,
  SIZE_T                DataLength
);

PNET_BUFFER_LIST NdisAllocateCloneNetBufferList(
  PNET_BUFFER_LIST OriginalNetBufferList,
  NDIS_HANDLE      NetBufferListPoolHandle,
  NDIS_HANDLE      NetBufferPoolHandle,
  ULONG            AllocateCloneFlags
);

PNET_BUFFER_LIST NdisAllocateReassembledNetBufferList(
  PNET_BUFFER_LIST FragmentNetBufferList,
  NDIS_HANDLE      NetBufferAndNetBufferListPoolHandle,
  ULONG            StartOffset,
  ULONG            DataOffsetDelta,
  ULONG            DataBackFill,
  ULONG            AllocateReassembleFlags
);

PNET_BUFFER_LIST NdisAllocateFragmentNetBufferList(
  PNET_BUFFER_LIST OriginalNetBufferList,
  NDIS_HANDLE      NetBufferListPool,
  NDIS_HANDLE      NetBufferPool,
  ULONG            StartOffset,
  ULONG            MaximumLength,
  ULONG            DataOffsetDelta,
  ULONG            DataBackFill,
  ULONG            AllocateFragmentFlags
);

void NdisFreeNetBufferList(
  __drv_freesMem(mem)PNET_BUFFER_LIST NetBufferList
);

void NdisFreeCloneNetBufferList(
  __drv_freesMem(mem)PNET_BUFFER_LIST CloneNetBufferList,
  ULONG                               FreeCloneFlags
);

void NdisFreeMdl(
  __drv_freesMem(mem)PMDL Mdl
);

void NdisFSendNetBufferListsComplete(
  NDIS_HANDLE      NdisFilterHandle,
  PNET_BUFFER_LIST NetBufferList,
  ULONG            SendCompleteFlags
);

void NdisAcquireRWLockRead(
  PNDIS_RW_LOCK_EX            Lock,
  _IRQL_saves_ PLOCK_STATE_EX LockState,
  UCHAR                       Flags
);

void NdisReleaseRWLock(
  PNDIS_RW_LOCK_EX               Lock,
  _IRQL_restores_ PLOCK_STATE_EX LockState
);

NDIS_HANDLE NdisAllocateIoWorkItem(
  NDIS_HANDLE NdisObjectHandle
);

// callback definitions

typedef NDIS_STATUS (*NDIS_SWITCH_ALLOCATE_NET_BUFFER_LIST_FORWARDING_CONTEXT)(
  NDIS_SWITCH_CONTEXT NdisSwitchContext,
  PNET_BUFFER_LIST NetBufferList
);

typedef void (*NDIS_SWITCH_FREE_NET_BUFFER_LIST_FORWARDING_CONTEXT)(
  NDIS_SWITCH_CONTEXT NdisSwitchContext,
  PNET_BUFFER_LIST NetBufferList
);

typedef NDIS_STATUS (*NDIS_SWITCH_COPY_NET_BUFFER_LIST_INFO)(
  NDIS_SWITCH_CONTEXT NdisSwitchContext,
  PNET_BUFFER_LIST DestNetBufferList,
  PNET_BUFFER_LIST SrcNetBufferList,
  UINT32 Flags
);

// fake types

typedef struct _NDIS_SWITCH_OPTIONAL_HANDLERS {
    NDIS_SWITCH_ADD_NET_BUFFER_LIST_DESTINATION_HANDLER             AddNetBufferListDestination;
    NDIS_SWITCH_ALLOCATE_NET_BUFFER_LIST_FORWARDING_CONTEXT         AllocateNetBufferListForwardingContext;
    NDIS_SWITCH_FREE_NET_BUFFER_LIST_FORWARDING_CONTEXT             FreeNetBufferListForwardingContext;
    NDIS_SWITCH_COPY_NET_BUFFER_LIST_INFO                           CopyNetBufferListInfo;
} NDIS_SWITCH_OPTIONAL_HANDLERS, *PNDIS_SWITCH_OPTIONAL_HANDLERS;
