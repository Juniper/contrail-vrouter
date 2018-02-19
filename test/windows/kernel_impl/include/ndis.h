/*
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */

#pragma once

#include <winsock2.h>
#include <windows.h>
#include <in6addr.h>

#include "wdm.h"
#include "ntstrsafe.h"

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

#define NDIS_INIT_MUTEX(x)
#define NDIS_RELEASE_MUTEX(x)
#define NDIS_WAIT_FOR_MUTEX(x)
#define NET_BUFFER_LIST_FIRST_NB(x) NULL
#define NET_BUFFER_DATA_LENGTH(x) 0
#define NET_BUFFER_LIST_SWITCH_FORWARDING_DETAIL(x) NULL

typedef int NDIS_MUTEX;
typedef int NDIS_SWITCH_CONTEXT;
typedef int NDIS_EVENT;
typedef int NDIS_STATUS;
typedef int NDIS_PORT_NUMBER;
typedef int NDIS_SWITCH_PORT_ID;
typedef int NDIS_SWITCH_NIC_INDEX;

typedef void *PNDIS_RW_LOCK_EX;
typedef void *PNDIS_SWITCH_NIC_ARRAY;
typedef void *PNDIS_FILTER_ATTACH_PARAMETERS;
typedef void *PNDIS_FILTER_PAUSE_PARAMETERS;
typedef void *PNDIS_FILTER_RESTART_PARAMETERS;
typedef void *PNDIS_OID_REQUEST;
typedef void *PNET_BUFFER;

// real types

#define NDIS_FILTER_MAJOR_VERSION 6
#define NDIS_FILTER_MINOR_VERSION 4

#define NET_BUFFER_LIST_INFO(_NBL, _Id)             ((_NBL)->NetBufferListInfo[(_Id)])

struct _NET_BUFFER_LIST;
typedef struct _NET_BUFFER_LIST *PNET_BUFFER_LIST;

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

typedef UNICODE_STRING NDIS_STRING, *PNDIS_STRING;
typedef PVOID NDIS_HANDLE, *PNDIS_HANDLE;

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

typedef struct _NET_BUFFER_LIST_CONTEXT {
    struct NET_BUFFER_LIST_CONTEXT *Next;
    USHORT                          Size;
    USHORT                          Offset;
    UCHAR                           ContextData[];
} NET_BUFFER_LIST_CONTEXT, *PNET_BUFFER_LIST_CONTEXT;

typedef struct _NET_BUFFER_LIST_DATA {
    PNET_BUFFER_LIST Next;
    PNET_BUFFER      FirstNetBuffer;
} NET_BUFFER_LIST_DATA, *PNET_BUFFER_LIST_DATA;

typedef union _NET_BUFFER_LIST_HEADER {
    NET_BUFFER_LIST_DATA NetBufferListData;
    SLIST_HEADER         Link;
} NET_BUFFER_LIST_HEADER, *PNET_BUFFER_LIST_HEADER;

typedef struct _NET_BUFFER_LIST {
    NET_BUFFER_LIST_HEADER   NetBufferListHeader;
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
} NET_BUFFER_LIST, *PNET_BUFFER_LIST;

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

typedef void NET_BUFFER_FREE_MDL_HANDLER(
    PMDL Mdl
);

PVOID NdisGetDataBuffer(
    PNET_BUFFER NetBuffer,
    ULONG       BytesNeeded,
    PVOID       Storage,
    UINT        AlignMultiple,
    UINT        AlignOffset
);

// fake types

typedef struct _NDIS_SWITCH_OPTIONAL_HANDLERS {
    NDIS_SWITCH_ADD_NET_BUFFER_LIST_DESTINATION_HANDLER             AddNetBufferListDestination;
} NDIS_SWITCH_OPTIONAL_HANDLERS, *PNDIS_SWITCH_OPTIONAL_HANDLERS;
