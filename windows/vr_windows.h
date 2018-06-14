/*
 * vr_windows.h -- common defines and declarations used in Windows-specific code
 *
 * Copyright (c) 2017 Juniper Networks, Inc. All rights reserved.
 */
#ifndef __VR_WINDOWS_H__
#define __VR_WINDOWS_H__

#include <ndis.h>

#ifdef __cplusplus
extern "C" {
#endif

#define VR_MINIPORT_VPKT_INDEX 0

#define VR_OID_SOURCE   0x00000001
#define VR_AGENT_SOURCE 0x00000002

typedef struct _vr_switch_context
{
    PNDIS_RW_LOCK_EX        lock;

    /* Following flags are ordered in module initialization order */
    BOOLEAN                 ksync_up;
    BOOLEAN                 pkt0_up;
    BOOLEAN                 shmem_devices_up;
    BOOLEAN                 message_up;
    BOOLEAN                 vrouter_up;
} vr_switch_context, *pvr_switch_context;

typedef struct _SWITCH_OBJECT
{
    pvr_switch_context ExtensionContext;

    // Ndis related fields.
    NDIS_HANDLE NdisFilterHandle;
    NDIS_SWITCH_CONTEXT NdisSwitchContext;
    NDIS_SWITCH_OPTIONAL_HANDLERS NdisSwitchHandlers;

    // Switch state.
    volatile BOOLEAN Running;

    // Management fields.
    volatile LONG PendingOidCount;

} SWITCH_OBJECT, *PSWITCH_OBJECT;

typedef struct _VR_OID_REQUEST_STATUS
{
    NDIS_EVENT ReqEvent;
    NDIS_STATUS Status;
    ULONG BytesNeeded;

} VR_OID_REQUEST_STATUS, *PVR_OID_REQUEST_STATUS;

extern const ULONG VrAllocationTag;
extern const ULONG VrOidRequestId;

extern PSWITCH_OBJECT VrSwitchObject;
extern NDIS_HANDLE VrNBLPool;
extern PNDIS_RW_LOCK_EX AsyncWorkRWLock;

/* Functions for OID request handling are located in windows/vr_oid.c */
extern FILTER_OID_REQUEST FilterOidRequest;
extern FILTER_OID_REQUEST_COMPLETE FilterOidRequestComplete;
extern FILTER_CANCEL_OID_REQUEST FilterCancelOidRequest;

/* Functions used to initialize message subsystem */
extern NTSTATUS vr_message_init(void);
extern void vr_message_exit(void);

NDIS_STATUS VrGetNicArray(PSWITCH_OBJECT Switch, PNDIS_SWITCH_NIC_ARRAY *OutputNicArray);
VOID VrFreeNicArray(PNDIS_SWITCH_NIC_ARRAY NicArray);

void get_random_bytes(void *buf, int nbytes);

struct host_os * vrouter_get_host(void);

NDIS_HANDLE vrouter_generate_pool(void);
void vrouter_free_pool(NDIS_HANDLE pool);

extern struct host_os windows_host;

extern void win_if_lock(void);
extern void win_if_unlock(void);

/* vRouter transport module init functions */
extern int vr_transport_init(void);
extern void vr_transport_exit(void);

#ifdef __cplusplus
}
#endif

#endif
