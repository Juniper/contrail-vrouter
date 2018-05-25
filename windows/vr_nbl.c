/*
 * Copyright (c) 2017 Juniper Networks, Inc. All rights reserved.
 */
#include "precomp.h"

#include "vr_interface.h"
#include "vr_packet.h"
#include "vr_windows.h"
#include "vrouter.h"
#include "windows_nbl.h"

/*
 * # Memory management of NBLs and vr_packets
 *
 * vr_packet is allocated in separate allocation and has a pointer
 *     void* vp_net_buffer_list;
 * that points to its NBL. There should be at most one vr_packet
 * per NBL (could be 0 for NBLs that are some "leftovers after Cloning").
 * An NBL doesn't have any pointers to the associated vr_packet.
 *
 * vr_packets are considered owned by dp-core.
 * vr_packets can only point to leaf NBLs.
 * Deallocating parent NBLs is not done directly,
 * but is triggered when the ChildRefCount drops to 0,
 * which is be caused by freeing the child NBL.
 *
 * vr_packet is usually freed either by calling win_pfree or win_if_tx.
 * Therefore, in the FilterSendNetBufferListComplete there are no vr_packets.
 */

FILTER_SEND_NET_BUFFER_LISTS FilterSendNetBufferLists;
FILTER_SEND_NET_BUFFER_LISTS_COMPLETE FilterSendNetBufferListsComplete;

static NDIS_STATUS
CreateForwardingContext(PNET_BUFFER_LIST nbl)
{
    ASSERT(nbl != NULL);
    return VrSwitchObject->NdisSwitchHandlers.AllocateNetBufferListForwardingContext(
        VrSwitchObject->NdisSwitchContext,
        nbl);
}

static void
FreeForwardingContext(PNET_BUFFER_LIST nbl)
{
    ASSERT(nbl != NULL);
    VrSwitchObject->NdisSwitchHandlers.FreeNetBufferListForwardingContext(
        VrSwitchObject->NdisSwitchContext,
        nbl);
}

static PNET_BUFFER_LIST
CreateNetBufferListUsingBuffer(unsigned int bytesCount, void *buffer)
{
    ASSERT(bytesCount > 0);
    ASSERT(buffer != NULL);

    PMDL mdl = NdisAllocateMdl(VrSwitchObject->NdisFilterHandle, buffer, bytesCount);
    if (mdl == NULL)
        return NULL;
    mdl->Next = NULL;

    PNET_BUFFER_LIST nbl = NdisAllocateNetBufferAndNetBufferList(VrNBLPool, 0, 0, mdl, 0, bytesCount);
    if (nbl == NULL)
        goto fail;
    nbl->SourceHandle = VrSwitchObject->NdisFilterHandle;

    NDIS_STATUS status = CreateForwardingContext(nbl);
    if (!NT_SUCCESS(status))
        goto fail;

    return nbl;

fail:
    if (nbl != NULL)
        NdisFreeNetBufferList(nbl);
    if (mdl != NULL)
        NdisFreeMdl(mdl);
    return NULL;
}

PNET_BUFFER_LIST
CreateNetBufferList(unsigned int bytesCount)
{
    ASSERT(bytesCount > 0);

    if (bytesCount == 0)
        return NULL;

    void *buffer = ExAllocatePoolWithTag(NonPagedPoolNx, bytesCount, VrAllocationTag);
    if (buffer == NULL)
        return NULL;
    RtlZeroMemory(buffer, bytesCount);

    PNET_BUFFER_LIST nbl = CreateNetBufferListUsingBuffer(bytesCount, buffer);
    if (nbl == NULL) {
        ExFreePool(buffer);
        return NULL;
    }

    return nbl;
}

static VOID
FreeClonedNetBufferList(PNET_BUFFER_LIST nbl, BOOLEAN recursive)
{
    ASSERT(nbl != NULL);
    ASSERT(nbl->ParentNetBufferList != NULL);

    PNET_BUFFER_LIST parentNbl = nbl->ParentNetBufferList;

    FreeForwardingContext(nbl);
    NdisFreeCloneNetBufferList(nbl, 0);

    if (InterlockedDecrement(&parentNbl->ChildRefCount) == 0 && recursive) {
        FreeNetBufferList(parentNbl);
    }
}

VOID
FreeClonedNetBufferListRecursive(PNET_BUFFER_LIST nbl)
{
    FreeClonedNetBufferList(nbl, true);
}

VOID
FreeClonedNetBufferListPreservingParent(PNET_BUFFER_LIST nbl)
{
    FreeClonedNetBufferList(nbl, false);
}

VOID
FreeCreatedNetBufferList(PNET_BUFFER_LIST nbl)
{
    ASSERT(nbl != NULL);
    ASSERTMSG("A non-singular NBL made it's way into the process", nbl->Next == NULL);

    PNET_BUFFER nb = NULL;
    PMDL mdl = NULL;
    PMDL mdl_next = NULL;
    PVOID data = NULL;

    FreeForwardingContext(nbl);

    /* Free MDLs associated with NET_BUFFERS */
    for (nb = NET_BUFFER_LIST_FIRST_NB(nbl); nb != NULL; nb = NET_BUFFER_NEXT_NB(nb))
        for (mdl = NET_BUFFER_FIRST_MDL(nb); mdl != NULL; mdl = mdl_next) {
            mdl_next = mdl->Next;
            data = MmGetSystemAddressForMdlSafe(mdl, LowPagePriority | MdlMappingNoExecute);
            NdisFreeMdl(mdl);
            if (data != NULL)
                ExFreePool(data);
        }

    NdisFreeNetBufferList(nbl);
}

static VOID
CompleteReceivedNetBufferList(PNET_BUFFER_LIST nbl)
{
    ASSERT(nbl != NULL);

    /* Flag SINGLE_SOURCE is used, because of singular NBLS */
    NdisFSendNetBufferListsComplete(VrSwitchObject->NdisFilterHandle,
        nbl,
        NDIS_SEND_COMPLETE_FLAGS_SWITCH_SINGLE_SOURCE);
}

VOID
FreeNetBufferList(PNET_BUFFER_LIST nbl)
{
    ASSERT(nbl != NULL);
    ASSERTMSG("A non-singular NBL made it's way into the process", nbl->Next == NULL);
    ASSERT(nbl->ChildRefCount == 0);

    if (IS_NBL_OWNED(nbl)) {
        if (IS_NBL_CLONE(nbl)) {
            FreeClonedNetBufferListRecursive(nbl);
        } else {
            FreeCreatedNetBufferList(nbl);
        }
    } else {
        CompleteReceivedNetBufferList(nbl);
    }
}

PNET_BUFFER_LIST
CloneNetBufferList(PNET_BUFFER_LIST originalNbl)
{
    ASSERT(originalNbl != NULL);

    BOOLEAN contextCreated = false;
    PNET_BUFFER_LIST newNbl = NdisAllocateCloneNetBufferList(originalNbl, VrNBLPool, NULL, 0);
    if (newNbl == NULL)
        goto cleanup;

    newNbl->SourceHandle = VrSwitchObject->NdisFilterHandle;
    newNbl->ParentNetBufferList = originalNbl;

    if (CreateForwardingContext(newNbl) != NDIS_STATUS_SUCCESS)
        goto cleanup;
    contextCreated = true;

    NDIS_STATUS status = VrSwitchObject->NdisSwitchHandlers.CopyNetBufferListInfo(
        VrSwitchObject->NdisSwitchContext, newNbl, originalNbl, 0);
    if (status != NDIS_STATUS_SUCCESS)
        goto cleanup;

    InterlockedIncrement(&originalNbl->ChildRefCount);

    return newNbl;

cleanup:
    if (contextCreated)
        FreeForwardingContext(newNbl);

    if (newNbl) {
        NdisFreeCloneNetBufferList(newNbl, 0);
    }

    return NULL;
}

// Free the vr_packet and associated nbl
void
win_free_packet(struct vr_packet *pkt)
{
    ASSERT(pkt != NULL);
    PNET_BUFFER_LIST nbl = pkt->vp_net_buffer_list;
    ASSERT(nbl != NULL);
    ExFreePool(pkt);
    FreeNetBufferList(nbl);
}

/*
 * Splits NBL with multiple NBs into list of NBLs,
 * in which each NBL has a single NB.
 *
 * The original NBL is set as a parent and left intact.
 * The returned value is a list of new NBLs.
 *
 * In case the NBL has a single Net Buffer List,
 * returns the original NBL.
 */
PNET_BUFFER_LIST
SplitMultiNetBufferNetBufferList(PNET_BUFFER_LIST origNbl)
{
    PNET_BUFFER nextNb, nb, firstNb = NET_BUFFER_LIST_FIRST_NB(origNbl);
    PNET_BUFFER_LIST *pNextNbl, nextNbl, clonedNbl = NULL, clonedNblList = NULL;
    pNextNbl = &clonedNblList;

    if (firstNb == NULL || NET_BUFFER_NEXT_NB(firstNb) == NULL) {
        return origNbl;
    }

    for (nb = firstNb; nb; nb = nextNb) {
        // Pretend it's a single-NB NBL for the time of cloning
        NET_BUFFER_LIST_FIRST_NB(origNbl) = nb;
        nextNb = NET_BUFFER_NEXT_NB(nb);
        NET_BUFFER_NEXT_NB(nb) = NULL;

        // TODO optimization: use NDIS_CLONE_FLAGS_USE_ORIGINAL_MDLS flag
        // (need to support it in free)
        clonedNbl = CloneNetBufferList(origNbl);

        NET_BUFFER_NEXT_NB(nb) = nextNb;

        if (clonedNbl == NULL) {
            goto cleanup;
        }

        *pNextNbl = clonedNbl;
        pNextNbl = &NET_BUFFER_LIST_NEXT_NBL(clonedNbl);
    }

    // Restore original NB chain
    NET_BUFFER_LIST_FIRST_NB(origNbl) = firstNb;

    return clonedNblList;

cleanup:
    NET_BUFFER_LIST_FIRST_NB(origNbl) = firstNb;

    for (clonedNbl = clonedNblList; clonedNbl; clonedNbl = nextNbl) {
        nextNbl = NET_BUFFER_LIST_NEXT_NBL(clonedNbl);
        NET_BUFFER_LIST_NEXT_NBL(clonedNbl) = NULL;
        FreeClonedNetBufferListPreservingParent(clonedNbl);
    }

    return NULL;
}

void
win_packet_map_from_mdl(struct vr_packet *pkt, PMDL mdl, ULONG mdl_offset, ULONG data_length)
{
    pkt->vp_head = (unsigned char*) MmGetSystemAddressForMdlSafe(mdl, LowPagePriority | MdlMappingNoExecute);
    if (!pkt->vp_head) {
        pkt->vp_end = pkt->vp_data = pkt->vp_tail = pkt->vp_len = 0;
        return;
    }

    pkt->vp_head += mdl_offset;
    /* vp_data is the offset from vp_head, where packet begins.
       TODO: When packet encapsulation comes into play, then vp_data should differ.
             There should be enough room between vp_head and vp_data to add packet headers.
    */
    pkt->vp_data = 0;

    // left_mdl_space is a space from begin of data section to the end of mdl
    ULONG left_mdl_space = MmGetMdlByteCount(mdl) - mdl_offset;
    pkt->vp_tail = pkt->vp_len = (data_length < left_mdl_space ? data_length : left_mdl_space);
    pkt->vp_end = left_mdl_space;

    return;
}

// Create vr_packet based on existing NBL
struct vr_packet *
win_get_packet(PNET_BUFFER_LIST nbl, struct vr_interface *vif)
{
    // Precondition: nbl has exactly one NetBuffer

    ASSERT(nbl != NULL);

    DbgPrint("%s()\n", __func__);

    struct vr_packet *pkt = ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(struct vr_packet), VrAllocationTag);
    if (!pkt) {
        return NULL;
    }

    RtlZeroMemory(pkt, sizeof(struct vr_packet));

    pkt->vp_net_buffer_list = nbl;
    pkt->vp_cpu = (unsigned char)KeGetCurrentProcessorNumberEx(NULL);

    /* vp_head points to the beginning of accesible non-paged memory of the packet */
    PNET_BUFFER nb = NET_BUFFER_LIST_FIRST_NB(nbl);
    ULONG data_length = NET_BUFFER_DATA_LENGTH(nb);

    if (IS_NBL_OWNED(nbl) && !IS_NBL_CLONE(nbl)) {
        data_length = 0;
    }

    win_packet_map_from_mdl(pkt, NET_BUFFER_CURRENT_MDL(nb),
                            NET_BUFFER_CURRENT_MDL_OFFSET(nb),
                            data_length);

    if (!pkt->vp_head) {
        goto drop;
    }

    pkt->vp_if = vif;
    pkt->vp_network_h = pkt->vp_inner_network_h = 0;
    pkt->vp_nh = NULL;
    pkt->vp_flags = 0;

    pkt->vp_ttl = VP_DEFAULT_INITIAL_TTL;
    pkt->vp_type = VP_TYPE_NULL;
    pkt->vp_queue = 0;
    pkt->vp_priority = 0;  /* PCP Field from IEEE 802.1Q. vp_priority = 0 is a default value for this. */

    return pkt;

drop:
    ExFreePool(pkt);
    return NULL;
}

// Crate vr_packet and NBL based on buffer
struct vr_packet *
win_allocate_packet(void *buffer, unsigned int size)
{
    ASSERT(size > 0);

    PNET_BUFFER_LIST nbl = NULL;
    struct vr_packet *pkt = NULL;
    unsigned char *ptr = NULL;

    if (buffer != NULL) {
        nbl = CreateNetBufferListUsingBuffer(size, buffer);
    } else {
        nbl = CreateNetBufferList(size);
    }
    if (nbl == NULL)
        goto fail;

    pkt = win_get_packet(nbl, NULL);
    if (pkt == NULL)
        goto fail;

    if (buffer != NULL) {
        ptr = pkt_pull_tail(pkt, size);
        if (ptr == NULL)
            goto fail;
    }

    return pkt;

fail:
    if (pkt)
        win_free_packet(pkt);
    else if (nbl)
        FreeCreatedNetBufferList(nbl);
    return NULL;
}

static VOID
SplitNetBufferListsByForwardingType(
    PNET_BUFFER_LIST nbl,
    PNET_BUFFER_LIST *nextExtForwardNbl,
    PNET_BUFFER_LIST *nextNativeForwardedNbl)
{
    PNET_BUFFER_LIST curNbl;
    PNET_BUFFER_LIST nextNbl;
    PNDIS_SWITCH_FORWARDING_DETAIL_NET_BUFFER_LIST_INFO fwdDetail;

    // Divide the NBL into two: part which requires native forwarding and the rest
    for (curNbl = nbl; curNbl != NULL; curNbl = nextNbl) {
        // Rememeber the next NBL
        nextNbl = curNbl->Next;

        fwdDetail = NET_BUFFER_LIST_SWITCH_FORWARDING_DETAIL(curNbl);
        if (fwdDetail->NativeForwardingRequired) {
            // Set the next NBL to current NBL. This pointer points to either first pointer to
            // native forwarded NBL or the "Next" field of the last one.
            *nextNativeForwardedNbl = curNbl;
            nextNativeForwardedNbl = &(curNbl->Next);
        } else {
            // Set the next NBL to current NBL. This pointer points to either first pointer to
            // non-native forwarded NBL or the "Next" field of the last one.
            *nextExtForwardNbl = curNbl;
            nextExtForwardNbl = &(curNbl->Next);
        }
    }
}

static struct vr_interface *
GetAssociatedVrInterface(NDIS_SWITCH_PORT_ID vifPort, NDIS_SWITCH_NIC_INDEX vifNic)
{
    struct vrouter *vrouter = vrouter_get(0);
    ASSERT(vrouter != NULL);

    for (int i = 0; i < vrouter->vr_max_interfaces; i++) {
        struct vr_interface* vif = vrouter->vr_interfaces[i];

        if (vif == NULL)
            continue;

        if (vif->vif_port == vifPort && vif->vif_nic == vifNic)
            return vif;
    }

    // VIF is not registered, very temporary state
    return NULL;
}

VOID
FilterSendNetBufferLists(
    NDIS_HANDLE filterModuleContext,
    PNET_BUFFER_LIST netBufferLists,
    NDIS_PORT_NUMBER portNumber,
    ULONG sendFlags)
{
    PSWITCH_OBJECT switchObject = (PSWITCH_OBJECT)filterModuleContext;

    LOCK_STATE_EX lockState;

    BOOLEAN sameSource;
    ULONG sendCompleteFlags = 0;
    BOOLEAN on_dispatch_level;

    PNET_BUFFER_LIST extForwardedNbls = NULL;  // NBLs forwarded by extension.
    PNET_BUFFER_LIST nativeForwardedNbls = NULL;  // NBLs that require native forwarding - extension just sends them.
    PNET_BUFFER_LIST curNbl = NULL;
    PNET_BUFFER_LIST nextNbl = NULL;

    UNREFERENCED_PARAMETER(portNumber);

    // True if packets come from the same switch source port.
    sameSource = NDIS_TEST_SEND_FLAG(sendFlags, NDIS_SEND_FLAGS_SWITCH_SINGLE_SOURCE);
    if (sameSource) {
        sendCompleteFlags |= NDIS_SEND_COMPLETE_FLAGS_SWITCH_SINGLE_SOURCE;
    }

    // Forward DISPATCH_LEVEL flag.
    on_dispatch_level = NDIS_TEST_SEND_FLAG(sendFlags, NDIS_SEND_FLAGS_DISPATCH_LEVEL);
    if (on_dispatch_level) {
        sendCompleteFlags |= NDIS_SEND_COMPLETE_FLAGS_DISPATCH_LEVEL;
    }

    if (switchObject->Running == FALSE) {
        NdisFSendNetBufferListsComplete(switchObject->NdisFilterHandle, netBufferLists, sendCompleteFlags);
        return;
    }

    // Acquire the lock, now interfaces cannot disconnect, etc.
    NdisAcquireRWLockRead(switchObject->ExtensionContext->lock, &lockState, on_dispatch_level);

    SplitNetBufferListsByForwardingType(netBufferLists, &extForwardedNbls, &nativeForwardedNbls);

    for (curNbl = extForwardedNbls; curNbl != NULL; curNbl = nextNbl) {
        /* Save next NBL, because after passing control to vRouter it might drop curNbl.
        Also vRouter handles packets one-by-one, so we operate on single NBLs.
        */
        nextNbl = curNbl->Next;
        curNbl->Next = NULL;

        PNDIS_SWITCH_FORWARDING_DETAIL_NET_BUFFER_LIST_INFO fwd_detail = NET_BUFFER_LIST_SWITCH_FORWARDING_DETAIL(curNbl);
        NDIS_SWITCH_PORT_ID source_port = fwd_detail->SourcePortId;
        NDIS_SWITCH_NIC_INDEX source_nic = fwd_detail->SourceNicIndex;

        struct vr_interface *vif = GetAssociatedVrInterface(source_port, source_nic);

        if (!vif) {
            // If no vif attached yet, then drop NBL.
            NdisFSendNetBufferListsComplete(switchObject->NdisFilterHandle, curNbl, sendCompleteFlags);
            continue;
        }

        // Enforce 1 to 1 NBL <-> NB relationship
        PNET_BUFFER_LIST splittedNblList = SplitMultiNetBufferNetBufferList(curNbl);
        if (splittedNblList == NULL) {
            NdisFSendNetBufferListsComplete(switchObject->NdisFilterHandle, curNbl, sendCompleteFlags);
            continue;
        }
        curNbl = splittedNblList;

        PNET_BUFFER_LIST innerLoopNextNbl;
        for (; curNbl; curNbl = innerLoopNextNbl) {
            innerLoopNextNbl = curNbl->Next;
            curNbl->Next = NULL;

            struct vr_packet *pkt = win_get_packet(curNbl, vif);
            ASSERTMSG("win_get_packed failed!", pkt != NULL);

            if (pkt == NULL) {
                FreeNetBufferList(curNbl);
                continue;
            }

            ASSERTMSG("VIF doesn't have a vif_rx method set!", vif->vif_rx != NULL);
            if (vif->vif_rx) {
                vif->vif_rx(vif, pkt, VLAN_ID_INVALID);
            }
            else {
                /* If `vif_rx` is not set (unlikely in production), then drop the packet. */
                vr_pfree(pkt, VP_DROP_INTERFACE_DROP);
                continue;
            }
        }
    }

    if (nativeForwardedNbls != NULL) {
        NdisFSendNetBufferLists(switchObject->NdisFilterHandle,
            nativeForwardedNbls,
            NDIS_DEFAULT_PORT_NUMBER,
            sendFlags);
    }

    // Release the lock, now interfaces can disconnect, etc.
    NdisReleaseRWLock(switchObject->ExtensionContext->lock, &lockState);
}

VOID
FilterSendNetBufferListsComplete(
    NDIS_HANDLE filterModuleContext,
    PNET_BUFFER_LIST netBufferLists,
    ULONG sendCompleteFlags)
{
    PNET_BUFFER_LIST next = netBufferLists;
    PNET_BUFFER_LIST current;

    UNREFERENCED_PARAMETER(filterModuleContext);
    UNREFERENCED_PARAMETER(sendCompleteFlags);

    do {
        current = next;
        next = current->Next;
        current->Next = NULL;

        FreeNetBufferList(current);
    } while (next != NULL);
}
