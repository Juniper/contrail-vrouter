/*
 * Copyright (c) 2017 Juniper Networks, Inc. All rights reserved.
 */
#include "precomp.h"

#include <errno.h>
#include "vr_os.h"
#include "vr_packet.h"
#include "vr_stats.h"
#include "vr_hash.h"
#include "vr_windows.h"
#include "vrouter.h"
#include "windows_nbl.h"

typedef void(*scheduled_work_cb)(void *arg);

struct deferred_work_cb_data {
    vr_defer_cb user_cb;
    struct vrouter * router;
    unsigned char user_data[0];
};

struct scheduled_work_cb_data {
    scheduled_work_cb user_cb;
    void * data;
};

static unsigned int win_get_cpu(void);
static void win_pfree(struct vr_packet *pkt, unsigned short reason);  // Forward declaration

static NDIS_IO_WORKITEM_FUNCTION deferred_work_routine;

static int
win_printf(const char *format, ...)
{
    int printed;
    va_list args;

    /* Only following version of DbgPrint correctly accepts va_list as an argument */
    _crt_va_start(args, format);
    printed = vDbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_INFO_LEVEL, format, args);
    _crt_va_end(args);

    return printed;
}

static void *
win_malloc(unsigned int size, unsigned int object)
{
    void *mem = ExAllocatePoolWithTag(NonPagedPoolNx, size, VrAllocationTag);
    if (mem != NULL)
        vr_malloc_stats(size, object);

    return mem;
}

static void *
win_zalloc(unsigned int size, unsigned int object)
{
    ASSERT(size > 0);

    void *mem = ExAllocatePoolWithTag(NonPagedPoolNx, size, VrAllocationTag);
    if (mem != NULL) {
        NdisZeroMemory(mem, size);
        vr_malloc_stats(size, object);
    }

    return mem;
}

static void *
win_page_alloc(unsigned int size)
{
    ASSERT(size > 0);

    void *mem = ExAllocatePoolWithTag(NonPagedPoolNx, size, VrAllocationTag);
    if (mem != NULL)
        NdisZeroMemory(mem, size);

    return mem;
}

static void
win_free(void *mem, unsigned int object)
{
    ASSERT(mem != NULL);

    UNREFERENCED_PARAMETER(object);

    if (mem != NULL) {
        vr_free_stats(object);
        ExFreePool(mem);
    }

    return;
}

static uint64_t
win_vtop(void *address)
{
    ASSERT(address != NULL);
    PHYSICAL_ADDRESS physical_address = MmGetPhysicalAddress(address);

    return physical_address.QuadPart;
}

static void
win_page_free(void *address, unsigned int size)
{
    UNREFERENCED_PARAMETER(size);

    ASSERT(address != NULL);

    if (address)
        ExFreePool(address);

    return;
}

static struct vr_packet *
win_palloc(unsigned int size)
{
    return win_allocate_packet(NULL, size);
}

// This is dead code!
static struct vr_packet *
win_palloc_head(struct vr_packet *pkt, unsigned int size)
{
    ASSERT(pkt != NULL);
    ASSERT(size > 0);

    PNET_BUFFER_LIST nbl = pkt->vp_net_buffer_list;
    if (nbl == NULL)
        return NULL;

    PNET_BUFFER_LIST nb_head = CreateNetBufferList(size);
    if (nb_head == NULL)
        return NULL;

    struct vr_packet *npkt = win_get_packet(nb_head, pkt->vp_if);
    if (npkt == NULL)
    {
        FreeCreatedNetBufferList(nb_head);
        return NULL;
    }

    npkt->vp_ttl = pkt->vp_ttl;
    npkt->vp_flags = pkt->vp_flags;
    npkt->vp_type = pkt->vp_type;

    npkt->vp_network_h += pkt->vp_network_h + npkt->vp_end;
    npkt->vp_inner_network_h += pkt->vp_inner_network_h + npkt->vp_end;

    ExFreePool(pkt);

    return npkt;
}

static struct vr_packet *
win_pexpand_head(struct vr_packet *pkt, unsigned int hspace)
{
    ASSERT(pkt != NULL);

    PNET_BUFFER_LIST original_nbl = pkt->vp_net_buffer_list;
    if (original_nbl == NULL)
        return NULL;

    PNET_BUFFER_LIST new_nbl = CloneNetBufferList(original_nbl);
    if (new_nbl == NULL)
        goto cleanup;

    PNET_BUFFER nb = NET_BUFFER_LIST_FIRST_NB(new_nbl);
    if (nb == NULL)
        goto cleanup;

    if (nb->CurrentMdlOffset >= hspace) {
        if (NdisRetreatNetBufferDataStart(nb, hspace, 0, NULL) != NDIS_STATUS_SUCCESS)
            goto cleanup;
    }
    else {
        UINT mdl_len = 0;
        PVOID old_buffer = NULL;
        PVOID new_buffer = NULL;
        NdisQueryMdl(nb->CurrentMdl, &old_buffer, &mdl_len, LowPagePriority);
        UINT data_size_in_current_mdl = mdl_len - nb->CurrentMdlOffset;
        UINT required_continuous_buffer_size = data_size_in_current_mdl + hspace;
        UINT data_offset = nb->CurrentMdlOffset;
        NdisAdvanceNetBufferDataStart(nb, data_size_in_current_mdl, TRUE, NULL);
        if (NdisRetreatNetBufferDataStart(nb, required_continuous_buffer_size, 0, NULL) != NDIS_STATUS_SUCCESS) {
            goto cleanup;
        }
        NdisQueryMdl(nb->CurrentMdl, &new_buffer, &mdl_len, LowPagePriority);
        RtlCopyMemory((uint8_t*)new_buffer + hspace, (uint8_t*)old_buffer + data_offset, data_size_in_current_mdl);
    }

    pkt->vp_net_buffer_list = new_nbl;

    pkt->vp_head =
        (unsigned char*)MmGetSystemAddressForMdlSafe(nb->CurrentMdl, LowPagePriority | MdlMappingNoExecute) + NET_BUFFER_CURRENT_MDL_OFFSET(nb);
    pkt->vp_data += (unsigned short)hspace;
    pkt->vp_tail += (unsigned short)hspace;
    pkt->vp_end = MmGetMdlByteCount(nb->CurrentMdl);

    pkt->vp_network_h += (unsigned short)hspace;
    pkt->vp_inner_network_h += (unsigned short)hspace;

    return pkt;

cleanup:
    if (new_nbl) {
        FreeClonedNetBufferListPreservingParent(new_nbl);
    }

    return NULL;
}

static void
win_preset(struct vr_packet *pkt)
{
    ASSERT(pkt != NULL);

    PNET_BUFFER_LIST nbl = pkt->vp_net_buffer_list;
    if (!nbl) {
        return;
    }

    PNET_BUFFER nb = NET_BUFFER_LIST_FIRST_NB(nbl);
    if (!nb) {
        return;
    }

    win_packet_map_from_mdl(pkt, NET_BUFFER_CURRENT_MDL(nb),
                            NET_BUFFER_CURRENT_MDL_OFFSET(nb), NET_BUFFER_DATA_LENGTH(nb));

    return;
}

static struct vr_packet *
win_pclone(struct vr_packet *pkt)
{
    // To keep the invariant that vr_packet references only leaf NBLs,
    // we need to create two CloneNetBufferLists.
    // leftNbl will be referenced by original packet
    // and rightNbl will be referenced by npkt.
    ASSERT(pkt != NULL);

    PNET_BUFFER_LIST originalNbl = pkt->vp_net_buffer_list;

    ASSERT(originalNbl != NULL);

    PNET_BUFFER_LIST leftNbl = CloneNetBufferList(originalNbl);
    if (leftNbl == NULL)
        return NULL;

    PNET_BUFFER_LIST rightNbl = CloneNetBufferList(originalNbl);
    if (rightNbl == NULL)
        goto cleanup_nbl;

    struct vr_packet *npkt = ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(struct vr_packet), VrAllocationTag);
    if (npkt == NULL)
        goto cleanup_both_nbls;

    *npkt = *pkt;

    pkt->vp_net_buffer_list = leftNbl;
    pkt->vp_cpu = (unsigned char)win_get_cpu();

    npkt->vp_net_buffer_list = rightNbl;
    npkt->vp_cpu = (unsigned char)win_get_cpu();

    return npkt;

cleanup_both_nbls:
    FreeClonedNetBufferListPreservingParent(rightNbl);

cleanup_nbl:
    FreeClonedNetBufferListPreservingParent(leftNbl);

    return NULL;
}

static void
win_pfree(struct vr_packet *pkt, unsigned short reason)
{
    ASSERT(pkt != NULL);

    struct vrouter *router = vrouter_get(0);
    unsigned int cpu = pkt->vp_cpu;

    if (router)
        ((uint64_t *)(router->vr_pdrop_stats[cpu]))[reason]++;

    win_free_packet(pkt);
}

static int
win_pcopy_from_nb(unsigned char *dst, PNET_BUFFER nb,
    unsigned int offset, unsigned int len)
{
    /*  Check if requested data lies inside NET_BUFFER data buffer:
        * data_offset - offset inside MDL list
        * data_length - size of the data stored in MDL list
        Relation between those is presented in https://msdn.microsoft.com/en-us/microsoft-r/ff568728.aspx
    */
    ULONG data_offset = NET_BUFFER_DATA_OFFSET(nb);
    ULONG data_length = NET_BUFFER_DATA_LENGTH(nb);
    ULONG data_size = data_offset + data_length;
    if (data_offset + (ULONG)offset + (ULONG)len > data_size) {
        return -EFAULT;
    }

    /* Check if requested data offset lies in the NET_BUFFER's current MDL. */
    PMDL current_mdl = NET_BUFFER_CURRENT_MDL(nb);
    if (NET_BUFFER_CURRENT_MDL_OFFSET(nb) + offset >= MmGetMdlByteCount(current_mdl)) {
        /* Requested offset lies outside of the first MDL => traverse MDL list until offset is reached */
        offset -= MmGetMdlByteCount(current_mdl) - NET_BUFFER_CURRENT_MDL_OFFSET(nb);
        current_mdl = current_mdl->Next;
        if (!current_mdl) {
            return -EFAULT;
        }
        while (offset >= MmGetMdlByteCount(current_mdl)) {
            offset -= MmGetMdlByteCount(current_mdl);
            current_mdl = current_mdl->Next;
            if (!current_mdl) {
                return -EFAULT;
            }
        }
    } else {
        /* Requested offset lies in the first MDL => add MDL_OFFSET to offset */
        offset += NET_BUFFER_CURRENT_MDL_OFFSET(nb);
    }

    /* Retrieve pointer to the beginning of MDL's data buffer */
    unsigned char *mdl_data =
        (unsigned char *)MmGetSystemAddressForMdlSafe(current_mdl, LowPagePriority | MdlMappingNoExecute);
    if (!mdl_data) {
        return -EFAULT;
    }

    /* Copy data from the first MDL where offset lies */
    ULONG copied_bytes = 0;
    ULONG bytes_left_in_first_mdl = MmGetMdlByteCount(current_mdl) - offset;
    if (bytes_left_in_first_mdl <= len) {
        NdisMoveMemory(dst, mdl_data + offset, bytes_left_in_first_mdl);
        copied_bytes += bytes_left_in_first_mdl;
    } else {
        /* All of the requested data lies in `current_mdl` */
        NdisMoveMemory(dst, mdl_data + offset, len);
        copied_bytes += len;
    }

    /*  Iterate MDL list, starting from where `current_mdl` now points and copy the rest
        of the requested data
    */
    current_mdl = current_mdl->Next;
    while (current_mdl && copied_bytes < len) {
        /* Get the pointer to the beginning of data represented in current MDL. */
        mdl_data =
            (unsigned char *)MmGetSystemAddressForMdlSafe(current_mdl, LowPagePriority | MdlMappingNoExecute);
        if (!mdl_data) {
            return -EFAULT;
        }

        unsigned int left_to_copy = len - copied_bytes;
        ULONG mdl_size = MmGetMdlByteCount(current_mdl);
        if (left_to_copy >= mdl_size) {
            /* If we need to copy more bytes than is stored in MDL, then copy whole MDL buffer. */
            NdisMoveMemory(dst + copied_bytes, mdl_data, mdl_size);
            copied_bytes += mdl_size;
        } else {
            /* Otherwise copy only the necessary amount. */
            NdisMoveMemory(dst + copied_bytes, mdl_data, left_to_copy);
            copied_bytes += left_to_copy;
        }

        current_mdl = current_mdl->Next;
    }

    if (copied_bytes < len) {
        /*  This case appears when MDL list has ended before all of the requested
            packet data could be copied.
        */
        return -EFAULT;
    }

    return len;
}

static int
win_pcopy(unsigned char *dst, struct vr_packet *p_src,
        unsigned int offset, unsigned int len)
{
    if (!p_src) {
        return -EFAULT;
    }
    PNET_BUFFER_LIST nbl = p_src->vp_net_buffer_list;
    if (!nbl) {
        return -EFAULT;
    }
    PNET_BUFFER nb = NET_BUFFER_LIST_FIRST_NB(nbl);
    if (!nb) {
        return -EFAULT;
    }

    return win_pcopy_from_nb(dst, nb, offset, len);
}

static unsigned short
win_pfrag_len(struct vr_packet *pkt)
{
    ASSERT(pkt != NULL);

    PNET_BUFFER_LIST nbl = pkt->vp_net_buffer_list;
    if (!nbl)
        return 0;

    PNET_BUFFER nb = NET_BUFFER_LIST_FIRST_NB(nbl);
    if (!nb)
        return 0;

    PMDL nb_mdl = NET_BUFFER_CURRENT_MDL(nb);
    ULONG overall_len = NET_BUFFER_DATA_LENGTH(nb);
    ULONG nb_mdl_data_len = MmGetMdlByteCount(nb_mdl) - NET_BUFFER_CURRENT_MDL_OFFSET(nb);

    if (overall_len <= nb_mdl_data_len) {
        return 0;
    } else {
        return overall_len - nb_mdl_data_len;
    }
}

static void *
win_pheader_pointer(struct vr_packet *pkt, unsigned short hdr_len, void *buf)
{
    PNET_BUFFER_LIST nbl = pkt->vp_net_buffer_list;

    PNET_BUFFER nb = NET_BUFFER_LIST_FIRST_NB(nbl);

    NdisAdvanceNetBufferDataStart(nb, pkt->vp_data, FALSE, NULL);
    // This will return NULL in case of an error so it's okay
    void* ret = NdisGetDataBuffer(nb, hdr_len, buf, 1, 0);
    NdisRetreatNetBufferDataStart(nb, pkt->vp_data, 0, NULL);

    return ret;
}

static unsigned short
win_phead_len(struct vr_packet *pkt)
{
    UNREFERENCED_PARAMETER(pkt);

    return 0;
}

static void
win_pset_data(struct vr_packet *pkt, unsigned short offset)
{
    /*
     * If dp-core calls vr_pset_data() it expects that underlying OS pointers will correctly
     * resemble packet structure. We cannot directly use Advance()/Retreat() there, because it breaks old
     * pointer references used throughout dp-core (i.e. pkt->vp_head).
     *
     * NBL will be modified on TX path by using offset located in `vp_data`.
     * Thus Windows implementation assumes that `vp_data` will point to the beginning
     * of the transmited packet.
     */

    if (pkt == NULL)
        return;

    ASSERT(pkt->vp_data == offset);
}

static unsigned int
win_pgso_size(struct vr_packet *pkt)
{
    UNREFERENCED_PARAMETER(pkt);

    /* TODO: More research on Generic Segmentation Offload mechanism in Windows is needed.
     *       As stated in https://msdn.microsoft.com/en-us/windows/hardware/drivers/network/offloading-the-segmentation-of-large-tcp-packets
     *       NDIS supported offload for TCP/IP packets only. dp-core code which does GSO checks is also
     *       considering only TCP/IP packets.
     *       However we do not know if there is further work needed in the NDIS driver to perform TCP offload.
     *
     * Returning 0 right now is a valid option, because dp-core code supports gso_size == 0 (i.e.
     * when GSO is not supported by NIC driver).
     */

    return 0;
}

static void
win_delete_timer(struct vr_timer *vtimer)
{
    EXT_DELETE_PARAMETERS params;
    ExInitializeDeleteTimerParameters(&params);
    params.DeleteContext = NULL;
    params.DeleteCallback = NULL;
    ExDeleteTimer(vtimer->vt_os_arg, TRUE, FALSE, &params);

    return;
}

void
win_timer_callback(PEX_TIMER Timer, void *Context)
{
    UNREFERENCED_PARAMETER(Timer);

    struct vr_timer *ctx = (struct vr_timer*)Context;
    ctx->vt_timer(ctx->vt_vr_arg);
}

static int
win_create_timer(struct vr_timer *vtimer)
{
    vtimer->vt_os_arg = ExAllocateTimer(win_timer_callback, (void *)vtimer, EX_TIMER_HIGH_RESOLUTION);

    // DueTime is negative, because it's then treated as relative time instead of absolute.
    ExSetTimer(vtimer->vt_os_arg, (-10000LL) * vtimer->vt_msecs, 10000LL * vtimer->vt_msecs, NULL);

    return 0;
}

static void
scheduled_work_routine(PVOID work_item_context, NDIS_HANDLE work_item_handle)
{
    struct scheduled_work_cb_data * cb_data = (struct scheduled_work_cb_data *)(work_item_context);
    LOCK_STATE_EX lock_state;

    NdisAcquireRWLockRead(AsyncWorkRWLock, &lock_state, 0);
    cb_data->user_cb(cb_data->data);
    NdisReleaseRWLock(AsyncWorkRWLock, &lock_state);

    if (work_item_handle) {
        NdisFreeIoWorkItem(work_item_handle);
    }
    ExFreePool(cb_data);

    return;
}

static int
win_schedule_work(unsigned int cpu, void(*fn)(void *), void *arg)
{
    UNREFERENCED_PARAMETER(cpu);

    struct scheduled_work_cb_data * cb_data;
    NDIS_HANDLE work_item;

    cb_data = ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(*cb_data), VrAllocationTag);
    if (!cb_data)
        return -ENOMEM;

    cb_data->user_cb = fn;
    cb_data->data = arg;

    work_item = NdisAllocateIoWorkItem(VrSwitchObject->NdisFilterHandle);
    if (!work_item) {
        scheduled_work_routine((PVOID)(cb_data), NULL);
    } else {
        NdisQueueIoWorkItem(work_item, scheduled_work_routine, (PVOID)(cb_data));
    }

    return 0;
}

static void
win_delay_op(void)
{
    /* Linux version uses `synchronize_net()` function from RCU API. It is a write-side function
     * which synchronously waits for any currently executing RCU read-side
     * critical sections to complete.
     * In Windows port RCU API is replaced with RW Locks. To simulate a wait for read-side sections to complete
     * Windows driver can attempt to acquire the RW lock for write operations.
     */
    LOCK_STATE_EX lock_state;

    NdisAcquireRWLockWrite(AsyncWorkRWLock, &lock_state, 0);
    NdisReleaseRWLock(AsyncWorkRWLock, &lock_state);

    return;
}

static VOID
deferred_work_routine(PVOID work_item_context, NDIS_HANDLE work_item_handle)
{
    struct deferred_work_cb_data * cb_data = (struct deferred_work_cb_data *)(work_item_context);
    LOCK_STATE_EX lock_state;

    NdisAcquireRWLockWrite(AsyncWorkRWLock, &lock_state, 0);
    cb_data->user_cb(cb_data->router, cb_data->user_data);
    NdisReleaseRWLock(AsyncWorkRWLock, &lock_state);

    if (work_item_handle) {
        NdisFreeIoWorkItem(work_item_handle);
    }
    win_free(cb_data, VR_DEFER_OBJECT);

    return;
}

static void
win_defer(struct vrouter *router, vr_defer_cb user_cb, void *data)
{
    struct deferred_work_cb_data * cb_data;
    NDIS_HANDLE work_item;

    cb_data = CONTAINER_OF(user_data, struct deferred_work_cb_data, data);
    cb_data->user_cb = user_cb;
    cb_data->router = router;

    work_item = NdisAllocateIoWorkItem(VrSwitchObject->NdisFilterHandle);
    if (!work_item) {
        deferred_work_routine((PVOID)(cb_data), NULL);
    } else {
        NdisQueueIoWorkItem(work_item, deferred_work_routine, (PVOID)(cb_data));
    }

    return;
}

static void *
win_get_defer_data(unsigned int len)
{
    struct deferred_work_cb_data * cb_data;

    if (len == 0)
        return NULL;

    cb_data = win_malloc(sizeof(*cb_data) + len, VR_DEFER_OBJECT);
    if (!cb_data) {
        return NULL;
    }

    return cb_data->user_data;
}

static void
win_put_defer_data(void *data)
{
    struct deferred_work_cb_data * cb_data;

    if (!data)
        return;

    cb_data = CONTAINER_OF(user_data, struct deferred_work_cb_data, data);
    win_free(cb_data, VR_DEFER_OBJECT);

    return;
}

static void
win_get_time(uint64_t *sec, uint64_t *usec)
{
    LARGE_INTEGER current_gmt_time, current_local_time;

    NdisGetCurrentSystemTime(&current_gmt_time);
    ExSystemTimeToLocalTime(&current_gmt_time, &current_local_time);

    /*
        Times is returned in 100-nanosecond intervals.
        1 s  = 10^9 ns = 10^7 * 100 ns
        1 us = 10^3 ns = 10 * 100 ns
    */
    *sec = (unsigned long)(current_local_time.QuadPart / (LONGLONG)(1000 * 1000 * 100));
    *usec = (unsigned long)((current_local_time.QuadPart % (LONGLONG)(1000 * 1000 * 100)) / 10);

    return;
}

static void
win_get_mono_time(uint64_t *sec, uint64_t *nsec)
{
    LARGE_INTEGER i;
    KeQueryTickCount(&i);

    i.QuadPart *= 100;

    *sec = i.HighPart;
    *nsec = i.LowPart;
}

static unsigned int
win_get_cpu(void)
{
    return KeGetCurrentProcessorNumberEx(NULL);
}

static void *
win_network_header(struct vr_packet *pkt)
{
    return pkt->vp_head + pkt->vp_network_h;
}

static void *
win_inner_network_header(struct vr_packet *pkt)
{
    return pkt->vp_head + pkt->vp_inner_network_h;
}

static void *
win_data_at_offset(struct vr_packet *pkt, unsigned short offset)
{
    // THIS FUNCTION IS NOT SECURE
    // DP-CORE assumes all headers will be contigous, ie. pointers
    // of type (struct vr_headertype*), when pointing to the beginning
    // of the header, will be valid for it's entiriety

    PNET_BUFFER_LIST nbl = pkt->vp_net_buffer_list;
    PNET_BUFFER nb = NET_BUFFER_LIST_FIRST_NB(nbl);
    PMDL current_mdl = NET_BUFFER_CURRENT_MDL(nb);
    unsigned length = MmGetMdlByteCount(current_mdl) - NET_BUFFER_CURRENT_MDL_OFFSET(nb);
    while (length < offset) {
        /* Get the pointer to the beginning of data represented in current MDL. */
        offset -= length;

        current_mdl = current_mdl->Next;
        if (current_mdl == NULL)
            return NULL;

        length = MmGetMdlByteCount(current_mdl);
    }

    void* ret = MmGetSystemAddressForMdlSafe(current_mdl,
        LowPagePriority | MdlMappingNoExecute);
    if (ret == NULL)
        return NULL;

    return (uint8_t*) ret + offset;
}

static int
win_pull_inner_headers(struct vr_packet *pkt,
    unsigned short ip_proto, unsigned short *reason,
    int (*tunnel_type_cb)(unsigned int, unsigned int, unsigned short *))
{
    UNREFERENCED_PARAMETER(pkt);
    UNREFERENCED_PARAMETER(ip_proto);
    UNREFERENCED_PARAMETER(reason);
    UNREFERENCED_PARAMETER(tunnel_type_cb);

    // TODO(Windows): Implement
    ASSERTMSG("Not implemented", FALSE);

    return 1;
}

static int
win_pcow(struct vr_packet **pkt, unsigned short head_room)
{
    UNREFERENCED_PARAMETER(pkt);
    UNREFERENCED_PARAMETER(head_room);

    // TODO(Windows): Implement
    ASSERTMSG("Not implemented", FALSE);

    return 0;
}

static int
win_pull_inner_headers_fast(struct vr_packet *pkt, unsigned char proto,
    int(*tunnel_type_cb)(unsigned int, unsigned int, unsigned short *),
    int *ret, int *encap_type)
{
    UNREFERENCED_PARAMETER(pkt);
    UNREFERENCED_PARAMETER(proto);
    UNREFERENCED_PARAMETER(tunnel_type_cb);
    UNREFERENCED_PARAMETER(ret);
    UNREFERENCED_PARAMETER(encap_type);

    // TODO(Windows): Implement
    ASSERTMSG("Not implemented", FALSE);

    return 0;
}

/*
 * This function should hash some src/dest addresses to get a UDP src port
 * that would nicely hash on MX but for now we only do some very basic hashing
 *
 * This cannot just return a const value because then load balancing on MX
 * wouldn't work as MX hashes src/dest addresses, port, etc. and all of those
 * values would be the same for all tunneled traffic from one compute node to
 * another. That's why we should differentiate the port very carefully.
 */
static uint16_t
win_get_udp_src_port(struct vr_packet *pkt, struct vr_forwarding_md *md,
    unsigned short vrf)
{
    UNREFERENCED_PARAMETER(md);

    uint32_t hashval, port_range;
    uint16_t port;

    if (hashrnd_inited == 0) {
        get_random_bytes(&vr_hashrnd, sizeof(vr_hashrnd));
        hashrnd_inited = 1;
    }

    if (pkt_head_len(pkt) < ETH_HLEN)
        return 0;

    hashval = vr_hash(pkt_data(pkt), ETH_HLEN, vr_hashrnd);
    hashval = vr_hash_2words(hashval, vrf, vr_hashrnd);

    port_range = VR_MUDP_PORT_RANGE_END - VR_MUDP_PORT_RANGE_START;
    port = (uint16_t)(((uint64_t)hashval * port_range) >> 32);

    if (port > port_range)
        return 0;

    return (port + VR_MUDP_PORT_RANGE_START);
}

static int
win_pkt_from_vm_tcp_mss_adj(struct vr_packet *pkt, unsigned short overlay_len)
{
    UNREFERENCED_PARAMETER(pkt);
    UNREFERENCED_PARAMETER(overlay_len);

    // TODO(Windows): Implement
    ASSERTMSG("Not implemented", FALSE);

    return 0;
}

static int
win_pkt_may_pull(struct vr_packet *pkt, unsigned int len)
{
    UNREFERENCED_PARAMETER(pkt);
    UNREFERENCED_PARAMETER(len);

    // TODO(Windows): Implement
    ASSERTMSG("Not implemented", FALSE);

    return 0;
}

static int
win_gro_process(struct vr_packet *pkt, struct vr_interface *vif, bool l2_pkt)
{
    UNREFERENCED_PARAMETER(pkt);
    UNREFERENCED_PARAMETER(vif);
    UNREFERENCED_PARAMETER(l2_pkt);

    // TODO(Windows): Implement
    ASSERTMSG("Not implemented", FALSE);

    return 0;
}

static int
win_enqueue_to_assembler(struct vrouter *router, struct vr_packet *pkt,
    struct vr_forwarding_md *fmd)
{
    UNREFERENCED_PARAMETER(router);
    UNREFERENCED_PARAMETER(pkt);
    UNREFERENCED_PARAMETER(fmd);

    // TODO(Windows): Implement
    ASSERTMSG("Not implemented", FALSE);

    return 0;
}

static void
win_set_log_level(unsigned int log_level)
{
    UNREFERENCED_PARAMETER(log_level);
    return;
}

static void
win_set_log_type(unsigned int log_type, int enable)
{
    UNREFERENCED_PARAMETER(log_type);
    UNREFERENCED_PARAMETER(enable);
    return;
}

static unsigned int
win_get_log_level(void)
{
    return 0;
}

static unsigned int *
win_get_enabled_log_types(int *size)
{
    UNREFERENCED_PARAMETER(size);

    size = 0;
    return NULL;
}

static void
win_soft_reset(struct vrouter *router)
{
    /*
        NOTE: Used in dp-code/vrouter.c:vrouter_exit() to perform safe exit.

        TODO: Implement using Windows mechanisms
        Linux code:
            flush_scheduled_work();
            rcu_barrier();
    */
    UNREFERENCED_PARAMETER(router);

    return;
}

static void
win_update_vif_port(struct vr_interface *vif, vr_interface_req *vifr, PNDIS_SWITCH_NIC_ARRAY array)
{
    for (unsigned int i = 0; i < array->NumElements; i++){
        PNDIS_SWITCH_NIC_PARAMETERS element = NDIS_SWITCH_NIC_AT_ARRAY_INDEX(array, i);

        // "Fake" interface pointing to the default interface, it's not needed.
        if (element->NicType == NdisSwitchNicTypeExternal && element->NicIndex == 0)
            continue;

        if (element->NicType == NdisSwitchNicTypeExternal || element->NicType == NdisSwitchNicTypeInternal)
        {
            if (memcmp(&element->NetCfgInstanceId, vifr->vifr_if_guid, sizeof(element->NetCfgInstanceId)) == 0)
            {
                vif->vif_port = element->PortId;
                vif->vif_nic = element->NicIndex;

                break;
            }
        }
        else if (element->NicType == NdisSwitchNicTypeEmulated || element->NicType == NdisSwitchNicTypeSynthetic)
        {
            ANSI_STRING ansi_name;
            ansi_name.Buffer = vifr->vifr_if_guid;
            ansi_name.Length = vifr->vifr_if_guid_size + 1; // For NULL character
            ansi_name.MaximumLength = vifr->vifr_if_guid_size + 1; // For NULL character

            UNICODE_STRING unicode_name;
            RtlAnsiStringToUnicodeString(&unicode_name, &ansi_name, TRUE);

            if (memcmp(unicode_name.Buffer, element->NicName.String, (element->NicName.Length < unicode_name.Length ? element->NicName.Length : unicode_name.Length)) == 0)
            {
                vif->vif_port = element->PortId;
                vif->vif_nic = element->NicIndex;

                RtlFreeUnicodeString(&unicode_name);

                break;
            } else {
                RtlFreeUnicodeString(&unicode_name);
            }
        }
    }
}

static void
win_register_nic(struct vr_interface* vif, vr_interface_req* vifr)
{
    PNDIS_SWITCH_NIC_ARRAY array;
    NDIS_STATUS status;

    if (vifr->vifr_if_guid == NULL)
        return; // Bad Sandesh version on utility tool

    status = VrGetNicArray(VrSwitchObject, &array);
    if (status != NDIS_STATUS_SUCCESS) {
        DbgPrint("vRouter:%s(): VrGetNicArray failed to get NIC array\n", __func__);
        return;
    }

    win_if_lock();
    win_update_vif_port(vif, vifr, array);
    win_if_unlock();

    VrFreeNicArray(array);

    vif_attach(vif);
}

struct host_os windows_host = {
    .hos_printf = win_printf,
    .hos_malloc = win_malloc,
    .hos_zalloc = win_zalloc,
    .hos_free = win_free,
    .hos_vtop = win_vtop,
    .hos_page_alloc = win_page_alloc,
    .hos_page_free = win_page_free,

    .hos_palloc = win_palloc,
    .hos_pfree = win_pfree,
    .hos_palloc_head = win_palloc_head,
    .hos_pexpand_head = win_pexpand_head,
    .hos_preset = win_preset,
    .hos_pclone = win_pclone,
    .hos_pcopy = win_pcopy,
    .hos_pfrag_len = win_pfrag_len,
    .hos_phead_len = win_phead_len,
    .hos_pset_data = win_pset_data,
    .hos_pgso_size = win_pgso_size,

    .hos_get_cpu = win_get_cpu,
    .hos_schedule_work = win_schedule_work,
    .hos_delay_op = win_delay_op,
    .hos_defer = win_defer,
    .hos_get_defer_data = win_get_defer_data,
    .hos_put_defer_data = win_put_defer_data,
    .hos_get_time = win_get_time,
    .hos_get_mono_time = win_get_mono_time,
    .hos_create_timer = win_create_timer,
    .hos_delete_timer = win_delete_timer,

    .hos_network_header = win_network_header,
    .hos_inner_network_header = win_inner_network_header,
    .hos_data_at_offset = win_data_at_offset,
    .hos_pheader_pointer = win_pheader_pointer,
    .hos_pull_inner_headers = win_pull_inner_headers,
    .hos_pcow = win_pcow,
    .hos_pull_inner_headers_fast = win_pull_inner_headers_fast,
    .hos_get_udp_src_port = win_get_udp_src_port,
    .hos_pkt_from_vm_tcp_mss_adj = win_pkt_from_vm_tcp_mss_adj,
    .hos_pkt_may_pull = win_pkt_may_pull,
    .hos_gro_process = win_gro_process,
    .hos_enqueue_to_assembler = NULL,
    .hos_set_log_level = win_set_log_level,
    .hos_set_log_type = win_set_log_type,
    .hos_get_log_level = win_get_log_level,
    .hos_get_enabled_log_types = win_get_enabled_log_types,
    .hos_soft_reset = win_soft_reset,
    .hos_register_nic = win_register_nic,
};

struct host_os *
vrouter_get_host(void)
{
    return &windows_host;
}
