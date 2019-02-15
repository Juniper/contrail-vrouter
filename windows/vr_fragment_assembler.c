/*
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */

#include <vr_os.h>
#include <vr_packet.h>
#include <vr_fragment.h>

#include "vr_windows.h"

struct vr_win_fragment_bucket {
    KSPIN_LOCK vfb_lock;
    struct vr_fragment *vfb_frag_list;
};
static struct vr_win_fragment_bucket *VrAssemblerTable;

struct vr_win_fragment_queue {
    KSPIN_LOCK vrwfq_lock;
    NDIS_HANDLE vrwfq_work;
    BOOLEAN vrwfq_pending;
    BOOLEAN vrwfq_initialized;
    UINT vrwfq_running;
    struct vr_fragment_queue vrwfq_queue;
};
struct vr_win_fragment_queue *vr_wfq_pcpu_queues;

static unsigned int vr_win_assembler_scan_index;
static int vr_win_assembler_scan_thresh = 1024;

static NDIS_IO_WORKITEM_FUNCTION VrFragmentAssembler;

static VOID
VrFragmentAssembler(PVOID Context, NDIS_HANDLE NdisIoWorkItemHandle)
{
    KIRQL old_irql;
    uint32_t hash, index;

    struct vr_packet_node *pnode;
    struct vr_win_fragment_bucket *vfb;
    struct vr_fragment_queue_element *tail, *tail_n, *tail_p, *tail_pn;
    struct vr_win_fragment_queue *wfq = (struct vr_win_fragment_queue *)Context;

    InterlockedIncrement(&wfq->vrwfq_running);
    wfq->vrwfq_pending = FALSE;
    vr_sync_synchronize();

    tail = InterlockedExchangePointer(&wfq->vrwfq_queue.vfq_tail, NULL);
    if (!tail) {
        InterlockedDecrement(&wfq->vrwfq_running);
        return;
    }

    /*
     * first, reverse the list, since packets that came later are at the
     * head of the list
     */
    tail_p = tail->fqe_next;
    tail->fqe_next = NULL;
    while (tail_p) {
        tail_pn = tail_p->fqe_next;
        tail_p->fqe_next = tail;
        tail = tail_p;
        tail_p = tail_pn;
    }

    /* go through the list and insert it in the assembler work area */
    while (tail) {
        tail_n = tail->fqe_next;
        tail->fqe_next = NULL;

        pnode = &tail->fqe_pnode;
        if (pnode->pl_packet) {
            hash = vr_fragment_get_hash(pnode);
            index = (hash % VR_ASSEMBLER_BUCKET_COUNT);
            vfb = &VrAssemblerTable[index];

            KeAcquireSpinLock(&vfb->vfb_lock, &old_irql);
            vr_fragment_assembler(&vfb->vfb_frag_list, tail);
            KeReleaseSpinLock(&vfb->vfb_lock, old_irql);
        }

        tail = tail_n;
    }

    InterlockedDecrement(&wfq->vrwfq_running);
}

int
win_enqueue_to_assembler(struct vrouter *router, struct vr_packet *pkt,
        struct vr_forwarding_md *fmd)
{
    KIRQL old_irql;
    int ret;
    unsigned int cpu;

    cpu = vr_get_cpu();
    if (cpu >= vr_num_cpus) {
        // Printk?
        vr_pfree(pkt, VP_DROP_FRAGMENTS);
        return -EINVAL;
    }

    struct vr_win_fragment_queue *fq = &vr_wfq_pcpu_queues[cpu];

    ret = vr_fragment_enqueue(router, &fq->vrwfq_queue, pkt, fmd);
    if (!ret) {
        KeAcquireSpinLock(&fq->vrwfq_lock, &old_irql);
        if (fq->vrwfq_initialized) {
            if (vr_sync_bool_compare_and_swap_8u(&fq->vrwfq_pending, FALSE, TRUE)) {
                NdisQueueIoWorkItem(fq->vrwfq_work, VrFragmentAssembler, fq);
            }
        }
        KeReleaseSpinLock(&fq->vrwfq_lock, old_irql);
    }

    return 0;
}

static void
VrAssemblerTableScan(void *arg)
{
    KIRQL old_irql;
    unsigned int i, j, scanned = 0;

    struct vr_win_fragment_bucket *vfb;

    i = vr_win_assembler_scan_index;
    for (j = 0; j < VR_ASSEMBLER_BUCKET_COUNT; j++) {
        ASSERTMSG("VrAssemblerTable should not be freed during this call", VrAssemblerTable != NULL);
        vfb = &VrAssemblerTable[(i + j) % VR_ASSEMBLER_BUCKET_COUNT];
        KeAcquireSpinLock(&vfb->vfb_lock, &old_irql);
        if (vfb->vfb_frag_list)
            scanned += vr_assembler_table_scan(&vfb->vfb_frag_list);
        KeReleaseSpinLock(&vfb->vfb_lock, old_irql);
        if (scanned > vr_win_assembler_scan_thresh) {
            j++;
            break;
        }
    }

    vr_win_assembler_scan_index = (i + j) % VR_ASSEMBLER_BUCKET_COUNT;
    return;
}

static int
VrFragmentQueueInit(void)
{
    unsigned int i, size;

    size = sizeof(struct vr_win_fragment_queue) * vr_num_cpus;
    vr_wfq_pcpu_queues = vr_zalloc(size, VR_FRAGMENT_QUEUE_OBJECT);
    if (!vr_wfq_pcpu_queues) {
        return -ENOMEM;
    }

    for (i = 0; i < vr_num_cpus; i++) {
        KeInitializeSpinLock(&vr_wfq_pcpu_queues[i].vrwfq_lock);
        vr_wfq_pcpu_queues[i].vrwfq_work = NdisAllocateIoWorkItem(VrDriverHandle);
        if (vr_wfq_pcpu_queues[i].vrwfq_work == NULL) {
            return -ENOMEM;
        }
        vr_wfq_pcpu_queues[i].vrwfq_initialized = TRUE;
    }

    return 0;
}

static void
VrFragmentQueueExit(void)
{
    int i;

    if (vr_wfq_pcpu_queues) {
        for (i = 0; i < vr_num_cpus; i++) {
            KIRQL old_irql;
            struct vr_win_fragment_queue *fq = &vr_wfq_pcpu_queues[i];

            if (fq->vrwfq_initialized) {
                KeAcquireSpinLock(&fq->vrwfq_lock, &old_irql);
                fq->vrwfq_initialized = FALSE;
                KeReleaseSpinLock(&fq->vrwfq_lock, old_irql);

                while (fq->vrwfq_pending) {
                    vr_sync_synchronize();
                }

                while (fq->vrwfq_running) {
                    vr_sync_synchronize();
                }

                NdisFreeIoWorkItem(fq->vrwfq_work);
            }
            vr_fragment_queue_free(&fq->vrwfq_queue);
        }

        vr_free(vr_wfq_pcpu_queues, VR_FRAGMENT_QUEUE_OBJECT);
        vr_wfq_pcpu_queues = NULL;
    }
}

static int
VrAssemblerTableInit(void)
{
    SIZE_T size = VR_ASSEMBLER_BUCKET_COUNT * sizeof(struct vr_win_fragment_bucket);

    VrAssemblerTable = vr_zalloc(size, VR_ASSEMBLER_TABLE_OBJECT);
    if (!VrAssemblerTable) {
        return 1;
    }

    for (unsigned int i = 0; i < VR_ASSEMBLER_BUCKET_COUNT; ++i) {
        KeInitializeSpinLock(&VrAssemblerTable[i].vfb_lock);
    }

    vr_win_assembler_scan_index = 0;

    int ret = vr_assembler_table_scan_init(VrAssemblerTableScan);
    if (ret != 0) {
        vr_free(VrAssemblerTable, VR_ASSEMBLER_TABLE_OBJECT);
        return ret;
    }

    return 0;
}

static void
VrAssemblerTableExit(void)
{
    vr_assembler_table_scan_exit();

    if (VrAssemblerTable) {
        vr_free(VrAssemblerTable, VR_ASSEMBLER_TABLE_OBJECT);
        VrAssemblerTable = NULL;
    }
}

int
VrAssemblerInit(void)
{
    int ret;

    if ((ret = VrFragmentQueueInit()))
        return ret;

    if ((ret = VrAssemblerTableInit()))
        return ret;

    return 0;
}

void
VrAssemblerExit(void)
{
    VrFragmentQueueExit();
    VrAssemblerTableExit();
}
