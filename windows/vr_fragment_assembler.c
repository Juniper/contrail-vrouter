/*
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */

#include <vr_os.h>
#include <vr_packet.h>
#include <vr_fragment.h>

#include "vr_windows.h"
#include "win_work_item.h"

struct vr_win_fragment_bucket {
    KSPIN_LOCK vfb_lock;
    struct vr_fragment *vfb_frag_list;
};
static struct vr_win_fragment_bucket *VrAssemblerTable;

struct vr_win_fragment_queue {
    PWIN_WORK_ITEM vrwfq_work;
    struct vr_fragment_queue vrwfq_queue;
};
struct vr_win_fragment_queue *vr_wfq_pcpu_queues;

static unsigned int vr_win_assembler_scan_index;
static int vr_win_assembler_scan_thresh = 1024;

void
win_fragment_sync_assemble(struct vr_fragment_queue_element *vfqe)
{
    KIRQL old_irql;

    uint32_t hash = vr_fragment_get_hash(&vfqe->fqe_pnode);
    uint32_t index = (hash % VR_ASSEMBLER_BUCKET_COUNT);

    struct vr_win_fragment_bucket *vfb = &VrAssemblerTable[index];

    KeAcquireSpinLock(&vfb->vfb_lock, &old_irql);
    vr_fragment_assemble(&vfb->vfb_frag_list, vfqe);
    KeReleaseSpinLock(&vfb->vfb_lock, old_irql);
}

static void
VrFragmentAssembler(void *Context)
{
    struct vr_fragment_queue *fq = (struct vr_fragment_queue *)Context;
    vr_fragment_assemble_queue(fq);
}

int
win_enqueue_to_assembler(struct vrouter *router, struct vr_packet *pkt,
        struct vr_forwarding_md *fmd)
{
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
        WinWorkItemQueueWork(fq->vrwfq_work);
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
        struct vr_win_fragment_queue *fq = &vr_wfq_pcpu_queues[i];
        PWIN_WORK_ITEM work = WinWorkItemCreate(
            VrFragmentAssembler, &fq->vrwfq_queue);
        if (work == NULL) {
            return -ENOMEM;
        }

        fq->vrwfq_work = work;
    }

    return 0;
}

static void
VrFragmentQueueExit(void)
{
    int i;

    if (vr_wfq_pcpu_queues) {
        for (i = 0; i < vr_num_cpus; i++) {
            struct vr_win_fragment_queue *fq = &vr_wfq_pcpu_queues[i];

            WinWorkItemWaitDestroy(fq->vrwfq_work);
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
        return -ENOMEM;
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
