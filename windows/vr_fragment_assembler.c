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

static unsigned int vr_win_assembler_scan_index;
static int vr_win_assembler_scan_thresh = 1024;

// Adapted from vr_fragment_enqueue.
// We're only pretending to have per-cpu queue,
// this function only creates a queue element instead
// of enqueueing it.
static struct vr_fragment_queue_element *
VrCreateFragmentQueueElement(struct vrouter *router,
        struct vr_packet *pkt, struct vr_forwarding_md *fmd)
{
    struct vr_fragment_queue_element *fqe = NULL;
    struct vr_packet_node *pnode;

    /* Check if the total number of fragmented packets exceeded. */
    if (vrouter_host->hos_is_frag_limit_exceeded &&
            vrouter_host->hos_is_frag_limit_exceeded()) {
            goto fail;
    }

    fqe = vr_malloc(sizeof(*fqe), VR_FRAGMENT_QUEUE_ELEMENT_OBJECT);
    if (!fqe) {
        goto fail;
    }
    fqe->fqe_router = router;
    fqe->fqe_next = NULL;

    pkt->vp_flags &= ~VP_FLAG_FLOW_SET;

    pnode = &fqe->fqe_pnode;
    vr_flow_fill_pnode(pnode, pkt, fmd);

    return fqe;

fail:
    if (fqe)
        vr_free(fqe, VR_FRAGMENT_QUEUE_ELEMENT_OBJECT);

    vr_pfree(pkt, VP_DROP_FRAGMENTS);
    return NULL;
}

static void
VrFragmentAssembler(struct vr_fragment_queue_element* vfqe)
{
    KIRQL old_irql;
    struct vr_packet_node *pnode;
    uint32_t hash, index;
    struct vr_win_fragment_bucket *vfb;

    pnode = &vfqe->fqe_pnode;
    if (pnode->pl_packet) {
        hash = vr_fragment_get_hash(pnode);
        index = (hash % VR_LINUX_ASSEMBLER_BUCKETS);
        vfb = &VrAssemblerTable[index];

        KeAcquireSpinLock(&vfb->vfb_lock, &old_irql);
        vr_fragment_assembler(&vfb->vfb_frag_list, vfqe);
        KeReleaseSpinLock(&vfb->vfb_lock, old_irql);
    }
}

int
win_enqueue_to_assembler(struct vrouter *router, struct vr_packet *pkt,
        struct vr_forwarding_md *fmd)
{
    struct vr_fragment_queue_element *vfqe;
    unsigned int cpu;

    cpu = vr_get_cpu();
    if (cpu >= vr_num_cpus) {
        // Printk?
        vr_pfree(pkt, VP_DROP_FRAGMENTS);
        return -EINVAL;
    }

    // We're going to pretend enqueueing on CPU-list,
    // by creating a single-element list
    // and immediately dispatching the work.
    vfqe = VrCreateFragmentQueueElement(router, pkt, fmd);
    if (vfqe)
        VrFragmentAssembler(vfqe);

    return 0;
}

static void
VrAssemblerTableScan(void *arg)
{
    KIRQL old_irql;
    unsigned int i, j, scanned = 0;

    struct vr_win_fragment_bucket *vfb;

    i = vr_win_assembler_scan_index;
    for (j = 0; j < VR_LINUX_ASSEMBLER_BUCKETS; j++) {
        vfb = &VrAssemblerTable[(i + j) % VR_LINUX_ASSEMBLER_BUCKETS];
        KeAcquireSpinLock(&vfb->vfb_lock, &old_irql);
        if (vfb->vfb_frag_list)
            scanned += vr_assembler_table_scan(&vfb->vfb_frag_list);
        KeReleaseSpinLock(&vfb->vfb_lock, old_irql);
        if (scanned > vr_win_assembler_scan_thresh) {
            j++;
            break;
        }
    }

    vr_win_assembler_scan_index = (i + j) % VR_LINUX_ASSEMBLER_BUCKETS;
    return;
}

static int
VrAssemblerTableInit(void)
{
    SIZE_T size = VR_LINUX_ASSEMBLER_BUCKETS * sizeof(struct vr_win_fragment_bucket);
    // Not using vr_zalloc here, because the hos table is not initialized yet. Todo?
    // VR_ASSEMBLER_TABLE_OBJECT
    VrAssemblerTable = vr_zalloc(size, VR_ASSEMBLER_TABLE_OBJECT);
    if (!VrAssemblerTable) {
        // Printk?
        return NDIS_STATUS_FAILURE; // More specific?
    }

    for (unsigned int i = 0; i < VR_LINUX_ASSEMBLER_BUCKETS; ++i) {
        KeInitializeSpinLock(&VrAssemblerTable[i].vfb_lock);
    }

    vr_assembler_table_scan_init(VrAssemblerTableScan);

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
    // We're not using fragment queue (yet),
    // only assembler table.
    return VrAssemblerTableInit();
}

void
VrAssemblerExit(void)
{
    // We're not using fragment queue (yet),
    // only assembler table.
    VrAssemblerTableExit();
}
