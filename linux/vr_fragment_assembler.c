/*
 * vr_fragment_assembler.c -- the OS specific parts of the assembler
 *
 * Copyright (c) 2015, Juniper Networks, Inc.
 * All rights reserved
 */
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/workqueue.h>

#include <vr_os.h>
#include <vr_packet.h>
#include <vr_fragment.h>

struct workqueue_struct *vr_linux_assembler_wq;

static struct vr_timer *vr_linux_assembler_table_scan_timer;
static int vr_linux_assembler_scan_index;
static int vr_linux_assembler_scan_thresh = 1024;

#define VR_LINUX_ASSEMBLER_BUCKETS        1024

struct vr_linux_fragment_bucket {
    spinlock_t vfb_lock;
    struct vr_fragment *vfb_frag_list;
};
struct vr_linux_fragment_bucket *vr_linux_assembler_table;

struct vr_linux_fragment_queue {
    struct work_struct vrlfq_work;
    struct vr_fragment_queue_element *vrlfq_tail;
};
struct vr_linux_fragment_queue *vr_lfq_pcpu_queues;

static void
vr_linux_fragment_queue_free(struct vr_linux_fragment_queue *vlfq)
{
    struct vr_fragment_queue_element *vfqe, *next;

    vfqe = vlfq->vrlfq_tail;
    vlfq->vrlfq_tail = NULL;
    while (vfqe) {
        next = vfqe->fqe_next;
        if (vfqe->fqe_pnode.pl_packet)
            vr_pfree(vfqe->fqe_pnode.pl_packet, VP_DROP_MISC);
        vfqe->fqe_pnode.pl_packet = NULL;
        vr_free(vfqe);
        vfqe = next;
    }

    return;
}

static void
vr_linux_fragment_assembler(struct work_struct *work)
{
    uint32_t hash, index;
    unsigned long flags;

    struct vr_packet *pkt;
    struct vr_linux_fragment_bucket *vfb;
    struct vr_fragment_queue_element *tail, *tail_n, *tail_p, *tail_pn;
    struct vr_linux_fragment_queue *lfq = CONTAINER_OF(vrlfq_work,
            struct vr_linux_fragment_queue, work);

    tail = __sync_lock_test_and_set(&lfq->vrlfq_tail, NULL);
    if (!tail)
        return;

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

        pkt = tail->fqe_pnode.pl_packet;
        if (pkt) {
            hash = vr_fragment_get_hash(tail->fqe_pnode.pl_vrf, pkt);
            index = (hash % VR_LINUX_ASSEMBLER_BUCKETS);
            vfb = &vr_linux_assembler_table[index];

            spin_lock_irqsave(&vfb->vfb_lock, flags);
            vr_fragment_assembler(&vfb->vfb_frag_list, tail);
            spin_unlock_irqrestore(&vfb->vfb_lock, flags);
        }

        tail = tail_n;
    }

    return;
}

int
lh_enqueue_to_assembler(struct vrouter *router, unsigned int action,
        struct vr_packet *pkt, struct vr_forwarding_md *fmd)
{
    int ret;
    unsigned int cpu;

    cpu = vr_get_cpu();
    if (cpu >= vr_num_cpus) {
        printk("cpu is %u, but max cpu is only %u\n", cpu, vr_num_cpus);
        vr_pfree(pkt, VP_DROP_FRAGMENTS);
        return -EINVAL;
    }

    ret = vr_fragment_enqueue(router, &vr_lfq_pcpu_queues[cpu].vrlfq_tail,
            action, pkt, fmd);
    if (!ret)
        queue_work(vr_linux_assembler_wq, &vr_lfq_pcpu_queues[cpu].vrlfq_work);

    return 0;
}

static void
vr_linux_assembler_table_scan(void *arg)
{
    unsigned int i, j, scanned = 0;
    unsigned long flags;

    struct vr_linux_fragment_bucket *vfb;

    i = vr_linux_assembler_scan_index;
    for (j = 0; j < VR_LINUX_ASSEMBLER_BUCKETS; j++) {
        vfb = &vr_linux_assembler_table[(i + j) % VR_LINUX_ASSEMBLER_BUCKETS];
        spin_lock_irqsave(&vfb->vfb_lock, flags);
        if (vfb->vfb_frag_list)
            scanned += vr_assembler_table_scan(&vfb->vfb_frag_list);
        spin_unlock_irqrestore(&vfb->vfb_lock, flags);
        if (scanned > vr_linux_assembler_scan_thresh) {
            j++;
            break;
        }
    }

    vr_linux_assembler_scan_index = (i + j) % VR_LINUX_ASSEMBLER_BUCKETS;
    return;
}

static void
vr_linux_assembler_table_scan_exit(void)
{
    if (vr_linux_assembler_table_scan_timer) {
        vr_delete_timer(vr_linux_assembler_table_scan_timer);
        vr_free(vr_linux_assembler_table_scan_timer);
        vr_linux_assembler_table_scan_timer = NULL;
    }

    return;
}

static int
vr_linux_assembler_table_scan_init(void)
{
    struct vr_timer *vtimer;

    vr_linux_assembler_table_scan_timer = vr_zalloc(sizeof(*vtimer));
    if (!vr_linux_assembler_table_scan_timer)
        return -ENOMEM;

    vtimer = vr_linux_assembler_table_scan_timer;
    vtimer->vt_timer = vr_linux_assembler_table_scan;
    vtimer->vt_vr_arg = NULL;
    vtimer->vt_msecs =
        (VR_ASSEMBLER_TIMEOUT_TIME * 1000) / VR_LINUX_ASSEMBLER_BUCKETS;
    if (vr_create_timer(vtimer)) {
        vr_free(vtimer);
        vr_linux_assembler_table_scan_timer = NULL;
    }

    return 0;
}

static void
vr_linux_assembler_table_exit(void)
{
    vr_linux_assembler_table_scan_exit();

    if (vr_linux_assembler_table) {
        vr_free(vr_linux_assembler_table);
        vr_linux_assembler_table = NULL;
    }

    return;
}

static int
vr_linux_assembler_table_init(void)
{
    unsigned int i, size;

    size = sizeof(struct vr_linux_fragment_bucket) * VR_LINUX_ASSEMBLER_BUCKETS;
    vr_linux_assembler_table = vr_zalloc(size);
    if (!vr_linux_assembler_table) {
        printk("%s:%d Allocation for %u failed\n",
                __FUNCTION__, __LINE__, size);
        return -ENOMEM;
    }

    for (i = 0; i < VR_LINUX_ASSEMBLER_BUCKETS; i++) {
        spin_lock_init(&vr_linux_assembler_table[i].vfb_lock);
    }

    vr_linux_assembler_table_scan_init();

    return 0;
}

static void
vr_linux_fragment_queue_exit(void)
{
    int i;

    if (vr_lfq_pcpu_queues) {
        if (vr_linux_assembler_wq) {
            for (i = 0; i < vr_num_cpus; i++) {
                cancel_work_sync(&vr_lfq_pcpu_queues[i].vrlfq_work);
            }
            flush_workqueue(vr_linux_assembler_wq);
            destroy_workqueue(vr_linux_assembler_wq);
            vr_linux_assembler_wq = NULL;
        }

        for (i = 0; i < vr_num_cpus; i++)
            vr_linux_fragment_queue_free(&vr_lfq_pcpu_queues[i]);

        vr_free(vr_lfq_pcpu_queues);
        vr_lfq_pcpu_queues = NULL;
    }

    return;
}

static int
vr_linux_fragment_queue_init(void)
{
    unsigned int i, size;

    size = sizeof(struct vr_linux_fragment_queue) * vr_num_cpus;
    vr_lfq_pcpu_queues = vr_zalloc(size);
    if (!vr_lfq_pcpu_queues) {
        printk("%s:%d Allocation for %u failed\n",
                __FUNCTION__, __LINE__, size);
        return -ENOMEM;
    }

    for (i = 0; i < vr_num_cpus; i++) {
        INIT_WORK(&vr_lfq_pcpu_queues[i].vrlfq_work,
                vr_linux_fragment_assembler);
    }

    vr_linux_assembler_wq = create_workqueue("vr_linux_assembler");
    if (!vr_linux_assembler_wq) {
        printk("%s:%d Failed to create assembler work queue\n",
                __FUNCTION__, __LINE__);
        return -ENOMEM;
    }

    return 0;
}

void
vr_assembler_exit(void)
{
    vr_linux_fragment_queue_exit();
    vr_linux_assembler_table_exit();

    return;
}

int
vr_assembler_init(void)
{
    int ret;

    if ((ret = vr_linux_fragment_queue_init()))
        return ret;

    if ((ret = vr_linux_assembler_table_init()))
        return ret;

    return 0;
}

