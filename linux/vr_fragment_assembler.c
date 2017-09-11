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

static int vr_linux_assembler_scan_index;
static int vr_linux_assembler_scan_thresh = 1024;

struct vr_linux_fragment_bucket {
    spinlock_t vfb_lock;
    struct vr_fragment *vfb_frag_list;
};
struct vr_linux_fragment_bucket *vr_linux_assembler_table;

struct vr_linux_fragment_queue {
    struct work_struct vrlfq_work;
    struct vr_fragment_queue vrlfq_queue;
};
struct vr_linux_fragment_queue *vr_lfq_pcpu_queues;

static void
vr_linux_fragment_assembler(struct work_struct *work)
{
    uint32_t hash, index;

    struct vr_packet_node *pnode;
    struct vr_linux_fragment_bucket *vfb;
    struct vr_fragment_queue_element *tail, *tail_n, *tail_p, *tail_pn;
    struct vr_linux_fragment_queue *lfq = CONTAINER_OF(vrlfq_work,
            struct vr_linux_fragment_queue, work);

    tail = __sync_lock_test_and_set(&lfq->vrlfq_queue.vfq_tail, NULL);
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

        pnode = &tail->fqe_pnode;
        if (pnode->pl_packet) {
            hash = vr_fragment_get_hash(pnode);
            index = (hash % VR_LINUX_ASSEMBLER_BUCKETS);
            vfb = &vr_linux_assembler_table[index];

            spin_lock_bh(&vfb->vfb_lock);
            vr_fragment_assembler(&vfb->vfb_frag_list, tail);
            spin_unlock_bh(&vfb->vfb_lock);
        }

        tail = tail_n;
    }

    return;
}

int
lh_enqueue_to_assembler(struct vrouter *router, struct vr_packet *pkt,
        struct vr_forwarding_md *fmd)
{
    int ret;
    unsigned int cpu;

    cpu = vr_get_cpu();
    if (cpu >= vr_num_cpus) {
        printk("cpu is %u, but max cpu is only %u\n", cpu, vr_num_cpus);
        vr_pfree(pkt, VP_DROP_FRAGMENTS);
        return -EINVAL;
    }

    ret = vr_fragment_enqueue(router, &vr_lfq_pcpu_queues[cpu].vrlfq_queue,
            pkt, fmd);
    if (!ret)
        queue_work(vr_linux_assembler_wq, &vr_lfq_pcpu_queues[cpu].vrlfq_work);

    return 0;
}

static void
vr_linux_assembler_table_scan(void *arg)
{
    unsigned int i, j, scanned = 0;

    struct vr_linux_fragment_bucket *vfb;

    i = vr_linux_assembler_scan_index;
    for (j = 0; j < VR_LINUX_ASSEMBLER_BUCKETS; j++) {
        vfb = &vr_linux_assembler_table[(i + j) % VR_LINUX_ASSEMBLER_BUCKETS];
        spin_lock_bh(&vfb->vfb_lock);
        if (vfb->vfb_frag_list)
            scanned += vr_assembler_table_scan(&vfb->vfb_frag_list);
        spin_unlock_bh(&vfb->vfb_lock);
        if (scanned > vr_linux_assembler_scan_thresh) {
            j++;
            break;
        }
    }

    vr_linux_assembler_scan_index = (i + j) % VR_LINUX_ASSEMBLER_BUCKETS;
    return;
}

static void
vr_linux_assembler_table_exit(void)
{
    vr_assembler_table_scan_exit();

    if (vr_linux_assembler_table) {
        vr_free(vr_linux_assembler_table, VR_ASSEMBLER_TABLE_OBJECT);
        vr_linux_assembler_table = NULL;
    }

    return;
}

static int
vr_linux_assembler_table_init(void)
{
    unsigned int i, size;

    size = sizeof(struct vr_linux_fragment_bucket) * VR_LINUX_ASSEMBLER_BUCKETS;
    vr_linux_assembler_table = vr_zalloc(size, VR_ASSEMBLER_TABLE_OBJECT);
    if (!vr_linux_assembler_table) {
        printk("%s:%d Allocation for %u failed\n",
                __FUNCTION__, __LINE__, size);
        return -ENOMEM;
    }

    for (i = 0; i < VR_LINUX_ASSEMBLER_BUCKETS; i++) {
        spin_lock_init(&vr_linux_assembler_table[i].vfb_lock);
    }

    vr_assembler_table_scan_init(vr_linux_assembler_table_scan);

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
            vr_fragment_queue_free(&vr_lfq_pcpu_queues[i].vrlfq_queue);

        vr_free(vr_lfq_pcpu_queues, VR_FRAGMENT_QUEUE_OBJECT);
        vr_lfq_pcpu_queues = NULL;
    }

    return;
}

static int
vr_linux_fragment_queue_init(void)
{
    unsigned int i, size;

    size = sizeof(struct vr_linux_fragment_queue) * vr_num_cpus;
    vr_lfq_pcpu_queues = vr_zalloc(size, VR_FRAGMENT_QUEUE_OBJECT);
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

