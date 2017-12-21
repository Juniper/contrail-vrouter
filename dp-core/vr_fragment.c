/*
 * vr_fragment.c -- basic fragment handling code
 *
 * Copyright (c) 2013, Juniper Networks Private Limited
 * All rights reserved
 */
#include <vr_os.h>
#include <vr_packet.h>
#include "vr_interface.h"
#include "vr_btable.h"
#include "vr_fragment.h"
#include "vr_hash.h"

/*
 * Handling out of order fragment arrival:
 *
 * Every fragment that does not have a corresponding entry in the fragment
 * metadata table (which is the primary table that the datapath will rely on),
 * will be enqueued to the assembler. The head of an ip fragment is a special
 * case. It will be both forwarded to the destination and enqueued to the
 * assembler. The assembler just extracts the required data from the packet
 * and will not forward the packet . The assembler will use the head of the
 * fragment to search and then to forward the other fragments of the packet,
 * while not forwarding the head itself.

 * Enqueue to per-cpu queue
 * ------------------------

 * Its important that locks are avoided as far as possible in datapath. To avoid
 * contention between multiple threads running datapath, we will have a per-cpu
 * queue to the assembler. Since both the assembler and the datapath will be
 * dequeueing from and enqueueing to the queue and frees will be involved, its
 * much easier and safer to enqueue the packet to the head of the queue (which
 * is a memory that is never freed and involves only updating the next pointer,
 * which can be a stale memory, but a safe operation nevertheless) rather than
 * at the tail (which is an element whose life cycle is not easy to determine).

 * Dequeue from the per-cpu queue
 * ------------------------------

 * The assembler will do an atomic read and update of head to NULL. There is a
 * small consistency issue to be taken care of while updating the head. The
 * enqueuer will first update the next pointer of the queued element and then
 * update the head. Updation of the head will be atomic read and update. Post
 * update, if the old head is not the same as the next, next will be updated to
 * NULL.

 * The Assembler
 * -------------

 * The assembler will be (a) kernel thread(s) which will wakeup when there is
 * work to do and go to sleep when there is nothing to do. The infrastructure to
 * wake up a thread when there is work to do is highly OS specific. Hence, to
 * accommodate that need, we will introduce a new host os entry point called
 * 'enqueue_to_assembler'. This entry point will enqueue to the per-cpu queue
 * as discussed above and will wakeup the kthread that does the assembly. The
 * enqueue code can be in platform independent part, so that all platforms can
 * reuse the code, with the infrastructure to wakeup the assembler being in
 * tail of the 'enqueue_to_assembler'.

 * For Linux kernel, we will use the workqueue infrastructure. We will create
 * a new workqueue for assembling the packets. The workqueue will have a dedicated
 * thread for each processor in the system(kernel infrastructure). So, once you
 * queue work to the queue, the thread for that processor will wakeup and do the
 * work of dequeuing it from the percpu queue and enqueuing it to the assembler
 * table.

 * When the assembler is woken up, it goes through the per-cpu queue and
 * dequeues all packets that have been enqueued and inserts them into the hash
 * list. The work area of the assembler is the hash table, where each bucket will
 * be a pointer to list of fragment metadata. Each such bucket will be protected
 * by a spinlock. The spinlock is mainly meant for exclusion between the aging
 * timer and the assembler.

 * Since a spinlock/mutex structure is needed and such structures are OS specific,
 * the assembler's origin will be in the OS specific part. The assembler will
 * define the hash buckets (that has the spinlock), with the individual and list
 * definitions coming from the OS independent part. While going through each
 * bucket, assembler will hold the bucket lock and pass control to the os
 * independent part.

 * For the linux kernel implementation, we will use spinlock rather than a mutex,
 * since the aging timer is invoked in an atomic context and hence can't block.

 * The assembler will dequeue packets from per-cpu queue and queue it in the
 * hash list. When the head of the fragment arrives, every fragment is dequeued
 * and flushed out of that entry, while still maintaining the metadata.
 */

#define FRAG_TABLE_ENTRIES  4096
#define FRAG_TABLE_BUCKETS  4
#define FRAG_OTABLE_ENTRIES 512

struct vr_timer *vr_assembler_table_scan_timer;

static inline void
__fragment_key(struct vr_fragment_key *key, unsigned short vrf,
        uint64_t sip_u, uint64_t sip_l, uint64_t dip_u, uint64_t dip_l,
        uint32_t id)
{
    key->fk_sip_u = sip_u;
    key->fk_sip_l = sip_l;
    key->fk_dip_u = dip_u;
    key->fk_dip_l = dip_l;
    key->fk_id = id;
    key->fk_vrf = vrf;

    return;
}

#define VR_FRAGMENT_FROM_HENTRY(entry)      \
    (struct vr_fragment *)((entry) ?\
    CONTAINER_OF(f_hentry, struct vr_fragment, entry) :\
    NULL)

#define VR_HENTRY_FROM_FRAGMENT(fe)        \
    (vr_hentry_t *)((fe) ? &fe->f_hentry : NULL)

static vr_hentry_key
vr_fragment_get_entry_key(vr_htable_t table, vr_hentry_t *entry,
        unsigned int *key_len)
{
    struct vr_fragment *fe =
        (struct vr_fragment *)CONTAINER_OF(f_hentry, struct vr_fragment, entry);

    if (key_len) {
        *key_len = sizeof(struct vr_fragment_key);
    }

    return &fe->f_key;
}

static inline void
fragment_entry_set(struct vr_fragment *fe, struct vr_fragment_key *key,
        unsigned short sport, unsigned short dport)
{
    uint64_t sec, nsec;

    fe->f_sip_u = key->fk_sip_u;
    fe->f_sip_l = key->fk_sip_l;
    fe->f_dip_u = key->fk_dip_u;
    fe->f_dip_l = key->fk_dip_l;
    fe->f_id = key->fk_id;
    fe->f_vrf = key->fk_vrf;
    fe->f_sport = sport;
    fe->f_dport = dport;
    vr_get_mono_time(&sec, &nsec);
    fe->f_time = sec;
    fe->f_expected = 0;
    fe->f_received = 0;

    return;
}

void
vr_fragment_queue_free(struct vr_fragment_queue *queue)
{
    struct vr_fragment_queue_element *vfqe, *next;

    vfqe = queue->vfq_tail;
    queue->vfq_tail = NULL;
    while (vfqe) {
        next = vfqe->fqe_next;
        if (vfqe->fqe_pnode.pl_packet)
            vr_pfree(vfqe->fqe_pnode.pl_packet, VP_DROP_MISC);
        vfqe->fqe_pnode.pl_packet = NULL;
        vr_free(vfqe, VR_FRAGMENT_QUEUE_ELEMENT_OBJECT);
        vfqe = next;
    }

    return;
}

static void
vr_fragment_queue_element_free(struct vr_fragment_queue_element *vfqe,
        unsigned int drop_reason)
{
    if (vfqe->fqe_pnode.pl_packet) {
        vr_pfree(vfqe->fqe_pnode.pl_packet, drop_reason);
    }

    vr_free(vfqe, VR_FRAGMENT_QUEUE_ELEMENT_OBJECT);
    return;
}

static void
fragment_free_frag(struct vr_fragment *frag)
{
    struct vr_fragment_queue_element *fqe;

    while ((fqe = frag->f_qe)) {
        frag->f_qe = fqe->fqe_next;
        vr_fragment_queue_element_free(fqe, VP_DROP_FRAGMENTS);
    }

    vr_free(frag, VR_FRAGMENT_OBJECT);
    return;
}

static void
fragment_unlink_frag(struct vr_fragment **prev, struct vr_fragment *frag)
{
    *prev = frag->f_next;
    return;
}

unsigned int
vr_assembler_table_scan(struct vr_fragment **head)
{
    unsigned int scanned = 0;
    uint64_t sec, nsec, dest;
    struct vr_fragment *frag = *head, *next, **prev;

    prev = head;
    while (frag) {
        next = frag->f_next;

        vr_get_mono_time(&sec, &nsec);
        dest = frag->f_time + VR_ASSEMBLER_TIMEOUT_TIME;
        if (dest < frag->f_time) {
            if ((sec < frag->f_time) && (dest < sec)) {
                fragment_unlink_frag(prev, frag);
                fragment_free_frag(frag);
            } else {
                prev = &frag->f_next;
            }
        } else {
            if ((sec > dest) || (sec < frag->f_time)) {
                fragment_unlink_frag(prev, frag);
                fragment_free_frag(frag);
            } else {
                prev = &frag->f_next;
            }
        }
        scanned++;
        frag = next;
    }

    return scanned;
}


void
vr_assembler_table_scan_exit(void)
{
    if (vr_assembler_table_scan_timer) {
        vr_delete_timer(vr_assembler_table_scan_timer);
        vr_free(vr_assembler_table_scan_timer, VR_TIMER_OBJECT);
        vr_assembler_table_scan_timer = NULL;
    }

    return;
}

int
vr_assembler_table_scan_init(void (*scanner)(void *))
{
    struct vr_timer *vtimer;

    vr_assembler_table_scan_timer = vr_zalloc(sizeof(*vtimer), VR_TIMER_OBJECT);
    if (!vr_assembler_table_scan_timer)
        return -ENOMEM;

    vtimer = vr_assembler_table_scan_timer;
    vtimer->vt_timer = scanner;
    vtimer->vt_vr_arg = NULL;
    vtimer->vt_msecs =
        (VR_ASSEMBLER_TIMEOUT_TIME * 1000) / VR_LINUX_ASSEMBLER_BUCKETS;
    if (vr_create_timer(vtimer)) {
        vr_free(vtimer, VR_TIMER_OBJECT);
        vr_assembler_table_scan_timer = NULL;
    }

    return 0;
}

static void
vr_fragment_flush_queue_element(struct vr_fragment_queue_element *vfqe)
{
    struct vrouter *router;
    struct vr_packet *pkt;

    struct vr_forwarding_md fmd;
    struct vr_packet_node *pnode;

    if (!vfqe)
        goto exit_flush;

    router = vfqe->fqe_router;
    pnode = &vfqe->fqe_pnode;
    pkt = pnode->pl_packet;
    if (!pkt)
        goto exit_flush;

    vr_init_forwarding_md(&fmd);
    fmd.fmd_vlan = pnode->pl_vlan;
    fmd.fmd_dvrf = pnode->pl_vrf;
    vr_flow_flush_pnode(router, pnode, NULL, &fmd);

exit_flush:
    vr_fragment_queue_element_free(vfqe, VP_DROP_CLONED_ORIGINAL);
    return;
}

int
vr_fragment_assembler(struct vr_fragment **head_p,
        struct vr_fragment_queue_element *vfqe)
{
    int ret = 0;
    uint64_t sec, nsec;
    unsigned int list_length = 0, drop_reason;
    bool found = false, frag_head = false;
    uint64_t *v6_addr;

    struct vrouter *router;
    struct vr_ip *ip;
    struct vr_ip6 *ip6;
    struct vr_ip6_frag *v6_frag;
    struct vr_packet *pkt;
    struct vr_packet_node *pnode;
    struct vr_fragment *frag, *frag_flow, **prev = NULL;
    struct vr_fragment_queue_element *fqe;
    struct vr_fragment_key vfk;


    router = vfqe->fqe_router;
    pnode = &vfqe->fqe_pnode;
    if (pnode->pl_flags & PN_FLAG_FRAGMENT_HEAD)
        frag_head = true;

    pkt = pnode->pl_packet;
    ip = (struct vr_ip *)pkt_network_header(pkt);
    if (vr_ip_is_ip6(ip)) {
       ip6 = (struct vr_ip6 *)ip;
       v6_frag = (struct vr_ip6_frag *)(ip6 + 1);
       v6_addr = (uint64_t *)(ip6->ip6_src);
        __fragment_key(&vfk, pnode->pl_vrf, *v6_addr, *(v6_addr + 1),
                *(v6_addr +2 ), *(v6_addr + 3), v6_frag->ip6_frag_id);
    } else {
        __fragment_key(&vfk, pnode->pl_vrf, 0, pnode->pl_inner_src_ip,
            0, pnode->pl_inner_dst_ip, ip->ip_id);
    }

    frag = *head_p;
    prev = head_p;
    while (frag) {
        list_length++;
        if (!memcmp(&frag->f_key, &vfk, sizeof(vfk))) {
            found = true;
            break;
        }

        prev = &frag->f_next;
        frag = frag->f_next;
    }

    if (!frag_head) {
        frag_flow = vr_fragment_get(router, pnode->pl_vrf, ip);
        if (frag_flow) {
            vr_fragment_flush_queue_element(vfqe);
            return 0;
        }
    }

    if (!found) {
        if (frag_head) {
            drop_reason = VP_DROP_CLONED_ORIGINAL;
            goto exit_assembly;
        }

        if (list_length > VR_MAX_FRAGMENTS_PER_ASSEMBLER_QUEUE) {
            drop_reason = VP_DROP_FRAGMENT_QUEUE_FAIL;
            goto exit_assembly;
        }

        frag = vr_zalloc(sizeof(*frag), VR_FRAGMENT_OBJECT);
        if (!frag) {
            ret = -ENOMEM;
            drop_reason = VP_DROP_NO_MEMORY;
            goto exit_assembly;
        }

        memcpy(&frag->f_key, &vfk, sizeof(vfk));
        frag->f_port_info_valid = false;
    }

    vr_get_mono_time(&sec, &nsec);
    frag->f_time = sec;
    if (!found) {
        prev = head_p;
        frag->f_next = *head_p;
        *head_p = frag;
    }

    if (!frag_head) {
        vfqe->fqe_next = NULL;
        fqe = frag->f_qe;
        if (!fqe) {
            frag->f_qe = vfqe;
        } else {
            while (fqe) {
                if (fqe->fqe_next) {
                    fqe = fqe->fqe_next;
                } else {
                    break;
                }
            }

            fqe->fqe_next = vfqe;
        }
    } else {
        frag->f_port_info_valid = true;
        vr_fragment_queue_element_free(vfqe, VP_DROP_CLONED_ORIGINAL);
    }


    if (frag->f_port_info_valid) {
        while ((fqe = frag->f_qe)) {
            frag->f_qe = fqe->fqe_next;
            vr_fragment_flush_queue_element(fqe);
        }

        fragment_unlink_frag(prev, frag);
        fragment_free_frag(frag);
    }

    return 0;

exit_assembly:
    vr_fragment_queue_element_free(vfqe, drop_reason);
    return ret;
}

uint32_t
__vr_fragment_get_hash(unsigned int vrf, uint64_t sip_u, uint64_t sip_l,
        uint64_t dip_u, uint64_t dip_l, uint32_t id)
{
    struct vr_fragment_key vfk;

    __fragment_key(&vfk, vrf, sip_u, sip_l, dip_u, dip_l, id);

    return vr_hash(&vfk, sizeof(vfk), 0);
}

uint32_t
vr_fragment_get_hash(struct vr_packet_node *pnode)
{
    uint64_t *v6_addr;
    struct vr_ip *ip;
    struct vr_ip6 *ip6;
    struct vr_ip6_frag *v6_frag;
    struct vr_packet *pkt;

    if (!pnode || !pnode->pl_packet)
        return (uint32_t)-1;

    pkt = pnode->pl_packet;

    ip = (struct vr_ip *)pkt_network_header(pkt);
    if (vr_ip_is_ip6(ip)) {
        ip6 = (struct vr_ip6 *)pkt_network_header(pkt);
        v6_frag = (struct vr_ip6_frag *)(ip6 + 1);
        v6_addr = (uint64_t *)(ip6->ip6_src);

        return __vr_fragment_get_hash(pnode->pl_vrf, *v6_addr, *(v6_addr+ 1),
                    *(v6_addr + 2), *(v6_addr + 3), v6_frag->ip6_frag_id);
    } else if(vr_ip_is_ip4(ip)) {
        return __vr_fragment_get_hash(pnode->pl_vrf, 0, pnode->pl_inner_src_ip,
                0, pnode->pl_inner_dst_ip, ip->ip_id);
    }

    return (uint32_t)-1;
}

int
vr_fragment_enqueue(struct vrouter *router,
        struct vr_fragment_queue *vfq,
        struct vr_packet *pkt, struct vr_forwarding_md *fmd)
{
    bool swapped = false;
    unsigned int i;

    struct vr_packet_node *pnode;
    struct vr_fragment_queue_element *fqe = NULL, *tail, **tailp;

    tailp = &vfq->vfq_tail;
    if (*tailp == NULL) {
        vfq->vfq_length = 0;
    } else {
        if ((vfq->vfq_length + 1) > VR_MAX_FRAGMENTS_PER_CPU_QUEUE)
            goto fail;
    }

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

    /*
     * we are actually competing with an existing assembler work that must
     * be in the process of dequeueing the list from the per-cpu queue.
     * we try thrice to enqueue our element. It is unlikely that it will
     * fail more than once
     *
     * calculation of vfq_length could be erroneous. But, we will err by
     * maximum 1, which is fine.
     */
    for (i = 0; i < VR_FRAG_ENQUEUE_ATTEMPTS; i++) {
        tail = *tailp;
        fqe->fqe_next = tail;
        vfq->vfq_length++;
        swapped = vr_sync_bool_compare_and_swap_p(tailp, tail, fqe);
        if (swapped) {
            if (tail == NULL)
                vfq->vfq_length = 1;
            break;
        } else {
            vfq->vfq_length--;
            if (i == (VR_FRAG_ENQUEUE_ATTEMPTS - 1)) {
                goto fail;
            }
        }
    }

    return 0;

fail:
    if (fqe)
        vr_free(fqe, VR_FRAGMENT_QUEUE_ELEMENT_OBJECT);

    vr_pfree(pkt, VP_DROP_FRAGMENTS);
    return -1;
}


void
vr_fragment_del(vr_htable_t table, struct vr_fragment *fe)
{
    fe->f_dip_u = fe->f_dip_l =  0;
    fe->f_received = 0;
    vr_htable_release_hentry(table, VR_HENTRY_FROM_FRAGMENT(fe));

    return;
}


static int
vr_fragment_add(struct vrouter *router, struct vr_fragment_key *key,
        unsigned short sport, unsigned short dport, unsigned short len)
{
    void *fe_ent;
    struct vr_fragment *fe;
    vr_htable_t ftable = router->vr_fragment_table;

    fe_ent = (void *) vr_htable_find_hentry(ftable, key, 0);
    fe = VR_FRAGMENT_FROM_HENTRY(fe_ent);
    if (fe)
        return 0;

    fe_ent = (void *) vr_htable_find_free_hentry(ftable, key, 0);
    fe = VR_FRAGMENT_FROM_HENTRY(fe_ent);
    if (!fe)
        return -ENOMEM;

    fragment_entry_set(fe, key, sport, dport);
    fe->f_received += len;

    return 0;
}

int
vr_v4_fragment_add(struct vrouter *router, unsigned short vrf,
        struct vr_ip *iph, unsigned short sport, unsigned short dport)
{
    struct vr_fragment_key key;

    __fragment_key(&key, vrf, 0, iph->ip_saddr, 0, iph->ip_daddr, iph->ip_id);

    return vr_fragment_add(router, &key, sport, dport,
                    (ntohs(iph->ip_len) - iph->ip_hl * 4));
}

int
vr_v6_fragment_add(struct vrouter *router, unsigned short vrf,
        struct vr_ip6 *ip6, unsigned short sport, unsigned short dport)
{
    uint64_t *v6_addr;
    struct vr_fragment_key key;
    struct vr_ip6_frag  *v6_frag;

    v6_addr = (uint64_t *)(ip6->ip6_src);
    v6_frag = (struct vr_ip6_frag *)(ip6 + 1);
    __fragment_key(&key, vrf, *v6_addr, *(v6_addr + 1), *(v6_addr + 2),
            *(v6_addr + 3), v6_frag->ip6_frag_id);

    return vr_fragment_add(router, &key, sport, dport,
            (ntohs(ip6->ip6_plen) - sizeof(struct vr_ip6_frag)));
}

struct vr_fragment *
vr_fragment_get(struct vrouter *router, unsigned short vrf, struct vr_ip *ip)
{
    uint64_t sec, nsec;
    uint64_t *v6_addr;
    struct vr_ip6 *ip6;
    struct vr_ip6_frag *v6_frag;
    struct vr_fragment *fe;
    struct vr_fragment_key key;
    vr_htable_t ftable;
    void *fe_ent;

    if (vr_ip_is_ip6(ip)) {
        ip6 = (struct vr_ip6 *)ip;
        if (ip6->ip6_nxt == VR_IP6_PROTO_FRAG) {
            v6_frag = (struct vr_ip6_frag *)(ip6 + 1);
            v6_addr = (uint64_t *)(ip6->ip6_src);
            __fragment_key(&key, vrf, *v6_addr, *(v6_addr+ 1),
                    *(v6_addr + 2), *(v6_addr+ 3), v6_frag->ip6_frag_id);
        }
    } else if (vr_ip_is_ip4(ip)) {
        __fragment_key(&key, vrf, 0, ip->ip_saddr, 0, ip->ip_daddr, ip->ip_id);
    } else {
        return NULL;
    }


    ftable = router->vr_fragment_table;

    fe_ent = (void *) vr_htable_find_hentry(ftable, &key, 0);
    fe = VR_FRAGMENT_FROM_HENTRY(fe_ent);
    if (fe) {
        vr_get_mono_time(&sec, &nsec);
        fe->f_time = sec;
    }

    return fe;
}

#define ENTRIES_PER_SCAN    64

struct scanner_params {
    struct vrouter *sp_router;
    int sp_scan_marker;
};

static void
__fragment_reap(vr_htable_t table, vr_hentry_t *ent,
        unsigned int index, void *data)
{
    uint64_t sec, nsec;
    struct vr_fragment *fe;

    fe = VR_FRAGMENT_FROM_HENTRY(ent);
    if (!fe || ((!fe->f_dip_u) && !(fe->f_dip_l)))
        return;

    vr_get_mono_time(&sec, &nsec);
    if (sec > fe->f_time + 1) {
        vr_fragment_del(table, fe);
    }

    return;
}

static int
fragment_reap(vr_htable_t htable, int start)
{
    return vr_htable_trav_range(htable, start, ENTRIES_PER_SCAN,
            __fragment_reap, NULL);
}

static void
fragment_table_scanner(void *arg)
{
    int ret;
    struct scanner_params *sp = (struct scanner_params *)arg;

    ret = fragment_reap(sp->sp_router->vr_fragment_table, sp->sp_scan_marker);
    if (ret < 0)
        return;

    sp->sp_scan_marker = ret;
    return;
}

static struct vr_timer *
fragment_table_scanner_init(struct vrouter *router)
{
    struct vr_timer *vtimer;
    struct scanner_params *scanner;

    scanner = vr_zalloc(sizeof(*scanner), VR_FRAGMENT_SCANNER_OBJECT);
    if (!scanner) {
        vr_module_error(-ENOMEM, __FUNCTION__, __LINE__, sizeof(*scanner));
        return NULL;
    }
    scanner->sp_router = router;
    scanner->sp_scan_marker = 0;

    vtimer = vr_malloc(sizeof(*vtimer), VR_TIMER_OBJECT);
    if (!vtimer) {
        vr_module_error(-ENOMEM, __FUNCTION__, __LINE__, sizeof(*vtimer));
        goto fail_init;
    }

    vtimer->vt_timer = fragment_table_scanner;
    vtimer->vt_vr_arg = scanner;
    vtimer->vt_msecs = 1000;
    if (vr_create_timer(vtimer)) {
        vr_module_error(-ENOMEM, __FUNCTION__, __LINE__, 0);
        goto fail_init;
    }

    return vtimer;

fail_init:
    if (scanner)
        vr_free(scanner, VR_FRAGMENT_SCANNER_OBJECT);

    return NULL;
}

static void
vr_fragment_table_scanner_exit(struct vrouter *router)
{
    if (router->vr_fragment_table_scanner) {
        vr_delete_timer(router->vr_fragment_table_scanner);
        vr_free(router->vr_fragment_table_scanner->vt_vr_arg,
                VR_FRAGMENT_SCANNER_OBJECT);
        vr_free(router->vr_fragment_table_scanner, VR_TIMER_OBJECT);
        router->vr_fragment_table_scanner = NULL;
    }

    return;
}

static int
vr_fragment_table_scanner_init(struct vrouter *router)
{
    if (!router->vr_fragment_table_scanner) {
        router->vr_fragment_table_scanner =
            fragment_table_scanner_init(router);
        if (!router->vr_fragment_table_scanner) {
            return -ENOMEM;
        }
    }

    return 0;
}

void
vr_fragment_table_exit(struct vrouter *router)
{
    vr_fragment_table_scanner_exit(router);

    if (router->vr_fragment_table) {
        vr_htable_delete(router->vr_fragment_table);
        router->vr_fragment_table = NULL;
    }

    return;
}

int
vr_fragment_table_init(struct vrouter *router)
{
    int ret;

    if (!router->vr_fragment_table) {
        router->vr_fragment_table = vr_htable_create(router,
                FRAG_TABLE_ENTRIES, FRAG_OTABLE_ENTRIES,
                sizeof(struct vr_fragment), sizeof(struct vr_fragment_key),
                FRAG_TABLE_BUCKETS, vr_fragment_get_entry_key);
        if (!router->vr_fragment_table) {
            return vr_module_error(-ENOMEM, __FUNCTION__, __LINE__,
                    FRAG_TABLE_ENTRIES + FRAG_OTABLE_ENTRIES);
        }
    }

    if ((ret = vr_fragment_table_scanner_init(router)))
        return ret;

    return 0;
}
