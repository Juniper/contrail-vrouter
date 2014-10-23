/*
 * vr_dpdk_virtio.c - implements DPDK forwarding infrastructure for 
 * virtio interfaces. The virtio data structures are setup by the user
 * space vhost server.
 *
 * Copyright (c) 2014 Juniper Networks, Inc. All rights reserved.
 */

#include <stdint.h>
#include <linux/vhost.h>
#include <linux/virtio_net.h>

#include "vr_dpdk.h"
#include "vr_dpdk_virtio.h"
#include "qemu_uvhost.h"
#include "vr_uvhost_client.h"

void *vr_dpdk_vif_clients[VR_MAX_INTERFACES];
vr_dpdk_virtioq_t vr_dpdk_virtio_rxqs[VR_MAX_INTERFACES][RTE_MAX_LCORE];
vr_dpdk_virtioq_t vr_dpdk_virtio_txqs[VR_MAX_INTERFACES][RTE_MAX_LCORE];

static int dpdk_virtio_from_vm_rx(void *arg, struct rte_mbuf **pkts, 
                                  uint32_t max_pkts);
static int dpdk_virtio_to_vm_tx(void *arg, struct rte_mbuf *pkt);
static int dpdk_virtio_to_vm_flush(void *arg);

struct rte_port_in_ops dpdk_virtio_reader_ops = {
    .f_create = NULL,
    .f_free = NULL,
    .f_rx = dpdk_virtio_from_vm_rx,
};

struct rte_port_out_ops dpdk_virtio_writer_ops = {
    .f_create = NULL,
    .f_free = NULL,
    .f_tx = dpdk_virtio_to_vm_tx, 
    .f_tx_bulk = NULL,
    .f_flush = dpdk_virtio_to_vm_flush,
};

/*
 * vr_dpdk_virtio_nrxqs - returns the number of receives queues for a virtio
 * interface.
 */
uint16_t
vr_dpdk_virtio_nrxqs(struct vr_interface *vif)
{
    return 1;
}

/*
 * vr_dpdk_virtio_ntxqs - returns the number of transmit queues for a virtio
 * interface.
 */
uint16_t
vr_dpdk_virtio_ntxqs(struct vr_interface *vif)
{
    return 1;
}

/*
 * vr_dpdk_virtio_rx_queue_init - initializes a virtio RX queue.
 *
 * Returns a pointer to the RX queue on success, NULL otherwise.
 */
struct vr_dpdk_rx_queue *
vr_dpdk_virtio_rx_queue_init(unsigned int lcore_id, struct vr_interface *vif,
                             unsigned int q_id)
{
    struct vr_dpdk_lcore *lcore = vr_dpdk.lcores[lcore_id];
    unsigned int vif_idx = vif->vif_idx;
    struct vr_dpdk_rx_queue *rx_queue = &lcore->lcore_rx_queues[vif_idx];

    if (q_id >= vr_dpdk_virtio_nrxqs(vif)) {
        return NULL;
    }

    rx_queue->rxq_ops = dpdk_virtio_reader_ops;
    vr_dpdk_virtio_rxqs[vif_idx][q_id].vdv_ready_state = VQ_NOT_READY;
    vr_dpdk_virtio_rxqs[vif_idx][q_id].vdv_zero_copy =  0;
    vr_dpdk_virtio_rxqs[vif_idx][q_id].vdv_soft_avail_idx = 0;
    vr_dpdk_virtio_rxqs[vif_idx][q_id].vdv_soft_used_idx = 0;
    vr_dpdk_virtio_rxqs[vif_idx][q_id].vdv_vif_idx = vif->vif_idx;
    rx_queue->rxq_queue_h = (void *) &vr_dpdk_virtio_rxqs[vif_idx][q_id];
    rx_queue->rxq_burst_size = VR_DPDK_VIRTIO_RX_BURST_SZ;
    rx_queue->rxq_vif = vif;

    return rx_queue;
}

/*
 * vr_dpdk_virtio_tx_queue_init - initializes a virtio TX queue.
 *
 * Returns a pointer to the TX queue on success, NULL otherwise.
 */
struct vr_dpdk_tx_queue *
vr_dpdk_virtio_tx_queue_init(unsigned int lcore_id, struct vr_interface *vif,
                             unsigned int q_id)
{
    struct vr_dpdk_lcore *lcore = vr_dpdk.lcores[lcore_id];
    unsigned int vif_idx = vif->vif_idx;
    struct vr_dpdk_tx_queue *tx_queue = &lcore->lcore_tx_queues[vif_idx];

    if (q_id >= vr_dpdk_virtio_ntxqs(vif)) {
        return NULL;
    }

    tx_queue->txq_ops = dpdk_virtio_writer_ops;
    vr_dpdk_virtio_txqs[vif_idx][q_id].vdv_ready_state = VQ_NOT_READY;
    vr_dpdk_virtio_txqs[vif_idx][q_id].vdv_zero_copy =  0;
    vr_dpdk_virtio_txqs[vif_idx][q_id].vdv_soft_avail_idx = 0;
    vr_dpdk_virtio_txqs[vif_idx][q_id].vdv_soft_used_idx = 0;
    vr_dpdk_virtio_txqs[vif_idx][q_id].vdv_vif_idx = vif->vif_idx;
    vr_dpdk_virtio_txqs[vif_idx][q_id].vdv_tx_mbuf_count = 0;
    tx_queue->txq_queue_h = (void *) &vr_dpdk_virtio_txqs[vif_idx][q_id];
    tx_queue->txq_vif = vif;

    return tx_queue;
}

/*
 * vr_dpdk_guest_phys_to_host_virt - convert a guest physical address
 * to a host virtual address. Uses the guest memory map stored in the
 * vhost client for the guest interface.
 *
 * Returns address on success, NULL otherwise.
 */
static char *
vr_dpdk_guest_phys_to_host_virt(vr_dpdk_virtioq_t *vq, uint64_t paddr)
{
    int i;
    vr_uvh_client_t *vru_cl;
    vr_uvh_client_mem_region_t *reg;

    vru_cl = vr_dpdk_virtio_get_vif_client(vq->vdv_vif_idx);
    if (vru_cl == NULL) {
        return NULL;
    }

    for (i = 0; i < vru_cl->vruc_num_mem_regions; i++) {
        reg = &vru_cl->vruc_mem_regions[i];

        if ((paddr >= reg->vrucmr_phys_addr) && 
                (paddr <= (reg->vrucmr_phys_addr + reg->vrucmr_size))) {
            return ((char *) reg->vrucmr_mmap_addr) + 
                        (paddr - reg->vrucmr_phys_addr);
        }
    }

    return NULL;
}

/* 
 * vr_dpdk_virtio_get_mempool - get the mempool to use for receiving 
 * packets from VMs.
 */
static struct rte_mempool *
vr_dpdk_virtio_get_mempool(void)
{
    return vr_dpdk.virtio_mempool;
}
    
/* 
 * dpdk_virtio_from_vm_rx - receive packets from a virtio client so that 
 * the packets can be handed to vrouter for forwarding. the virtio client is
 * usually a VM.
 *
 * Returns the number of packets to be sent to vrouter (0 if there is nothing
 * to do).
 */
static int
dpdk_virtio_from_vm_rx(void *arg, struct rte_mbuf **pkts, uint32_t max_pkts)
{
    vr_dpdk_virtioq_t *vq = (vr_dpdk_virtioq_t *) arg;
    uint16_t vq_hard_avail_idx, i;
    uint16_t num_pkts, next_desc_idx, next_avail_idx, pkts_sent = 0;
    struct vring_desc *desc;
    char *pkt_addr;
    struct rte_mbuf *mbuf;
    uint32_t pkt_len;
 
    if (vq->vdv_ready_state == VQ_NOT_READY) {
        return 0;
    }

    vq_hard_avail_idx = (*((volatile uint16_t *)&vq->vdv_avail->idx));

    /*  
     * Unsigned subtraction gives the right result even with wrap around.
     */
    num_pkts = vq_hard_avail_idx - vq->vdv_soft_avail_idx;
    if (num_pkts == 0) {
        return 0;
    }

    if (num_pkts > max_pkts) {
        num_pkts = max_pkts;
    }

    for (i = 0; i < num_pkts; i++) {
        next_avail_idx = (vq->vdv_soft_avail_idx + i) &
                             (vq->vdv_vvs.num - 1);
        next_desc_idx = vq->vdv_avail->ring[next_avail_idx]; 
        desc = &vq->vdv_desc[next_desc_idx];

        /*
         * Ignore virtio header in first descriptor as we don't support
         * mergeable receive buffers yet. Before that, move the descriptors
         * (chain of 2) to the used list. The used index will, however, only
         * be updated at the end of the loop.
         */
        vq->vdv_used->ring[next_avail_idx].id = next_desc_idx;
        vq->vdv_used->ring[next_avail_idx].len = 0; 
        if (desc->flags & VRING_DESC_F_NEXT) {
            /*
             * TODO - make sure desc->next is sane
             */
            desc = &vq->vdv_desc[desc->next];
            pkt_addr = vr_dpdk_guest_phys_to_host_virt(vq, desc->addr);
            pkt_len = desc->len;
        } else {
            pkt_addr = vr_dpdk_guest_phys_to_host_virt(vq, desc->addr);
            if (pkt_addr) {
                pkt_addr += sizeof(struct virtio_net_hdr);
                pkt_len = desc->len - sizeof(struct virtio_net_hdr);
            }
        }

        if (pkt_addr) {
            mbuf = rte_pktmbuf_alloc(vr_dpdk_virtio_get_mempool());
            if (mbuf != NULL) {
                mbuf->pkt.data_len = pkt_len;
                mbuf->pkt.pkt_len = mbuf->pkt.data_len;

                rte_memcpy(mbuf->pkt.data, pkt_addr, pkt_len);
                pkts[pkts_sent] = mbuf;
                pkts_sent++;
            }
        }
    }

    /* 
     * TODO - need a memory barrier here. Also, might need to kick guest.
     */
    vq->vdv_soft_avail_idx += num_pkts;
    vq->vdv_used->idx += num_pkts;

    return pkts_sent;
}

/*
 * dpdk_virtio_to_vm_tx - sends a packet from vrouter to a virtio client. The
 * virtio client is usually a VM.
 *
 * Returns nothing.
 */
static int
dpdk_virtio_to_vm_tx(void *arg, struct rte_mbuf *pkt)
{
    vr_dpdk_virtioq_t *vq = (vr_dpdk_virtioq_t *) arg;

    if (vq->vdv_ready_state == VQ_NOT_READY) {
        rte_pktmbuf_free(pkt);

        return 0;
    }

    vq->vdv_tx_mbuf[vq->vdv_tx_mbuf_count++] = pkt;
    if (vq->vdv_tx_mbuf_count >= VR_DPDK_VIRTIO_TX_BURST_SZ) {
        dpdk_virtio_to_vm_flush(vq);
    }    
    
    return 0;
}

/*
 * dpdk_virtio_to_vm_flush - flushes packets from vrouter to a virtio client.
 * The virtio client is usually a VM.
 *
 * Returns nothing.
 */
static int
dpdk_virtio_to_vm_flush(void *arg)
{
    vr_dpdk_virtioq_t *vq = (vr_dpdk_virtioq_t *) arg;
    uint16_t i;
    uint16_t num_buf_posted, vq_hard_avail_idx, num_pkts;
    uint16_t next_desc_idx, next_avail_idx, size;
    struct vring_desc *desc;
    char *buf_addr;
    struct virtio_net_hdr vhdr = {0, 0, 0, 0, 0, 0};

    if (vq->vdv_ready_state == VQ_NOT_READY) {
        return 0;
    }

    if (vq->vdv_tx_mbuf_count == 0) {
        return 0;
    }

    vq_hard_avail_idx = (*((volatile uint16_t *)&vq->vdv_avail->idx));

    /*  
     * Unsigned subtraction gives the right result even with wrap around.
     */
    num_buf_posted = vq_hard_avail_idx - vq->vdv_soft_avail_idx;
    if (num_buf_posted < vq->vdv_tx_mbuf_count) {
        num_pkts = num_buf_posted;
    } else {
        num_pkts = vq->vdv_tx_mbuf_count;   
    }
  
    for (i = 0; i < num_pkts; i++) {
        next_avail_idx = (vq->vdv_soft_avail_idx + i) &
                             (vq->vdv_vvs.num - 1);
        next_desc_idx = vq->vdv_avail->ring[next_avail_idx];

        /*
         * Move the descriptor (single or chain of 2) to the used list. The
         * used index will, however, only be updated at the end of the loop.
         * This needs to be done even if any failures occur below in the loop.
         * Set the descriptor length to 0 for now and update it at the end
         * of the loop if there were no errors.
         */
        vq->vdv_used->ring[next_avail_idx].id = next_desc_idx;
        vq->vdv_used->ring[next_avail_idx].len = 0;

        desc = &vq->vdv_desc[next_desc_idx];
        buf_addr = vr_dpdk_guest_phys_to_host_virt(vq, desc->addr);
        if (buf_addr == NULL) { 
            rte_pktmbuf_free(vq->vdv_tx_mbuf[i]);
            continue;
        }

        /*
         * No support for checksum offload or GSO at the moment, so zero 
         * out the virtio header.
         */
        size = sizeof(vhdr);
        rte_memcpy(buf_addr, &vhdr, size);
        buf_addr += sizeof(vhdr);

        /*
         * If the descriptor has VRING_DESC_F_NEXT set, the virtio_net header
         * and packet data use separate descriptors.
         */ 
        if (desc->flags & VRING_DESC_F_NEXT) {
            desc->len = sizeof(struct virtio_net_hdr);
            /*
             * TODO: verify that desc->next is sane below.
             */
            desc = &vq->vdv_desc[desc->next];

            buf_addr = vr_dpdk_guest_phys_to_host_virt(vq, desc->addr);
            if (buf_addr == NULL) {
                rte_pktmbuf_free(vq->vdv_tx_mbuf[i]);
                continue;
            }
            
            desc->len = rte_pktmbuf_data_len(vq->vdv_tx_mbuf[i]);
        } else {
            desc->len = sizeof(struct virtio_net_hdr) + 
                            rte_pktmbuf_data_len(vq->vdv_tx_mbuf[i]);
        }

        rte_memcpy(buf_addr, vq->vdv_tx_mbuf[i]->pkt.data,
                   rte_pktmbuf_data_len(vq->vdv_tx_mbuf[i]));
            
        vq->vdv_used->ring[next_avail_idx].len =
            sizeof(struct virtio_net_hdr) +
            rte_pktmbuf_data_len(vq->vdv_tx_mbuf[i]);

        rte_pktmbuf_free(vq->vdv_tx_mbuf[i]);
    }
 
    /*
     * Free any packets that could not be sent to the VM because it didn't
     * post receive buffers soon enough.
     */
    for (; i < vq->vdv_tx_mbuf_count; i++) {
        /*
         * TODO: increment stats here
         */
        rte_pktmbuf_free(vq->vdv_tx_mbuf[i]);
    }

    vq->vdv_tx_mbuf_count = 0;

    /*
     * Now update the used index in the vring. 
     * TODO - need memory barrier + VM kick here.
     */
    vq->vdv_soft_avail_idx += num_pkts;
    vq->vdv_used->idx += num_pkts;

    return 0;
}

/*
 * vr_dpdk_virtio_set_vring_base - sets the vring base using data sent by
 * vhost client.
 *
 * Returns 0 on success, -1 otherwise.
 */
int
vr_dpdk_virtio_set_vring_base(unsigned int vif_idx, unsigned int vring_idx,
                               unsigned int vring_base)
{
    vr_dpdk_virtioq_t *vq;

    if ((vif_idx >= VR_MAX_INTERFACES) || (vring_idx >= (2 * RTE_MAX_LCORE))) {
        return -1;
    }

    /*
     * RX rings are even numbered and TX rings are odd numbered from the
     * VM's point of view. From vrouter's point of view, VM's TX ring is
     * vrouter's RX ring and vice versa.
     */
    if (vring_idx & 1) {
        vq = &vr_dpdk_virtio_rxqs[vif_idx][vring_idx/2];
    } else {
        vq = &vr_dpdk_virtio_txqs[vif_idx][vring_idx/2];
    }

    vq->vdv_base_idx = vring_base;
    return 0;
}

/*
 * vr_dpdk_virtio_get_vring_base - gets the vring base for the specified vring 
 * sent by the vhost client.
 *
 * Returns 0 on success, -1 otherwise.
 */
int
vr_dpdk_virtio_get_vring_base(unsigned int vif_idx, unsigned int vring_idx,
                               unsigned int *vring_basep)
{
    vr_dpdk_virtioq_t *vq;

    if ((vif_idx >= VR_MAX_INTERFACES) || (vring_idx >= (2 * RTE_MAX_LCORE))) {
        return -1;
    }

    /*
     * RX rings are even numbered and TX rings are odd numbered from the
     * VM's point of view. From vrouter's point of view, VM's TX ring is
     * vrouter's RX ring and vice versa.
     */
    if (vring_idx & 1) {
        vq = &vr_dpdk_virtio_rxqs[vif_idx][vring_idx/2];
    } else {
        vq = &vr_dpdk_virtio_txqs[vif_idx][vring_idx/2];
    }

    *vring_basep =  vq->vdv_base_idx;

    return 0;
}

/*
 * vr_dpdk_set_vring_addr - Sets the address of the virtio descruptor and
 * available/used rings based on messages sent by the vhost client.
 *
 * Returns 0 on suucess, -1 otherwise.
 */
int
vr_dpdk_set_vring_addr(unsigned int vif_idx, unsigned int vring_idx,
                       struct vring_desc *vrucv_desc, 
                       struct vring_avail *vrucv_avail,
                       struct vring_used *vrucv_used)
{
    vr_dpdk_virtioq_t *vq;

    if ((vif_idx >= VR_MAX_INTERFACES) || (vring_idx >= (2 * RTE_MAX_LCORE))) {
        return -1;
    }

    /*
     * RX rings are even numbered and TX rings are odd numbered from the
     * VM's point of view. From vrouter's point of view, VM's TX ring is
     * vrouter's RX ring and vice versa.
     */
    if (vring_idx & 1) {
        vq = &vr_dpdk_virtio_rxqs[vif_idx][vring_idx/2];
    } else {
        vq = &vr_dpdk_virtio_txqs[vif_idx][vring_idx/2];
    }

    vq->vdv_desc = vrucv_desc;
    vq->vdv_avail = vrucv_avail;
    vq->vdv_used = vrucv_used;

    return 0;
}

/*
 * vr_dpdk_set_ring_num_desc - sets the number of descriptors in a vring
 * based on messages from the vhost client.
 *
 * Returns 0 on success, -1 otherwise.
 */
int
vr_dpdk_set_ring_num_desc(unsigned int vif_idx, unsigned int vring_idx,
                          unsigned int num_desc)
{
    vr_dpdk_virtioq_t *vq;

    if ((vif_idx >= VR_MAX_INTERFACES) || (vring_idx >= (2 * RTE_MAX_LCORE))) {
        return -1;
    }

    /*
     * RX rings are even numbered and TX rings are odd numbered from the
     * VM's point of view. From vrouter's point of view, VM's TX ring is
     * vrouter's RX ring and vice versa.
     */
    if (vring_idx & 1) {
        vq = &vr_dpdk_virtio_rxqs[vif_idx][vring_idx/2];
    } else {
        vq = &vr_dpdk_virtio_txqs[vif_idx][vring_idx/2];
    }

    vq->vdv_vvs.index = vring_idx;
    vq->vdv_vvs.num = num_desc;

    return 0;
}

/*
 * vr_dpdk_set_virtq_ready - sets the virtio queue ready state to indicate
 * whether forwarding can start on the virtio queue or not.
 *
 * Returns 0 on success, -1 otherwise.
 */
int
vr_dpdk_set_virtq_ready(unsigned int vif_idx, unsigned int vring_idx,
                        vq_ready_state_t ready)
{
    vr_dpdk_virtioq_t *vq;

    if ((vif_idx >= VR_MAX_INTERFACES) || (vring_idx >= (2 * RTE_MAX_LCORE))) {
        return -1;
    }

    /*
     * RX rings are even numbered and TX rings are odd numbered from the
     * VM's point of view. From vrouter's point of view, VM's TX ring is
     * vrouter's RX ring and vice versa.
     */
    if (vring_idx & 1) {
        vq = &vr_dpdk_virtio_rxqs[vif_idx][vring_idx/2];
    } else {
        vq = &vr_dpdk_virtio_txqs[vif_idx][vring_idx/2];
    }

    vq->vdv_ready_state = ready;

    return 0;
}

/*
 * vr_dpdk_virtio_set_vif_client - sets a pointer to per vif state. Currently
 * used to store a pointer to the vhost client structure.
 *
 * Returns nothing.
 */
void
vr_dpdk_virtio_set_vif_client(unsigned int idx, void *client)
{
    if (idx >= VR_MAX_INTERFACES) {
        return;
    }

    vr_dpdk_vif_clients[idx] = client;
    
    return;
}     

/*
 * vr_dpdk_virtio_get_vif_client - returns a pointer to per vif state if it
 * exists, NULL otherwise.
 */
void *
vr_dpdk_virtio_get_vif_client(unsigned int idx)
{
    if (idx >= VR_MAX_INTERFACES) {
        return NULL;
    }

    return vr_dpdk_vif_clients[idx];
}

