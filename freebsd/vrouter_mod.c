/*-
 * Copyright (c) 2014 Semihalf
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#include <sys/param.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/endian.h>
#include <sys/pcpu.h>
#include <sys/malloc.h>
#include <sys/smp.h>
#include <sys/time.h>
#include <sys/callout.h>
#include <sys/mbuf.h>
#include <sys/socket.h>

#include <vm/uma.h>
#include <vm/vm.h>
#include <vm/vm_extern.h>
#include <vm/vm_kern.h>

#include <net/if.h>
#include <net/if_var.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include "vr_freebsd.h"
#include "vr_proto.h"
#include "vr_sandesh.h"
#include "vrouter.h"

/* UMA zone for vr_packet */
extern uma_zone_t zone_vr_packet;

extern int vr_flow_entries;
extern int vr_oflow_entries;
/* Prototypes */
struct host_os *vrouter_get_host(void);

/*
 * Overlay length used for TCP MSS adjust. For UDP outer header, overlay
 * len is 20 (IP header) + 8 (UDP) + 4 (MPLS). For GRE, it is 20 (IP header)
 * + 8 (GRE header + key) + 4 (MPLS). Instead of allowing for only one
 * label, we will allow a maximum of 3 labels, so we end up with 40 bytes
 * of overleay headers.
 */
#define VROUTER_OVERLAY_LEN 40

/*
 * The following macro is used to update an
 * internet checksum . Code taken from sys/netgraph/ng_tcpmss.c
 * Copyright (c) 2004, Alexey Popov <lollypop@flexuser.ru>
 */
#define TCPMSS_ADJUST_CHECKSUM(acc, cksum) do {		\
	acc += cksum;					\
	if (acc < 0) {					\
		acc = -acc;				\
		acc = (acc >> 16) + (acc & 0xffff);	\
		acc += acc >> 16;			\
		cksum = (u_short) ~acc;			\
	} else {					\
		acc = (acc >> 16) + (acc & 0xffff);	\
		acc += acc >> 16;			\
		cksum = (u_short) acc;			\
	}						\
} while (0);

unsigned int vr_num_cpus = 1;

int vr_log_level = 0;
int vrouter_dbg = 0;

/* Create malloc type for vrouter */
MALLOC_DECLARE(M_VROUTER);
MALLOC_DEFINE(M_VROUTER, "vrouter", "vrouter");

static void *
fh_malloc(unsigned int size)
{

	return (malloc(size, M_VROUTER, M_NOWAIT));
}

static void *
fh_zalloc(unsigned int size)
{

	return (malloc(size, M_VROUTER, M_NOWAIT|M_ZERO));
}

static void
fh_free(void *mem)
{

	if (mem)
		free(mem, M_VROUTER);

	return;
}

static uint64_t
fh_vtop(void *address)
{

	vr_log(VR_ERR, "%s: not implemented\n", __func__);
	return (0);
}

static void *
fh_page_alloc(unsigned int size)
{

	return ((void *)(kmem_malloc(kernel_arena, size, M_NOWAIT|M_ZERO)));
}

static void
fh_page_free(void *address, unsigned int size)
{

	if (address)
		kmem_free(kernel_arena, (vm_offset_t)address, size);

	return;
}

static struct vr_packet *
fh_palloc(unsigned int size)
{
	struct mbuf *m;

	m = m_get2(size, M_NOWAIT, MT_DATA, M_PKTHDR);
	if (!m)
		return (NULL);

	m->m_len = m->m_pkthdr.len = size;

	return (freebsd_get_packet(m, NULL));
}

static struct vr_packet *
fh_palloc_head(struct vr_packet *pkt, unsigned int size)
{

	vr_log(VR_ERR, "%s: not implemented\n", __func__);
	return (NULL);
}

static struct vr_packet *
fh_pexpand_head(struct vr_packet *pkt, unsigned int hspace)
{
	struct mbuf *m;
	struct vr_packet_wrapper *wrapper = (struct vr_packet_wrapper *) pkt;
	int offset;

	m = vp_os_packet(pkt);
	if (!m)
		return NULL;

	offset = M_LEADINGSPACE(m);
	M_PREPEND(m, hspace, M_NOWAIT);
	if (m == NULL)
		return NULL;

	/* Data must be continuous, so mbuf must be defragged */
	m = m_defrag(m, M_NOWAIT);
	hspace -= offset;

	pkt->vp_head =
	    (unsigned char *)(m->m_flags & M_EXT ? m->m_ext.ext_buf :
	    m->m_flags & M_PKTHDR ? m->m_pktdat : m->m_dat);
	pkt->vp_data += hspace;
	pkt->vp_tail += hspace;
	pkt->vp_end = m->m_flags & M_EXT ? m->m_ext.ext_size :
		((m->m_flags & M_PKTHDR) ? MHLEN : MLEN);

	pkt->vp_network_h += hspace;
	pkt->vp_inner_network_h += hspace;

	wrapper->vrw_m = m;

	return (pkt);
}

static void
fh_pfree(struct vr_packet *pkt, unsigned short reason)
{
	struct vrouter *router;
	struct mbuf *m;

	KASSERT(pkt, ("Null packet"));

	/* Fetch original mbuf from packet structure */
	m = vp_os_packet(pkt);
	KASSERT(m, ("NULL mbuf in pkt:%p", pkt));

	router = vrouter_get(0);
	if (router)
		((uint64_t *)(router->vr_pdrop_stats[pkt->vp_cpu]))[reason]++;

	m_freem(m);
	uma_zfree(zone_vr_packet, pkt);
}

static void
fh_preset(struct vr_packet *pkt)
{
	struct mbuf *m;

	KASSERT(pkt, ("NULL pkt"));

	m = vp_os_packet(pkt);
	KASSERT(m, ("NULL mbuf"));

	/* Reset packet data */
	pkt->vp_data = M_LEADINGSPACE(m);
	pkt->vp_tail = M_LEADINGSPACE(m) + m->m_len;
	pkt->vp_len = m->m_len;
}

static struct vr_packet *
fh_pclone(struct vr_packet *pkt)
{
	struct mbuf *m, *m_clone;
	struct vr_packet *pkt_clone;
	struct vr_packet_wrapper *wrapper;

	KASSERT(pkt, ("NULL pkt"));

	m = vp_os_packet(pkt);
	m_clone = m_dup(m, M_NOWAIT);

	wrapper = uma_zalloc(zone_vr_packet, M_NOWAIT);
	if (!wrapper) {
		vr_log(VR_ERR, "cannot alloc wrapper");
		m_freem(m_clone);
		return (NULL);
	}

	memcpy(&wrapper->vrw_pkt, pkt, sizeof(*pkt));
	wrapper->vrw_m = m_clone;
	pkt_clone = &wrapper->vrw_pkt;
	return (pkt_clone);
}

static int
fh_pcopy(unsigned char *dst, struct vr_packet *p_src,
    unsigned int offset, unsigned int len)
{
	struct mbuf *m;

	KASSERT(p_src, ("NULL pkt"));
	KASSERT(dst, ("NULL dst"));

	m = vp_os_packet(p_src);
	m_copydata(m, offset, len, (caddr_t)dst);
	m->m_len = m->m_pkthdr.len = len;
	return (len);
}

static unsigned short
fh_pfrag_len(struct vr_packet *pkt)
{
	struct mbuf *m;

	KASSERT(pkt, ("NULL pkt"));

	m = vp_os_packet(pkt);
	KASSERT(m, ("NULL mbuf"));

	return (m_length(m, NULL) - m->m_len);
}

static unsigned short
fh_phead_len(struct vr_packet *pkt)
{
	struct mbuf *m;

	KASSERT(pkt, ("NULL pkt"));

	m = vp_os_packet(pkt);
	KASSERT(m, ("NULL mbuf"));

	return (m->m_len);
}

static void
fh_pset_data(struct vr_packet *pkt, unsigned short offset)
{
	struct mbuf *m;

	m = vp_os_packet(pkt);
	m->m_data = (caddr_t)(pkt->vp_head + offset);

	return;
}

static unsigned int
fh_get_cpu(void)
{
	unsigned int cpuid;

	critical_enter();
	cpuid = PCPU_GET(cpuid);
	critical_exit();
	return (cpuid);
}

static void
fh_schedule_work(unsigned int cpu, void (*fn)(void *), void *arg)
{

	vr_log(VR_ERR, "%s: not implemented\n", __func__);
}

static void
fh_delay_op(void)
{

	vr_log(VR_ERR, "%s: not implemented\n", __func__);
	return;
}

static void
fh_defer(struct vrouter *router, vr_defer_cb user_cb, void *data)
{

	vr_log(VR_ERR, "%s: not implemented\n", __func__);
	return;
}

static void *
fh_get_defer_data(unsigned int len)
{

	vr_log(VR_ERR, "%s: not implemented\n", __func__);
	return (NULL);
}

static void
fh_set_defer_data(void *data)
{

	vr_log(VR_ERR, "%s: not implemented\n", __func__);
	return;
}

static void
fh_get_time(unsigned int *sec, unsigned int *nsec)
{
	struct timespec tsp;

	nanotime(&tsp);

	*sec = tsp.tv_sec;
	*nsec = tsp.tv_nsec;

	return;
}

static void
fh_get_mono_time(unsigned int *sec, unsigned int *nsec)
{
	struct timespec tsp;

	nanouptime(&tsp);
	*sec = tsp.tv_sec;
	*nsec = tsp.tv_nsec;

	return;
}

static void
freebsd_timer(void *arg)
{
	struct vr_timer *vtimer = (struct vr_timer *)arg;

	vtimer->vt_timer(vtimer->vt_vr_arg);
	callout_schedule(vtimer->vt_os_arg, (vtimer->vt_msecs * hz) / 1000);
}

static void
fh_delete_timer(struct vr_timer *vtimer)
{
	struct callout *callout = (struct callout *)vtimer->vt_os_arg;

	vr_log(VR_DEBUG, "stop timer %p\n", callout);
	if (callout) {
		callout_drain(callout);
		vr_free(vtimer->vt_os_arg);
		vtimer->vt_os_arg = NULL;
	}

	return;
}

static int
fh_create_timer(struct vr_timer *vtimer)
{
	struct callout *callout;

	callout = vr_zalloc(sizeof(*callout));
	if (!callout) {
		vr_log(VR_ERR, "Failed to alloc callout\n");
		return (-1);
	}

	callout_init(callout, 1);
	vtimer->vt_os_arg = (void *)callout;
	callout_reset(callout, (vtimer->vt_msecs * hz) / 1000, freebsd_timer,
	    (void *)vtimer);

	return (0);
}

static void *
fh_network_header(struct vr_packet *pkt)
{

	vr_log(VR_ERR, "%s: not implemented\n", __func__);
	return (NULL);
}

static void *
fh_inner_network_header(struct vr_packet *pkt)
{

	vr_log(VR_ERR, "%s: not implemented\n", __func__);
	return (NULL);
}

static void *
fh_data_at_offset(struct vr_packet *pkt, unsigned short off)
{

	vr_log(VR_ERR, "%s: not implemented\n", __func__);
	return (NULL);
}

static void *
fh_pheader_pointer(struct vr_packet *pkt, unsigned short hdr_len, void *buf)
{
	int offset;
	struct mbuf *m = vp_os_packet(pkt);
	int hlen = m->m_len;

	offset = pkt->vp_data - M_LEADINGSPACE(m);

	if (hlen - hdr_len >= offset)
		return (mtodo(m, offset));

	m_copydata(m, offset, hdr_len, buf);

	return (buf);
}

static int
fh_pcow(struct vr_packet *pkt, unsigned short head_room)
{

	vr_log(VR_ERR, "%s: not implemented\n", __func__);
	return (0);
}

static uint16_t
fh_get_udp_src_port(struct vr_packet *pkt, struct vr_forwarding_md *fmd,
    unsigned short vrf)
{

	vr_log(VR_ERR, "%s: not implemented\n", __func__);
	return (0);
}

/*
 * Adjust the TCP MSS in the given packet based on
 * vrouter physical interface MTU. Returns 0 on success, non-zero
 * otherwise
 */
static void
fh_adjust_tcp_mss(struct tcphdr *tcph, struct mbuf *m)
{
	struct vrouter *router;
	struct ifnet *ifp;
	uint8_t *opt_ptr;
	int opt_off, diff;
	uint16_t pkt_mss, max_mss, sum;

	KASSERT((tcph && m), ("Null arguments tcph:%p m:%p", tcph, m));

	if (!(tcph->th_flags & TH_SYN))
		return;

	router = vrouter_get(0);
	KASSERT(router, ("NULL vrouter"));

	if (router->vr_eth_if == NULL)
		return;

	opt_ptr = (uint8_t *)tcph;
	opt_off = sizeof(struct tcphdr);
	while (opt_off < (tcph->th_off * 4)) {
		switch (opt_ptr[opt_off]) {
		case TCPOPT_EOL:
			return;
		case TCPOPT_NOP:
			opt_off++;
			break;
		case TCPOPT_MAXSEG:
			if ((opt_off + TCPOLEN_MAXSEG) > (tcph->th_off * 4))
				return;

			if (opt_ptr[opt_off + 1] != TCPOLEN_MAXSEG)
				return;

			pkt_mss = be16dec(&opt_ptr[opt_off+2]);

			ifp = (struct ifnet *) router->vr_eth_if->vif_os;
			if (!ifp)
				return;
			max_mss = ifp->if_mtu -
			    (VROUTER_OVERLAY_LEN + sizeof(struct vr_ip) +
			    sizeof(struct tcphdr));

			if (pkt_mss > max_mss) {
				if ((m->m_pkthdr.csum_flags & CSUM_TCP) == 0) {
					diff = pkt_mss - max_mss;
					sum = be16dec(&tcph->th_sum);
					TCPMSS_ADJUST_CHECKSUM(diff, sum);
					be16enc(&tcph->th_sum, sum);
				}
				be16enc(&opt_ptr[opt_off+2], max_mss);
			}

			return;
		default:
			if ((opt_off + 1) == (tcph->th_off * 4))
				return;

			if (opt_ptr[opt_off + 1])
				opt_off += opt_ptr[opt_off + 1];
			else
				opt_off++;

			break;
		}
	}

	return;
}

static void
fh_reset_mbuf_fields(struct vr_packet *pkt)
{
	struct mbuf *m;
	KASSERT(pkt, ("NULL pkt"));

	m = vp_os_packet(pkt);
	KASSERT(m, ("NULL mbuf"));

	pkt->vp_head =
        (unsigned char *)(m->m_flags & M_EXT ? m->m_ext.ext_buf :
	    m->m_flags & M_PKTHDR ? m->m_pktdat : m->m_dat);
	pkt->vp_data = M_LEADINGSPACE(m);

	pkt->vp_tail = M_LEADINGSPACE(m) + m->m_len;
	pkt->vp_end = m->m_flags & M_EXT ? m->m_ext.ext_size :
	    ((m->m_flags & M_PKTHDR) ? MHLEN : MLEN);
	pkt->vp_len = m->m_len;
}

static int
fh_pkt_from_vm_tcp_mss_adj(struct vr_packet *pkt, unsigned short unu)
{
	struct tcphdr *tcph;
	struct vr_ip *iph;
	struct mbuf *m;
	int hlen, pull_len;

	KASSERT(pkt, ("NULL pkt"));

	m = vp_os_packet(pkt);
	KASSERT(m, ("NULL mbuf"));

	pull_len = pkt->vp_data + sizeof(struct vr_ip);
	if (pull_len > m->m_len)
		m = m_pullup(m, pull_len);

	iph = (struct vr_ip *)(mtod(m, char *) + pkt->vp_data);
	if (iph->ip_proto != VR_IP_PROTO_TCP)
		goto out;

	/*
	 * If this is a fragment and not the first one, it can be ignored
	 */
	if (iph->ip_frag_off & htons(IP_OFFMASK))
		goto out;

	hlen = iph->ip_hl * 4;
	pull_len += (hlen - sizeof(struct vr_ip));
	pull_len += sizeof(struct tcphdr);
	if (pull_len > m->m_len)
		m = m_pullup(m, pull_len);
	iph = (struct vr_ip *)(mtod(m, char *) + pkt->vp_data);
	tcph = (struct tcphdr *)(mtod(m, char *) + (pkt->vp_data + hlen));

	if ((tcph->th_off << 2) <= sizeof(struct tcphdr))
		goto out;

	pull_len += ((tcph->th_off << 2) - sizeof(struct tcphdr));
	if (pull_len > m->m_len)
		m = m_pullup(m, pull_len);
	iph = (struct vr_ip *)(mtod(m, char *) + pkt->vp_data);
	tcph = (struct tcphdr *)(mtod(m, char *) + (pkt->vp_data + hlen));

	fh_adjust_tcp_mss(tcph, m);

out:
	fh_reset_mbuf_fields(pkt);

	return (0);
}

struct host_os freebsd_host = {
	.hos_malloc			= fh_malloc,
	.hos_zalloc			= fh_zalloc,
	.hos_free			= fh_free,
	.hos_vtop			= fh_vtop,
	.hos_page_alloc			= fh_page_alloc,
	.hos_page_free			= fh_page_free,

	.hos_palloc			= fh_palloc,
	.hos_palloc_head		= fh_palloc_head,
	.hos_pexpand_head		= fh_pexpand_head,
	.hos_pfree			= fh_pfree,
	.hos_preset			= fh_preset,
	.hos_pclone			= fh_pclone,
	.hos_pcopy			= fh_pcopy,
	.hos_pfrag_len			= fh_pfrag_len,
	.hos_phead_len			= fh_phead_len,
	.hos_pset_data			= fh_pset_data,

	.hos_get_cpu			= fh_get_cpu,
	.hos_schedule_work		= fh_schedule_work,
	.hos_delay_op			= fh_delay_op,
	.hos_defer			= fh_defer,
	.hos_get_defer_data		= fh_get_defer_data,
	.hos_put_defer_data		= fh_set_defer_data,
	.hos_get_time			= fh_get_time,
	.hos_get_mono_time		= fh_get_mono_time,
	.hos_create_timer		= fh_create_timer,
	.hos_delete_timer		= fh_delete_timer,

	.hos_network_header		= fh_network_header,
	.hos_inner_network_header	= fh_inner_network_header,
	.hos_data_at_offset		= fh_data_at_offset,
	.hos_pheader_pointer		= fh_pheader_pointer,
	.hos_pull_inner_headers		= NULL, /* TODO(md): to implement */
	.hos_pcow			= fh_pcow,
	.hos_pull_inner_headers_fast	= NULL, /* TODO(md): to implement */
	.hos_get_udp_src_port		= fh_get_udp_src_port,
	.hos_pkt_from_vm_tcp_mss_adj	= fh_pkt_from_vm_tcp_mss_adj,
};

struct host_os *
vrouter_get_host(void)
{

	return (&freebsd_host);
}

static void
vr_message_exit(void)
{

	vr_transport_exit();
	vr_sandesh_exit();

	return;
}

static int
vr_message_init(void)
{
	int ret;

	ret = vr_sandesh_init();
	if (ret) {
		vr_log(VR_ERR, "sandesh init failed:%d\n", ret);
		return (ret);
	}

	ret = vr_transport_init();
	if (ret) {
		vr_log(VR_ERR, "sandesh init failed:%d\n", ret);
		vr_sandesh_exit();
		return (ret);
	}

	return (0);
}

static void
vrouter_freebsd_exit(void)
{
	vr_message_exit();
	vrouter_exit(false);
	vhost_exit();
	vr_mem_exit();
	contrail_socket_destroy();
}

static int
vrouter_freebsd_init(void)
{
	int ret;

	printf("vrouter version: %d\n", VROUTER_VERSIONID);

	vr_num_cpus = mp_ncpus & VR_CPU_MASK;
	if (!vr_num_cpus) {
		vr_log(VR_ERR, "Failed to get number of CPUs\n");
		ret = (-1);
		goto out0;
	}

	ret = contrail_socket_init();
	if (ret) {
		vr_log(VR_ERR, "contrail socket init failed:%d\n", ret);
		goto out0;
	}

	ret = vhost_init();
	if (ret) {
		vr_log(VR_ERR, "vhost init error:%d\n", ret);
		goto out1;
	}

	ret = vrouter_init();
	if (ret) {
		vr_log(VR_ERR, "vrouter initialization failed:%d\n", ret);
		goto out2;
	}

	ret = vr_mem_init();
	if (ret) {
		vr_log(VR_ERR, "flow device initialization failed:%d\n", ret);
		goto out3;
	}

	ret = vr_message_init();
	if (ret) {
		vr_log(VR_ERR, "message init error:%d\n", ret);
		goto out4;
	}

	return (0);

out4:
	vr_mem_exit();
out3:
	vrouter_exit(false);
out2:
	vhost_exit();
out1:
	contrail_socket_destroy();
out0:
	return (ret);

}

static int
vrouter_event_handler(struct module *module, int event, void *arg)
{
	int ret = 0;

	switch (event)
	{
	case MOD_LOAD:
		/* Make size of flow tables the same as linux defaults */
		vr_flow_entries = 4096;
		vr_oflow_entries = 512;

		ret = vrouter_freebsd_init();
		if (ret) {
			vr_log(VR_ERR, "vrouter load failed: %d\n", ret);
			return (ret);
		}
		break;
	case MOD_UNLOAD:
		vrouter_freebsd_exit();
		break;
	default:
		ret = EOPNOTSUPP;
		break;
	}

	return(ret);
}

static moduledata_t vrouter_mod = {
	"vrouter",
	vrouter_event_handler,
	NULL
};

DECLARE_MODULE(vrouter, vrouter_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
MODULE_VERSION(vrouter, VROUTER_VERSIONID);
