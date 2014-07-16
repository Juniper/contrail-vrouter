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
#include <sys/mbuf.h>
#include <sys/socket.h>

#include <vm/uma.h>
#include <vm/vm.h>
#include <vm/vm_extern.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/if_media.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <net/ethernet.h>
#include <machine/in_cksum.h>

#include "vr_freebsd.h"
#include "vr_packet.h"
#include "vr_interface.h"

#define OUTER_HEADER (VR_MPLS_HDR_LEN + sizeof(struct vr_ip) + sizeof(struct vr_gre))

/* UMA zone for vr_packet */
uma_zone_t zone_vr_packet;

void vr_host_vif_init(struct vrouter *);
void vr_host_interface_exit(void);
struct vr_host_interface_ops *vr_host_interface_init(void);

struct vr_packet *
freebsd_get_packet(struct mbuf *m, struct vr_interface *vif)
{
	struct vr_packet_wrapper *wrapper;
	struct vr_packet *pkt;
	uint32_t bufsize;

	wrapper = uma_zalloc(zone_vr_packet, M_NOWAIT | M_ZERO);
	if (!wrapper) {
		vr_log(VR_ERR, "cannot alloc wrapper");
		return (NULL);
	}

	wrapper->vrw_m = m;
	pkt = &wrapper->vrw_pkt;

	pkt->vp_cpu = vr_get_cpu();
	pkt->vp_head = (unsigned char *)
	    (m->m_flags & M_EXT ? m->m_ext.ext_buf :
	     m->m_flags & M_PKTHDR ? m->m_pktdat : m->m_dat);

	if (M_TRAILINGSPACE(m) >= (1 << (sizeof(pkt->vp_tail) * 8)))
		goto drop;
	pkt->vp_tail = M_LEADINGSPACE(m) + m->m_len;

	pkt->vp_data = M_LEADINGSPACE(m);

	bufsize = m->m_flags & M_EXT ? m->m_ext.ext_size :
	    ((m->m_flags & M_PKTHDR) ? MHLEN : MLEN);
	if (bufsize >= (1 << (sizeof(pkt->vp_end) * 8)))
		goto drop;
	pkt->vp_end = bufsize;

	if (m->m_len >= (1 << (sizeof(pkt->vp_len) * 8)))
		goto drop;
	pkt->vp_len = m->m_len;

	pkt->vp_if = vif;
	pkt->vp_network_h = pkt->vp_inner_network_h = 0;
	pkt->vp_nh = 0;

	pkt->vp_type = VP_TYPE_NULL;

	return (pkt);
drop:
	uma_zfree(zone_vr_packet, wrapper);
	return (NULL);
}

int
freebsd_to_vr(struct vr_interface *vif, struct mbuf* m)
{
	struct vr_packet *pkt;
	int ret;

	pkt = freebsd_get_packet(m, vif);
	if (!pkt) {
		vr_log(VR_ERR, "Cannot create packet\n");
		return (1);
	}

	ret = vif->vif_rx(vif, pkt, VLAN_ID_INVALID);
	if (ret) {
		vr_log(VR_ERR, "vif_rx failed, ret:%d\n", ret);
		uma_zfree(zone_vr_packet, pkt);
		return (2);
	}

	return (0);
}

static void
freebsd_rx_handler(struct ifnet *ifp, struct mbuf *m)
{
	struct vr_interface *vif;
	struct vr_packet *pkt;
	int ret;

	KASSERT((ifp && m), ("Null arguments: ifp:%p m:%p\n", ifp, m));

	vif = ifp->if_pspare[1];
	KASSERT(vif, ("Null vif pointer in ifp:%p\n", ifp));

	pkt = freebsd_get_packet(m, vif);
	if (!pkt) {
		vr_log(VR_ERR, "Cannot create packet\n");
		return;
	}

	/* Pass packet to virtual interface. */
	ret = vif->vif_rx(vif, pkt, VLAN_ID_INVALID);
	if (ret) {
		vr_log(VR_ERR, "vif_rx failed, ret:%d\n", ret);
		uma_zfree(zone_vr_packet, pkt);
		m_freem(m);
	}
}

static int
freebsd_if_add(struct vr_interface *vif)
{
	struct ifnet *ifp;

	if (vif->vif_os_idx) {
		ifp = ifnet_byindex_ref(vif->vif_os_idx);
		KASSERT(ifp, ("Can't find ifnet at idx:%d", vif->vif_os_idx));

		vif->vif_os = (void *)ifp;
		ifp->if_pspare[1] = (void *)vif;
	}

	/* In case of vhost dev, let it know which vif is for it */
	if (vif_is_vhost(vif))
		vhost_if_add(vif);

	return (0);
}

static int
freebsd_if_del(struct vr_interface *vif)
{

	KASSERT(vif, ("NULL vif"));
	if (vif_is_vhost(vif))
		vhost_if_del((struct ifnet *)vif->vif_os);

	if (vif->vif_os)
		if_rele((struct ifnet *)vif->vif_os);

	vif->vif_os = NULL;
	vif->vif_os_idx = 0;

	return (0);
}

static int
freebsd_if_add_tap(struct vr_interface *vif)
{
	struct ifnet *ifp;

	KASSERT(vif, ("NULL vif"));

	ifp = (struct ifnet *)vif->vif_os;
	KASSERT(ifp, ("NULL ifp in vif:%p", vif));

	/* Replace input routine */
	vif->saved_if_input = ifp->if_input;
	ifp->if_input = freebsd_rx_handler;

	return (0);
}

static int
freebsd_if_del_tap(struct vr_interface *vif)
{
	struct ifnet *ifp;

	KASSERT(vif, ("NULL vif"));

	ifp = (struct ifnet *)vif->vif_os;
	KASSERT(ifp, ("NULL ifp in vif:%p", vif));

	/* Restore original input routine */
	ifp->if_input = vif->saved_if_input;
	vif->saved_if_input = NULL;

	return (0);
}

static int
freebsd_if_tx(struct vr_interface *vif, struct vr_packet *pkt)
{
	struct ifnet *ifp;
	struct mbuf *m, *m0;
	struct ether_header *eh;
	struct ip *ip;
	char *hdr;
	int ip_off;
	int ret = 0;
	char header[OUTER_HEADER + sizeof(struct vr_eth)];
	unsigned short len, type;

	KASSERT((vif && pkt), ("Null argument: vif:%p pkt:%p\n", vif, pkt));

	ifp = (struct ifnet *)vif->vif_os;
	KASSERT(ifp, ("NULL ifp in vif:%p", vif));

	/* Fetch original mbuf from packet structure */
	m = vp_os_packet(pkt);

	/* Trim mbuf if vp_data is not at the beginning */
	if (pkt->vp_data != M_LEADINGSPACE(m))
		m_adj(m, pkt->vp_data - M_LEADINGSPACE(m));

	eh = mtod(m, struct ether_header *);
	type = ntohs(eh->ether_type);
	ip_off = sizeof (struct ether_header);
	if (m->m_len < ip_off + sizeof(struct ip))
		m = m_pullup(m, ip_off + sizeof(struct ip));
	ip = (struct ip *) (mtod(m, char *) + ip_off);
	if (ip->ip_p == VR_IP_PROTO_GRE) {
		ip->ip_sum = 0;
		ip->ip_sum = in_cksum_hdr(ip);
	}

	if ((type == ETHERTYPE_IP) && ntohs(ip->ip_len) > ifp->if_mtu) {
		/* First save outer header: eth + ip + gre/mpls XXX save as mbuf?*/
		hdr = mtod(m, char *);
		m_copydata(m, 0, OUTER_HEADER + sizeof(struct vr_eth), (caddr_t) header);
		/* Get rid of outer header */
		m_adj(m, OUTER_HEADER + sizeof(struct vr_eth));

		/* Go into inner ip header */
		ip = (struct ip *) (mtod(m, char *));
		/* Clear DONT FRAGMENT */
		ip->ip_off = 0;

		ret = ip_fragment(ip, &m, ifp->if_mtu - OUTER_HEADER, ifp->if_hwassist);
		for (; m; m = m0) {
			m0 = m->m_nextpkt;
			m_clrprotoflags(m);

			/* Modify innef header checksum */
			ip = (struct ip *) (mtod(m, char *));
			ip->ip_sum = 0;
			ip->ip_sum = in_cksum_hdr(ip);

			/* Add outer header */
			len = ntohs(ip->ip_len);
			M_PREPEND(m, OUTER_HEADER + sizeof(struct vr_eth), M_NOWAIT);
			bcopy(header, mtod(m, caddr_t), OUTER_HEADER + sizeof(struct vr_eth));

			/* Update outer header checksum */
			ip = (struct ip *) (mtod(m, char *) + sizeof(struct vr_eth));
			ip->ip_len = htons(len + OUTER_HEADER);
			ip->ip_sum = 0;
			ip->ip_sum = in_cksum_hdr(ip);
		}
	}

	/* Pass mbuf to driver for sending */
	ret = ifp->if_transmit(ifp, m);
	if (ret)
		vr_log(VR_ERR, "if_transmit failed, ret:%d\n", ret);


	/* Free packet */
	uma_zfree(zone_vr_packet, pkt);

	return (ret);
}

static int
freebsd_if_rx(struct vr_interface *vif, struct vr_packet *pkt)
{
	struct ifnet *ifp;
	struct mbuf *m, *mn;

	KASSERT((vif && pkt), ("Null argument: vif:%p pkt:%p\n", vif, pkt));

	ifp = (struct ifnet *)vif->vif_os;
	KASSERT(ifp, ("NULL ifp in vif:%p", vif));

	/* Fetch original mbuf from packet structure */
	m = vp_os_packet(pkt);

	/* Pass mbuf to network stack using original routine */
	mn = m;
	while (mn) {
		mn->m_pkthdr.rcvif = ifp;
		mn = mn->m_nextpkt;
	}

	ifp->if_input(ifp, m);

	/* Free packet */
	uma_zfree(zone_vr_packet, pkt);

	return (0);
}

static int
freebsd_if_get_settings(struct vr_interface *vif,
    struct vr_interface_settings *settings)
{

	/* TODO This one needs to be implemented eventually */
	return (-1);
}

struct vr_host_interface_ops vr_freebsd_interface_ops = {
	.hif_add		= freebsd_if_add,
	.hif_del		= freebsd_if_del,
	.hif_add_tap		= freebsd_if_add_tap,
	.hif_del_tap		= freebsd_if_del_tap,
	.hif_tx			= freebsd_if_tx,
	.hif_rx			= freebsd_if_rx,
	.hif_get_settings	= freebsd_if_get_settings,
};

void
vr_host_vif_init(struct vrouter *router)
{
    return;
}

void
vr_host_interface_exit(void)
{

	uma_zdestroy(zone_vr_packet);

	return;
}

struct vr_host_interface_ops *
vr_host_interface_init(void)
{
	zone_vr_packet = uma_zcreate("vrouter",
	    sizeof(struct vr_packet_wrapper), NULL, NULL, NULL, NULL,
		    0, 0);
	if (!zone_vr_packet) {
		vr_log(VR_ERR, "cannot create zone\n");
		return (NULL);
	}

	return (&vr_freebsd_interface_ops);
}
