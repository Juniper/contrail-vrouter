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
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/mbuf.h>
#include <sys/socketvar.h>

#include "vr_freebsd.h"
#include "vr_message.h"
#include "vr_genetlink.h"
#include "vr_os.h"

#define NETLINK_HEADER_LEN	(NLMSG_HDRLEN + GENL_HDRLEN + NLA_HDRLEN)

static char *
bsd_trans_alloc(unsigned int size)
{
	char *buf;

	/* Netlink requires buffers to be aligned/padded to NLMSG_ALINGTO
	 * bytes, even if it will actually use less bytes than aligned
	 * buffer offers.
	 */
	buf = malloc(NLMSG_ALIGN(size) + NETLINK_HEADER_LEN, M_VROUTER, M_NOWAIT|M_ZERO);
	if (!buf)
		return (NULL);
	return (buf + NETLINK_HEADER_LEN);
}

static void
bsd_trans_free(char *buf)
{

	KASSERT((buf != NULL), ("Cannot free NULLed buf"));
	free(buf - NETLINK_HEADER_LEN, M_VROUTER);
}

static int
bsd_trans_ext_free(struct mbuf *m, void *arg1, void* arg2)
{
	char *buf = (char *)arg1;

	KASSERT((buf != NULL), ("Cannot free NULLed buf"));
	free(buf - NETLINK_HEADER_LEN, M_VROUTER);

    return 0;
}

static struct vr_mtransport bsd_transport = {
	.mtrans_alloc	=	bsd_trans_alloc,
	.mtrans_free	=	bsd_trans_free,
};

int
vr_transport_request(struct socket *so, char *buf, size_t len)
{
	struct vr_message request, *resp;
	struct mbuf *m;
	struct nlmsghdr *req_nlh, *resp_nlh;
	struct genlmsghdr *req_genlh, *resp_genlh;
	struct nlattr *nla;
	caddr_t data;
	uint32_t multi_flag;
	int ret;

	request.vr_message_buf = buf + NETLINK_HEADER_LEN;
	request.vr_message_len = len - NETLINK_HEADER_LEN;

	ret = vr_message_request(&request);
	if (ret)
		vr_log(VR_ERR, "Message request failed, ret:%d\n", ret);

	multi_flag = 0;
	while ((resp = vr_message_dequeue_response())) {
		if (!multi_flag && !vr_response_queue_empty())
			multi_flag = NLM_F_MULTI;

		MGETHDR(m, M_NOWAIT, MT_DATA);
		if (m == NULL) {
			vr_log(VR_ERR, "Cannot create mbuf\n");
			vr_message_free(resp);
			return (1);
		}
		data = (caddr_t)resp->vr_message_buf - NETLINK_HEADER_LEN;
		m->m_data = data;
		m->m_pkthdr.len = m->m_len =
		    NLA_ALIGN(resp->vr_message_len) + NETLINK_HEADER_LEN;
		MEXTADD(m, data,
		    NLA_ALIGN(resp->vr_message_len) + NETLINK_HEADER_LEN,
		    bsd_trans_ext_free, resp->vr_message_buf,
		    NULL, 0, EXT_NET_DRV);
		m->m_flags |= M_EOR;

		len = NLMSG_ALIGN(resp->vr_message_len + NETLINK_HEADER_LEN);

		resp_nlh = mtod(m, struct nlmsghdr *);
		req_nlh = (struct nlmsghdr *)buf;
		resp_nlh->nlmsg_len = len;
		resp_nlh->nlmsg_type = req_nlh->nlmsg_type;
		resp_nlh->nlmsg_flags = multi_flag;
		resp_nlh->nlmsg_seq = req_nlh->nlmsg_seq;
		resp_nlh->nlmsg_pid = 0;

		resp_genlh = (struct genlmsghdr *)(mtod(m, char *) + NLMSG_HDRLEN);
		req_genlh = (struct genlmsghdr *)(buf + NLMSG_HDRLEN);
		memcpy(resp_genlh, req_genlh, GENL_HDRLEN);

		nla = (struct nlattr *)(mtod(m, char *) + (NLMSG_HDRLEN + GENL_HDRLEN));
		nla->nla_len = resp->vr_message_len;
		nla->nla_type = NL_ATTR_VR_MESSAGE_PROTOCOL;

		/* Enqueue mbuf in socket's receive sockbuf */
		sbappend(&so->so_rcv, m);
		sorwakeup(so);

		/* Free buffer and response */
		resp->vr_message_buf = NULL;
		vr_message_free(resp);
	}

	if (multi_flag) {
		m = m_gethdr(M_NOWAIT, MT_DATA);

		if (!m) {
			vr_log(VR_ERR, "Cannot create mbuf of len %d\n",
			    NLMSG_HDRLEN);
			return (2);
		}
		m->m_pkthdr.len = NLMSG_HDRLEN;
		m->m_len = NLMSG_HDRLEN;
		m->m_flags |= M_EOR;

		resp_nlh = mtod(m, struct nlmsghdr *);
		req_nlh = (struct nlmsghdr *)buf;
		resp_nlh->nlmsg_len = NLMSG_HDRLEN;
		resp_nlh->nlmsg_type = NLMSG_DONE;
		resp_nlh->nlmsg_flags = 0;
		resp_nlh->nlmsg_seq = req_nlh->nlmsg_seq;
		resp_nlh->nlmsg_pid = 0;

		/* Enqueue mbuf in socket's receive sockbuf */
		sbappend(&so->so_rcv, m);
		sorwakeup(so);
	}

	return (0);
}

void
vr_transport_exit(void)
{

	vr_message_transport_unregister(&bsd_transport);
}

int
vr_transport_init(void)
{
	int ret;

	ret = vr_message_transport_register(&bsd_transport);
	if (ret) {
		vr_log(VR_ERR, "trasport registration failed:%d\n", ret);
		return (ret);
	}

	return (0);
}
