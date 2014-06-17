#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <malloc.h>
#include <stdbool.h>
#include <getopt.h>

#include <asm/types.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <asm/types.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_ether.h>

#include <net/if.h>
#include <netinet/ether.h>

#include "vr_types.h"
#include "vr_message.h"
#include "vr_nexthop.h"
#include "vr_genetlink.h"
#include "nl_util.h"

static struct nl_client *cl;


int main()
{
	int ret;
	int opt;
	int ind;
	int  error, attr_len;
	struct nl_response *resp;

	cl = nl_register_client();
	if (!cl) {
		exit(1);
	}

	ret = nl_socket(cl, NETLINK_GENERIC);
	if (ret <= 0) {
		exit(1);
	}

	if (vrouter_get_family_id(cl) <= 0) {
		return 0;
	}

	ret = nl_build_nlh(cl, cl->cl_genl_family_id, NLM_F_REQUEST);
	if (ret) {
		return ret;
	}

	/* Generic nlmsg header */
	ret = nl_build_genlh(cl, SANDESH_REQUEST, 0);
	if (ret) {
		return ret;
	}

	attr_len = nl_get_attr_hdr_size();
	vrouter_ops vops;
	vops.h_op=SANDESH_OP_RESET;
	error = 0;
	ret = sandesh_encode(&vops, "vrouter_ops", vr_find_sandesh_info,
			(nl_get_buf_ptr(cl) + attr_len),
			(nl_get_buf_len(cl) - attr_len), &error);

	if ((ret <= 0) || error) {
		return ret;
	}

	/* Add sandesh attribute */
	nl_build_attr(cl, ret, NL_ATTR_VR_MESSAGE_PROTOCOL);
	nl_update_nlh(cl);

	/* Send the request to kernel */
	ret = nl_sendmsg(cl);
	while ((ret = nl_recvmsg(cl)) > 0) {
		resp = nl_parse_reply(cl);
		if (resp->nl_op == SANDESH_REQUEST) {
			sandesh_decode(resp->nl_data, resp->nl_len, vr_find_sandesh_info, &ret);
		}
	}

	return 0;
}
