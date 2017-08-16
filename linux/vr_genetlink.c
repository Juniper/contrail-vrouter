/*
 * vr_genetlink.c -- generic netlink stuff needed for vnsw
 *
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/rtnetlink.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <linux/version.h>

#include <net/genetlink.h>

#include "vr_genetlink.h"
#include "vr_types.h"
#include "vr_message.h"
#include "sandesh.h"
#include "vr_response.h"
#include "vrouter.h"

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0))
#define GENL_ID_GENERATE 0
#endif /* Linux 4.10.0 */
static int netlink_trans_request(struct sk_buff *, struct genl_info *);

static struct genl_ops vrouter_genl_ops[] = {
    {
        .cmd        =   SANDESH_REQUEST,
        .doit       =   netlink_trans_request,
        .flags      =   GENL_ADMIN_PERM,
    },
};

struct genl_family vrouter_genl_family = {
    .id         =   GENL_ID_GENERATE,
    .name       =   "vrouter",
    .version    =   1,
    .maxattr    =   NL_ATTR_MAX - 1,
    .netnsok    =   true,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0))
    .ops        =   vrouter_genl_ops,
    .n_ops      =   ARRAY_SIZE(vrouter_genl_ops),
#endif /* Linux 4.10.0 */
};

struct genl_multicast_group vrouter_genl_groups[] = {
  { .name = "VRouterGroup" },
};

#define NETLINK_RESPONSE_HEADER_LEN       (NLMSG_HDRLEN + GENL_HDRLEN + \
                                            NLA_HDRLEN)
#define NETLINK_BUFFER(skb_data)          ((char *)skb_data + \
                                            NETLINK_RESPONSE_HEADER_LEN) 
#define NETLINK_SKB(buf)                  *(struct sk_buff **)((char *)buf - \
                                            NETLINK_RESPONSE_HEADER_LEN) 

static char *
netlink_trans_alloc(unsigned int size)
{
    struct sk_buff *skb;
    int len;

    len = NETLINK_RESPONSE_HEADER_LEN;
    len += SKB_DATA_ALIGN(sizeof(struct skb_shared_info));

    skb = alloc_skb(size + len, GFP_ATOMIC);
    if (!skb)
        return NULL;

    /* Store the skb address at the beginning of the skb itself */
    *(struct sk_buff **)(skb->data) = skb;
    return skb->data + NETLINK_RESPONSE_HEADER_LEN;
}

static struct sk_buff *
netlink_skb(char *buf)
{
    return NETLINK_SKB(buf);
}

static void
netlink_trans_free(char *buf)
{
    struct sk_buff *skb;

    skb = netlink_skb(buf);
    kfree_skb(skb);

    return;
}

static int
netlink_trans_request(struct sk_buff *in_skb, struct genl_info *info)
{
    char *buf;
    int ret;
    unsigned int len;
    uint32_t multi_flag;
    struct nlmsghdr *rep, *nlh = info->nlhdr;
    struct genlmsghdr *genlh;
    struct nlattr **aap = info->attrs;
    struct nlattr *nla;
    struct vr_message request, *response;
    struct sk_buff *skb;
    uint32_t netlink_id;
    void *msg_head;

    if (!aap || !(nla = aap[NL_ATTR_VR_MESSAGE_PROTOCOL]))
        return -EINVAL;

    request.vr_message_buf = nla_data(nla);
    request.vr_message_len = nla_len(nla);

    ret = vr_message_request(&request);
    if (ret < 0) {
        if (vr_send_response(ret))
            return ret;
    }

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,7,0))
    netlink_id =  NETLINK_CB(in_skb).pid;
#else
    netlink_id =  NETLINK_CB(in_skb).portid;
#endif

    multi_flag = 0;
    while ((response = vr_message_dequeue_response())) {
        if (!response->vr_message_broadcast) {
            if ((multi_flag == 0) && (!vr_response_queue_empty()))
                multi_flag = NLM_F_MULTI;

            buf = response->vr_message_buf;
            skb = netlink_skb(buf);
            if (!skb)
                goto next;

            len = response->vr_message_len;
            len += GENL_HDRLEN + NLA_HDRLEN;
            len = NLMSG_ALIGN(len);
            rep = __nlmsg_put(skb, netlink_id, nlh->nlmsg_seq,
                            nlh->nlmsg_type, len, multi_flag);
            genlh = nlmsg_data(rep);
            memcpy(genlh, info->genlhdr, sizeof(*genlh));

            nla = (struct nlattr *)((char *)genlh + GENL_HDRLEN);
            nla->nla_len = response->vr_message_len;
            nla->nla_type = NL_ATTR_VR_MESSAGE_PROTOCOL;

            netlink_unicast(in_skb->sk, skb, netlink_id, MSG_DONTWAIT);
        } else {
            // If there is no listener, we don't broadcast
            if (!netlink_has_listeners(in_skb->sk, vrouter_genl_family.mcgrp_offset)) {
                goto next;
            }

            skb = genlmsg_new(nla->nla_len, GFP_KERNEL);
            if (!skb)
                goto next;
            msg_head = genlmsg_put(skb, 0, 0, &vrouter_genl_family, 0, SANDESH_REQUEST);
            if (!msg_head) {
                nlmsg_free(skb);
                goto next;
            }
            if (nla_put(skb, NL_ATTR_VR_MESSAGE_PROTOCOL, response->vr_message_len, response->vr_message_buf) < 0) {
                nlmsg_free(skb);
                goto next;
            }
            genlmsg_end(skb, msg_head);

            genlmsg_multicast(&vrouter_genl_family, skb, 0, 0, GFP_KERNEL);
        }
next:
        response->vr_message_buf = NULL;
        vr_message_free(response);
    }

    if (multi_flag) {
        skb = alloc_skb(NLMSG_HDRLEN, GFP_ATOMIC);
        if (!skb)
            return 0;

        __nlmsg_put(skb, netlink_id, nlh->nlmsg_seq, NLMSG_DONE, 0, 0);
        netlink_unicast(in_skb->sk, skb, netlink_id, MSG_DONTWAIT);
    }


    return 0;
}

static struct vr_mtransport netlink_transport = {
    .mtrans_alloc              =       netlink_trans_alloc,
    .mtrans_free               =       netlink_trans_free,
};


void
vr_genetlink_exit(void)
{
    genl_unregister_family(&vrouter_genl_family);
    vr_message_transport_unregister(&netlink_transport);
    return;
}

int
vr_genetlink_init(void)
{
    int ret;

    ret = vr_message_transport_register(&netlink_transport);
    if (ret)
        return ret;

#if ((LINUX_VERSION_CODE < KERNEL_VERSION(3,13,0)) && \
     (!(defined(RHEL_MAJOR) && (RHEL_MAJOR >= 7))))
    return genl_register_family_with_ops(&vrouter_genl_family, vrouter_genl_ops,
        ARRAY_SIZE(vrouter_genl_ops));
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0))
    return genl_register_family(&vrouter_genl_family);
#else
    return genl_register_family_with_ops_groups(&vrouter_genl_family,
             vrouter_genl_ops, vrouter_genl_groups);
#endif
}
