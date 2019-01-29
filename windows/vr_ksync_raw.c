/* 
 * vr_ksync_raw.c
 *
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */
#include "vr_ksync_raw.h"
#include "vr_message.h"
#include "vr_genetlink.h"

inline PIRP PirpRawToPirp(PIRP_DOLL IrpRaw)
{
    return (PIRP) IrpRaw;
}

NTSTATUS
KSyncCompleteIrpRaw(PIRP_DOLL IrpRaw,
                    NTSTATUS Status,
                    ULONG Information)
{
    PIRP Irp = PirpRawToPirp(IrpRaw);
    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = Information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

PKSYNC_RESPONSE
KsyncResponseCreate()
{
    PKSYNC_RESPONSE resp;

    resp = ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(*resp),
                                 KsyncAllocationTag);
    if (resp != NULL) {
        RtlZeroMemory(resp, sizeof(*resp));
    }

    return resp;
}

VOID
KsyncAppendResponse(PKSYNC_DEVICE_CONTEXT ctx, PKSYNC_RESPONSE resp)
{
    PKSYNC_RESPONSE  elem;
    PKSYNC_RESPONSE *iter = &ctx->responses;

    while (*iter != NULL) {
        elem = *iter;
        iter = &(elem->next);
    }

    *iter = resp;
}

NTSTATUS
KsyncHandleWrite(PKSYNC_DEVICE_CONTEXT ctx,
                 uint8_t *buffer,
                 size_t buffer_size)
{
    struct vr_message request;
    struct vr_message *response;
    uint32_t multi_flag;
    int ret;

    /* Received buffer contains tightly packed Netlink headers, thus we can
       just increment appropriate headers */
    struct nlmsghdr   *nlh   = (struct nlmsghdr *)(buffer);
    struct genlmsghdr *genlh = (struct genlmsghdr *)(nlh + 1);
    struct nlattr     *nla   = (struct nlattr *)(genlh + 1);

    request.vr_message_buf = NLA_DATA(nla);
    request.vr_message_len = NLA_LEN(nla);

    ret = vr_message_request(&request);
    if (ret) {
        if (vr_send_response(ret)) {
            DbgPrint("%s: generating error response has failed\n", __func__);
            return STATUS_INVALID_PARAMETER;
        }
    }

    multi_flag = 0;
    while ((response = vr_message_dequeue_response())) {
        if (!multi_flag && !vr_response_queue_empty())
            multi_flag = NLM_F_MULTI;

        char *data = response->vr_message_buf - NETLINK_HEADER_LEN;
        size_t data_len = NLMSG_ALIGN(response->vr_message_len +
                                      NETLINK_HEADER_LEN);

        struct nlmsghdr *nlh_resp = (struct nlmsghdr *)(data);
        nlh_resp->nlmsg_len = data_len;
        nlh_resp->nlmsg_type = nlh->nlmsg_type;
        nlh_resp->nlmsg_flags = multi_flag;
        nlh_resp->nlmsg_seq = nlh->nlmsg_seq;
		nlh_resp->nlmsg_pid = 0;

        /* 'genlmsghdr' should be put directly after 'nlmsghdr', thus we can 
           just increment previous header pointer */
        struct genlmsghdr *genlh_resp = (struct genlmsghdr *)(nlh_resp + 1);
        RtlCopyMemory(genlh_resp, genlh, sizeof(*genlh_resp));

        /* 'nlattr' should be put directly after 'genlmsghdr', thus we can
           just increment previous header pointer */
        struct nlattr *nla_resp = (struct nlattr *)(genlh_resp + 1);
        nla_resp->nla_len = response->vr_message_len;
        nla_resp->nla_type = NL_ATTR_VR_MESSAGE_PROTOCOL;

        PKSYNC_RESPONSE ks_resp = KsyncResponseCreate();
        if (ks_resp != NULL) {
            ks_resp->message_len = data_len;
            RtlCopyMemory(ks_resp->buffer, data, ks_resp->message_len);
            KsyncAppendResponse(ctx, ks_resp);
        } else {
            DbgPrint("%s: ksync_response allocation failed\n", __func__);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        response->vr_message_buf = NULL;
        vr_message_free(response);
    }

    if (multi_flag) {
        PKSYNC_RESPONSE ks_resp = KsyncResponseCreate();
        if (ks_resp == NULL) {
            DbgPrint("%s: ksync_response allocation failed\n", __func__);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        struct nlmsghdr *nlh_done = (struct nlmsghdr *)ks_resp->buffer;
        nlh_done->nlmsg_len = NLMSG_HDRLEN;
        nlh_done->nlmsg_type = NLMSG_DONE;
        nlh_done->nlmsg_flags = 0;
        nlh_done->nlmsg_seq = nlh->nlmsg_seq;
        nlh_done->nlmsg_pid = 0;

        ks_resp->message_len = NLMSG_HDRLEN;

        KsyncAppendResponse(ctx, ks_resp);
    }

    return STATUS_SUCCESS;
}
