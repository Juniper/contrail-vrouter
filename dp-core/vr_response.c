/*
 * vr_response.c --
 *
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */

#include "vr_sandesh.h"
#include "vr_os.h"
#include "vr_types.h"

int vr_generate_response(vr_response *, int code, unsigned char *, int);

void
vr_response_process(void *s_req)
{
}

int
vr_generate_response(vr_response *resp, int code, unsigned char *buf,
        int buf_len)
{
    int ret;
    int error;

    resp->h_op = SANDESH_OP_RESPONSE;
    resp->resp_code = code;

    ret = sandesh_encode(resp, "vr_response", vr_find_sandesh_info,
                    buf, buf_len, &error);
    return ret;
}

