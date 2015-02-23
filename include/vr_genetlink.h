/*
 * vr_genetlink.h -- a place for all the common definitions required by the
 * generic netlink part
 *
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#ifndef __VR_GENETLINK_H__
#define __VR_GENETLINK_H__

#ifdef __cplusplus
extern "C" {
#endif

enum vnsw_nl_attrs {
    NL_ATTR_UNSPEC,
    NL_ATTR_VR_MESSAGE_PROTOCOL,
    NL_ATTR_MAX
};

#define SANDESH_REQUEST     1

#ifdef __cplusplus
}
#endif

#endif /* __VR_GENETLINK_H__ */
