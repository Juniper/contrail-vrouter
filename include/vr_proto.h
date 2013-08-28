/*
 * vr_proto.h
 *
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#ifndef __VR_PROTO_H__
#define __VR_PROTO_H__

#ifdef __cplusplus
extern "C" {
#endif

extern int vrouter_init(void);
extern void vrouter_exit(bool);
#ifdef __KERNEL__
extern int vr_genetlink_init(void);
extern void vr_genetlink_exit(void);
extern int vr_mem_init(void);
extern void vr_mem_exit(void);
extern void vhost_exit(void);
#endif

#ifdef __cplusplus
}
#endif

#endif /* __VR_PROTO_H__ */
