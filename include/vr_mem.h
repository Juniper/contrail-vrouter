/*
 * vr_mem.h -- table map definitions
 *
 * Copyright(c) 2016, Juniper Networks, Inc.
 * All rights reserved
 */
#ifndef __VR_MEM_H__
#define	__VR_MEM_H__

#ifdef __cplusplus
extern "C" {
#endif


#define VR_MEM_FLOW_TABLE_OBJECT    0
#define VR_MEM_BRIDGE_TABLE_OBJECT  1
#define VR_MEM_MAX_OBJECT           2

struct vr_mem_object {
    struct vrouter *vmo_router;
    unsigned int vmo_object_type;
};

#define MEM_DEV_MINOR_START         0
#define MEM_DEV_NUM_DEVS            2

#define ROUTER_FROM_MINOR(minor)    (((minor) >> 7) & 0xFF)
#define OBJECT_FROM_MINOR(minor)    ((minor) & 0x7F)


#define VR_MAX_HUGE_PAGES   4
#define VR_MEM_1G           (1024 * 1024 * 1024)
#define VR_MEM_2M           (2 * 1024 * 1024)

void vr_huge_pages_exit(void);
int vr_huge_pages_init(void);
int vr_huge_pages_config(uint64_t *, int, int*);
void *vr_huge_mem_get(int);


#ifdef __cplusplus
}
#endif

#endif /* __VR_MEM_H__ */
