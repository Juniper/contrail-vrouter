/*
 * vr_test.h -- stuff needed for vr test
 *
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#ifndef __VR_TEST_H__
#define __VR_TEST_H__

#define VR_TEST_MARK_FAILED \
    ((failed = true) && (line = __LINE__))

extern int vr_test_errno;

extern int vr_test_log(const char *, ...);
extern int vr_test_log_OK(int);
extern int vr_test_log_FAILED(int);

extern int vr_test_nh_encap_create(int);
extern int vr_test_nh_destroy(int);
extern vr_nexthop_req *vr_nh_test_init(void);
extern void vr_nh_test_cleanup(void);

extern int tif_init(void);
extern void tif_cleanup(void);
extern int tif_create(unsigned int);
extern int tif_delete(unsigned int);

#endif /* __VR_TEST_H__ */
