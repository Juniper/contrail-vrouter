/*
 * vtest.h --
 *
 * Copyright (c) 2015, Juniper Networks, Inc.
 * All rights reserved
 */
#ifndef __VTEST_H__
#define __VTEST_H__

#define VT_PROG_NAME                "vtest"
#define VT_MAX_TEST_NAME_LEN        128
#define VT_MAX_TEST_MODULE_NAME_LEN 128

struct vtest {
    int vtest_return;
    int vtest_iteration;
    bool vtest_break;
    unsigned char *vtest_name;
    unsigned char *vtest_error_module;
};
    
struct vtest_module {
    unsigned char *vt_name;
    int (*vt_node)(xmlNodePtr, struct vtest *);
    int (*vt_init)(void);
};

extern int vt_message(xmlNodePtr, struct vtest *);

#endif /* __VTEST_H__ */
