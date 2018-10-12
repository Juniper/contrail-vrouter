/*
 * win_assert.h
 *
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */
#ifndef _WIN_ASSERT_H_
#define _WIN_ASSERT_H_

#ifdef __KERNEL__
#include <ntddk.h>
#define WinAssert(expression) ASSERT(expression)
#define WinAssertMsg(msg, expression) ASSERTMSG(msg, expression)
#else
extern void mock_assert(const int result, const char* const expression,
                        const char * const file, const int line);

#define WinAssert(expression) \
    mock_assert((int)(expression), #expression, __FILE__, __LINE__);
#define WinAssertMsg(msg, expression) \
    mock_assert((int)(expression), msg, __FILE__, __LINE__);
#endif

#endif // _WIN_ASSERT_H_
