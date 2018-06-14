/*
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */

#pragma once

extern void mock_assert(const int result, const char* const expression,
                        const char * const file, const int line);

#define ASSERT(expression) \
    mock_assert((int)(expression), #expression, __FILE__, __LINE__)
#define ASSERTMSG(_Msg, _Expr) ASSERT((_Expr) && (_Msg))
#define assert ASSERT
