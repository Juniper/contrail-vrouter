/*
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */

#pragma once

#include <windows.h>
#include <subauth.h>

typedef struct _ANSI_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PCHAR  Buffer;
} ANSI_STRING, *PANSI_STRING;

#define DECLARE_CONST_UNICODE_STRING(_var, _string) \
const WCHAR _var ## _buffer[] = _string; \
__pragma(warning(push)) \
__pragma(warning(disable:4221)) __pragma(warning(disable:4204)) \
const UNICODE_STRING _var = { sizeof(_string) - sizeof(WCHAR), sizeof(_string), (PWCH) _var ## _buffer } \
__pragma(warning(pop))

typedef const UNICODE_STRING *PCUNICODE_STRING;
