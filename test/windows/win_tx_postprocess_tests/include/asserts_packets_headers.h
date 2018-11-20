/*
 * asserts_packets_headers.h
 *
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */
#ifndef _WIN_TX_HEADERS_ASSERTIONS_H_
#define _WIN_TX_HEADERS_ASSERTIONS_H_

#include <win_packet.h>
#include <common.h>

#define CONCAT_INSIDE(A,B) A ## B
#define CONCAT(A,B) CONCAT_INSIDE(A,B)

#define PrintErrorInField(HeaderType, FieldName) \
    print_error("In "#HeaderType" header, field "#FieldName" " \
    LargestIntegralTypePrintfFormat " != " LargestIntegralTypePrintfFormat "\n", \
    cast_to_largest_integral_type(headers->FieldName), cast_to_largest_integral_type(expectedHeaders->FieldName))

#define CheckIfHeaderFieldEquals(HeaderType, FieldName) \
    if(headers->FieldName != expectedHeaders->FieldName) \
    { \
        PrintErrorInField(HeaderType, FieldName); \
        equal = FALSE; \
    }

#define CheckIfHeaderEqualsFunctionName(HeaderType) \
    CONCAT(CONCAT(CheckIf_,HeaderType),_HeaderEquals)

#define CheckIfHeaderEqualsFunctionDeclaration(HeaderType) \
    bool CheckIfHeaderEqualsFunctionName(HeaderType)(struct HeaderType *headers, struct HeaderType *expectedHeaders)

#define CheckIfHeaderEqualsFunctionDefinition \
    CheckIfHeaderEqualsFunctionDeclaration(HEADER_TYPE) \
    { \
        bool equal = TRUE; \
        HEADER_FIELDS  \
        return equal;\
    }

#define FIELD(x) CheckIfHeaderFieldEquals(HEADER_TYPE, x);

// TODO MOVE IT SOMEWHERE!!!
__attribute__packed__open__
struct vr_mpls {
    uint32_t data;
} __attribute__packed__close__;

void AssertHeadersAreValid(PWIN_MULTI_PACKET Segments, PHEADERFILLERFUNCTION fillers[], size_t dataSize);

#endif // _WIN_TX_HEADERS_ASSERTIONS_H_
