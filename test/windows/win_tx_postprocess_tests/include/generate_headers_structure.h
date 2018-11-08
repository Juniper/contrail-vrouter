/*
 * generate_headers_structure.h
 *
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */

#ifndef HEADERS
    #error "Included generate_headers_structure.h without prior HEADERS definition."
#endif

#define HEADER(type,name) struct type name;
__attribute__packed__open__
struct PacketHeaders
{
    HEADERS
} __attribute__packed__close__;
#undef HEADER

static bool CheckIfHeadersEqual(struct PacketHeaders* headers, struct PacketHeaders* expectedHeaders)
{
    bool equal = TRUE;
    #define HEADER(type,name) \
        if(!(CheckIfHeaderEqualsFunctionName(type)(&headers->name, &expectedHeaders->name))) \
        { \
            print_error("Header name: "#name "\n"); \
            equal = FALSE; \
        }
    HEADERS
    #undef HEADER

    return equal;
}

static bool CheckHeadersAreValidDef(PWIN_SUB_PACKET subPacket, PHEADERFILLERFUNCTION filler, size_t dataSize)
{
    struct PacketHeaders *headers = (struct PacketHeaders*) Fake_WinSubPacketGetData(subPacket);
    struct PacketHeaders expectedheaders;
    (filler)(&expectedheaders, dataSize);

    return CheckIfHeadersEqual(headers, &expectedheaders);
}

static const size_t headersSize = sizeof(struct PacketHeaders);

extern PCHECKHEADERSAREVALIDFUNCTION CheckHeadersAreValid;

#undef HEADERS
