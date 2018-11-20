/*
 * payload_generators.h
 *
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */
#ifndef _WIN_TX_PAYLOAD_GENERATORS_H_
#define _WIN_TX_PAYLOAD_GENERATORS_H_

#include <stdint.h>

void GenerateAZPayload(uint8_t* buffer, size_t payloadSize);

void GenerateEmptyPayload(uint8_t* buffer, size_t payloadSize);

#endif // _WIN_TX_PAYLOAD_GENERATORS_H_
