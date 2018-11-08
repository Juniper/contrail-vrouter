#include "include/payload_generators.h"

#include <stdio.h>

void
GenerateAZPayload(uint8_t* buffer, size_t payloadSize)
{
    char x = 'a';
    for(unsigned int i = 0; i < payloadSize; i++)
    {
        buffer[i] = x;
        x++;
        if(x == ('a'+26)) x = 'a';
    }
}

void
GenerateEmptyPayload(uint8_t* buffer, size_t payloadSize)
{
    memset(buffer, 0, payloadSize);
}
