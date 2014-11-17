#include "vr_types.h"

void
get_random_bytes(void *buf, int nbytes)
{
}

uint32_t
jhash(void *key, uint32_t length, uint32_t interval)
{
    uint32_t ret;
    int i;
    unsigned char *data = (unsigned char *)key;

    for (i = 0; i < length; i ++)
        ret +=  data[i];

    return ret;
}

