#ifndef __COMMON_TEST_H__
#define __COMMON_TEST_H__

#include "vr_types.h"

void get_random_bytes(void *buf, int nbytes);
uint32_t jhash(void *key, uint32_t length, uint32_t interval);

#endif /* __COMMON_TEST_H__ */
