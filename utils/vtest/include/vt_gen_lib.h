/*
 * gen_lib.h --
 *
 * Copyright (c) 2015, Juniper Networks, Inc.
 * All rights reserved
 */

#ifndef __GEN_LIB_H__
#define __GEN_LIB_H__

enum gen_types {
    GEN_TYPE_U8,
    GEN_TYPE_U16,
    GEN_TYPE_U32,
    GEN_TYPE_U64,
};

unsigned char *vt_gen_skip_space(unsigned char *);
unsigned char *vt_gen_reach_char(unsigned char *, unsigned char);
unsigned char *vt_gen_reach_space(unsigned char *);
bool vt_gen_byte_compare(uint8_t, uint8_t);
bool vt_gen_short_compare(uint16_t, uint16_t);
bool vt_gen_int_compare(unsigned int, unsigned int);
bool vt_gen_int64_compare(uint64_t, uint64_t);
bool vt_gen_flow_op_compare(int, unsigned char *);
int vt_gen_flow_op(unsigned char *);
bool vt_gen_op_compare(int, unsigned char *);
int vt_gen_op(unsigned char *);
void *vt_gen_list(unsigned char *, unsigned int, unsigned int *);
bool vt_gen_list_compare(void *, unsigned int, unsigned char *, unsigned int);
void *vt_gen_string(char *);

#endif /* __GEN_LIB_H__ */
