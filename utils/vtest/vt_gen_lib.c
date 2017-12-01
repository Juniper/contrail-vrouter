/*
 * vt_gen_lib.c --
 *
 * Copyright(c) 2015, Juniper Networks, Inc.
 * All rights reserved
 */
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <ctype.h>
#include <strings.h>

#include <vr_types.h>
#include <vt_gen_lib.h>

unsigned char *
vt_gen_skip_space(unsigned char *string)
{
    unsigned int i = 0, len;

    if (!string)
        return string;

    len = strlen(string);
    if (!len)
        return string;

    while ((i < len) && isspace(string[i])) {
        i++;
    }

    if (i == len)
        return NULL;

    return &string[i];
}

unsigned char *
vt_gen_skip_char(unsigned char *string, unsigned char c)
{
    unsigned int i = 0, len;

    if (!string)
        return string;

    len = strlen(string);
    if (!len)
        return string;

    while ((i < len) && string[i] == c) {
        i++;
    }

    if (i == len)
        return NULL;

    return &string[i];
}

unsigned char *
vt_gen_reach_char(unsigned char *string, unsigned char c)
{
    unsigned int i = 0, len;

    if (!string)
        return string;

    len = strlen(string);
    if (!len)
        return string;

    while ((i < len) && (string[i] != c)) {
        i++;
    }

    return &string[i];
}

unsigned char *
vt_gen_reach_space(unsigned char *string)
{
    return vt_gen_reach_char(string, ' ');
}

bool
vt_gen_byte_compare(uint8_t one, uint8_t two)
{
    return one == two;
}

bool
vt_gen_short_compare(uint16_t one, uint16_t two)
{
    return one == two;
}

bool
vt_gen_int_compare(unsigned int one, unsigned int two)
{
    return one == two;
}

bool
vt_gen_int64_compare(uint64_t one, uint64_t two)
{
    return one == two;
}

bool
vt_gen_flow_op_compare(int op, unsigned char *string)
{
    int expected_op = 0;

    if (!string)
        return -1;

    if (!strncasecmp(string, "flow_set", strlen("flow_set"))) {
        expected_op = FLOW_OP_FLOW_SET;
    } else if (!strncasecmp(string, "flow_table_get",
                strlen("flow_table_get"))) {
        expected_op = FLOW_OP_FLOW_TABLE_GET;
    }

    return op == expected_op;
}

int
vt_gen_flow_op(unsigned char *string)
{
    if (!string)
        return -1;

    if (!strncasecmp(string, "flow_set", strlen("flow_set"))) {
        return FLOW_OP_FLOW_SET;
    } else if (!strncasecmp(string, "flow_table_get",
                strlen("flow_table_get"))) {
        return FLOW_OP_FLOW_TABLE_GET;
    }

    return -1;
}

bool
vt_gen_op_compare(int op, unsigned char *string)
{
    int expected_op = 0;

    if (!strncasecmp(string, "Add", strlen("Add"))) {
        expected_op = SANDESH_OP_ADD;
    } else if (!strncasecmp(string, "Get", strlen("Get"))) {
        expected_op = SANDESH_OP_GET;
    } else if (!strncasecmp(string, "Delete", strlen("Delete"))) {
        expected_op = SANDESH_OP_DEL;
    } else if (!strncasecmp(string, "Dump", strlen("Dump"))) {
        expected_op = SANDESH_OP_DUMP;
    } else if (!strncasecmp(string, "Reset", strlen("Reset"))) {
        expected_op = SANDESH_OP_RESET;
    }

    return op == expected_op;
}

int
vt_gen_op(unsigned char *string)
{
    if (!string)
        return -1;

    if (!strncasecmp(string, "Add", strlen("Add"))) {
        return SANDESH_OP_ADD;
    } else if (!strncasecmp(string, "Get", strlen("Get"))) {
        return SANDESH_OP_GET;
    } else if (!strncasecmp(string, "Delete", strlen("Delete"))) {
        return SANDESH_OP_DEL;
    } else if (!strncasecmp(string, "Dump", strlen("Dump"))) {
        return SANDESH_OP_DUMP;
    } else if (!strncasecmp(string, "Reset", strlen("Reset"))) {
        return SANDESH_OP_RESET;
    }

    return -1;
}


/*TODO 
 *
 * Create a generic function -> delimiter and base
 * */

void *
vt_gen_list(unsigned char *list, unsigned int type, unsigned int *list_size)
{
    unsigned int i = 0, j = 0, type_size;
    unsigned int string_size;
    unsigned char *local_list = list;
    unsigned char *end;
    char *tmp;
    char *is_colon = NULL;

    unsigned char *store;
    uint8_t  *store_b;
    uint16_t *store_i16;
    uint32_t *store_i32;
    uint64_t *store_i64;

    *list_size = 0;
    if (!list)
        return NULL;

    switch (type) {
        case GEN_TYPE_U8:
            type_size = 1;
            break;

        case GEN_TYPE_U16:
            type_size = 2;
            break;

        case GEN_TYPE_U32:
            type_size = 4;
            break;

        case GEN_TYPE_U64:
            type_size = 8;
            break;

        default:
            return NULL;
    }

    string_size = strlen(list);
    end = list + string_size;



    while (1) {
        local_list = vt_gen_skip_char(local_list, ':');
        if (!strlen(local_list))
            break;

        j++;

        local_list = vt_gen_reach_char(local_list, ':');
        if (!local_list)
            break;
    }


    store = calloc(j, type_size);
    if (!store)
        return NULL;

    *list_size = type_size * j;

    store_b = (uint8_t *)store;
    store_i16 = (uint16_t *)store;
    store_i32 = (uint32_t *)store;
    store_i64 = (uint64_t *)store;

    local_list = list;
    for (i = 0; i < j; i++) {
        switch (type) {
            case GEN_TYPE_U8:
                /*TODO  For now only mac addresses are mapped to base 16*/
                store_b[i] = strtoul(local_list, &tmp, 16);
                break;

            case GEN_TYPE_U16:
                store_i16[i] = strtoul(local_list, &tmp, 0);
                break;

            case GEN_TYPE_U32:
                store_i32[i] = strtoul(local_list, &tmp, 0);
                break;

            case GEN_TYPE_U64:
                store_i64[i] = strtoul(local_list, &tmp, 0);
                break;
        }

        if (errno == ERANGE) {
            free(store);
            return NULL;
        }

        local_list = tmp;

        local_list = vt_gen_skip_char(local_list, ':');

        if (!local_list)
            break;
    }

    return store;
}

bool
vt_gen_list_compare(void *list, unsigned int list_size,
        unsigned char *string, unsigned int type)
{
    unsigned int buf_size;
    void *buf;

    buf = vt_gen_list(string, type, &buf_size);
    if (!buf)
        return false;

    if (buf_size != list_size)
        return false;

    if (memcmp(list, buf, list_size))
        return false;

    return true;
}

void *
vt_gen_string(char *string)
{
    unsigned int string_len;
    char *store;

    string_len = strlen(string);
    store = malloc(string_len + 1);
    if (!store)
        return NULL;

    strcpy(store, string);

    return store;
}

