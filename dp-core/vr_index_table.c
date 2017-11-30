/*
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#include <vr_index_table.h>
#include <vr_os.h>
#include <vrouter.h>
#if defined(__linux__) || defined(_WIN32)
#include <stdarg.h>
#elif defined(__FreeBSD__)
#include <machine/stdarg.h>
#endif

struct vr_itbl {
    unsigned int stride_cnt;
    unsigned int index_len;
    unsigned int *stride_len;
    unsigned int *stride_shift;
    void **data;
};

void vr_print_table_struct(vr_itable_t);

static int
vr_stride_empty(void **ptr, unsigned int cnt)
{
    unsigned int i;
    for (i = 0; i < cnt; i++) {
        if (ptr[i] != NULL) {
            return 0;
        }
    }

    return 1;
}

/* Default print function */
static int
print_ind(unsigned int index, void *data, void *udata)
{
    vr_printf("Index %d Data 0x%p\n", index, data);
    return 1;
}

#ifdef __KERNEL__
static unsigned int
get_page_shift(void)
{
    return PAGE_SHIFT;
}
#else
static unsigned int
get_page_shift(void)
{
    return ffs(getpagesize());
}
#endif



static int
__vr_itable_del(struct vr_itbl *table, unsigned int index,
                        void **ptr, unsigned int cnt, void **old)
{
    unsigned int id;

    if (cnt == table->stride_cnt-1) {
        id = (index >> table->stride_shift[cnt]) & (table->stride_len[cnt] - 1);
        *old = ptr[id];

        /*
         * IF an entry exists to delete, mark it null. If the whole
         * stride is null, delete the stride itself
         */
        if (*old) {
            ptr[id] = NULL;
            if (vr_stride_empty(ptr, table->stride_len[cnt]) == 1) {
                vr_free(ptr, VR_ITABLE_OBJECT);
                return 1;
            }
        }
        return 0;
    }

    if ((cnt < (table->stride_cnt - 1)) && ptr) {
        id = (index >> table->stride_shift[cnt]) & (table->stride_len[cnt] - 1);
        if (ptr[id] && __vr_itable_del(table, index, (void **)(ptr[id]),
                                            (cnt+1), old) == 1) {

            /*
             * If a later stride is deleted, check for the
             * earliter stride as well
             */
            ptr[id] = NULL;
            if (vr_stride_empty(ptr, table->stride_len[cnt]) == 1) {
                vr_free(ptr, VR_ITABLE_OBJECT);

                /* If the stride deleted is first, mark the head null */
                if (cnt == 0) {
                    table->data = NULL;
                }
                return 1;
            }

        }
    }

    return 0;
}

static int
__vr_itable_dump(struct vr_itbl *table, vr_itable_trav_cb_t func, void **ptr,
        unsigned int cnt, unsigned int index, unsigned int marker, void *udata)
{
    unsigned int i, j;
    int res = 1;

    if (!ptr || cnt >= table->stride_cnt) {
        return res;
    }

    if (cnt == table->stride_cnt - 1) {
        /* Last stride. Contains the elements */
        for (j = 0; j < table->stride_len[cnt]; j++) {
            if (ptr[j]) {
                unsigned int tmp = index | (j << table->stride_shift[cnt]);
                /* Ensure that we traverse entries above marker given by user */
                if (tmp >= marker) {
                    res = func(tmp, ptr[j], udata);
                    /* Stop the traversal if function return error or hold */
                    if (res <= 0) {
                        return res;
                    }
                }
            }
        }
        return res;
    }

    for (i = 0; i < table->stride_len[cnt]; i++) {

        /* Rectursively call all strides */
        if (ptr[i]) {
            res = __vr_itable_dump(table, func, (void **)ptr[i], (cnt + 1),
                    (index | (i << table->stride_shift[cnt])), marker, udata);

            /* No more traversal if upper stride stopped it */
            if (res <= 0) {
                break;
            }
        }
    }

    return res;
}

static void
__vr_itable_exit(struct vr_itbl *table, vr_itable_del_cb_t func,
                        void **ptr, unsigned int cnt, unsigned int index)
{
    unsigned int i, j;

    if (!ptr || cnt >= table->stride_cnt) {
        return;
    }

    if (cnt == table->stride_cnt - 1) {

        /* This handles the last stride which contain elements*/
        for (j = 0; j < table->stride_len[cnt]; j++) {
            if (ptr[j]) {

                /* Call the user function which might cleanup index entry */
                if (func) {
                    func((index | (j << table->stride_shift[cnt])), ptr[j]);
                }
                ptr[j] = NULL;
            }
        }

        /* All stride entries are delete invoked. Delete the stride now */
        vr_free(ptr, VR_ITABLE_OBJECT);
        return;
    }

    for (i = 0; i < table->stride_len[cnt]; i++) {
        if (ptr[i]) {
            __vr_itable_exit(table, func, (void **)ptr[i], (cnt + 1),
                    (index | (i << table->stride_shift[cnt])));

            /* Upper strides are deleted. Delete the current */
            ptr[i] = NULL;
            vr_free(ptr[i], VR_ITABLE_OBJECT);
        }
    }

    /* Destruct the head as well*/
    if (cnt == 0) {
        vr_free(table->data, VR_ITABLE_OBJECT);
        table->data = NULL;
    }

    return;
}

void
vr_print_table_struct(vr_itable_t t)
{
    struct vr_itbl *table = (struct vr_itbl *)t;
    unsigned int i;

    if (!table) {
        return;
    }

    vr_printf("Index Len           :%d\n", table->index_len);
    vr_printf("Stride cnt          :%d\n", table->stride_cnt);
    for (i = 0; i < table->stride_cnt; i++) {
        vr_printf("\nStride[%d] Len      :%d\n", i, table->stride_len[i]);
        vr_printf("Stride[%d] Shift    :%d\n", i, table->stride_shift[i]);
    }

    return;
}

int
vr_itable_trav(vr_itable_t t, vr_itable_trav_cb_t func,
                                     unsigned int marker, void *udata)
{
    struct vr_itbl *table = (struct vr_itbl *) t;
    void **ptr = table->data;

    if (!table) {
        return 0;
    }

    /* Keep some default function to print */
    if (!func) {
        func = print_ind;
    }

    return __vr_itable_dump(table, func, ptr, 0, 0, marker, udata);
}

void *
vr_itable_del(vr_itable_t t, unsigned int index)
{
    struct vr_itbl *table = (struct vr_itbl *)t;
    void *old = NULL;

    if (!table) {
        return NULL;
    }

    __vr_itable_del(table, index, table->data, 0, &old);

    /* Return the deleted value */
    return old;
}

void *
vr_itable_get(vr_itable_t t, unsigned int index)
{
    void **ptr;
    struct vr_itbl *table = (struct vr_itbl *)t;
    unsigned int i;
    unsigned int id;

    if (!table) {
        return NULL;
    }

    /* Go till last stride as long as data exists */
    for (i = 0, ptr = table->data; (i < table->stride_cnt) && ptr; i++) {
        id = (index >> table->stride_shift[i]) & (table->stride_len[i] - 1);
        ptr = (void **)(ptr[id]);
    }

    return (void *)ptr;
}

/*
 * Insert an entry into index table.
 * Returns the old entry at that index in success case. The old entry can be null.
 * Incase of error returns ((void *)-1)
 */

void *
vr_itable_set(vr_itable_t t, unsigned int index, void *data)
{
    struct vr_itbl *table = (struct vr_itbl *)t;
    unsigned int id;
    void **ptr;
    void *old;
    unsigned int i;

    if (!table) {
        return VR_ITABLE_ERR_PTR;
    }

    if (index & (~(((0x1 << (table->index_len - 1)) - 1) |
        (0x1 << (table->index_len - 1 ))))) {
        vr_printf("Index %x has more bits than %d Ignoring MSB\n",
                index, table->index_len);
    }

    if (!table->data) {
        table->data = vr_zalloc(table->stride_len[0] * sizeof(void *),
                VR_ITABLE_OBJECT);
        if (!table->data) {
            return VR_ITABLE_ERR_PTR;
        }
    }
    ptr = table->data;

    for (i = 0; i < table->stride_cnt - 1; i++) {
        id = (index >> table->stride_shift[i]) & (table->stride_len[i] - 1);

        if (!ptr[id]) {
            ptr[id] = vr_zalloc(table->stride_len[i + 1] * sizeof(void *),
                    VR_ITABLE_OBJECT);
            /* To fix: We might return with some empty strides */
            if (!ptr[id]) {
                return VR_ITABLE_ERR_PTR;
            }
        }

        ptr = (void **)ptr[id];
    }

    /* Store the data in the last stride */
    id = (index >> table->stride_shift[i]) & (table->stride_len[i] - 1);

    /* Return the old data */
    old = ptr[id];
    ptr[id] = data;
    return old;
}

/*
 * Delete the whole index table. After deleting the individual entries
 * Delete all strides. After strides delete table management data as well
 */
void
vr_itable_delete(vr_itable_t t, vr_itable_del_cb_t func)
{
    struct vr_itbl *table = (struct vr_itbl *)t;

    if (!table) {
        return;
    }

    /* Delete all entries and strides */
    __vr_itable_exit(table, func, table->data, 0, 0);

    /* Free the table itself */
    vr_free(table->stride_len, VR_ITABLE_OBJECT);
    vr_free(table->stride_shift, VR_ITABLE_OBJECT);
    vr_free(table, VR_ITABLE_OBJECT);

    return;
}

/*
 * index_len - How many bits does index consist of. Max is 32 and any length
 * of bits can be used.
 * stride_cnt - How many strides user wants. Minimum of 2.
 * Varable arguments follow to identify how many bits is each stride.
 *
 */

vr_itable_t
vr_itable_create(unsigned int index_len, unsigned int stride_cnt, ...)
{
    va_list vargs;
    struct vr_itbl *table;
    unsigned int tot_stride_len;
    unsigned int i;

    table = NULL;

    /* Index length can not be more than int size */
    if (index_len > (sizeof(unsigned int) * 8)) {
        goto fail;
    }

    /* Atleast two strides please.. */
    if (stride_cnt < 2) {
        goto fail;
    }

    table = vr_zalloc(sizeof(struct vr_itbl), VR_ITABLE_OBJECT);
    if (!table) {
        goto fail;
    }

    table->index_len = index_len;
    table->stride_cnt = stride_cnt;

    table->stride_shift = vr_zalloc(table->stride_cnt * sizeof(unsigned int),
            VR_ITABLE_OBJECT);
    if (!table->stride_shift) {
        goto fail;
    }

    table->stride_len = vr_zalloc(table->stride_cnt * sizeof(unsigned int),
            VR_ITABLE_OBJECT);
    if (!table->stride_len) {
        goto fail;
    }

    va_start(vargs, stride_cnt);
    for (i = 0, tot_stride_len = 0; i < table->stride_cnt; i++) {
        table->stride_len[i] = va_arg(vargs, unsigned int);

        /* Ensure one kalloc can not be more than a page size */
        if ((table->stride_len[i] > get_page_shift())) {
            goto fail;
        }

        /* All strides together can not be more than total index length */
        tot_stride_len += table->stride_len[i];
        if (tot_stride_len > table->index_len) {
            goto fail;
        }

        table->stride_len[i] = 0x1 << table->stride_len[i];
        /* Get the trailing zeros as well */
        table->stride_shift[i] = table->index_len - tot_stride_len;
    }

    /* All strides togwether should be equal to index length */
    if (tot_stride_len != table->index_len) {
        goto fail;
    }

    return (vr_itable_t)table;

fail:

    if (table) {
        if (table->stride_shift) {
            vr_free(table->stride_shift, VR_ITABLE_OBJECT);
        }

        if (table->stride_len) {
            vr_free(table->stride_len, VR_ITABLE_OBJECT);
        }

        vr_free(table, VR_ITABLE_OBJECT);
    }

    return NULL;
}

