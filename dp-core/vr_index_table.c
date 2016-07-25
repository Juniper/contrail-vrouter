/*
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#include <vr_index_table.h>
#include <vr_os.h>
#include <vrouter.h>
#if defined(__linux__)
#include <stdarg.h>
#elif defined(__FreeBSD__)
#include <machine/stdarg.h>
#endif

#define VR_ITABLE_VALUE(p) ((unsigned long)(p))

struct vr_itbl_data {
    unsigned int itbld_ref_cnt;
    unsigned int itbld_ac_cnt;
    uint8_t itbld_data[0];
};

struct vr_itbl {
    unsigned int stride_cnt;
    unsigned int index_len;
    unsigned int *stride_len;
    unsigned int *stride_shift;
    struct vr_itbl_data *data;
};

void vr_print_table_struct(vr_itable_t);

static inline int
vr_stride_mem_size(struct vr_itbl *table, int stride_num)
{
    int size  = table->stride_len[stride_num] * sizeof(void *);

    size += (2 * sizeof(unsigned int));

    return size;
}

static inline struct vr_itbl_data *
vr_itbld_from_ptr(struct vr_itbl_data *ptr)
{
    return (struct vr_itbl_data *)((unsigned long)ptr & (~0x3)); 
}

static void
vr_itbl_free_cb(struct vrouter *router, void *data)
{
    struct vr_defer_data *vdd = (struct vr_defer_data *)data;

    if (!vdd)
        return; 

    vr_free(vdd->vdd_data, VR_ITABLE_OBJECT);

    return; 
}


static int
vr_itable_defer(void *ptr)
{
    struct vr_defer_data *defer;

    defer = vr_get_defer_data(sizeof(*defer));
    if (!defer)
        return -ENOMEM;

    defer->vdd_data = ptr;
    vr_defer(vrouter_get(0), vr_itbl_free_cb, (void *)defer);

    return 0; 
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
                        struct vr_itbl_data **tbldp, unsigned int cnt, void **old)
{
    unsigned int id;
    struct vr_itbl_data *tbld;
    void **ptr, *tmp;
    
    tbld = vr_itbld_from_ptr(*tbldp);

    if (!tbld || (cnt > (table->stride_cnt - 1)))
        return 0;

    ptr = (void **)tbld->itbld_data;
    id = (index >> table->stride_shift[cnt]) & (table->stride_len[cnt] - 1);

    if (cnt == table->stride_cnt-1) {
        *old = ptr[id];

        if (!(*old))
            return 0;

        ptr[id] = NULL;
    
    } else {
        tmp = vr_itbld_from_ptr(ptr[id]);

        if (!__vr_itable_del(table, index, (struct vr_itbl_data **)(ptr+id),
                                                            (cnt+1), old)) {
            return 0;
        }

        if (!__sync_bool_compare_and_swap((ptr + id),
                    (VR_ITABLE_VALUE(tmp)  | 0x2), NULL)) {
            return 0;
        }

        if (!vr_not_ready)
            vr_itable_defer(tmp);
        else
            vr_free(tmp, VR_ITABLE_OBJECT);
    }

    if (!__sync_sub_and_fetch(&tbld->itbld_ref_cnt, 1)) {
        tmp = vr_itbld_from_ptr(tbld);
        if (__sync_bool_compare_and_swap(tbldp, tbld,
                            (VR_ITABLE_VALUE(tbld) | 0x2))) {
            if (!cnt) {
                *tbldp = NULL;
                if (!vr_not_ready)
                    vr_itable_defer(tmp);
                else
                    vr_free(tmp, VR_ITABLE_OBJECT);
            }
            return 1;
        }
    }

    return 0;
}

static int
__vr_itable_dump(struct vr_itbl *table, vr_itable_trav_cb_t func,
        struct vr_itbl_data *tbld, unsigned int cnt, unsigned int index,
        unsigned int marker, void *udata)
{
    unsigned int i, j;
    int res = 1;
    void **ptr;
    struct vr_itbl_data *tmp;

    tbld = vr_itbld_from_ptr(tbld);

    if (!tbld || cnt >= table->stride_cnt) {
        return res;
    }

    ptr = (void **)tbld->itbld_data;

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

        if (VR_ITABLE_VALUE(ptr[i]) & 0x2)
            continue;

        tmp = vr_itbld_from_ptr(ptr[i]);
        if (tmp) {
            res = __vr_itable_dump(table, func, tmp, (cnt + 1),
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
                        struct vr_itbl_data *tbld, unsigned int cnt, unsigned int index)
{
    unsigned int i, j;
    void **ptr;
    struct vr_itbl_data *tmp;

    if (!tbld)
        return;

    tbld = vr_itbld_from_ptr(tbld);
    ptr = (void **)tbld->itbld_data;

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

        return;
    }

    for (i = 0; i < table->stride_len[cnt]; i++) {
        tmp = vr_itbld_from_ptr(ptr[i]);
        if (tmp) {
            __vr_itable_exit(table, func, tmp, (cnt + 1),
                    (index | (i << table->stride_shift[cnt])));

            /* Upper strides are deleted. Delete the current */
            vr_free(ptr[i], VR_ITABLE_OBJECT);
            ptr[i] = NULL;
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

    if (!table) {
        return 0;
    }

    /* Keep some default function to print */
    if (!func) {
        func = print_ind;
    }

    return __vr_itable_dump(table, func, table->data, 0, 0, marker, udata);
}

void *
vr_itable_del(vr_itable_t t, unsigned int index)
{
    struct vr_itbl *table = (struct vr_itbl *)t;
    void *old = NULL;

    if (!table) {
        return NULL;
    }

    __vr_itable_del(table, index, &table->data, 0, &old);
    if (vr_itable_get(t, index))
        vr_printf("Vrouter: Itable Del 0x%x  is not deleted\n", index);

    /* Return the deleted value */
    return old;
}

void *
vr_itable_get(vr_itable_t t, unsigned int index)
{
    unsigned int i, id;
    struct vr_itbl *table = (struct vr_itbl *)t;
    struct vr_itbl_data *tbld;
    void **ptr;

    if (!table) {
        return NULL;
    }

    /* Go till last stride as long as data exists */
    for (i = 0, tbld = table->data; i < table->stride_cnt; i++) {

        if ((!tbld) || (VR_ITABLE_VALUE(tbld) & 0x2))
            return NULL;

        tbld = vr_itbld_from_ptr(tbld);

        id = (index >> table->stride_shift[i]) & (table->stride_len[i] - 1);
        ptr = (void **)tbld->itbld_data;
        tbld = ptr[id];
    }

    return tbld;
}

/*
 * Insert an entry into index table.
 * Returns the old entry at that index in success case. The old entry can be null.
 * Incase of error returns ((void *)-1)
 */

void *
vr_itable_set(vr_itable_t t, unsigned int index, void *data)
{
    unsigned int id = 0, i, ret;
    void *old, **ptr = NULL;
    struct vr_itbl *table = (struct vr_itbl *)t;
    struct vr_itbl_data **tbldp, *prev_tbld, *tbld = NULL, *cmp_tbld, **ac_tbld[16];

    if (!table) {
        return VR_ITABLE_ERR_PTR;
    }

    if (index & (~(((0x1 << (table->index_len - 1)) - 1) |
        (0x1 << (table->index_len - 1 ))))) {
        vr_printf("Index %x has more bits than %d Ignoring MSB\n",
                index, table->index_len);
    }

    tbldp = &table->data;
    prev_tbld = NULL;

    for (i = 0; i < table->stride_cnt; i++) {
        id = (index >> table->stride_shift[i]) & (table->stride_len[i] - 1);

        do {

           cmp_tbld = *tbldp;

            if (!cmp_tbld || (VR_ITABLE_VALUE(cmp_tbld) & 0x2)) {

                if (cmp_tbld)
                    prev_tbld = NULL;

                tbld= vr_zalloc(vr_stride_mem_size(table, i), VR_ITABLE_OBJECT);
                if (!tbld)
                    return VR_ITABLE_ERR_PTR;

                /* If some one else allocates the data, free ours */
                ret = __sync_bool_compare_and_swap(tbldp, cmp_tbld, tbld);
                cmp_tbld = *tbldp;
                if (ret) {
                    if (prev_tbld) {
                        (void)__sync_add_and_fetch(&prev_tbld->itbld_ref_cnt, 1);
                    }

                } else {
                    vr_free(tbld, VR_ITABLE_OBJECT);
                    if (!cmp_tbld)
                        continue;
                }
            }

            tbld = vr_itbld_from_ptr(cmp_tbld);

            (void)__sync_add_and_fetch(&tbld->itbld_ac_cnt, 1);
            ret = __sync_bool_compare_and_swap(tbldp, tbld,
                                    (VR_ITABLE_VALUE(tbld)| 0x1));
            cmp_tbld = *tbldp;
            ac_tbld[i] = tbldp;

            if (!ret) {
                if (VR_ITABLE_VALUE(cmp_tbld) & 0x2) {
                    (void)__sync_sub_and_fetch(&tbld->itbld_ac_cnt, 1);
                }
            }

        } while ((!cmp_tbld) || (VR_ITABLE_VALUE(cmp_tbld) & 0x2));

        if (!(VR_ITABLE_VALUE(cmp_tbld) & 0x1)) {
            vr_printf("Vrouter: Itable Set no modify flag set");
        }

        tbld = vr_itbld_from_ptr(cmp_tbld);
        ptr = (void **)(tbld->itbld_data);
        prev_tbld = tbld;
        tbldp = (struct vr_itbl_data **)(ptr + id);
    }

    /* Store the data in the last stride */
    old = ptr[id];
    ptr[id] = data;

    if (!old)
        (void)__sync_add_and_fetch(&tbld->itbld_ref_cnt, 1);

    for (i = table->stride_cnt; i; i--) {
        tbld = *(ac_tbld[i-1]);
        tbld = vr_itbld_from_ptr(tbld);
        if (!__sync_sub_and_fetch(&tbld->itbld_ac_cnt, 1)) {
            (void)__sync_bool_compare_and_swap(ac_tbld[i-1],
                    (VR_ITABLE_VALUE(tbld) | 0x1),
                    (VR_ITABLE_VALUE(tbld) | (tbld->itbld_ac_cnt != 0)));
        }
    }

    void *junk;
    junk = vr_itable_get(t, index);
    if (junk != data)
        vr_printf("Vrouter: Itable set 0x%x does not match data %p retrieved %p\n", index, data, junk);

    /* Return the old data */
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

