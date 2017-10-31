/*
 * vr_mem.c -- the memory driver. /dev/mem is extremely restrictive to be
 * of use reliably. hence, we need to have our own driver to expose memory.
 *
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/mm.h>
#include <asm/page.h>
#include <linux/netdevice.h>
#include <linux/pagemap.h>

#include "vrouter.h"
#include "vr_mem.h"

#define MEM_DEV_MINOR_START         0
#define MEM_DEV_NUM_DEVS            2

struct vr_mem_config {
    void *vr_mcfg_uspace_vmem[VR_MAX_MEM_SEGMENTS];
    void *vr_mcfg_mem[VR_MAX_MEM_SEGMENTS];
    struct page **vr_mcfg_pages[VR_MAX_MEM_SEGMENTS];
    unsigned int vr_mcfg_npages[VR_MAX_MEM_SEGMENTS];
    unsigned int vr_mcfg_free_size[VR_MAX_MEM_SEGMENTS];
    unsigned int vr_mcfg_mem_inited;
};

short vr_flow_major = -1;
short vr_bridge_table_major = -1;

static dev_t mem_dev;
struct cdev *mem_cdev;

static struct vr_mem_config *vr_mcfg;

void *
vr_huge_mem_get(int size)
{
    int i,offset;
    void *mptr;

    if ((!vr_mcfg) || (vr_mcfg->vr_mcfg_mem_inited == 0))
        return NULL;

    /* Align it to be a multiple of 8 bytes */
    size = ((size + 7) / 8) * 8;

    for (i = 0; i < VR_MAX_MEM_SEGMENTS; i++) {
        if (!vr_mcfg->vr_mcfg_mem[i])
            continue;

        if (vr_mcfg->vr_mcfg_free_size[i] < size)
            continue;

        offset = VR_MEM_1G - vr_mcfg->vr_mcfg_free_size[i];
        mptr = vr_mcfg->vr_mcfg_mem[i] + offset;
        vr_mcfg->vr_mcfg_free_size[i] -= size;

        /* Zero the requested memory*/
        memset(mptr, 0, size);

        return mptr;
    }

    return NULL;
}


int
vr_huge_pages_config(u64 *hpages, int npages)
{
    int i, spages, succeeded_pages = 0;

    /* If memory is already inited, nothing to do further */
    if (vr_mcfg && vr_mcfg->vr_mcfg_mem_inited)
        return -EEXIST;

    /* Hold the user provided virtual memory address */
    for (i = 0; i < npages; i++)
        vr_mcfg->vr_mcfg_uspace_vmem[i] = (void *)hpages[i];

    for (i = 0; i < VR_MAX_MEM_SEGMENTS; i++) {

        if (!vr_mcfg->vr_mcfg_uspace_vmem[i])
            continue;

        /* Allocate the memory for required number of pages */
        vr_mcfg->vr_mcfg_npages[i] =  1 + (VR_MEM_1G - 1) / PAGE_SIZE;
        vr_mcfg->vr_mcfg_pages[i] = (struct page **)
            kzalloc((vr_mcfg->vr_mcfg_npages[i] * sizeof(struct page *)),
                       GFP_ATOMIC);
        if (!vr_mcfg->vr_mcfg_pages[i])
            continue;

        /*
         * Get the kernel pages corresponding to the 1G memory.
         * Expectation is that the pages are pinned in the physical
         * memory and are not going to be faulted
         */
        down_read(&current->mm->mmap_sem);
        spages = get_user_pages(current, current->mm,
                (unsigned long)vr_mcfg->vr_mcfg_uspace_vmem[i],
                vr_mcfg->vr_mcfg_npages[i], 1, 0, vr_mcfg->vr_mcfg_pages[i], NULL);
        up_read(&current->mm->mmap_sem);

        /*
         * If number of pinned pages are less than requested,
         * skip that segment config and return partial success
         */
        if (spages != vr_mcfg->vr_mcfg_npages[i])
            continue;

        /* Hold the first page virtual address as it is contiguous memory */
        vr_mcfg->vr_mcfg_mem[i] = page_address(vr_mcfg->vr_mcfg_pages[i][0]);
        vr_mcfg->vr_mcfg_free_size[i] = VR_MEM_1G;
        succeeded_pages++;
    }

    if (!succeeded_pages)
        return -ENOMEM;

    /* Lets consider, partial success also init complete */
    vr_mcfg->vr_mcfg_mem_inited = 1;

    if (succeeded_pages < npages) {
        for (i = 0; i < VR_MAX_MEM_SEGMENTS; i++) {

            /* If succeeded, dont touch it */
            if (vr_mcfg->vr_mcfg_mem[i])
                continue;

            if (!vr_mcfg->vr_mcfg_uspace_vmem[i])
                continue;

            for (spages = 0; spages < vr_mcfg->vr_mcfg_npages[i]; spages++) {
                if (vr_mcfg->vr_mcfg_pages[i][spages]) {
                    if (!PageReserved(vr_mcfg->vr_mcfg_pages[i][spages]))
                        SetPageDirty(vr_mcfg->vr_mcfg_pages[i][spages]);
                    page_cache_release(vr_mcfg->vr_mcfg_pages[i][spages]);
                    vr_mcfg->vr_mcfg_pages[i][spages] = NULL;
                }
            }
            if (vr_mcfg->vr_mcfg_pages[i])
                kfree(vr_mcfg->vr_mcfg_pages[i]);

            vr_mcfg->vr_mcfg_pages[i] = NULL;
            vr_mcfg->vr_mcfg_npages[i] = 0;
            vr_mcfg->vr_mcfg_free_size[i] = 0;
            vr_mcfg->vr_mcfg_uspace_vmem[i] = NULL;
        }

        return -E2BIG;
    }

    return 0;
}

void
vr_huge_pages_exit(void)
{
    int i, j;

    if (!vr_mcfg)
        return ;

    for (i = 0; i < VR_MAX_MEM_SEGMENTS; i++) {
        if (!vr_mcfg->vr_mcfg_uspace_vmem[i])
            continue;

        vr_mcfg->vr_mcfg_free_size[i] = 0;
        vr_mcfg->vr_mcfg_mem[i] = 0;

        /* Put back the pages after marking dirty */
        for (j = 0; j < vr_mcfg->vr_mcfg_npages[i]; j++) {
            if (vr_mcfg->vr_mcfg_pages[i][j]) {
                if (!PageReserved(vr_mcfg->vr_mcfg_pages[i][j]))
                    SetPageDirty(vr_mcfg->vr_mcfg_pages[i][j]);
                page_cache_release(vr_mcfg->vr_mcfg_pages[i][j]);
                vr_mcfg->vr_mcfg_pages[i][j] = NULL;
            }
        }

        if (vr_mcfg->vr_mcfg_pages[i]) {
            kfree(vr_mcfg->vr_mcfg_pages[i]);
            vr_mcfg->vr_mcfg_pages[i] = NULL;
        }
        vr_mcfg->vr_mcfg_npages[i] = 0;
    }
    vr_mcfg->vr_mcfg_mem_inited = 0;
    kfree(vr_mcfg);
    vr_mcfg = NULL;

    return;
}

/*
 * The huge page memory is meat for large allocations and is meant to
 * present in Vrouter for its complete life time.  The memory received
 * using vr_huge_mem_get() is not going to be returned to the pool till
 * the module is removed. Hence no calls to put the memory back to the
 * huge pages
 */
int
vr_huge_pages_init()
{
    if (!vr_mcfg) {
        vr_mcfg = kzalloc(sizeof(*vr_mcfg), GFP_ATOMIC);
        if (!vr_mcfg)
            return -ENOMEM;
    }

    return 0;
}


static int
mem_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
    void *va;
    struct vr_mem_object *vmo = (struct vr_mem_object *)vma->vm_private_data;
    struct vrouter *router = vmo->vmo_router;
    struct page *page;
    pgoff_t offset;

    offset = vmf->pgoff;

    switch (vmo->vmo_object_type) {
    case VR_MEM_FLOW_TABLE_OBJECT:
        va = vr_flow_get_va(router, offset << PAGE_SHIFT);
        break;

    case VR_MEM_BRIDGE_TABLE_OBJECT:
        va = vr_bridge_get_va(router, offset << PAGE_SHIFT);
        break;

    default:
        return -EFAULT;
    }

    page = virt_to_page(va);
    get_page(page);
    vmf->page = page;

    return 0;
}

static struct vm_operations_struct mem_vm_ops = {
    .fault     =   mem_fault,
};

static int
mem_dev_mmap(struct file *fp, struct vm_area_struct *vma)
{
    struct vr_mem_object *vmo = (struct vr_mem_object *)fp->private_data;
    struct vrouter *router = vmo->vmo_router;
    unsigned long size, table_size;

    size = vma->vm_end - vma->vm_start;
    switch (vmo->vmo_object_type) {
    case VR_MEM_FLOW_TABLE_OBJECT:
        table_size = vr_flow_table_size(router);
        break;

    case VR_MEM_BRIDGE_TABLE_OBJECT:
        table_size = vr_bridge_table_size(router);
        break;

    default:
        return -EINVAL;
    }

    if (size > table_size)
        return -EINVAL;

    if (vma->vm_pgoff + (size >> PAGE_SHIFT) >
            (table_size >> PAGE_SHIFT))
        return -EINVAL;

    vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
    vma->vm_private_data = (void *)vmo;
    vma->vm_ops = &mem_vm_ops;

    return 0;
}

static int
mem_dev_release(struct inode *inode, struct file *filp)
{
    struct vr_mem_object *vmo = (struct vr_mem_object *)filp->private_data;

    if (vmo) {
        vr_free(vmo, VR_MEM_OBJECT);
        filp->private_data = NULL;
    }

    return 0;
}

static int
mem_dev_open(struct inode *inode, struct file *filp)
{
    dev_t dev = inode->i_rdev;
    int ret = 0;
    unsigned int minor = MINOR(dev);
    unsigned int router_id = ROUTER_FROM_MINOR(minor);
    unsigned int object_id = OBJECT_FROM_MINOR(minor);

    struct vr_mem_object *vmo;

    if (object_id > VR_MEM_MAX_OBJECT)
        return -EINVAL;

    vmo = vr_malloc(sizeof(*vmo), VR_MEM_OBJECT);
    if (!vmo)
        return -ENOMEM;

    vmo->vmo_router = (void *)vrouter_get(router_id);
    if (!vmo->vmo_router) {
        ret = -EINVAL;
        goto fail;
    }

    vmo->vmo_object_type = object_id;

    filp->private_data = vmo;

    return 0;

fail:
    if (vmo) {
        vr_free(vmo, VR_MEM_OBJECT);
        vmo = NULL;
    }

    return ret;
}

struct file_operations mdev_ops = {
    .owner      =       THIS_MODULE,
    .open       =       mem_dev_open,
    .release    =       mem_dev_release,
    .mmap       =       mem_dev_mmap,
};



void
vr_mem_exit(void)
{
    unregister_chrdev_region(mem_dev, MEM_DEV_NUM_DEVS);

    if (mem_cdev) {
        cdev_del(mem_cdev);
    }

    return;
}

int
vr_mem_init(void)
{
    int ret;

    ret = alloc_chrdev_region(&mem_dev, MEM_DEV_MINOR_START,
            MEM_DEV_NUM_DEVS, "vrouter_mem");
    if (ret < 0) {
        printk("%s:%d Device number reservation failed with return %d\n",
                __FUNCTION__, __LINE__, ret);
        return ret;
    }

    mem_cdev = cdev_alloc();
    if (!mem_dev) {
        printk("%s:%d Character device allocation failed\n",
                __FUNCTION__, __LINE__);
        goto init_fail;
    }

    mem_cdev->owner = THIS_MODULE;
    cdev_init(mem_cdev, &mdev_ops);
    if ((ret = cdev_add(mem_cdev, mem_dev, MEM_DEV_NUM_DEVS)) < 0) {
        printk("%s:%d Character device addition failed with return %d\n",
                __FUNCTION__, __LINE__, ret);
        goto init_fail;
    }

    vr_flow_major = vr_bridge_table_major =  MAJOR(mem_dev);

    return ret;

init_fail:
    vr_mem_exit();
    return ret;
}
