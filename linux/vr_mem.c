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

void *
vr_huge_mem_get(int size)
{
    int i,offset;
    void *mptr;
    struct vrouter *router = vrouter_get(0);
    struct vr_mem_config *mcfg = (struct vr_mem_config *)router->vr_mcfg;

    if ((!mcfg) || (mcfg->vr_mcfg_mem_inited == 0))
        return NULL;

    vr_printf("Vrouter: init value in get is %d mcfg is %p \n",
            mcfg->vr_mcfg_mem_inited, mcfg );

    /* Align it to be a multiple of 8 bytes */
    size = ((size + 7) / 8) * 8;

    for (i = 0; i < VR_MAX_MEM_SEGMENTS; i++) {
        if (!mcfg->vr_mcfg_mem[i])
            continue;

        if (mcfg->vr_mcfg_free_size[i] < size)
            continue;

        offset = VR_MEM_1G - mcfg->vr_mcfg_free_size[i];
        mptr = mcfg->vr_mcfg_mem[i] + offset;
        mcfg->vr_mcfg_free_size[i] -= size;

        vr_printf("Vrouter: vr_huge_mem_get segment %d size %d ptr %p free_mem_left %d\n",
                i, size, mptr, mcfg->vr_mcfg_free_size[i]);

        /* Zero the requested memory*/
        memset(mptr, 0, size);

        return mptr;
    }

    return NULL;
}


int
vr_huge_pages_config(u64 *hpages, int npages)
{
    int i, spages;
    struct vrouter *router = vrouter_get(0);
    struct vr_mem_config *mcfg;

    if (!router)
        return -1;

    mcfg = (struct vr_mem_config *)router->vr_mcfg;

    /* If memory is already inited, nothing to do further */
    if (mcfg && mcfg->vr_mcfg_mem_inited)
        return -EEXIST;

    /* Hold the user provided virtual memory address */
    for (i = 0; i < npages; i++) {
        mcfg->vr_mcfg_uspace_vmem[i] = (void *)hpages[i];
        vr_printf("Vrouter: hugepage userspace mem is %p\n",
                mcfg->vr_mcfg_uspace_vmem[i]);
    }

    for (i = 0; i < VR_MAX_MEM_SEGMENTS; i++) {

        if (!mcfg->vr_mcfg_uspace_vmem[i])
            continue;

        /* Allocate the memory for required number of pages */
        mcfg->vr_mcfg_npages[i] =  1 + (VR_MEM_1G - 1) / PAGE_SIZE;
        mcfg->vr_mcfg_pages[i] = (struct page **)
            vr_zalloc((mcfg->vr_mcfg_npages[i] * sizeof(struct page *)),
                       VR_HPAGE_PAGES_OBJECT);
        if (!mcfg->vr_mcfg_pages[i]) {
            vr_printf("Vrouter: npages malloc failure\n");
            goto err;
        }

        /*
         * Get the kernel pages corresponding to the 1G memory.
         * Expectation is that the pages are pinned in the physical
         * memory and are not going to be faulted
         */
        down_read(&current->mm->mmap_sem);
        spages = get_user_pages(current, current->mm,
                (unsigned long)mcfg->vr_mcfg_uspace_vmem[i],
                mcfg->vr_mcfg_npages[i], 1, 0, mcfg->vr_mcfg_pages[i], NULL);
        up_read(&current->mm->mmap_sem);

        /* If the pages are pinned are not the requested, flag the error */
        if (spages != mcfg->vr_mcfg_npages[i]) {
            vr_printf("Vrouter: for huage_page [%d] requested pages %d pinned pages %d\n", i, mcfg->vr_mcfg_npages[i], spages);
            goto err;
        }

        /* Hold the first page virtual address as it is contiguous memory */
        mcfg->vr_mcfg_mem[i] = page_address(mcfg->vr_mcfg_pages[i][0]);

        vr_printf("Vrouter: Huge page memory [%d] pointer is %p\n", i, mcfg->vr_mcfg_mem[i]);

        mcfg->vr_mcfg_free_size[i] = VR_MEM_1G;
    }

    mcfg->vr_mcfg_mem_inited = 1;
    return 0;

err:
    vr_huge_pages_exit();
    return -ENOMEM;
}

void
vr_huge_pages_exit(void)
{
    int i, j;
    struct vrouter *router = vrouter_get(0);
    struct vr_mem_config *mcfg;

    if (!router || !router->vr_mcfg)
        return ;

    mcfg = (struct vr_mem_config *)router->vr_mcfg;

    for (i = 0; i < VR_MAX_MEM_SEGMENTS; i++) {
        if (!mcfg->vr_mcfg_uspace_vmem[i])
            continue;

        mcfg->vr_mcfg_free_size[i] = 0;
        mcfg->vr_mcfg_mem[i] = 0;

        /* Put back the pages after marking dirty */
        for (j = 0; j < mcfg->vr_mcfg_npages[i]; j++) {
            if (mcfg->vr_mcfg_pages[i][j]) {
                if (!PageReserved(mcfg->vr_mcfg_pages[i][j]))
                    SetPageDirty(mcfg->vr_mcfg_pages[i][j]);
                page_cache_release(mcfg->vr_mcfg_pages[i][j]);
                mcfg->vr_mcfg_pages[i][j] = NULL;
            }
        }

        if (mcfg->vr_mcfg_pages[i]) {
            vr_free(mcfg->vr_mcfg_pages[i], VR_HPAGE_PAGES_OBJECT);
            mcfg->vr_mcfg_pages[i] = NULL;
        }
        mcfg->vr_mcfg_npages[i] = 0;
    }
    mcfg->vr_mcfg_mem_inited = 0;
    vr_free(mcfg, VR_HPAGE_CONFIG_OBJECT);
    router->vr_mcfg = NULL;

    vr_printf("Vrouter: huge_page_exit completed\n");

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
    struct vrouter *router = vrouter_get(0);
    struct vr_mem_config *mcfg;
    mcfg = (struct vr_mem_config *)router->vr_mcfg;
    if (!mcfg) {
        mcfg = vr_zalloc(sizeof(*mcfg), VR_HPAGE_CONFIG_OBJECT);
        if (!mcfg)
            return -ENOMEM;
        router->vr_mcfg = (vr_mem_config_t)mcfg;
    }

    vr_printf("Vrouter: Init val is %d mcfg %p \n",
            mcfg->vr_mcfg_mem_inited, mcfg);
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

    vr_huge_pages_exit();
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

    ret = vr_huge_pages_init();
    if (ret)
        goto init_fail;

    return ret;

init_fail:
    vr_mem_exit();
    return ret;
}
