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

#include "vrouter.h"

#define MEM_DEV_MINOR_START     0
#define MEM_DEV_NUM_DEVS        1

short vr_flow_major = -1;
static dev_t mem_dev;
struct cdev *mem_cdev;

static int
mem_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
    struct vrouter *router = (struct vrouter *)vma->vm_private_data;
    struct page *page;
    pgoff_t offset;

    offset = vmf->pgoff;
    page = virt_to_page(vr_flow_get_va(router, offset << PAGE_SHIFT));
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
    struct vrouter *router = (struct vrouter *)fp->private_data;
    unsigned long size, flow_table_size;

    if (!router)
        return -ENOMEM;

    size = vma->vm_end - vma->vm_start;
    flow_table_size = vr_flow_table_size(router);
    if (size > flow_table_size)
        return -EINVAL;

    if (vma->vm_pgoff + (size >> PAGE_SHIFT) >
            (flow_table_size >> PAGE_SHIFT))
        return -EINVAL;

    vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
    vma->vm_private_data = (void *)router;
    vma->vm_ops = &mem_vm_ops;

    return 0;
}

static int
mem_dev_release(struct inode *inode, struct file *filp)
{
    struct vrouter *router = (struct vrouter *)filp->private_data;

    if (router)
        filp->private_data = NULL;

    return 0;
}

static int
mem_dev_open(struct inode *inode, struct file *filp)
{
    dev_t dev = inode->i_rdev;
    unsigned int minor = MINOR(dev);

    filp->private_data = (void *)vrouter_get(minor);
    if (!filp->private_data)
        return -EINVAL;

    return 0;
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
            MEM_DEV_NUM_DEVS, "flow");
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

    vr_flow_major = MAJOR(mem_dev);

    return ret;

init_fail:
    vr_mem_exit();
    return ret;
}
