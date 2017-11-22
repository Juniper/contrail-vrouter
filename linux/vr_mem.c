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

struct vr_hpage_config {
    void *hcfg_uspace_vmem;
    void *hcfg_mem;
    struct page **hcfg_pages;
    unsigned int hcfg_npages;
    unsigned int hcfg_free_size;
    unsigned int hcfg_tot_size;
    unsigned int hcfg_mem_attached;
};

short vr_flow_major = -1;
short vr_bridge_table_major = -1;

static dev_t mem_dev;
struct cdev *mem_cdev;

bool vr_hpage_config_inited = false;
static struct vr_hpage_config *vr_hcfg;

void *
vr_huge_mem_get(int size)
{
    int i, offset;
    void *mptr;

    if (!vr_hpage_config_inited || !vr_hcfg)
        return NULL;

    /* Align it to be a multiple of 8 bytes */
    size = ((size + 7) / 8) * 8;

    for (i = 0; i < VR_MAX_HUGE_PAGES; i++) {
        if (!vr_hcfg[i].hcfg_mem)
            continue;

        if (vr_hcfg[i].hcfg_free_size < size)
            continue;

        offset = vr_hcfg[i].hcfg_tot_size - vr_hcfg[i].hcfg_free_size;
        mptr = vr_hcfg[i].hcfg_mem + offset;
        vr_hcfg[i].hcfg_free_size -= size;

        /* Zero the requested memory*/
        memset(mptr, 0, size);

        return mptr;
    }

    return NULL;
}

static struct vr_hpage_config *
vr_huge_page_2M_get(void)
{
    int i;

    if (!vr_hcfg)
        return NULL;

    for (i = 0; i < VR_MAX_HUGE_PAGES; i++) {

        if (!vr_hcfg[i].hcfg_mem)
            continue;

        /* If not a 2M page, not bothered */
        if (vr_hcfg[i].hcfg_tot_size != VR_MEM_2M)
            continue;

        /* Free size is used as marker to identify whether this has been
         * used or not
         */
        if (vr_hcfg[i].hcfg_free_size != VR_MEM_2M)
            continue;

        return vr_hcfg + i;
    }

    return NULL;
}

static struct vr_hpage_config *
__vr_huge_page_get(uint64_t uspace_vmem, int npages, int mem_size, struct page **pmem)
{
    int i, size = 0, spages;
    struct vr_hpage_config *hcfg = NULL;

    for (i = 0; i < VR_MAX_HUGE_PAGES; i++) {
        hcfg = vr_hcfg + i;
        if (!hcfg->hcfg_mem)
            break;
    }

    if (i == VR_MAX_HUGE_PAGES)
        return NULL;

    if (!pmem) {
        size = sizeof(struct page *) * npages;
        pmem = (struct page **)__get_free_pages(GFP_ATOMIC |
                      __GFP_ZERO | __GFP_COMP, get_order(size));
        if (!pmem)
            return NULL;
    }

    /*
     * Get the kernel pages corresponding to the huge memory.
     * Expectation is that the pages are pinned in the physical
     * memory and are not going to be faulted
     */
    down_read(&current->mm->mmap_sem);
    spages = get_user_pages(current, current->mm, uspace_vmem,
                                        npages, 1, 0, pmem, NULL);
    up_read(&current->mm->mmap_sem);

    /*
     * If number of pinned pages are less than requested,
     * skip that segment config
     */
    if (spages != npages) {
        for (i = 0; i < spages; i++) {
            if (!PageReserved(pmem[i]))
                SetPageDirty(pmem[i]);
            page_cache_release(pmem[i]);
        }
        if (size)
            free_pages((unsigned long)pmem, get_order(size));

        return NULL;
    }

    hcfg->hcfg_uspace_vmem = (void *)uspace_vmem;
    hcfg->hcfg_mem = page_address(pmem[0]);
    hcfg->hcfg_npages = npages;
    hcfg->hcfg_free_size = mem_size;
    hcfg->hcfg_tot_size = mem_size;
    hcfg->hcfg_pages = pmem;

    return hcfg;
}

/*
 * This function configures the huge pages that  are required for
 * Vrouter kernel module. It receives the n_hpages of huge pages and the
 * corresponding user space Virtual memory addresses in hpages.
 * hpage_size contains the size of every huge page.
 * As of now, two sizes of huge pages are going to be received - 2M and
 * 1G. The memory required to hold 1G huge page in terms of 4K size
 * pages is 2M. So the received 2M pages are used to hold 1G huge pages.
 * The intention behind doing this is to avoid a dynamic allocation of the
 * memroy every time 1G pages need to be configured.  If no 2M pages are
 * received, we create 2M of memory for every 1G huge page using
 * __get_free_pages(). The memory required to hold 2M page in terms of
 * 4K huge pages is 4Kb, which is exactly one page - and is unlikely
 * to fail - leading to lesser failures.
 * As the huge page memory is in use for the complete life time of
 * Vrouter module, there is no 'put'/'free'/'delete' routines provided
 * for the release of the memory. These huge pages are de-referenced
 * only at the time of removal of the module.
 */
int
vr_huge_pages_config(uint64_t *hpages, int n_hpages, int *hpage_size)
{
    int i, spages, succeeded_pages = 0;
    struct page **pmem;
    struct vr_hpage_config *temp, *hcfg;

    /* If memory is already inited, nothing to do further */
    if (vr_hpage_config_inited == true)
        return -EEXIST;

    /* Initialise 2Mb pages first - this memory can be used later for 1G  */
    spages =  1 + (VR_MEM_2M - 1) / PAGE_SIZE;
    for (i = 0; i < n_hpages; i++) {

        if (hpage_size[i] != VR_MEM_2M)
            continue;

        if (__vr_huge_page_get(hpages[i], spages, hpage_size[i], NULL))
            succeeded_pages++;
    }

    for (i = 0; i < n_hpages; i++) {

        if (hpage_size[i] == VR_MEM_2M)
            continue;

        temp = NULL;
        pmem = NULL;

        spages =  1 + (hpage_size[i] - 1) / PAGE_SIZE;

        /* if we can use 2M pages, try to find a free page */
        if ((spages * sizeof(struct page *)) <= VR_MEM_2M) {
            temp = vr_huge_page_2M_get();
            if (temp)
                pmem = (struct page **)temp->hcfg_mem;
        }

        hcfg = __vr_huge_page_get(hpages[i], spages, hpage_size[i], pmem);
        if (hcfg) {
            succeeded_pages++;
            if (temp) {
                temp->hcfg_free_size = 0;
                hcfg->hcfg_mem_attached = 1;
            }
        }
    }

    if (!succeeded_pages)
        return -ENOMEM;

    /* Lets consider, partial success also init complete */
    vr_hpage_config_inited = true;

    if (succeeded_pages < n_hpages)
        return -E2BIG;

    return 0;
}

void
vr_huge_pages_exit(void)
{
    int i, j, iter;
    struct vr_hpage_config *hcfg;

    if (!vr_hcfg)
        return;

    for (iter = 0; iter < 2; iter++) {
        for (i = 0; i < VR_MAX_HUGE_PAGES; i++) {
            hcfg = vr_hcfg + i;
            if (!hcfg->hcfg_uspace_vmem)
                continue;

            if (iter == 0) {
                if (hcfg->hcfg_tot_size == VR_MEM_2M)
                    continue;
            }

            /* Put back the pages after marking dirty */
            for (j = 0; j < hcfg->hcfg_npages; j++) {
                if (!PageReserved(hcfg->hcfg_pages[j]))
                    SetPageDirty(hcfg->hcfg_pages[j]);
                page_cache_release(hcfg->hcfg_pages[j]);
                hcfg->hcfg_pages[j] = NULL;
            }

            if (!hcfg->hcfg_mem_attached) {
                free_pages((unsigned long)hcfg->hcfg_pages,
                      get_order((hcfg->hcfg_npages * sizeof(struct page *))));
            }

            memset(hcfg, 0, sizeof(*hcfg));
        }
    }

    kfree(vr_hcfg);
    vr_hcfg = NULL;
    vr_hpage_config_inited = false;

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
    int msize;

    if (!vr_hcfg) {
        msize = sizeof(struct vr_hpage_config) * VR_MAX_HUGE_PAGES;
        vr_hcfg = (struct vr_hpage_config *) kzalloc(msize, GFP_ATOMIC);
        if (!vr_hcfg)
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
