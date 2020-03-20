/*
 * vr_mem.c -- the memory driver. /dev/mem is extremely restrictive to be
 * of use reliably. hence, we need to have our own driver to expose memory.
 *
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#include <linux/init.h>
#include <linux/version.h>
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

    for (i = 0; i < VR_MAX_HUGE_PAGE_CFG; i++) {
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

/*
 * This api gets the kernel pages corresponding to the uspace huge pages
 * and pins them. Since kernel doesn't gaurantee contiguous huge pages
 * across huge pages, we use vmap to return kernel contiguous virtual
 * memory for those pages.
 */
static struct vr_hpage_config *
__vr_huge_page_get(uint64_t uspace_vmem, int npages, int mem_size, int hugepage_size, struct page **pmem)
{
    int i, size = 0, spages;
    struct vr_hpage_config *hcfg = NULL;
    void *kmem = NULL;

    for (i = 0; i < VR_MAX_HUGE_PAGE_CFG; i++) {
        hcfg = vr_hcfg + i;
        if (!hcfg->hcfg_mem)
            break;
    }

    if (i == VR_MAX_HUGE_PAGE_CFG)
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
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,9,0))
    spages = get_user_pages(uspace_vmem, npages, FOLL_WRITE, pmem, NULL);
#else

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,168))
    spages = get_user_pages(current, current->mm, uspace_vmem,
                                        npages, 1, pmem, NULL);
#else
    spages = get_user_pages(current, current->mm, uspace_vmem,
                                        npages, 1, 0, pmem, NULL);
#endif

#endif
    up_read(&current->mm->mmap_sem);

    /*
     * If number of pinned pages are less than requested,
     * skip that segment config
     */
    if (spages != npages) {
        for (i = 0; i < spages; i++) {
            if (!PageReserved(pmem[i]))
                SetPageDirty(pmem[i]);
            put_page(pmem[i]);
        }
        if (size)
            free_pages((unsigned long)pmem, get_order(size));

        return NULL;
    }
 
    kmem = page_address(pmem[0]);
    /*
     * The hugepages got may not be contiguous, hence map them into
     * kernel virtual memory contiguously if mem_size/hugepage_size > 1
     * i.e more than 1 hugepages are involved
     */
    if ((mem_size/hugepage_size) > 1) {
        kmem = vmap(pmem, npages, VM_MAP, PAGE_KERNEL);
        if (!kmem) {
            vr_printf("vmap failed\n");
            return NULL;
        }
    }

    hcfg->hcfg_uspace_vmem = (void *)uspace_vmem;
    hcfg->hcfg_mem = kmem;
    hcfg->hcfg_npages = npages;
    hcfg->hcfg_free_size = mem_size;
    hcfg->hcfg_tot_size = mem_size;
    hcfg->hcfg_pages = pmem;

    vr_printf("Pinned huge page uspace_vmem %p start_page_addr %p num 4k pages %d mem_size %d\n",
               hcfg->hcfg_uspace_vmem, hcfg->hcfg_mem, hcfg->hcfg_npages, hcfg->hcfg_tot_size);

    return hcfg;
}

/*
 * This function configures the huge pages that  are required for
 * Vrouter kernel module. It receives the n_hpages of huge pages and the
 * corresponding user space Virtual memory addresses in hpages.
 * hpage_size contains the size of every huge page.
 * hpage_mem_sz contains the size of huge page memory required.
 * Both 2MB and 1GB hugepage sizes are supported.
 * As the huge page memory is in use for the complete life time of
 * Vrouter module, there is no 'put'/'free'/'delete' routines provided
 * for the release of the memory. These huge pages are de-referenced
 * only at the time of removal of the module.
 */
int
vr_huge_pages_config(uint64_t *hpages, int n_hpages, int *hpage_size, int *hpage_mem_sz)
{
    int i, spages, succeeded_pages = 0;

    /* If memory is already inited, nothing to do further */
    if (vr_hpage_config_inited == true)
        return -EEXIST;

    for (i = 0; i < n_hpages; i++) {

        spages =  1 + (hpage_mem_sz[i] - 1) / PAGE_SIZE;

        vr_printf("Config Hugepage vmem %p psize %d mem_sz %d\n", hpages[i],
                  hpage_size[i], hpage_mem_sz[i]);

        if (__vr_huge_page_get(hpages[i], spages, hpage_mem_sz[i], hpage_size[i], NULL))
            succeeded_pages++;
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
    int i, j;
    struct vr_hpage_config *hcfg;

    if (!vr_hcfg)
        return;

    for (i = 0; i < VR_MAX_HUGE_PAGE_CFG; i++) {
        hcfg = vr_hcfg + i;
        if (!hcfg->hcfg_uspace_vmem)
            continue;

        /* If we vmapped the pages, release the vmapping first */
        if (is_vmalloc_addr(hcfg->hcfg_mem)) {
            vunmap(hcfg->hcfg_mem);
        }

        /* Put back the pages after marking dirty */
        for (j = 0; j < hcfg->hcfg_npages; j++) {
             if (!PageReserved(hcfg->hcfg_pages[j]))
                 SetPageDirty(hcfg->hcfg_pages[j]);
             put_page(hcfg->hcfg_pages[j]);
             hcfg->hcfg_pages[j] = NULL;
        }

        if (!hcfg->hcfg_mem_attached) {
            free_pages((unsigned long)hcfg->hcfg_pages,
                      get_order((hcfg->hcfg_npages * sizeof(struct page *))));
        }

        memset(hcfg, 0, sizeof(*hcfg));
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
        msize = sizeof(struct vr_hpage_config) * VR_MAX_HUGE_PAGE_CFG;
        vr_hcfg = (struct vr_hpage_config *) kzalloc(msize, GFP_ATOMIC);
        if (!vr_hcfg)
            return -ENOMEM;
    }

    return 0;
}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,11,0))
static int
mem_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
    struct vr_mem_object *vmo = (struct vr_mem_object *)vma->vm_private_data;
#else
static int
mem_fault(struct vm_fault *vmf)
{
    struct vr_mem_object *vmo =
        (struct vr_mem_object *)vmf->vma->vm_private_data;
#endif /*KERNEL_4.11*/
    void *va;
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

    if (is_vmalloc_addr(va)) {
        page = vmalloc_to_page(va);
    } else {
        page = virt_to_page(va);
    }
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
