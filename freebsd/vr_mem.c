/*-
 * Copyright (c) 2014 Semihalf
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/module.h>
#include <sys/conf.h>

#include <vm/vm.h>
#include <vm/vm_object.h>
#include <vm/pmap.h>
#include <machine/pmap.h>

#include "vrouter.h"
#include "vr_flow.h"

int flowopen(struct cdev *, int, int, struct thread *);
int flowmmap(struct cdev *, vm_ooffset_t, vm_paddr_t *, int, vm_memattr_t *);
void vr_mem_exit(void);
int vr_mem_init(void);

int
flowopen(struct cdev *dev __unused, int flags, int fmt __unused,
    struct thread *td)
{

	return (0);
}

int flowmmap(struct cdev *kdev, vm_ooffset_t offset, vm_paddr_t *paddr,
    int prot, vm_memattr_t *memattr)
{
	struct vrouter *router;

	/* Support only for one vrouter */
	router = (struct vrouter *)vrouter_get(0);

	*paddr = vtophys(vr_flow_get_va(router, offset));
	return (0);
}

static struct cdev *mem_cdev;

static struct cdevsw mem_cdevsw = {
	.d_version =		D_VERSION,
	.d_flags =		D_MEM,
	.d_open =		flowopen,
	.d_mmap =		flowmmap,
	.d_name =		"flow",
};

void
vr_mem_exit(void)
{

	destroy_dev(mem_cdev);
}

int
vr_mem_init(void)
{

	mem_cdev = make_dev(&mem_cdevsw, 0, UID_ROOT, GID_KMEM, 0640, "flow");

	return (0);
}
