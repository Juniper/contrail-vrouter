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

/* vhost interface driver for Contrail vrouter */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/module.h>
#include <sys/socket.h>
#include <sys/lock.h>
#include <sys/mutex.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/if_clone.h>
#include <net/if_types.h>
#include <net/ethernet.h>

#include "vr_freebsd.h"
#include "vr_proto.h"
#include "vhost.h"

static struct if_clone *vhost_cloner;
static const char vhost_name[] = "vhost";
static const u_int8_t vhost_mac[ETHER_ADDR_LEN] =
                { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };

static void
vhost_if_start(struct ifnet *ifp)
{
    struct vr_interface *vif;
    struct vhost_priv *sc;
    struct mbuf *m;
    int ret;

    sc = ifp->if_softc;
    KASSERT(sc, ("NULL sc"));

    vif = sc->vp_vifp;
    if (!vif) {
        vr_log(VR_DEBUG, "VIF not initialized\n");
        return;
    }

    mtx_lock(&sc->vp_mtx);
    for (;;) {
        IF_DEQUEUE(&ifp->if_snd, m);
        if (m) {
            ret = freebsd_to_vr(vif, m);
            if (ret) {
                vr_log(VR_ERR, "Cannot pass mbuf to vrouter "
                    "ret%d\n", ret);
                m_freem(m);
            }
        } else
            break;
    }

    mtx_unlock(&sc->vp_mtx);
}

static void
vhost_if_init(void *arg)
{
    struct vhost_priv *sc;
    struct ifnet *ifp;

    sc = (struct vhost_priv *)arg;

    mtx_lock(&sc->vp_mtx);
    ifp = sc->vp_ifp;
    ifp->if_drv_flags |= IFF_DRV_RUNNING;
    ifp->if_drv_flags &= ~IFF_DRV_OACTIVE;
    mtx_unlock(&sc->vp_mtx);
}

static int
vhost_if_ioctl(struct ifnet *ifp, u_long cmd, caddr_t data)
{
    struct ifreq *ifr;
    int error;

    ifr = (struct ifreq *)data;
    switch (cmd) {
    default:
        error = ether_ioctl(ifp, cmd, data);
        break;
    }

    return (error);
}

static int
vhost_clone_match(struct if_clone *ifc, const char *name)
{
    /* If name is not vhost0 than no match */
    if (strncmp(name, vhost_name, strlen(vhost_name)) == 0)
        return (1);

    return (0);
}

static int
vhost_clone_create(struct if_clone *ifc, char *name, size_t len,
    caddr_t params)
{
    struct vhost_priv *sc;
    struct ifnet *ifp;

    sc = malloc(sizeof(*sc), M_VROUTER, M_WAITOK|M_ZERO);

    ifp = if_alloc(IFT_ETHER);
    if (!ifp)
        return (ENOSPC);

    /* Set up private data */
    ifp->if_softc = sc;
    sc->vp_ifp = ifp;
    mtx_init(&sc->vp_mtx, "vhost_mtx", NULL, MTX_DEF);

    /* Set up interface */
    if_initname(ifp, name, IF_DUNIT_NONE);
    ifp->if_init = vhost_if_init;
    ifp->if_start = vhost_if_start;
    ifp->if_ioctl = vhost_if_ioctl;
    ifp->if_flags = (IFF_BROADCAST|IFF_SIMPLEX|IFF_MULTICAST);

    ether_ifattach(ifp, vhost_mac);
    ifp->if_capabilities = ifp->if_capenable = 0;

    return (0);
}

static int
vhost_clone_destroy(struct if_clone *ifc, struct ifnet *ifp)
{
    struct vhost_priv *sc;

    sc = ifp->if_softc;
    if_detach(ifp);
    if_free(ifp);

    mtx_destroy(&sc->vp_mtx);
    free(sc, M_VROUTER);

    return (0);
}

static int
vhost_cloner_init(void)
{
    vhost_cloner = if_clone_advanced(vhost_name, 1, vhost_clone_match,
        vhost_clone_create, vhost_clone_destroy);
    if (!vhost_cloner) {
        vr_log(VR_ERR, "Cannot create vhost cloner");
        return (1);
    }

    return (0);
}

void
vhost_if_add(struct vr_interface *vif)
{
    struct ifnet *ifp;
    struct vhost_priv *sc;

    KASSERT(vif, ("NULL vif"));

    ifp = (struct ifnet *)vif->vif_os;
    KASSERT(ifp, ("NULL ifp for vif:%p", vif));

    sc = ifp->if_softc;
    KASSERT(sc, ("NULL sc for ifp:%p", ifp));
    sc->vp_vifp = vif;
}

void
vhost_if_del(struct ifnet* ifp)
{
    struct vhost_priv *sc;

    KASSERT(ifp, ("NULL ifp"));

    sc = (struct vhost_priv *)ifp->if_softc;
    KASSERT(sc, ("NULL sc for ifp:%p", ifp));
    sc->vp_vifp = NULL;
}

void
vhost_exit(void)
{

    if_clone_detach(vhost_cloner);
}

int
vhost_init(void)
{
    return (vhost_cloner_init());
}

void
vhost_remove_xconnect(void)
{
    return;
}
