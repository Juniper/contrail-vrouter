/*
 * Copyright (c) 2017 Juniper Networks, Inc. All rights reserved.
 */
#include <ndis.h>
#include <netiodef.h>

#include "vr_interface.h"
#include "vr_packet.h"
#include "vr_windows.h"
#include "vr_mpls.h"
#include "vrouter.h"

#include "win_csum.h"
#include "win_packet.h"
#include "win_packet_raw.h"
#include "win_packet_impl.h"
#include "win_packet_splitting.h"
#include "windows_devices.h"
#include "windows_nbl.h"
#include "win_tx_postprocess.h"

static BOOLEAN physicalVifAdded;

static NDIS_MUTEX win_if_mutex;

void
win_if_lock(void)
{
    NDIS_WAIT_FOR_MUTEX(&win_if_mutex);
}

void
win_if_unlock(void)
{
    NDIS_RELEASE_MUTEX(&win_if_mutex);
}

BOOLEAN IsPacketPassthroughEnabled(void) {
    return !physicalVifAdded;
}

static int
win_if_add(struct vr_interface* vif)
{
    if (vif->vif_type == VIF_TYPE_STATS)
        return 0;

    if (vif->vif_name[0] == '\0')
        return -ENODEV;

    if (vif->vif_type == VIF_TYPE_PHYSICAL)
        physicalVifAdded = true;

    // Unlike FreeBSD/Linux, we don't have to register handlers here
    return 0;
}

static int
win_if_add_tap(struct vr_interface* vif)
{
    UNREFERENCED_PARAMETER(vif);
    // NOOP - no bridges on Windows
    return 0;
}

static int
win_if_del(struct vr_interface *vif)
{
    if (vif->vif_type == VIF_TYPE_PHYSICAL)
        physicalVifAdded = false;

    return 0;
}

static int
win_if_del_tap(struct vr_interface *vif)
{
    UNREFERENCED_PARAMETER(vif);
    // NOOP - no bridges on Windows; most *_drv_del function which call if_del_tap
    // also call if_del
    return 0;
}

static NDIS_SWITCH_PORT_DESTINATION
VrInterfaceToDestination(struct vr_interface *vif)
{
    NDIS_SWITCH_PORT_DESTINATION destination = { 0 };

    destination.PortId = vif->vif_port;
    destination.NicIndex = vif->vif_nic;

    return destination;
}

static VOID
MarkNetBufferListAsSafe(PNET_BUFFER_LIST NetBufferList)
{
    PNDIS_SWITCH_FORWARDING_DETAIL_NET_BUFFER_LIST_INFO fwd;

    fwd = NET_BUFFER_LIST_SWITCH_FORWARDING_DETAIL(NetBufferList);
    fwd->IsPacketDataSafe = TRUE;
}

static int
__win_if_tx(struct vr_interface *vif, struct vr_packet *pkt)
{
    PWIN_MULTI_PACKET postprocessedWinPacket = WinTxPostprocess(pkt);
    PWIN_PACKET_RAW winPacketRaw = WinMultiPacketToRawPacket(postprocessedWinPacket);

    PNET_BUFFER_LIST nbl = WinPacketRawToNBL(winPacketRaw);

    NDIS_SWITCH_PORT_DESTINATION newDestination = VrInterfaceToDestination(vif);
    VrSwitchObject->NdisSwitchHandlers.AddNetBufferListDestination(VrSwitchObject->NdisSwitchContext, nbl, &newDestination);

    MarkNetBufferListAsSafe(nbl);

    NdisAdvanceNetBufferListDataStart(nbl, pkt->vp_data, TRUE, NULL);

    ExFreePool(pkt);

    ASSERTMSG("Trying to pass non-leaf NBL to NdisFSendNetBufferLists", nbl->ChildRefCount == 0);

    NdisFSendNetBufferLists(VrSwitchObject->NdisFilterHandle,
        nbl,
        NDIS_DEFAULT_PORT_NUMBER,
        0);

    return 0;
}

static int
win_if_tx(struct vr_interface *vif, struct vr_packet* pkt)
{
    if (vif == NULL) {
        win_free_packet(pkt);
        return 0; // Sent into /dev/null
    }

    if (vif->vif_type == VIF_TYPE_AGENT)
        return pkt0_if_tx(vif, pkt);
    else
        return __win_if_tx(vif, pkt);
}

static int
win_if_rx(struct vr_interface *vif, struct vr_packet* pkt)
{
    // Since we are operating from virtual switch's PoV and not from OS's PoV, RXing is the same as TXing
    // On Linux, we receive the packet as an OS, but in Windows we are a switch to we simply push the packet to OS's networking stack
    // See vhost_tx for reference (it calls hif_ops->hif_rx)

    win_if_tx(vif, pkt);

    return 0;
}

static int
win_if_get_settings(struct vr_interface *vif, struct vr_interface_settings *settings)
{
    UNREFERENCED_PARAMETER(vif);
    UNREFERENCED_PARAMETER(settings);

    /* TODO: Implement */
    DbgPrint("%s(): dummy implementation called\n", __func__);

    return -EINVAL;
}

static unsigned int
win_if_get_mtu(struct vr_interface *vif)
{
    // vif_mtu is set correctly in win_register_nic
    return vif->vif_mtu;
}

static unsigned short
win_if_get_encap(struct vr_interface *vif)
{
    UNREFERENCED_PARAMETER(vif);

    /* TODO: Implement */
    DbgPrint("%s(): dummy implementation called\n", __func__);

    return VIF_ENCAP_TYPE_ETHER;
}

static struct vr_host_interface_ops win_host_interface_ops = {
    .hif_lock           = win_if_lock,
    .hif_unlock         = win_if_unlock,
    .hif_add            = win_if_add,
    .hif_del            = win_if_del,
    .hif_add_tap        = win_if_add_tap,
    .hif_del_tap        = win_if_del_tap,
    .hif_tx             = win_if_tx,
    .hif_rx             = win_if_rx,
    .hif_get_settings   = win_if_get_settings,
    .hif_get_mtu        = win_if_get_mtu,
    .hif_get_encap      = win_if_get_encap,
    .hif_stats_update   = NULL,
};

void
vr_host_vif_init(struct vrouter *router)
{
    UNREFERENCED_PARAMETER(router);
}

void
vr_host_interface_exit(void)
{
    /* Noop */
}

void
vhost_xconnect(void)
{
    struct vrouter *vrouter = vrouter_get(0);
    struct vr_interface *host_if;

    if (vrouter->vr_host_if != NULL) {
        host_if = vrouter->vr_host_if;
        vif_set_xconnect(host_if);

        if (host_if->vif_bridge != NULL)
            vif_set_xconnect(host_if->vif_bridge);
    }
}

void
vhost_remove_xconnect(void)
{
    struct vrouter *vrouter = vrouter_get(0);
    struct vr_interface *host_if;

    if (vrouter->vr_host_if != NULL) {
        host_if = vrouter->vr_host_if;
        vif_remove_xconnect(host_if);

        if (host_if->vif_bridge != NULL)
            vif_remove_xconnect(host_if->vif_bridge);
    }
}

struct vr_host_interface_ops *
vr_host_interface_init(void)
{
    NDIS_INIT_MUTEX(&win_if_mutex);

    return &win_host_interface_ops;
}
