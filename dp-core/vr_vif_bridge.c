/*
 * vr_vif_bridge.c -- small bridge table in an interface. Well, we could have
 * reused the original bridge table, but it adds some complexity to the
 * bridging code too.
 *
 * Copyright (c) 2014, Juniper Networks, Inc.
 * All rights reserved
 */
#include <vr_os.h>
#include "vr_message.h"
#include "vr_sandesh.h"
#include "vr_htable.h"
#include "vr_defs.h"
#include "vr_packet.h"
#include "vr_interface.h"
#include "vr_bridge.h"

#define VIF_BRIDGE_ENTRIES      1024
#define VIF_BRIDGE_OENTRIES     512

__attribute__packed__open__
struct vif_bridge_key {
    unsigned short vbk_vlan;
    unsigned char vbk_mac[VR_ETHER_ALEN];
} __attribute__packed__close__;

__attribute__packed__open__
struct vif_bridge_entry {
    vr_hentry_t vif_bridge_hentry;
    struct vif_bridge_key vbe_key;
    struct vr_interface *vbe_vif;
} __attribute__packed__close__;

static struct vif_bridge_entry *
vif_bridge_get(vr_htable_t htable, unsigned short vlan,
        unsigned char *mac)
{
    struct vif_bridge_key key;

    key.vbk_vlan = vlan;
    VR_MAC_COPY(key.vbk_mac, mac);

    return (struct vif_bridge_entry *)vr_htable_find_hentry(htable, &key, 0);
}

struct vr_interface *
vif_bridge_get_sub_interface(vr_htable_t htable, unsigned short vlan,
        unsigned char *mac)
{
    struct vif_bridge_entry *vbe;

    vbe = vif_bridge_get(htable, vlan, mac);
    if (!vbe)
        return NULL;
    return vbe->vbe_vif;
}

int
vif_bridge_get_index(struct vr_interface *pvif, struct vr_interface
        *vif, uint8_t *mac)
{
    struct vif_bridge_entry *be;

    if (!pvif || !pvif->vif_btable || !vif)
        return -1;

    be = vif_bridge_get(pvif->vif_btable, vif->vif_vlan_id, mac);
    if (!be)
        return -1;

    return be->vif_bridge_hentry.hentry_index;
}

static void
vif_bridge_free(vr_htable_t htable, vr_hentry_t *hentry,
        unsigned int index __attribute__unused__,
        void *data __attribute__unused__)
{
    struct vif_bridge_entry *be = (struct vif_bridge_entry *)hentry;

    if (!be)
        return;

    memset(&be->vbe_key, 0, sizeof(struct vif_bridge_key));
    be->vbe_vif = NULL;

    vr_htable_release_hentry(htable, hentry);
    return;
}

struct vif_bridge_entry *
vif_bridge_alloc(vr_htable_t htable, unsigned short vlan,
        unsigned char *mac)
{
    struct vif_bridge_key key;
    struct vif_bridge_entry *vbe;

    key.vbk_vlan = vlan;
    VR_MAC_COPY(key.vbk_mac, mac);

    vbe = (struct vif_bridge_entry *)vr_htable_find_free_hentry(htable,
                                                                &key, 0);
    if (!vbe)
        return NULL;

    memcpy(&vbe->vbe_key, &key, sizeof(key));
    return vbe;
}

int
vif_bridge_delete(struct vr_interface *pvif, struct vr_interface *vif,
        uint8_t *src_mac)
{
    struct vif_bridge_entry *be;

    if (!pvif->vif_btable)
        return -EINVAL;

    be = vif_bridge_get(pvif->vif_btable, vif->vif_vlan_id, src_mac);
    if (!be)
        return -ENOENT;

    vif_bridge_free(pvif->vif_btable, (vr_hentry_t *)be, 0, NULL);

    return 0;
}

int
vif_bridge_add(struct vr_interface *pvif, struct vr_interface *vif,
        uint8_t *src_mac)
{
    struct vif_bridge_entry *be;

    if (!pvif->vif_btable)
        return -EINVAL;

    be = vif_bridge_get(pvif->vif_btable, vif->vif_vlan_id, src_mac);
    if (!be) {
        be = vif_bridge_alloc(pvif->vif_btable, vif->vif_vlan_id, src_mac);
        if (!be)
            return -ENOMEM;
    }

    be->vbe_vif = vif;

    return 0;
}

vr_hentry_key
vif_bridge_get_key(vr_htable_t table, vr_hentry_t *entry, unsigned int
        *key_size)
{
    struct vif_bridge_entry *vif_be = CONTAINER_OF(vif_bridge_hentry,
                struct vif_bridge_entry, entry);

    if (!entry)
        return entry;

    if (key_size)
        *key_size = sizeof(struct vif_bridge_key);

    return (vr_hentry_key)(&vif_be->vbe_key);
}

void
vif_bridge_deinit(struct vr_interface *vif)
{
    if (!vif || !vif->vif_btable)
        return;

    vr_htable_reset(vif->vif_btable, vif_bridge_free, NULL);
    vr_htable_delete(vif->vif_btable);
    vif->vif_btable = NULL;

    return;
}

int
vif_bridge_init(struct vr_interface *vif)
{
    if (!vif)
        return -EINVAL;

    vif->vif_btable = vr_htable_create(vrouter_get(0), VIF_BRIDGE_ENTRIES,
            VIF_BRIDGE_OENTRIES, sizeof(struct vif_bridge_entry),
            sizeof(struct vif_bridge_key), 0, vif_bridge_get_key);

    if (!vif->vif_btable)
        return -ENOMEM;

    return 0;
}
