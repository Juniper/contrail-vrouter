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

#define VIF_BRIDGE_ENTRIES      1024
#define VIF_BRIDGE_OENTRIES     512

struct vif_bridge_key {
    unsigned short vbk_vlan;
    unsigned char vbk_mac[VR_ETHER_ALEN];
} __attribute__((packed));

struct vif_bridge_entry {
    struct vif_bridge_key vbe_key;
    struct vr_interface *vbe_vif;
} __attribute__((packed));

static bool
vif_bridge_valid(vr_htable_t htable, vr_hentry_t hentry,
        unsigned int index)
{
    struct vif_bridge_entry *be = (struct vif_bridge_entry *)hentry;

    if (!be->vbe_vif)
        return false;

    return true;
}

static struct vif_bridge_entry *
vif_bridge_get(vr_htable_t htable, unsigned short vlan,
        unsigned char *mac, int *index)
{
    struct vif_bridge_key key;

    key.vbk_vlan = vlan;
    VR_MAC_COPY(key.vbk_mac, mac);

    return (struct vif_bridge_entry *)vr_find_hentry(htable, &key, index);
}

struct vr_interface *
vif_bridge_get_sub_interface(vr_htable_t htable, unsigned short vlan,
        unsigned char *mac)
{
    struct vif_bridge_entry *vbe;

    vbe = vif_bridge_get(htable, vlan, mac, NULL);
    if (!vbe)
        return NULL;
    return vbe->vbe_vif;
}

int
vif_bridge_get_index(struct vr_interface *pvif, struct vr_interface *vif)
{
    int index = -1;

    if (!pvif || !pvif->vif_btable || !vif)
        return -1;

    (void)vif_bridge_get(pvif->vif_btable, vif->vif_vlan_id,
            vif->vif_src_mac, &index);
    return index;
}

static void
vif_bridge_free(vr_htable_t htable, vr_hentry_t hentry,
        unsigned int index __attribute__((unused)),
        void *data __attribute__((unused)))
{
    struct vif_bridge_entry *be = (struct vif_bridge_entry *)hentry;

    if (!be)
        return;

    memset(&be->vbe_key, 0, sizeof(struct vif_bridge_key));
    be->vbe_vif = NULL;

    return;
}

struct vif_bridge_entry *
vif_bridge_alloc(vr_htable_t htable, unsigned short vlan,
        unsigned char *mac, int *index)
{
    struct vif_bridge_key key;
    struct vif_bridge_entry *vbe;

    key.vbk_vlan = vlan;
    VR_MAC_COPY(key.vbk_mac, mac);

    vbe = vr_find_free_hentry(htable, &key, index);
    if (!vbe)
        return NULL;
    memcpy(&vbe->vbe_key, &key, sizeof(key));
    return vbe;
}

int
vif_bridge_delete(struct vr_interface *pvif, struct vr_interface *vif)
{
    struct vif_bridge_entry *be;

    if (!pvif->vif_btable)
        return -EINVAL;

    be = vif_bridge_get(pvif->vif_btable, vif->vif_vlan_id,
            vif->vif_src_mac, NULL);
    if (!be)
        return -ENOENT;

    vif_bridge_free(pvif->vif_btable, (vr_hentry_t)be, 0, NULL);

    return 0;
}

int
vif_bridge_add(struct vr_interface *pvif, struct vr_interface *vif)
{
    struct vif_bridge_entry *be;
    int index = -1;

    if (!pvif->vif_btable)
        return -EINVAL;

    be = vif_bridge_get(pvif->vif_btable, vif->vif_vlan_id,
            vif->vif_src_mac, &index);
    if (!be) {
        be = vif_bridge_alloc(pvif->vif_btable, vif->vif_vlan_id,
                vif->vif_src_mac, &index);
        if (!be)
            return -ENOMEM;
    }

    be->vbe_vif = vif;

    return 0;
}

void
vif_bridge_deinit(struct vr_interface *vif)
{
    if (!vif || !vif->vif_btable)
        return;

    vr_htable_trav(vif->vif_btable, 0, vif_bridge_free, NULL);
    vr_htable_delete(vif->vif_btable);
    vif->vif_btable = NULL;

    return;
}

int
vif_bridge_init(struct vr_interface *vif)
{
    if (!vif)
        return -EINVAL;

    vif->vif_btable = vr_htable_create(VIF_BRIDGE_ENTRIES,
            VIF_BRIDGE_OENTRIES, sizeof(struct vif_bridge_entry),
            sizeof(struct vif_bridge_key), vif_bridge_valid);
    if (!vif->vif_btable)
        return -ENOMEM;

    return 0;
}
