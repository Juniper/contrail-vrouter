#ifndef FAKE_GENERIC_NETLINK_H
#define FAKE_GENERIC_NETLINK_H

#include <sys/types.h>

/*
 * Most of below structures and definitions have similar structures and
 * values as the original from Linux; this "compatibility" has been kept in case
 * hardcoded values would be used in ported code instead of defines.
 */
/*
 * Generic Netlink Message Header
 */
struct genlmsghdr {
    uint8_t    cmd;
    uint8_t    version;
    uint16_t    reserved;
};

#define GENL_HDRLEN    NLMSG_ALIGN(sizeof(struct genlmsghdr))

/*
 * Below identifiers have similar meaning as in Linux and the same
 * values; this is incomplete list as only values used by Contrail
 * code has been defined.
 */
enum {
    GENL_ID_GENERATE = 0,
    GENL_ID_CTRL = NLMSG_MIN_TYPE,
    CTRL_CMD_NEWFAMILY = 1,
    CTRL_CMD_GETFAMILY = 3,
    CTRL_ATTR_FAMILY_ID = 1,
    CTRL_ATTR_FAMILY_NAME,
};

#endif /* FAKE_GENERIC_NETLINK_H */

