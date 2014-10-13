#ifndef FAKE_NETLINK_H
#define FAKE_NETLINK_H

/*
 * This is "fake" implementation of Netlink provided to serve Netlink layer
 * over raw socket (or other type of socket) on BSD system where Netlink
 * itself is not implemented. It is not part of system as in case of Linux.
 */
#include <sys/types.h>

/* Only supported via "fake implementation" */
#define NETLINK_GENERIC 0


/*
 * Most of below structures and definitions have similar structures and
 * values as the original from Linux; this "compatibility" has been kept
 * in case hard coded values would be used in ported code instead of 
 * defines.
 */
/*
 * Netlink Message Header
 */
struct nlmsghdr {
    uint32_t    nlmsg_len;  /* Length of message including header;
                     * header needs to be padded to
                     * NLMSG_ALIGNTO */
    uint16_t    nlmsg_type; /* Message content */
    uint16_t    nlmsg_flags;    /* Additional flags */
    uint32_t    nlmsg_seq;  /* Sequence number */
    uint32_t    nlmsg_pid;  /* Sending process port ID */
};

/* Original alignment, from Linux, has been preserved */
#define NLMSG_ALIGNTO   4U
#define NLMSG_ALIGN(len) ( ((len)+NLMSG_ALIGNTO-1) & ~(NLMSG_ALIGNTO-1) )
#define NLMSG_HDRLEN    ((int) NLMSG_ALIGN(sizeof(struct nlmsghdr)))
#define NLMSG_LENGTH(len) ((len) + NLMSG_HDRLEN)
#define NLMSG_DATA(nlhp)  ((void*)(((char*)nlhp) + NLMSG_HDRLEN)
#define NLMSG_NEXT(nlhp,len)     ((len) -= NLMSG_ALIGN((nlhp)->nlmsg_len),  \
                  (struct nlmsghdr*)(((char*)(nlhp)) +      \
                   NLMSG_ALIGN((nlhp)->nlmsg_len)))

#define NLMSG_OK(nlh,len) ((len) >= (int)sizeof(struct nlmsghdr) &&         \
               (nlhp)->nlmsg_len >= sizeof(struct nlmsghdr) &&  \
               (nlhp)->nlmsg_len <= (len))


#define NLM_F_REQUEST   1   /* Request type of message */
#define NLM_F_MULTI 2   /* Part of multiple message sequence */
#define NLM_F_ACK   4   /* Ack reply */

#define NLM_F_DUMP  0x300
#define NLM_F_CREATE    0x400

#define NLMSG_ERROR 0x2
#define NLMSG_DONE  0x3 /* End of multi-message stream */

#define NLMSG_MIN_TYPE  0x10    /* Linux reserves below values for control
                                 * messages */


/*
 * Netlink Attribute Header.
 * NOTE: Payload, following the header, needs to be padded (at the end)
 * to NLA_ALIGNTO, but this padding is not included into the length of
 * attribute in the header. This means that the size taken by the
 * attribute in memory buffer (or packet) might be greater than the
 * header does state.
 */
struct nlattr {
    uint16_t    nla_len;    /* Length of attribute header
                             * aligned to NLA_ALIGNTO + payload
                             * length. */
    uint16_t    nla_type;
};

#define NLA_ALIGNTO 4
#define NLA_ALIGN(len)  (((len) + NLA_ALIGNTO - 1) & ~(NLA_ALIGNTO - 1))
#define NLA_HDRLEN  ((int) NLA_ALIGN(sizeof(struct nlattr)))

#endif /* FAKE_NETLINK_H */
