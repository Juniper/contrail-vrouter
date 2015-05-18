/*
 * vr_uvhost.c - implements a user-space vhost server that peers with
 * the vhost client inside qemu (version 2.1 and later).
 *
 * Copyright (c) 2014 Juniper Networks, Inc. All rights reserved.
 */

#include "vr_dpdk.h"
#include "vr_dpdk_usocket.h"
#include "vr_uvhost.h"
#include "vr_uvhost_client.h"
#include "vr_uvhost_msg.h"
#include "vr_uvhost_util.h"

#include <pthread.h>
#include <stdint.h>
#include <unistd.h>
#include <linux/vhost.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>

#include <rte_errno.h>

/* Global variables */
vr_uvh_exit_callback_t vr_uvhost_exit_fn;

/*
 * vr_uvhost_init - initializes the user space vhost server and waits
 * for messages from the netlink thread or qemu clients. The netlink thread
 * sends messages on a UNIX pipe in order to specify the names of the UNIX
 * domain socket on which a qemu client will connect. Once this message is
 * received, the vhost server creates the UNIX domain socket and includes it
 * in the list of fds it waits on.
 *
 * Returns 0 on success, error otherwise.
 */
int
vr_uvhost_init(pthread_t *th, vr_uvh_exit_callback_t exit_fn)
{
    if (pthread_create(th, NULL, vr_uvhost_start, NULL)) {
        return -1;
    }

    vr_uvhost_exit_fn = exit_fn;
    return 0;
}

/*
 * vr_uvhost_exit - exits the user space vhost server thread. Also forces
 * other threads in the process to exit by calling the process exit
 * callback.
 *
 * Returns nothing.
 */
static void
vr_uvhost_exit(void)
{
    vr_uvhost_exit_fn();

    return;
}

void
vr_uvhost_wakeup(void)
{
    struct vr_dpdk_lcore *lcore = vr_dpdk.lcores[VR_DPDK_UVHOST_LCORE_ID];

    if (likely(lcore->lcore_event_fd > 0)) {
        eventfd_write(lcore->lcore_event_fd, 1);
    }
}

/*
 * vr_uvhost_start - starts the user space vhost server
 *
 * Returns NULL if an error occurs. Otherwise, it runs forever.
 */
void *
vr_uvhost_start(void *arg)
{
    int s = 0, ret, err;
    struct sockaddr_un sun;
    fd_set *rfdset, *wfdset;
    struct vr_dpdk_lcore *lcore = vr_dpdk.lcores[rte_lcore_id()];

    vr_uvhost_client_init();

    vr_uvhost_log("Starting uvhost server...\n");
    lcore->lcore_event_fd = eventfd(0, 0);
    if (lcore->lcore_event_fd == -1) {
        vr_uvhost_log("    error creating event FD: %s (%d)\n",
                        rte_strerror(errno), errno);
        goto error;
    }
    vr_uvhost_log("    server event FD is %d\n", lcore->lcore_event_fd);

    s = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    if (s == -1) {
        vr_uvhost_log("    error creating server socket: %s (%d)\n",
                        rte_strerror(errno), errno);
        goto error;
    }
    vr_uvhost_log("    server socket FD is %d\n", s);

    memset(&sun, 0, sizeof(sun));
    sun.sun_family = AF_UNIX;
    strncpy(sun.sun_path, VR_UVH_NL_SOCK, sizeof(sun.sun_path) - 1);

    mkdir(VR_SOCKET_DIR, VR_SOCKET_DIR_MODE);
    unlink(sun.sun_path);
    ret = bind(s, (struct sockaddr *) &sun, sizeof(sun));
    if (ret == -1) {
        vr_uvhost_log("    error binding server FD %d to %s: %s (%d)\n",
                        s, sun.sun_path, rte_strerror(errno), errno);
        goto error;
    }

    if (listen(s, 1) == -1) {
        vr_uvhost_log("    error listening server socket FD %d: %s (%d)\n",
                        s, rte_strerror(errno), errno);
        goto error;
    }

    vr_uvhost_fdset_init();

    if (vr_uvhost_add_fd(lcore->lcore_event_fd, UVH_FD_READ, NULL, NULL)) {
        vr_uvhost_log("    error adding server event FD %d\n", lcore->lcore_event_fd);
        goto error;
    }
    if (vr_uvhost_add_fd(s, UVH_FD_READ, NULL, vr_uvh_nl_listen_handler)) {
        vr_uvhost_log("    error adding server socket FD %d\n", s);
        goto error;
    }

    while (1) {
        vr_uvh_recalc_max_fd();
        rfdset = vr_uvh_rfdset_p();
        wfdset = vr_uvh_wfdset_p();

        if (select(vr_uvh_max_fd()+1, rfdset, wfdset, NULL, NULL) == -1) {
            vr_uvhost_log("    error selecting FDs: %s (%d)\n",
                            rte_strerror(errno), errno);
            goto error;
        }

        if (vr_dpdk_is_stop_flag_set())
            break;

        if (vr_uvh_call_fd_handlers()) {
            vr_uvhost_log("    error calling socket handlers\n");
            goto error;
        }
    }

error:

    err = errno;
    if (s) {
        close(s);
        unlink(sun.sun_path);
    }
    if (lcore->lcore_event_fd > 0) {
        close(lcore->lcore_event_fd);
        lcore->lcore_event_fd = 0;
    }

    vr_uvhost_exit();
    errno = err;

    return NULL;
}

