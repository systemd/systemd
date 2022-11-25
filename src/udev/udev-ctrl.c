/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <poll.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/un.h>
#include <unistd.h>

#include "sd-event.h"

#include "alloc-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "format-util.h"
#include "io-util.h"
#include "socket-util.h"
#include "strxcpyx.h"
#include "udev-ctrl.h"

struct UdevCtrl {
        unsigned n_ref;
        int sock;
        int sock_connect;
        union sockaddr_union saddr;
        socklen_t addrlen;
        bool bound;
        bool connected;
        bool maybe_disconnected;
        sd_event *event;
        sd_event_source *event_source;
        sd_event_source *event_source_connect;
        Varlink *varlink;
        void *userdata;
};

int udev_ctrl_new_from_fd(UdevCtrl **ret, int fd) {
        _cleanup_close_ int sock = -EBADF;
        UdevCtrl *uctrl;

        assert(ret);

        if (fd < 0) {
                sock = socket(AF_UNIX, SOCK_SEQPACKET|SOCK_NONBLOCK|SOCK_CLOEXEC, 0);
                if (sock < 0)
                        return log_error_errno(errno, "Failed to create socket: %m");
        }

        uctrl = new(UdevCtrl, 1);
        if (!uctrl)
                return -ENOMEM;

        *uctrl = (UdevCtrl) {
                .n_ref = 1,
                .sock = fd >= 0 ? fd : TAKE_FD(sock),
                .sock_connect = -EBADF,
                .bound = fd >= 0,
        };

        uctrl->saddr.un = (struct sockaddr_un) {
                .sun_family = AF_UNIX,
                .sun_path = "/run/udev/control",
        };

        uctrl->addrlen = SOCKADDR_UN_LEN(uctrl->saddr.un);

        *ret = TAKE_PTR(uctrl);
        return 0;
}

int udev_ctrl_new_with_link(UdevCtrl **ret, Varlink *link) {
        UdevCtrl *uctrl;
        int r;

        assert(ret);
        assert(link);

        r = udev_ctrl_new_from_fd(&uctrl, -1);
        if (r < 0)
                return r;

        uctrl->varlink = varlink_ref(link);

        *ret = TAKE_PTR(uctrl);
        return 0;
}

int udev_ctrl_enable_receiving(UdevCtrl *uctrl) {
        assert(uctrl);

        if (uctrl->bound)
                return 0;

        (void) sockaddr_un_unlink(&uctrl->saddr.un);
        if (bind(uctrl->sock, &uctrl->saddr.sa, uctrl->addrlen) < 0)
                return log_error_errno(errno, "Failed to bind udev control socket: %m");

        if (listen(uctrl->sock, 0) < 0)
                return log_error_errno(errno, "Failed to listen udev control socket: %m");

        uctrl->bound = true;
        return 0;
}

static void udev_ctrl_disconnect(UdevCtrl *uctrl) {
        if (!uctrl)
                return;

        uctrl->event_source_connect = sd_event_source_unref(uctrl->event_source_connect);
        uctrl->sock_connect = safe_close(uctrl->sock_connect);
}

static UdevCtrl *udev_ctrl_free(UdevCtrl *uctrl) {
        assert(uctrl);

        udev_ctrl_disconnect(uctrl);

        sd_event_source_unref(uctrl->event_source);
        safe_close(uctrl->sock);

        sd_event_unref(uctrl->event);

        varlink_unref(uctrl->varlink);

        return mfree(uctrl);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(UdevCtrl, udev_ctrl, udev_ctrl_free);

int udev_ctrl_attach_event(UdevCtrl *uctrl, sd_event *event) {
        int r;

        assert_return(uctrl, -EINVAL);
        assert_return(!uctrl->event, -EBUSY);

        if (event)
                uctrl->event = sd_event_ref(event);
        else {
                r = sd_event_default(&uctrl->event);
                if (r < 0)
                        return r;
        }

        return 0;
}

sd_event_source *udev_ctrl_get_event_source(UdevCtrl *uctrl) {
        assert(uctrl);

        return uctrl->event_source;
}

static void udev_ctrl_disconnect_and_listen_again(UdevCtrl *uctrl) {
        udev_ctrl_disconnect(uctrl);
        udev_ctrl_unref(uctrl);
        (void) sd_event_source_set_enabled(uctrl->event_source, SD_EVENT_ON);
        /* We don't return NULL here because uctrl is not freed */
}

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(UdevCtrl*, udev_ctrl_disconnect_and_listen_again, NULL);
