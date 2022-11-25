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
        void *userdata;
};

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
