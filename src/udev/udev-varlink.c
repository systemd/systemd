/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "udev-manager.h"
#include "udev-varlink.h"

int manager_open_varlink(Manager *m) {
        int r;

        assert(m);
        assert(m->event);
        assert(!m->varlink_server);

        r = sd_varlink_server_new(&m->varlink_server, SD_VARLINK_SERVER_ROOT_ONLY|SD_VARLINK_SERVER_INHERIT_USERDATA);
        if (r < 0)
                return r;

        sd_varlink_server_set_userdata(m->varlink_server, m);

        r = sd_varlink_server_listen_address(m->varlink_server, UDEV_VARLINK_ADDRESS, 0600);
        if (r < 0)
                return r;

        r = sd_varlink_server_attach_event(m->varlink_server, m->event, SD_EVENT_PRIORITY_NORMAL);
        if (r < 0)
                return r;

        return 0;
}
