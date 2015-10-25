/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <net/if.h>
#include <stdlib.h>

#include "sd-netlink.h"

#include "loopback-setup.h"
#include "missing.h"
#include "netlink-util.h"

static int start_loopback(sd_netlink *rtnl) {
        _cleanup_netlink_message_unref_ sd_netlink_message *req = NULL;
        int r;

        r = sd_rtnl_message_new_link(rtnl, &req, RTM_SETLINK, LOOPBACK_IFINDEX);
        if (r < 0)
                return r;

        r = sd_rtnl_message_link_set_flags(req, IFF_UP, IFF_UP);
        if (r < 0)
                return r;

        r = sd_netlink_call(rtnl, req, 0, NULL);
        if (r < 0)
                return r;

        return 0;
}

static bool check_loopback(sd_netlink *rtnl) {
        _cleanup_netlink_message_unref_ sd_netlink_message *req = NULL, *reply = NULL;
        unsigned flags;
        int r;

        r = sd_rtnl_message_new_link(rtnl, &req, RTM_GETLINK, LOOPBACK_IFINDEX);
        if (r < 0)
                return false;

        r = sd_netlink_call(rtnl, req, 0, &reply);
        if (r < 0)
                return false;

        r = sd_rtnl_message_link_get_flags(reply, &flags);
        if (r < 0)
                return false;

        return flags & IFF_UP;
}

int loopback_setup(void) {
        _cleanup_netlink_unref_ sd_netlink *rtnl = NULL;
        int r;

        r = sd_netlink_open(&rtnl);
        if (r < 0)
                return r;

        r = start_loopback(rtnl);
        if (r < 0) {

                /* If we lack the permissions to configure the
                 * loopback device, but we find it to be already
                 * configured, let's exit cleanly, in order to
                 * supported unprivileged containers. */
                if (r == -EPERM && check_loopback(rtnl))
                        return 0;

                return log_warning_errno(r, "Failed to configure loopback device: %m");
        }

        return 0;
}
