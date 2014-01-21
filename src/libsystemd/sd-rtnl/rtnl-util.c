/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
 This file is part of systemd.

 Copyright (C) 2013 Tom Gundersen <teg@jklm.no>

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

#include <linux/rtnetlink.h>
#include <netinet/ether.h>

#include "sd-rtnl.h"

#include "rtnl-util.h"

int rtnl_set_link_name(sd_rtnl *rtnl, int ifindex, const char *name) {
        _cleanup_sd_rtnl_message_unref_ sd_rtnl_message *message = NULL;
        int r;

        assert(rtnl);
        assert(ifindex > 0);
        assert(name);

        r = sd_rtnl_message_link_new(RTM_SETLINK, ifindex, &message);
        if (r < 0)
                return r;

        r = sd_rtnl_message_append_string(message, IFLA_IFNAME, name);
        if (r < 0)
                return r;

        r = sd_rtnl_call(rtnl, message, 0, NULL);
        if (r < 0)
                return r;

        return 0;
}

int rtnl_set_link_properties(sd_rtnl *rtnl, int ifindex, const char *alias,
                             const struct ether_addr *mac, unsigned mtu) {
        _cleanup_sd_rtnl_message_unref_ sd_rtnl_message *message = NULL;
        bool need_update = false;
        int r;

        assert(rtnl);
        assert(ifindex > 0);

        if (!alias && !mac && mtu == 0)
                return 0;

        r = sd_rtnl_message_link_new(RTM_SETLINK, ifindex, &message);
        if (r < 0)
                return r;

        if (alias) {
                r = sd_rtnl_message_append_string(message, IFLA_IFALIAS, alias);
                if (r < 0)
                        return r;

                need_update = true;

        }

        if (mac) {
                r = sd_rtnl_message_append_ether_addr(message, IFLA_ADDRESS, mac);
                if (r < 0)
                        return r;

                need_update = true;
        }

        if (mtu > 0) {
                r = sd_rtnl_message_append_u32(message, IFLA_MTU, mtu);
                if (r < 0)
                        return r;

                need_update = true;
        }

        if  (need_update) {
                r = sd_rtnl_call(rtnl, message, 0, NULL);
                if (r < 0)
                        return r;
        }

        return 0;
}
