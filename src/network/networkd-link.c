/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2013 Tom Gundersen <teg@jklm.no>

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

#include <netinet/ether.h>
#include <linux/if.h>

#include "networkd.h"
#include "libudev-private.h"
#include "util.h"

int link_new(Manager *manager, struct udev_device *device, Link **ret) {
        _cleanup_link_free_ Link *link = NULL;
        uint64_t ifindex;
        int r;

        assert(device);
        assert(ret);

        link = new0(Link, 1);
        if (!link)
                return -ENOMEM;

        ifindex = udev_device_get_ifindex(device);
        if (ifindex <= 0)
                return -EINVAL;

        link->ifindex = ifindex;
        link->manager = manager;

        r = hashmap_put(manager->links, &ifindex, link);
        if (r < 0)
                return r;

        *ret = link;
        link = NULL;

        return 0;
}

void link_free(Link *link) {
        if (!link)
                return;

        network_free(link->network);

        hashmap_remove(link->manager->links, link);

        free(link);
}

int link_add(Manager *m, struct udev_device *device) {
        Link *link;
        Network *network;
        int r;
        uint64_t ifindex;

        assert(m);
        assert(device);

        ifindex = udev_device_get_ifindex(device);
        link = hashmap_get(m->links, &ifindex);
        if (link)
                return 0;

        r = link_new(m, device, &link);
        if (r < 0) {
                log_error("could not create link: %s", strerror(-r));
                return r;
        }

        r = network_get(m, device, &network);
        if (r < 0)
                return r == -ENOENT ? 0 : r;

        r = network_apply(m, network, link);
        if (r < 0)
                return r;

        return 0;
}

int link_up(Manager *manager, Link *link) {
        _cleanup_sd_rtnl_message_unref_ sd_rtnl_message *req = NULL;
        int r;

        r = sd_rtnl_message_link_new(RTM_NEWLINK, link->ifindex, 0, IFF_UP, &req);
        if (r < 0) {
                log_error("Could not allocate RTM_NEWLINK message");
                return r;
        }

        r = sd_rtnl_call(manager->rtnl, req, 0, NULL);
        if (r < 0) {
                log_error("Could not UP link: %s", strerror(-r));
                return r;
        }

        log_info("Link is UP");

        return 0;
}
