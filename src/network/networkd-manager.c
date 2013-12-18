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

#include "path-util.h"
#include "networkd.h"
#include "libudev-private.h"
#include "udev-util.h"

int manager_new(Manager **ret) {
        _cleanup_manager_free_ Manager *m = NULL;
        int r;

        m = new0(Manager, 1);
        if (!m)
                return -ENOMEM;

        r = sd_event_default(&m->event);
        if (r < 0)
                return r;

        sd_event_set_watchdog(m->event, true);

        r = sd_rtnl_open(RTMGRP_LINK | RTMGRP_IPV4_IFADDR, &m->rtnl);
        if (r < 0)
                return r;

        m->udev = udev_new();
        if (!m->udev)
                return -ENOMEM;

        m->udev_monitor = udev_monitor_new_from_netlink(m->udev, "udev");
        if (!m->udev_monitor)
                return -ENOMEM;

        m->links = hashmap_new(uint64_hash_func, uint64_compare_func);
        if (!m->links)
                return -ENOMEM;

        m->bridges = hashmap_new(string_hash_func, string_compare_func);
        if (!m->bridges)
                return -ENOMEM;

        LIST_HEAD_INIT(m->networks);

        m->network_dirs = strv_new("/etc/systemd/network/",
                        "/run/systemd/network/",
                        "/usr/lib/systemd/network",
#ifdef HAVE_SPLIT_USER
                        "/lib/systemd/network",
#endif
                        NULL);
        if (!m->network_dirs)
                return -ENOMEM;

        if (!path_strv_canonicalize_uniq(m->network_dirs))
                return -ENOMEM;

        *ret = m;
        m = NULL;

        return 0;
}

void manager_free(Manager *m) {
        Network *network;
        Bridge *bridge;
        Link *link;

        udev_monitor_unref(m->udev_monitor);
        udev_unref(m->udev);
        sd_event_source_unref(m->udev_event_source);
        sd_event_unref(m->event);

        while ((network = m->networks))
                network_free(network);

        while ((link = hashmap_first(m->links)))
                link_free(link);
        hashmap_free(m->links);

        while ((bridge = hashmap_first(m->bridges)))
                bridge_free(bridge);
        hashmap_free(m->bridges);

        strv_free(m->network_dirs);
        sd_rtnl_unref(m->rtnl);

        free(m);
}

int manager_load_config(Manager *m) {
        int r;

        /* update timestamp */
        paths_check_timestamp(m->network_dirs, &m->network_dirs_ts_usec, true);

        r = bridge_load(m);
        if (r < 0)
                return r;

        r = network_load(m);
        if (r < 0)
                return r;

        return 0;
}

bool manager_should_reload(Manager *m) {
        return paths_check_timestamp(m->network_dirs, &m->network_dirs_ts_usec, false);
}

static int manager_process_link(Manager *m, struct udev_device *device) {
        Link *link;
        int r;

        if (streq_ptr(udev_device_get_action(device), "remove")) {
                uint64_t ifindex;

                log_debug("Link removed: %s", udev_device_get_sysname(device));

                ifindex = udev_device_get_ifindex(device);
                link = hashmap_get(m->links, &ifindex);
                if (!link)
                        return 0;

                link_free(link);
        } else {
                log_debug("New link: %s", udev_device_get_sysname(device));

                r = link_add(m, device);
                if (r < 0) {
                        log_error("Could not handle link %s: %s",
                                        udev_device_get_sysname(device),
                                        strerror(-r));
                }
        }

        return 0;
}

int manager_udev_enumerate_links(Manager *m) {
        _cleanup_udev_enumerate_unref_ struct udev_enumerate *e = NULL;
        struct udev_list_entry *item = NULL, *first = NULL;
        int r;

        assert(m);

        e = udev_enumerate_new(m->udev);
        if (!e)
                return -ENOMEM;

        r = udev_enumerate_add_match_subsystem(e, "net");
        if (r < 0)
                return r;

        r = udev_enumerate_add_match_is_initialized(e);
        if (r < 0)
                return r;

        r = udev_enumerate_scan_devices(e);
        if (r < 0)
                return r;

        first = udev_enumerate_get_list_entry(e);
        udev_list_entry_foreach(item, first) {
                _cleanup_udev_device_unref_ struct udev_device *d = NULL;
                int k;

                d = udev_device_new_from_syspath(m->udev, udev_list_entry_get_name(item));
                if (!d)
                        return -ENOMEM;

                k = manager_process_link(m, d);
                if (k < 0)
                        r = k;
        }

        return r;
}

static int manager_dispatch_link_udev(sd_event_source *source, int fd, uint32_t revents, void *userdata) {
        Manager *m = userdata;
        struct udev_monitor *monitor = m->udev_monitor;
        _cleanup_udev_device_unref_ struct udev_device *device = NULL;

        device = udev_monitor_receive_device(monitor);
        if (!device)
                return -ENOMEM;

        manager_process_link(m, device);
        return 0;
}

int manager_udev_listen(Manager *m) {
        int r;

        r = udev_monitor_filter_add_match_subsystem_devtype(m->udev_monitor, "net", NULL);
        if (r < 0) {
                log_error("Could not add udev monitor filter: %s", strerror(-r));
                return r;
        }

        r = udev_monitor_enable_receiving(m->udev_monitor);
        if (r < 0) {
                log_error("Could not enable udev monitor");
                return r;
        }

        r = sd_event_add_io(m->event,
                        udev_monitor_get_fd(m->udev_monitor),
                        EPOLLIN, manager_dispatch_link_udev,
                        m, &m->udev_event_source);
        if (r < 0)
                return r;

        return 0;
}

static int manager_rtnl_process_link(sd_rtnl *rtnl, sd_rtnl_message *message, void *userdata) {
        Manager *m = userdata;
        Link *link;
        int r, ifindex;

        r = sd_rtnl_message_link_get_ifindex(message, &ifindex);
        if (r < 0)
                return 0;

        link = hashmap_get(m->links, &ifindex);
        if (!link)
                return 0;

        r = link_update(link, message);
        if (r < 0)
                return 0;

        return 1;
}

int manager_rtnl_listen(Manager *m) {
        int r;

        r = sd_rtnl_attach_event(m->rtnl, m->event, 0);
        if (r < 0)
                return r;

        r = sd_rtnl_add_match(m->rtnl, RTM_NEWLINK, &manager_rtnl_process_link, m);
        if (r < 0)
                return r;

        return 0;
}
