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

int manager_new(Manager **ret) {
        _cleanup_manager_free_ Manager *m = NULL;
        int r;

        m = new0(Manager, 1);
        if (!m)
                return -ENOMEM;

        r = sd_event_default(&m->event);
        if (r < 0)
                return r;

        r = sd_rtnl_open(0, &m->rtnl);
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
        udev_monitor_unref(m->udev_monitor);
        udev_unref(m->udev);
        sd_event_source_unref(m->udev_event_source);
        sd_event_unref(m->event);
        hashmap_free(m->links);
        strv_free(m->network_dirs);
        sd_rtnl_unref(m->rtnl);

        free(m);
}

static int manager_process_link(Manager *m, struct udev_device *device) {
        Link *link;
        int r;

        if (streq_ptr(udev_device_get_action(device), "remove")) {
                uint64_t ifindex;

                ifindex = udev_device_get_ifindex(device);
                link = hashmap_get(m->links, &ifindex);
                if (!link)
                        return 0;

                link_free(link);
        } else {
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
        struct udev_list_entry *item = NULL, *first = NULL;
        struct udev_enumerate *e;
        int r;

        assert(m);

        e = udev_enumerate_new(m->udev);
        if (!e) {
                r = -ENOMEM;
                goto finish;
        }

        r = udev_enumerate_add_match_subsystem(e, "net");
        if (r < 0)
                goto finish;

        r = udev_enumerate_add_match_tag(e, "systemd-networkd");
        if (r < 0)
                goto finish;

        r = udev_enumerate_scan_devices(e);
        if (r < 0)
                goto finish;

        first = udev_enumerate_get_list_entry(e);
        udev_list_entry_foreach(item, first) {
                struct udev_device *d;
                int k;

                d = udev_device_new_from_syspath(m->udev, udev_list_entry_get_name(item));
                if (!d) {
                        r = -ENOMEM;
                        goto finish;
                }

                k = manager_process_link(m, d);
                udev_device_unref(d);

                if (k < 0)
                        r = k;
        }

finish:
        if (e)
                udev_enumerate_unref(e);

        return r;
}

static int manager_dispatch_link_udev(sd_event_source *source, int fd, uint32_t revents, void *userdata) {
        Manager *m = userdata;
        struct udev_monitor *monitor = m->udev_monitor;
        struct udev_device *device;
        int r;

        device = udev_monitor_receive_device(monitor);
        if (!device)
                return -ENOMEM;

        r = manager_process_link(m, device);
        if (r < 0)
                return r;

        udev_device_unref(device);

        return 0;
}

int manager_udev_listen(Manager *m) {
        int r;

        r = udev_monitor_filter_add_match_subsystem_devtype(m->udev_monitor, "net", NULL);
        if (r < 0) {
                log_error("Could not add udev monitor filter: %s", strerror(-r));
                return r;
        }

        r = udev_monitor_filter_add_match_tag(m->udev_monitor, "systemd-networkd");
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
