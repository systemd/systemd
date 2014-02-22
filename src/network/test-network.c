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

#include "networkd.h"

static void test_link(Manager *manager, struct udev_device *loopback) {
        Link *link = NULL;

        assert_se(link_new(manager, loopback, &link) >= 0);
        assert_se(link);
}

static void test_load_config(Manager *manager) {
/*  TODO: should_reload, is false if the config dirs do not exist, so
 *        so we can't do this test here, move it to a test for paths_check_timestamps
 *        directly
 *
 *        assert_se(network_should_reload(manager) == true);
*/
        assert_se(manager_load_config(manager) >= 0);
        assert_se(manager_should_reload(manager) == false);
}

static void test_network_get(Manager *manager, struct udev_device *loopback) {
        Network *network;

        /* let's assume that the test machine does not have a .network file
           that applies to the loopback device... */
        assert_se(network_get(manager, loopback, &network) == -ENOENT);
        assert_se(!network);
}

int main(void) {
        _cleanup_manager_free_ Manager *manager = NULL;
        struct udev *udev;
        struct udev_device *loopback;

        assert_se(manager_new(&manager) >= 0);

        test_load_config(manager);

        udev = udev_new();
        assert_se(udev);

        loopback = udev_device_new_from_syspath(udev, "/sys/class/net/lo");
        assert_se(loopback);
        assert_se(udev_device_get_ifindex(loopback) == 1);

        test_network_get(manager, loopback);

        test_link(manager, loopback);

        assert_se(manager_udev_listen(manager) >= 0);
        assert_se(manager_udev_enumerate_links(manager) >= 0);
        assert_se(manager_rtnl_listen(manager) >= 0);

        udev_device_unref(loopback);
        udev_unref(udev);
}
