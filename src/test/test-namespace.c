/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2013 Zbigniew Jędrzejewski-Szmek

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

#include <libgen.h>

#include "namespace.h"
#include "util.h"

static void test_tmpdir(const char *id, const char *A, const char *B) {
        _cleanup_free_ char *a, *b;

        assert_se(setup_tmpdirs(id, &a, &b) == 0);
        assert(startswith(a, A));
        assert(startswith(b, B));
        assert(access(a, F_OK) == 0);
        assert(access(b, F_OK) == 0);

        assert_se(rmdir(a) == 0);
        assert_se(rmdir(b) == 0);

        assert(endswith(a, "/tmp"));
        assert(endswith(b, "/tmp"));

        assert_se(rmdir(dirname(a)) == 0);
        assert_se(rmdir(dirname(b)) == 0);
}

int main(int argc, char *argv[]) {
        test_tmpdir("abcd.service",
                    "/tmp/systemd-abcd.service-",
                    "/var/tmp/systemd-abcd.service-");

        test_tmpdir("sys-devices-pci0000:00-0000:00:1a.0-usb3-3\\x2d1-3\\x2d1:1.0-bluetooth-hci0.device",
                    "/tmp/systemd-sys-devices-pci0000:00-0000:00:1a.0-usb3-3\\x2d1-3\\x2d1:1.0-bluetooth-hci0.device-",
                    "/var/tmp/systemd-sys-devices-pci0000:00-0000:00:1a.0-usb3-3\\x2d1-3\\x2d1:1.0-bluetooth-hci0.device-");

        return 0;
}
