/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2013 Lennart Poettering

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

#include <fcntl.h>
#include <sys/mman.h>

#include "util.h"
#include "log.h"

#include "sd-bus.h"
#include "sd-memfd.h"
#include "bus-message.h"
#include "bus-error.h"
#include "bus-kernel.h"

int main(int argc, char *argv[]) {
        _cleanup_free_ char *bus_name = NULL, *address = NULL;
        void *p;
        sd_bus *a, *b;
        int r, bus_ref;
        sd_bus_message *m;
        sd_memfd *f;

        log_set_max_level(LOG_DEBUG);

        bus_ref = bus_kernel_create("deine-mutter", &bus_name);
        if (bus_ref == -ENOENT)
                return EXIT_TEST_SKIP;

        assert_se(bus_ref >= 0);

        address = strappend("kernel:path=", bus_name);
        assert_se(address);

        r = sd_bus_new(&a);
        assert_se(r >= 0);

        r = sd_bus_new(&b);
        assert_se(r >= 0);

        r = sd_bus_set_address(a, address);
        assert_se(r >= 0);

        r = sd_bus_set_address(b, address);
        assert_se(r >= 0);

        r = sd_bus_start(a);
        assert_se(r >= 0);

        r = sd_bus_start(b);
        assert_se(r >= 0);

        r = sd_bus_message_new_method_call(b, ":1.1", "/a/path", "an.inter.face", "AMethod", &m);
        assert_se(r >= 0);

        r = sd_bus_message_open_container(m, 'r', "ayay");
        assert_se(r >= 0);

        r = sd_bus_message_append_array_space(m, 'y', 32, &p);
        assert_se(r >= 0);

        memset(p, 'L', 32);

        r = sd_memfd_new_and_map(&f, 32, &p);
        assert_se(r >= 0);

        memset(p, 'P', 32);
        munmap(p, 32);

        r = sd_memfd_set_size(f, 32);
        assert_se(r >= 0);

        r = sd_bus_message_append_array_memfd(m, 'y', f);
        assert_se(r >= 0);

        r = sd_bus_message_close_container(m);
        assert_se(r >= 0);

        r = bus_message_seal(m, 55);
        assert_se(r >= 0);

        bus_message_dump(m);

        r = sd_bus_send(b, m, NULL);
        assert_se(r >= 0);

        sd_bus_message_unref(m);

        sd_bus_unref(a);
        sd_bus_unref(b);
        sd_memfd_free(f);

        return 0;
}
