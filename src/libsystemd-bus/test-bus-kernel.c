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

#include "util.h"

#include "sd-bus.h"
#include "bus-message.h"
#include "bus-error.h"
#include "bus-kernel.h"

int main(int argc, char *argv[]) {
        _cleanup_close_ int bus_ref = -1;
        _cleanup_free_ char *bus_name = NULL, *address = NULL;
        _cleanup_bus_message_unref_ sd_bus_message *m = NULL;
        const char *ua = NULL, *ub = NULL, *the_string = NULL;
        sd_bus *a, *b;
        int r;

        bus_ref = bus_kernel_create("deine-mutter", &bus_name);
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

        r = sd_bus_get_unique_name(a, &ua);
        assert_se(r >= 0);

        printf("unique a: %s\n", ua);

        r = sd_bus_get_unique_name(b, &ub);
        assert_se(r >= 0);

        printf("unique b: %s\n", ub);

        r = sd_bus_emit_signal(a, "/foo", "waldo.com", "Piep", "s", "I am a string");
        assert_se(r >= 0);

        r = sd_bus_process(b, &m);
        assert_se(r > 0);
        assert_se(m);

        bus_message_dump(m);
        assert_se(sd_bus_message_rewind(m, true) >= 0);

        r = sd_bus_message_read(m, "s", &the_string);
        assert_se(r >= 0);
        assert_se(streq(the_string, "I am a string"));

        sd_bus_unref(a);
        sd_bus_unref(b);

        return 0;
}
