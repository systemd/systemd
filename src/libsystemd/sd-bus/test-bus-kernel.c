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

#include "sd-bus.h"

#include "alloc-util.h"
#include "bus-dump.h"
#include "bus-kernel.h"
#include "bus-util.h"
#include "fd-util.h"
#include "log.h"
#include "util.h"

int main(int argc, char *argv[]) {
        _cleanup_close_ int bus_ref = -1;
        _cleanup_free_ char *name = NULL, *bus_name = NULL, *address = NULL, *bname = NULL;
        _cleanup_bus_message_unref_ sd_bus_message *m = NULL;
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        const char *ua = NULL, *ub = NULL, *the_string = NULL;
        sd_bus *a, *b;
        int r, pipe_fds[2];
        const char *nn;

        log_set_max_level(LOG_DEBUG);

        assert_se(asprintf(&name, "deine-mutter-%u", (unsigned) getpid()) >= 0);

        bus_ref = bus_kernel_create_bus(name, false, &bus_name);
        if (bus_ref == -ENOENT)
                return EXIT_TEST_SKIP;

        assert_se(bus_ref >= 0);

        address = strappend("kernel:path=", bus_name);
        assert_se(address);

        r = sd_bus_new(&a);
        assert_se(r >= 0);

        r = sd_bus_new(&b);
        assert_se(r >= 0);

        r = sd_bus_set_description(a, "a");
        assert_se(r >= 0);

        r = sd_bus_set_address(a, address);
        assert_se(r >= 0);

        r = sd_bus_set_address(b, address);
        assert_se(r >= 0);

        assert_se(sd_bus_negotiate_timestamp(a, 1) >= 0);
        assert_se(sd_bus_negotiate_creds(a, true, _SD_BUS_CREDS_ALL) >= 0);

        assert_se(sd_bus_negotiate_timestamp(b, 0) >= 0);
        assert_se(sd_bus_negotiate_creds(b, true, 0) >= 0);

        r = sd_bus_start(a);
        assert_se(r >= 0);

        r = sd_bus_start(b);
        assert_se(r >= 0);

        assert_se(sd_bus_negotiate_timestamp(b, 1) >= 0);
        assert_se(sd_bus_negotiate_creds(b, true, _SD_BUS_CREDS_ALL) >= 0);

        r = sd_bus_get_unique_name(a, &ua);
        assert_se(r >= 0);
        printf("unique a: %s\n", ua);

        r = sd_bus_get_description(a, &nn);
        assert_se(r >= 0);
        printf("name of a: %s\n", nn);

        r = sd_bus_get_unique_name(b, &ub);
        assert_se(r >= 0);
        printf("unique b: %s\n", ub);

        r = sd_bus_get_description(b, &nn);
        assert_se(r >= 0);
        printf("name of b: %s\n", nn);

        assert_se(bus_kernel_get_bus_name(b, &bname) >= 0);
        assert_se(endswith(bname, name));

        r = sd_bus_call_method(a, "this.doesnt.exist", "/foo", "meh.mah", "muh", &error, NULL, "s", "yayayay");
        assert_se(sd_bus_error_has_name(&error, SD_BUS_ERROR_SERVICE_UNKNOWN));
        assert_se(r == -EHOSTUNREACH);

        r = sd_bus_add_match(b, NULL, "interface='waldo.com',member='Piep'", NULL, NULL);
        assert_se(r >= 0);

        r = sd_bus_emit_signal(a, "/foo/bar/waldo", "waldo.com", "Piep", "sss", "I am a string", "/this/is/a/path", "and.this.a.domain.name");
        assert_se(r >= 0);

        r = sd_bus_try_close(b);
        assert_se(r == -EBUSY);

        r = sd_bus_process_priority(b, -10, &m);
        assert_se(r == 0);

        r = sd_bus_process(b, &m);
        assert_se(r > 0);
        assert_se(m);

        bus_message_dump(m, stdout, BUS_MESSAGE_DUMP_WITH_HEADER);
        assert_se(sd_bus_message_rewind(m, true) >= 0);

        r = sd_bus_message_read(m, "s", &the_string);
        assert_se(r >= 0);
        assert_se(streq(the_string, "I am a string"));

        sd_bus_message_unref(m);
        m = NULL;

        r = sd_bus_request_name(a, "net.x0pointer.foobar", 0);
        assert_se(r >= 0);

        r = sd_bus_message_new_method_call(b, &m, "net.x0pointer.foobar", "/a/path", "an.inter.face", "AMethod");
        assert_se(r >= 0);

        assert_se(pipe2(pipe_fds, O_CLOEXEC) >= 0);

        assert_se(write(pipe_fds[1], "x", 1) == 1);

        pipe_fds[1] = safe_close(pipe_fds[1]);

        r = sd_bus_message_append(m, "h", pipe_fds[0]);
        assert_se(r >= 0);

        pipe_fds[0] = safe_close(pipe_fds[0]);

        r = sd_bus_send(b, m, NULL);
        assert_se(r >= 0);

        for (;;) {
                sd_bus_message_unref(m);
                m = NULL;
                r = sd_bus_process(a, &m);
                assert_se(r > 0);
                assert_se(m);

                bus_message_dump(m, stdout, BUS_MESSAGE_DUMP_WITH_HEADER);
                assert_se(sd_bus_message_rewind(m, true) >= 0);

                if (sd_bus_message_is_method_call(m, "an.inter.face", "AMethod")) {
                        int fd;
                        char x;

                        r = sd_bus_message_read(m, "h", &fd);
                        assert_se(r >= 0);

                        assert_se(read(fd, &x, 1) == 1);
                        assert_se(x == 'x');
                        break;
                }
        }

        r = sd_bus_release_name(a, "net.x0pointer.foobar");
        assert_se(r >= 0);

        r = sd_bus_release_name(a, "net.x0pointer.foobar");
        assert_se(r == -ESRCH);

        r = sd_bus_try_close(a);
        assert_se(r >= 0);

        sd_bus_unref(a);
        sd_bus_unref(b);

        return 0;
}
