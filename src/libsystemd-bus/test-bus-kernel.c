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
        int r, pipe_fds[2];

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

        r = sd_bus_get_unique_name(a, &ua);
        assert_se(r >= 0);

        printf("unique a: %s\n", ua);

        r = sd_bus_get_unique_name(b, &ub);
        assert_se(r >= 0);

        printf("unique b: %s\n", ub);

        {
                //FIXME:
                struct kdbus_cmd_match cmd_match;

                cmd_match.size = sizeof(cmd_match);
                cmd_match.src_id = KDBUS_MATCH_SRC_ID_ANY;

                r = ioctl(sd_bus_get_fd(a), KDBUS_CMD_MATCH_ADD, &cmd_match);
                assert_se(r >= 0);

                r = ioctl(sd_bus_get_fd(b), KDBUS_CMD_MATCH_ADD, &cmd_match);
                assert_se(r >= 0);
        }

        r = sd_bus_emit_signal(a, "/foo/bar/waldo", "waldo.com", "Piep", "sss", "I am a string", "/this/is/a/path", "and.this.a.domain.name");
        assert_se(r >= 0);

        r = sd_bus_process(b, &m);
        assert_se(r > 0);
        assert_se(m);

        bus_message_dump(m);
        assert_se(sd_bus_message_rewind(m, true) >= 0);

        r = sd_bus_message_read(m, "s", &the_string);
        assert_se(r >= 0);
        assert_se(streq(the_string, "I am a string"));

        sd_bus_message_unref(m);
        m = NULL;

        r = sd_bus_request_name(a, "net.x0pointer.foobar", 0);
        assert_se(r >= 0);

        r = sd_bus_message_new_method_call(b, "net.x0pointer.foobar", "/a/path", "an.inter.face", "AMethod", &m);
        assert_se(r >= 0);

        assert_se(pipe2(pipe_fds, O_CLOEXEC) >= 0);

        assert_se(write(pipe_fds[1], "x", 1) == 1);

        close_nointr_nofail(pipe_fds[1]);
        pipe_fds[1] = -1;

        r = sd_bus_message_append(m, "h", pipe_fds[0]);
        assert_se(r >= 0);

        close_nointr_nofail(pipe_fds[0]);
        pipe_fds[0] = -1;

        r = sd_bus_send(b, m, NULL);
        assert_se(r >= 0);

        for (;;) {
                sd_bus_message_unref(m);
                m = NULL;
                r = sd_bus_process(a, &m);
                assert_se(r > 0);
                assert_se(m);

                bus_message_dump(m);
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

        sd_bus_unref(a);
        sd_bus_unref(b);

        return 0;
}
