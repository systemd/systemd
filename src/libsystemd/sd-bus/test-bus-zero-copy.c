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
#include "bus-dump.h"

#define FIRST_ARRAY 17
#define SECOND_ARRAY 33

#define STRING_SIZE 123

int main(int argc, char *argv[]) {
        _cleanup_free_ char *name = NULL, *bus_name = NULL, *address = NULL;
        uint8_t *p;
        sd_bus *a, *b;
        int r, bus_ref;
        sd_bus_message *m;
        sd_memfd *f;
        uint64_t sz;
        uint32_t u32;
        size_t i, l;
        char *s;

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

        r = sd_bus_set_address(a, address);
        assert_se(r >= 0);

        r = sd_bus_set_address(b, address);
        assert_se(r >= 0);

        r = sd_bus_start(a);
        assert_se(r >= 0);

        r = sd_bus_start(b);
        assert_se(r >= 0);

        r = sd_bus_message_new_method_call(b, &m, ":1.1", "/a/path", "an.inter.face", "AMethod");
        assert_se(r >= 0);

        r = sd_bus_message_open_container(m, 'r', "aysay");
        assert_se(r >= 0);

        r = sd_bus_message_append_array_space(m, 'y', FIRST_ARRAY, (void**) &p);
        assert_se(r >= 0);

        p[0] = '<';
        memset(p+1, 'L', FIRST_ARRAY-2);
        p[FIRST_ARRAY-1] = '>';

        r = sd_memfd_new_and_map(&f, NULL, STRING_SIZE, (void**) &s);
        assert_se(r >= 0);

        s[0] = '<';
        for (i = 1; i < STRING_SIZE-2; i++)
                s[i] = '0' + (i % 10);
        s[STRING_SIZE-2] = '>';
        s[STRING_SIZE-1] = 0;
        munmap(s, STRING_SIZE);

        r = sd_memfd_get_size(f, &sz);
        assert_se(r >= 0);
        assert_se(sz == STRING_SIZE);

        r = sd_bus_message_append_string_memfd(m, f);
        assert_se(r >= 0);

        sd_memfd_free(f);

        r = sd_memfd_new_and_map(&f, NULL, SECOND_ARRAY, (void**) &p);
        assert_se(r >= 0);

        p[0] = '<';
        memset(p+1, 'P', SECOND_ARRAY-2);
        p[SECOND_ARRAY-1] = '>';
        munmap(p, SECOND_ARRAY);

        r = sd_memfd_get_size(f, &sz);
        assert_se(r >= 0);
        assert_se(sz == SECOND_ARRAY);

        r = sd_bus_message_append_array_memfd(m, 'y', f);
        assert_se(r >= 0);

        sd_memfd_free(f);

        r = sd_bus_message_close_container(m);
        assert_se(r >= 0);

        r = sd_bus_message_append(m, "u", 4711);
        assert_se(r >= 0);

        r = bus_message_seal(m, 55, 99*USEC_PER_SEC);
        assert_se(r >= 0);

        bus_message_dump(m, stdout, true);

        r = sd_bus_send(b, m, NULL);
        assert_se(r >= 0);

        sd_bus_message_unref(m);

        r = sd_bus_process(a, &m);
        assert_se(r > 0);

        bus_message_dump(m, stdout, true);
        sd_bus_message_rewind(m, true);

        r = sd_bus_message_enter_container(m, 'r', "aysay");
        assert_se(r > 0);

        r = sd_bus_message_read_array(m, 'y', (const void**) &p, &l);
        assert_se(r > 0);
        assert_se(l == FIRST_ARRAY);

        assert_se(p[0] == '<');
        for (i = 1; i < l-1; i++)
                assert_se(p[i] == 'L');
        assert_se(p[l-1] == '>');

        r = sd_bus_message_read(m, "s", &s);
        assert_se(r > 0);

        assert_se(s[0] == '<');
        for (i = 1; i < STRING_SIZE-2; i++)
                assert_se(s[i] == (char) ('0' + (i % 10)));
        assert_se(s[STRING_SIZE-2] == '>');
        assert_se(s[STRING_SIZE-1] == 0);

        r = sd_bus_message_read_array(m, 'y', (const void**) &p, &l);
        assert_se(r > 0);
        assert_se(l == SECOND_ARRAY);

        assert_se(p[0] == '<');
        for (i = 1; i < l-1; i++)
                assert_se(p[i] == 'P');
        assert_se(p[l-1] == '>');

        r = sd_bus_message_exit_container(m);
        assert_se(r > 0);

        r = sd_bus_message_read(m, "u", &u32);
        assert_se(r > 0);
        assert_se(u32 == 4711);

        sd_bus_message_unref(m);

        sd_bus_unref(a);
        sd_bus_unref(b);

        return 0;
}
