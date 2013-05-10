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

#include <sys/mman.h>

#include "log.h"
#include "macro.h"
#include "util.h"

#include "sd-memfd.h"

int main(int argc, char *argv[]) {
        sd_memfd *m;
        char *s;
        uint64_t sz;
        int r, fd;

        log_set_max_level(LOG_DEBUG);

        r = sd_memfd_new(&m);
        if (r == -ENOENT)
                return EXIT_TEST_SKIP;

        r = sd_memfd_map(m, 0, 6, (void**) &s);
        assert_se(r >= 0);

        strcpy(s, "hallo");
        assert_se(munmap(s, 6) == 0);

        assert_se(write(sd_memfd_get_fd(m), "he", 2) == 2);

        r = sd_memfd_get_sealed(m);
        assert_se(r == 0);

        r = sd_memfd_set_sealed(m, 1);
        assert_se(r >= 0);

        r = sd_memfd_get_sealed(m);
        assert_se(r == 1);

        r = sd_memfd_get_size(m, &sz);
        assert_se(r >= 0);
        assert_se(sz = page_size());

        r = sd_memfd_set_size(m, 6);
        assert_se(r >= 0);

        fd = sd_memfd_dup_fd(m);
        assert_se(fd >= 0);

        sd_memfd_free(m);

        r = sd_memfd_make(fd, &m);
        assert_se(r >= 0);

        r = sd_memfd_get_size(m, &sz);
        assert_se(r >= 0);
        assert_se(sz = 6);

        r = sd_memfd_map(m, 0, 6, (void**) &s);
        assert_se(r >= 0);

        assert_se(streq(s, "hello"));
        assert_se(munmap(s, 6) == 0);

        return 0;
}
