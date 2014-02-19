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
#include <sys/uio.h>

#include "log.h"
#include "macro.h"
#include "util.h"

#include "sd-memfd.h"

int main(int argc, char *argv[]) {
        sd_memfd *m;
        char *s, *name;
        uint64_t sz;
        int r, fd;
        FILE *f = NULL;
        char buf[3] = {};
        struct iovec iov[3] = {};
        char bufv[3][3] = {};

        log_set_max_level(LOG_DEBUG);

        r = sd_memfd_new(&m, NULL);
        if (r == -ENOENT)
                return EXIT_TEST_SKIP;

        assert_se(r >= 0);

        assert_se(sd_memfd_get_name(m, &name) >= 0);
        log_info("name: %s", name);
        free(name);

        r = sd_memfd_map(m, 0, 12, (void**) &s);
        assert_se(r >= 0);

        strcpy(s, "----- world");

        r = sd_memfd_set_sealed(m, 1);
        assert_se(r == -ETXTBSY);

        assert_se(write(sd_memfd_get_fd(m), "he", 2) == 2);
        assert_se(write(sd_memfd_get_fd(m), "XXX", 3) == 3);
        assert_se(streq(s, "heXXX world"));

        /* fix "hello" */
        assert_se(lseek(sd_memfd_get_fd(m), 2, SEEK_SET) == 2);
        assert_se(write(sd_memfd_get_fd(m), "ll", 2) == 2);

        assert_se(sd_memfd_get_file(m, &f) >= 0);
        fputc('o', f);
        fflush(f);

        /* check content  */
        assert_se(streq(s, "hello world"));

        assert_se(munmap(s, 12) == 0);

        r = sd_memfd_get_sealed(m);
        assert_se(r == 0);

        r = sd_memfd_get_size(m, &sz);
        assert_se(r >= 0);
        assert_se(sz = page_size());

        /* truncate it */
        r = sd_memfd_set_size(m, 6);
        assert_se(r >= 0);

        /* get back new value */
        r = sd_memfd_get_size(m, &sz);
        assert_se(r >= 0);
        assert_se(sz == 6);

        r = sd_memfd_set_sealed(m, 1);
        assert_se(r >= 0);

        r = sd_memfd_get_sealed(m);
        assert_se(r == 1);

        fd = sd_memfd_dup_fd(m);
        assert_se(fd >= 0);

        sd_memfd_free(m);

        /* new sd_memfd, same underlying memfd */
        r = sd_memfd_new_from_fd(&m, fd);
        assert_se(r >= 0);

        /* we did truncate it to 6 */
        r = sd_memfd_get_size(m, &sz);
        assert_se(r >= 0 && sz == 6);

        /* map it, check content */
        r = sd_memfd_map(m, 0, 12, (void **)&s);
        assert_se(r >= 0);

        /* we only see the truncated size */
        assert_se(streq(s, "hello "));

        /* it was already sealed */
        r = sd_memfd_set_sealed(m, 1);
        assert_se(r == -EALREADY);

        /* we cannot break the seal, it is mapped */
        r = sd_memfd_set_sealed(m, 0);
        assert_se(r == -ETXTBSY);

        /* unmap it; become the single owner */
        assert_se(munmap(s, 12) == 0);

        /* now we can do flip the sealing */
        r = sd_memfd_set_sealed(m, 0);
        assert_se(r == 0);
        r = sd_memfd_get_sealed(m);
        assert_se(r == 0);

        r = sd_memfd_set_sealed(m, 1);
        assert_se(r == 0);
        r = sd_memfd_get_sealed(m);
        assert_se(r == 1);

        r = sd_memfd_set_sealed(m, 0);
        assert_se(r == 0);
        r = sd_memfd_get_sealed(m);
        assert_se(r == 0);

        /* seek at 2, read() 2 bytes */
        assert_se(lseek(fd, 2, SEEK_SET) == 2);
        assert_se(read(fd, buf, 2) == 2);

        /* check content */
        assert_se(memcmp(buf, "ll", 2) == 0);

        /* writev it out*/
        iov[0].iov_base = (char *)"ABC";
        iov[0].iov_len = 3;
        iov[1].iov_base = (char *)"DEF";
        iov[1].iov_len = 3;
        iov[2].iov_base = (char *)"GHI";
        iov[2].iov_len = 3;
        assert_se(pwritev(fd, iov, 3, 0) == 9);

        /* readv it back */
        iov[0].iov_base = bufv[0];
        iov[0].iov_len = 3;
        iov[1].iov_base = bufv[1];
        iov[1].iov_len = 3;
        iov[2].iov_base = bufv[2];
        iov[2].iov_len = 3;
        assert_se(preadv(fd, iov, 3, 0) == 9);

        /* check content */
        assert_se(memcmp(bufv[0], "ABC", 3) == 0);
        assert_se(memcmp(bufv[1], "DEF", 3) == 0);
        assert_se(memcmp(bufv[2], "GHI", 3) == 0);

        sd_memfd_free(m);

        return 0;
}
