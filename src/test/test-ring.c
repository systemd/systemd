/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2014 David Herrmann <dh.herrmann@gmail.com>

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

#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <locale.h>
#include <errno.h>

#include "def.h"
#include "ring.h"
#include "util.h"

static void test_ring(void) {
        static const char buf[8192];
        struct ring r;
        size_t l;
        struct iovec vec[2];
        int s;

        memset(&r, 0, sizeof(r));

        l = ring_peek(&r, vec);
        assert_se(l == 0);

        s = ring_push(&r, buf, 2048);
        assert_se(!s);
        assert_se(ring_get_size(&r) == 2048);

        l = ring_peek(&r, vec);
        assert_se(l == 1);
        assert_se(vec[0].iov_len == 2048);
        assert_se(!memcmp(vec[0].iov_base, buf, vec[0].iov_len));
        assert_se(ring_get_size(&r) == 2048);

        ring_pull(&r, 2048);
        assert_se(ring_get_size(&r) == 0);

        l = ring_peek(&r, vec);
        assert_se(l == 0);
        assert_se(ring_get_size(&r) == 0);

        s = ring_push(&r, buf, 2048);
        assert_se(!s);
        assert_se(ring_get_size(&r) == 2048);

        l = ring_peek(&r, vec);
        assert_se(l == 1);
        assert_se(vec[0].iov_len == 2048);
        assert_se(!memcmp(vec[0].iov_base, buf, vec[0].iov_len));
        assert_se(ring_get_size(&r) == 2048);

        s = ring_push(&r, buf, 1);
        assert_se(!s);
        assert_se(ring_get_size(&r) == 2049);

        l = ring_peek(&r, vec);
        assert_se(l == 2);
        assert_se(vec[0].iov_len == 2048);
        assert_se(vec[1].iov_len == 1);
        assert_se(!memcmp(vec[0].iov_base, buf, vec[0].iov_len));
        assert_se(!memcmp(vec[1].iov_base, buf, vec[1].iov_len));
        assert_se(ring_get_size(&r) == 2049);

        ring_pull(&r, 2048);
        assert_se(ring_get_size(&r) == 1);

        l = ring_peek(&r, vec);
        assert_se(l == 1);
        assert_se(vec[0].iov_len == 1);
        assert_se(!memcmp(vec[0].iov_base, buf, vec[0].iov_len));
        assert_se(ring_get_size(&r) == 1);

        ring_pull(&r, 1);
        assert_se(ring_get_size(&r) == 0);

        s = ring_push(&r, buf, 2048);
        assert_se(!s);
        assert_se(ring_get_size(&r) == 2048);

        s = ring_push(&r, buf, 2049);
        assert_se(!s);
        assert_se(ring_get_size(&r) == 4097);

        l = ring_peek(&r, vec);
        assert_se(l == 1);
        assert_se(vec[0].iov_len == 4097);
        assert_se(!memcmp(vec[0].iov_base, buf, vec[0].iov_len));
        assert_se(ring_get_size(&r) == 4097);

        ring_pull(&r, 1);
        assert_se(ring_get_size(&r) == 4096);

        s = ring_push(&r, buf, 4096);
        assert_se(!s);
        assert_se(ring_get_size(&r) == 8192);

        l = ring_peek(&r, vec);
        assert_se(l == 2);
        assert_se(vec[0].iov_len == 8191);
        assert_se(vec[1].iov_len == 1);
        assert_se(!memcmp(vec[0].iov_base, buf, vec[0].iov_len));
        assert_se(!memcmp(vec[1].iov_base, buf, vec[1].iov_len));
        assert_se(ring_get_size(&r) == 8192);

        ring_clear(&r);
        assert_se(ring_get_size(&r) == 0);
}

int main(int argc, char *argv[]) {
        log_parse_environment();
        log_open();

        test_ring();

        return 0;
}
