/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2012 Lennart Poettering

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

#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>

#include "macro.h"
#include "util.h"
#include "mmap-cache.h"

int main(int argc, char *argv[]) {
        int x, y, z, r;
        char px[] = "/tmp/testmmapXXXXXXX", py[] = "/tmp/testmmapYXXXXXX", pz[] = "/tmp/testmmapZXXXXXX";
        MMapCache *m;
        void *p, *q;

        assert_se(m = mmap_cache_new());

        x = mkostemp_safe(px, O_RDWR|O_CLOEXEC);
        assert_se(x >= 0);
        unlink(px);

        y = mkostemp_safe(py, O_RDWR|O_CLOEXEC);
        assert_se(y >= 0);
        unlink(py);

        z = mkostemp_safe(pz, O_RDWR|O_CLOEXEC);
        assert_se(z >= 0);
        unlink(pz);

        r = mmap_cache_get(m, x, PROT_READ, 0, false, 1, 2, NULL, &p);
        assert_se(r >= 0);

        r = mmap_cache_get(m, x, PROT_READ, 0, false, 2, 2, NULL, &q);
        assert_se(r >= 0);

        assert_se((uint8_t*) p + 1 == (uint8_t*) q);

        r = mmap_cache_get(m, x, PROT_READ, 1, false, 3, 2, NULL, &q);
        assert_se(r >= 0);

        assert_se((uint8_t*) p + 2 == (uint8_t*) q);

        r = mmap_cache_get(m, x, PROT_READ, 0, false, 16ULL*1024ULL*1024ULL, 2, NULL, &p);
        assert_se(r >= 0);

        r = mmap_cache_get(m, x, PROT_READ, 1, false, 16ULL*1024ULL*1024ULL+1, 2, NULL, &q);
        assert_se(r >= 0);

        assert_se((uint8_t*) p + 1 == (uint8_t*) q);

        mmap_cache_unref(m);

        safe_close(x);
        safe_close(y);
        safe_close(z);

        return 0;
}
