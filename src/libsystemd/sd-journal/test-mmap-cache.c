/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

#include "fd-util.h"
#include "macro.h"
#include "mmap-cache.h"
#include "tmpfile-util.h"
#include "util.h"

int main(int argc, char *argv[]) {
        MMapFileDescriptor *fx;
        int x, y, z, r;
        char px[] = "/tmp/testmmapXXXXXXX", py[] = "/tmp/testmmapYXXXXXX", pz[] = "/tmp/testmmapZXXXXXX";
        MMapCache *m;
        void *p, *q;

        assert_se(m = mmap_cache_new());

        x = mkostemp_safe(px);
        assert_se(x >= 0);
        unlink(px);

        assert_se(fx = mmap_cache_add_fd(m, x, PROT_READ));

        y = mkostemp_safe(py);
        assert_se(y >= 0);
        unlink(py);

        z = mkostemp_safe(pz);
        assert_se(z >= 0);
        unlink(pz);

        r = mmap_cache_fd_get(fx, 0, false, 1, 2, NULL, &p);
        assert_se(r >= 0);

        r = mmap_cache_fd_get(fx, 0, false, 2, 2, NULL, &q);
        assert_se(r >= 0);

        assert_se((uint8_t*) p + 1 == (uint8_t*) q);

        r = mmap_cache_fd_get(fx, 1, false, 3, 2, NULL, &q);
        assert_se(r >= 0);

        assert_se((uint8_t*) p + 2 == (uint8_t*) q);

        r = mmap_cache_fd_get(fx, 0, false, 16ULL*1024ULL*1024ULL, 2, NULL, &p);
        assert_se(r >= 0);

        r = mmap_cache_fd_get(fx, 1, false, 16ULL*1024ULL*1024ULL+1, 2, NULL, &q);
        assert_se(r >= 0);

        assert_se((uint8_t*) p + 1 == (uint8_t*) q);

        mmap_cache_fd_free(fx);
        mmap_cache_unref(m);

        safe_close(x);
        safe_close(y);
        safe_close(z);

        return 0;
}
