/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/mman.h>
#include <unistd.h>

#include "fd-util.h"
#include "mmap-cache.h"
#include "tests.h"
#include "tmpfile-util.h"

int main(int argc, char *argv[]) {
        MMapFileDescriptor *fx;
        int x, y, z;
        char px[] = "/tmp/testmmapXXXXXXX", py[] = "/tmp/testmmapYXXXXXX", pz[] = "/tmp/testmmapZXXXXXX";
        MMapCache *m;
        void *p, *q;

        test_setup_logging(LOG_DEBUG);

        ASSERT_NOT_NULL(m = mmap_cache_new());

        ASSERT_OK(x = mkostemp_safe(px));
        (void) unlink(px);

        ASSERT_OK_POSITIVE(mmap_cache_add_fd(m, x, PROT_READ, &fx));

        ASSERT_OK(y = mkostemp_safe(py));
        (void) unlink(py);

        ASSERT_OK(z = mkostemp_safe(pz));
        (void) unlink(pz);

        ASSERT_OK(mmap_cache_fd_get(fx, 0, false, 1, 2, NULL, &p));

        ASSERT_OK(mmap_cache_fd_get(fx, 0, false, 2, 2, NULL, &q));

        ASSERT_PTR_EQ((uint8_t*) p + 1, (uint8_t*) q);

        ASSERT_OK(mmap_cache_fd_get(fx, 1, false, 3, 2, NULL, &q));

        ASSERT_PTR_EQ((uint8_t*) p + 2, (uint8_t*) q);

        ASSERT_OK(mmap_cache_fd_get(fx, 0, false, 16ULL*1024ULL*1024ULL, 2, NULL, &p));

        ASSERT_OK(mmap_cache_fd_get(fx, 1, false, 16ULL*1024ULL*1024ULL+1, 2, NULL, &q));

        ASSERT_PTR_EQ((uint8_t*) p + 1, (uint8_t*) q);

        mmap_cache_fd_free(fx);
        mmap_cache_unref(m);

        safe_close(x);
        safe_close(y);
        safe_close(z);

        return 0;
}
