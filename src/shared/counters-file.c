/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "counters-file.h"
#include "fd-util.h"
#include "fs-util.h"
#include "log.h"
#include "memory-util.h"
#include "stat-util.h"

int counters_file_map(const char *path, size_t size, uint64_t version, void **ret) {
        _cleanup_close_ int fd = -EBADF;
        struct stat st;
        bool reset;
        void *p;
        int r;

        assert(path);
        assert(size >= sizeof(uint64_t));
        assert(size % sizeof(uint64_t) == 0);
        assert(version > 0);
        assert(ret);

        fd = open(path, O_RDWR|O_CREAT|O_CLOEXEC|O_NOCTTY|O_NOFOLLOW, 0644);
        if (fd < 0)
                return log_debug_errno(errno, "Failed to open counters file '%s': %m", path);

        if (fstat(fd, &st) < 0)
                return log_debug_errno(errno, "Failed to stat counters file '%s': %m", path);

        r = stat_verify_regular(&st);
        if (r < 0)
                return log_debug_errno(r, "Counters file '%s' is not a regular file: %m", path);

        /* If the file has a different size than we expect it has been written by a different version of
         * us, hence start from zero. */
        reset = (uint64_t) st.st_size != size;
        if (reset && ftruncate(fd, 0) < 0)
                return log_debug_errno(errno, "Failed to truncate counters file '%s': %m", path);

        r = posix_fallocate_loop(fd, /* offset= */ 0, size);
        if (r < 0)
                return log_debug_errno(r, "Failed to allocate counters file '%s': %m", path);

        p = mmap(/* addr= */ NULL, size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, /* offset= */ 0);
        if (p == MAP_FAILED)
                return log_debug_errno(errno, "Failed to map counters file '%s': %m", path);

        /* The version field comes first. A freshly allocated file reads as version 0. */
        uint64_t *v = p;
        if (reset || *v != version) {
                memzero(p, size);
                *v = version;
        }

        *ret = p;
        return 0;
}
