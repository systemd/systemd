/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <linux/fiemap.h>
#include <stdlib.h>
#include <unistd.h>

#include "argv-util.h"
#include "fd-util.h"
#include "hibernate-util.h"
#include "log.h"
#include "tests.h"

static int test_fiemap_one(const char *path) {
        _cleanup_free_ struct fiemap *fiemap = NULL;
        _cleanup_close_ int fd = -EBADF;
        int r;

        log_info("/* %s */", __func__);

        fd = open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
        if (fd < 0)
                return log_error_errno(errno, "failed to open %s: %m", path);
        r = read_fiemap(fd, &fiemap);
        if (r == -EOPNOTSUPP)
                exit(log_tests_skipped("Not supported"));
        if (r < 0)
                return log_error_errno(r, "Unable to read extent map for '%s': %m", path);
        log_info("extent map information for %s:", path);
        log_info("\t start: %" PRIu64, (uint64_t) fiemap->fm_start);
        log_info("\t length: %" PRIu64, (uint64_t) fiemap->fm_length);
        log_info("\t flags: %" PRIu32, fiemap->fm_flags);
        log_info("\t number of mapped extents: %" PRIu32, fiemap->fm_mapped_extents);
        log_info("\t extent count: %" PRIu32, fiemap->fm_extent_count);
        if (fiemap->fm_extent_count > 0)
                log_info("\t first extent location: %" PRIu64,
                         (uint64_t) (fiemap->fm_extents[0].fe_physical / page_size()));

        return 0;
}

TEST_RET(fiemap) {
        int r = 0;

        assert_se(test_fiemap_one(saved_argv[0]) == 0);
        for (int i = 1; i < saved_argc; i++) {
                int k = test_fiemap_one(saved_argv[i]);
                if (r == 0)
                        r = k;
        }

        return r;
}

static int intro(void) {
        if (getuid() != 0)
                log_warning("This program is unlikely to work for unprivileged users");

        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_DEBUG, intro);
