/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <unistd.h>

#include "async.h"
#include "fs-util.h"
#include "tmpfile-util.h"
#include "tests.h"

static bool test_async = false;

static void *async_func(void *arg) {
        test_async = true;

        return NULL;
}

TEST(test_async) {
        _cleanup_(unlink_tempfilep) char name[] = "/tmp/test-asynchronous_close.XXXXXX";
        int fd;

        fd = mkostemp_safe(name);
        assert_se(fd >= 0);
        asynchronous_close(fd);

        assert_se(asynchronous_job(async_func, NULL) >= 0);
        assert_se(asynchronous_sync(NULL) >= 0);

        sleep(1);

        assert_se(fcntl(fd, F_GETFD) == -1);
        assert_se(errno == EBADF);
        assert_se(test_async);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
