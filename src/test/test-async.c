/* SPDX-License-Identifier: LGPL-2.1+ */

#include <fcntl.h>
#include <unistd.h>

#include "async.h"
#include "macro.h"
#include "tmpfile-util.h"
#include "util.h"

static bool test_async = false;

static void *async_func(void *arg) {
        test_async = true;

        return NULL;
}

int main(int argc, char *argv[]) {
        int fd;
        char name[] = "/tmp/test-asynchronous_close.XXXXXX";

        fd = mkostemp_safe(name);
        assert_se(fd >= 0);
        asynchronous_close(fd);

        assert_se(asynchronous_job(async_func, NULL) >= 0);

        assert_se(asynchronous_sync(NULL) >= 0);

        sleep(1);

        assert_se(fcntl(fd, F_GETFD) == -1);
        assert_se(test_async);

        (void) unlink(name);

        return 0;
}
