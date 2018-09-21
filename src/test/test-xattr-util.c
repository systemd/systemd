/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <unistd.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "macro.h"
#include "string-util.h"
#include "tests.h"
#include "xattr-util.h"

static void test_fgetxattrat_fake(void) {
        char t[] = "/var/tmp/xattrtestXXXXXX";
        _cleanup_close_ int fd = -1;
        const char *x;
        char v[3];
        int r;
        size_t size;

        assert_se(mkdtemp(t));
        x = strjoina(t, "/test");
        assert_se(touch(x) >= 0);

        r = setxattr(x, "user.foo", "bar", 3, 0);
        if (r < 0 && errno == EOPNOTSUPP) /* no xattrs supported on /var/tmp... */
                goto cleanup;
        assert_se(r >= 0);

        fd = open(t, O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOCTTY);
        assert_se(fd >= 0);

        assert_se(fgetxattrat_fake(fd, "test", "user.foo", v, 3, 0, &size) >= 0);
        assert_se(size == 3);
        assert_se(memcmp(v, "bar", 3) == 0);

        safe_close(fd);
        fd = open("/", O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOCTTY);
        assert_se(fd >= 0);
        assert_se(fgetxattrat_fake(fd, "usr", "user.idontexist", v, 3, 0, &size) == -ENODATA);

cleanup:
        assert_se(unlink(x) >= 0);
        assert_se(rmdir(t) >= 0);
}

static void test_getcrtime(void) {

        _cleanup_close_ int fd = -1;
        char ts[FORMAT_TIMESTAMP_MAX];
        const char *vt;
        usec_t usec, k;
        int r;

        assert_se(tmp_dir(&vt) >= 0);

        fd = open_tmpfile_unlinkable(vt, O_RDWR);
        assert_se(fd >= 0);

        r = fd_getcrtime(fd, &usec);
        if (r < 0)
                log_debug_errno(r, "btime: %m");
        else
                log_debug("btime: %s", format_timestamp(ts, sizeof(ts), usec));

        k = now(CLOCK_REALTIME);

        r = fd_setcrtime(fd, 1519126446UL * USEC_PER_SEC);
        if (!IN_SET(r, -EOPNOTSUPP, -ENOTTY)) {
                assert_se(fd_getcrtime(fd, &usec) >= 0);
                assert_se(k < 1519126446UL * USEC_PER_SEC ||
                          usec == 1519126446UL * USEC_PER_SEC);
        }
}

int main(void) {
        test_setup_logging(LOG_DEBUG);

        test_fgetxattrat_fake();
        test_getcrtime();

        return 0;
}
