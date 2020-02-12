/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <unistd.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "fs-util.h"
#include "macro.h"
#include "string-util.h"
#include "tests.h"
#include "tmpfile-util.h"
#include "xattr-util.h"

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
        test_getcrtime();

        return 0;
}
