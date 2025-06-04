/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/eventfd.h>

#include "sd-daemon.h"

#include "fd-util.h"
#include "parse-util.h"
#include "pidfd-util.h"
#include "process-util.h"
#include "strv.h"
#include "tests.h"
#include "time-util.h"

int main(int argc, char *argv[]) {
        _cleanup_strv_free_ char **l = NULL;
        int r, n, i;
        usec_t duration = USEC_PER_SEC / 10;

        test_setup_logging(LOG_DEBUG);

        if (argc >= 2) {
                unsigned x;

                ASSERT_OK(safe_atou(argv[1], &x));
                duration = x * USEC_PER_SEC;
        }

        n = sd_listen_fds_with_names(false, &l);
        if (n < 0) {
                log_error_errno(n, "Failed to get listening fds: %m");
                return EXIT_FAILURE;
        }

        for (i = 0; i < n; i++)
                log_info("fd=%i name=%s", SD_LISTEN_FDS_START + i, l[i]);

        sd_notify(0,
                  "STATUS=Starting up");
        usleep_safe(duration);

        sd_notify(0,
                  "STATUS=Running\n"
                  "READY=1");
        usleep_safe(duration);

        sd_notify(0,
                  "STATUS=Reloading\n"
                  "RELOADING=1");
        usleep_safe(duration);

        sd_notify(0,
                  "STATUS=Running\n"
                  "READY=1");
        usleep_safe(duration);

        sd_notify(0,
                  "STATUS=Quitting\n"
                  "STOPPING=1");
        usleep_safe(duration);

        _cleanup_close_ int fd = eventfd(0, EFD_CLOEXEC);
        ASSERT_OK_ERRNO(fd);

        r = sd_pidfd_get_inode_id(fd, NULL);
        ASSERT_TRUE(IN_SET(r, -EOPNOTSUPP, -EBADF));
        if (r == -EBADF) {
                safe_close(fd);
                ASSERT_OK_ERRNO(fd = pidfd_open(getpid_cached(), 0));
                ASSERT_OK(sd_pidfd_get_inode_id(fd, NULL));
        }

        return EXIT_SUCCESS;
}
