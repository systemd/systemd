/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "sd-daemon.h"

#include "parse-util.h"
#include "strv.h"
#include "time-util.h"

int main(int argc, char *argv[]) {
        _cleanup_strv_free_ char **l = NULL;
        int n, i;
        usec_t duration = USEC_PER_SEC / 10;

        if (argc >= 2) {
                unsigned x;

                assert_se(safe_atou(argv[1], &x) >= 0);
                duration = x * USEC_PER_SEC;
        }

        n = sd_listen_fds_with_names(false, &l);
        if (n < 0) {
                log_error_errno(n, "Failed to get listening fds: %m");
                return EXIT_FAILURE;
        }

        for (i = 0; i < n; i++)
                log_info("fd=%i name=%s\n", SD_LISTEN_FDS_START + i, l[i]);

        sd_notify(0,
                  "STATUS=Starting up");
        usleep(duration);

        sd_notify(0,
                  "STATUS=Running\n"
                  "READY=1");
        usleep(duration);

        sd_notify(0,
                  "STATUS=Reloading\n"
                  "RELOADING=1");
        usleep(duration);

        sd_notify(0,
                  "STATUS=Running\n"
                  "READY=1");
        usleep(duration);

        sd_notify(0,
                  "STATUS=Quitting\n"
                  "STOPPING=1");
        usleep(duration);

        return EXIT_SUCCESS;
}
