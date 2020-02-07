/* SPDX-License-Identifier: LGPL-2.1+ */

#include <sys/stat.h>
#include <sys/types.h>

#include "daemon-util.h"
#include "homed-manager.h"
#include "log.h"
#include "main-func.h"
#include "signal-util.h"

static int run(int argc, char *argv[]) {
        _cleanup_(notify_on_cleanup) const char *notify_stop = NULL;
        _cleanup_(manager_freep) Manager *m = NULL;
        int r;

        log_setup_service();

        umask(0022);

        if (argc != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "This program takes no arguments.");

        if (setenv("SYSTEMD_BYPASS_USERDB", "io.systemd.Home", 1) < 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to set $SYSTEMD_BYPASS_USERDB: %m");

        assert_se(sigprocmask_many(SIG_BLOCK, NULL, SIGCHLD, SIGTERM, SIGINT, -1) >= 0);

        r = manager_new(&m);
        if (r < 0)
                return log_error_errno(r, "Could not create manager: %m");

        r = manager_startup(m);
        if (r < 0)
                return log_error_errno(r, "Failed to start up daemon: %m");

        notify_stop = notify_start(NOTIFY_READY, NOTIFY_STOPPING);

        r = sd_event_loop(m->event);
        if (r < 0)
                return log_error_errno(r, "Event loop failed: %m");

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
