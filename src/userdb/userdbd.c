/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/stat.h>
#include <sys/types.h>

#include "daemon-util.h"
#include "userdbd-manager.h"
#include "log.h"
#include "main-func.h"
#include "signal-util.h"

/* This service offers two Varlink services, both implementing io.systemd.UserDatabase:
 *
 *         → io.systemd.NameServiceSwitch: this is a compatibility interface for glibc NSS: it responds to
 *           name lookups by checking the classic NSS interfaces and responding that.
 *
 *         → io.systemd.Multiplexer: this multiplexes lookup requests to all Varlink services that have a
 *           socket in /run/systemd/userdb/. It's supposed to simplify clients that don't want to implement
 *           the full iterative logic on their own.
 *
 *         → io.systemd.DropIn: this makes JSON user/group records dropped into /run/userdb/ available as
 *           regular users.
 */

static int run(int argc, char *argv[]) {
        _cleanup_(manager_freep) Manager *m = NULL;
        _unused_ _cleanup_(notify_on_cleanup) const char *notify_stop = NULL;
        int r;

        log_setup();

        umask(0022);

        if (argc != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "This program takes no arguments.");

        if (setenv("SYSTEMD_BYPASS_USERDB", "io.systemd.NameServiceSwitch:io.systemd.Multiplexer:io.systemd.DropIn", 1) < 0)
                return log_error_errno(errno, "Failed to set $SYSTEMD_BYPASS_USERDB: %m");

        assert_se(sigprocmask_many(SIG_BLOCK, NULL, SIGCHLD, SIGTERM, SIGINT, SIGUSR2, -1) >= 0);

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
