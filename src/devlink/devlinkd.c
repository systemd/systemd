/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/stat.h>

#include "sd-event.h"

#include "capability-util.h"
#include "daemon-util.h"
#include "main-func.h"
#include "signal-util.h"
#include "user-util.h"

#include "devlinkd-manager.h"

static int run(int argc, char *argv[]) {
        _cleanup_(manager_freep) Manager *m = NULL;
        _cleanup_(notify_on_cleanup) const char *notify_message = NULL;
        int r;

        log_setup();

        umask(0022);

        if (argc != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "This program takes no arguments.");

        /* Drop privileges, but only if we have been started as root. If we are not running as root we assume all
         * privileges are already dropped and we can't create our runtime directory. */
        if (geteuid() == 0) {
                const char *user = "systemd-devlink";
                uid_t uid;
                gid_t gid;

                r = get_user_creds(&user, &uid, &gid, NULL, NULL, 0);
                if (r < 0)
                        return log_error_errno(r, "Cannot resolve user name %s: %m", user);

                r = drop_privileges(uid, gid,
                                    (1ULL << CAP_NET_ADMIN) |
                                    (1ULL << CAP_NET_BIND_SERVICE) |
                                    (1ULL << CAP_NET_BROADCAST) |
                                    (1ULL << CAP_NET_RAW));
                if (r < 0)
                        return log_error_errno(r, "Failed to drop privileges: %m");
        }

        assert_se(sigprocmask_many(SIG_BLOCK, NULL, SIGTERM, SIGINT, -1) >= 0);

        r = manager_new(&m);
        if (r < 0)
                return log_error_errno(r, "Could not create manager: %m");

        r = manager_setup(m);
        if (r < 0)
                return log_error_errno(r, "Could not setup manager: %m");

        r = manager_config_load(m);
        if (r < 0)
                return log_error_errno(r, "Could not load configuration files: %m");

        r = manager_enumerate(m);
        if (r < 0)
                return r;

        r = manager_start(m);
        if (r < 0)
                return log_error_errno(r, "Could not start manager: %m");

        log_info("Enumeration completed");

        notify_message = notify_start(NOTIFY_READY_MESSAGE, NOTIFY_STOPPING_MESSAGE);

        r = sd_event_loop(m->event);
        if (r < 0)
                return log_error_errno(r, "Event loop failed: %m");

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
