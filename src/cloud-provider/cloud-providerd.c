/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/stat.h>
#include <sys/types.h>

#include "sd-daemon.h"
#include "sd-event.h"

#include "capability-util.h"
#include "clock-util.h"
#include "cloud-provider-manager.h"
#include "daemon-util.h"
#include "fd-util.h"
#include "fs-util.h"
#include "main-func.h"
#include "mkdir.h"
#include "network-util.h"
#include "process-util.h"
#include "signal-util.h"
#include "user-util.h"

static int run(int argc, char *argv[]) {
        _cleanup_(notify_on_cleanup) const char *notify_message = NULL;
        _cleanup_(manager_freep) Manager *m = NULL;
        int r;

        log_set_facility(LOG_CRON);
        log_setup();

        umask(0022);

        if (argc != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "This program does not take arguments.");

        if (geteuid() == 0) {
                const char *user = "systemd-cloud-provider";
                uid_t uid;
                gid_t gid;

                r = get_user_creds(&user, &uid, &gid, NULL, NULL, 0);
                if (r < 0)
                        return log_error_errno(r, "Cannot resolve user name %s: %m", user);

                r = mkdir_safe_label("/run/systemd/cloud-provider", 0755, uid, gid, MKDIR_WARN_MODE);
                if (r < 0)
                        log_warning_errno(r, "Could not create runtime directory '/run/systemd/cloud-provider': %m");

                r = mkdir_safe_label("/run/systemd/cloud-provider/netif", 0755, uid, gid, MKDIR_WARN_MODE);
                if (r < 0)
                        log_warning_errno(r, "Could not create runtime directory 'netif': %m");

                r = drop_privileges(uid, gid,
                                    (1ULL << CAP_NET_ADMIN) |
                                    (1ULL << CAP_NET_BIND_SERVICE));
                if (r < 0)
                        return log_error_errno(r, "Failed to drop privileges: %m");
        }

        r = mkdir_safe_label("/run/systemd/cloud-provider/netif/links", 0755, UID_INVALID, GID_INVALID, MKDIR_WARN_MODE);
        if (r < 0)
                log_warning_errno(r, "Could not create runtime directory 'links': %m");

        assert_se(sigprocmask_many(SIG_BLOCK, NULL, SIGTERM, SIGINT, -1) >= 0);

        r = manager_new(&m);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate manager: %m");

        log_debug("systemd-cloud-providerd running as pid " PID_FMT, getpid_cached());

        notify_message = notify_start("READY=1\n"
                                      "STATUS=Daemon is running",
                                      NOTIFY_STOPPING);

        if (network_is_online()) {
                r = manager_connect(m);
                if (r < 0)
                        return r;
        }

        r = sd_event_loop(m->event);
        if (r < 0)
                return log_error_errno(r, "Failed to run event loop: %m");

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
