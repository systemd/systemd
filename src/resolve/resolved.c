/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "sd-daemon.h"
#include "sd-event.h"

#include "bus-log-control-api.h"
#include "capability-util.h"
#include "daemon-util.h"
#include "main-func.h"
#include "mkdir-label.h"
#include "resolved-bus.h"
#include "resolved-conf.h"
#include "resolved-manager.h"
#include "resolved-resolv-conf.h"
#include "selinux-util.h"
#include "service-util.h"
#include "signal-util.h"
#include "user-util.h"

static int run(int argc, char *argv[]) {
        _cleanup_(manager_freep) Manager *m = NULL;
        _unused_ _cleanup_(notify_on_cleanup) const char *notify_stop = NULL;
        int r;

        log_setup();

        r = service_parse_argv("systemd-resolved.service",
                               "Provide name resolution with caching using DNS, mDNS, LLMNR.",
                               BUS_IMPLEMENTATIONS(&manager_object,
                                                   &log_control_object),
                               argc, argv);
        if (r <= 0)
                return r;

        umask(0022);

        r = mac_init();
        if (r < 0)
                return r;

        /* Drop privileges, but only if we have been started as root. If we are not running as root we assume most
         * privileges are already dropped and we can't create our directory. */
        if (getuid() == 0) {
                const char *user = "systemd-resolve";
                uid_t uid;
                gid_t gid;

                r = get_user_creds(&user, &uid, &gid, NULL, NULL, 0);
                if (r < 0)
                        return log_error_errno(r, "Cannot resolve user name %s: %m", user);

                /* As we're root, we can create the directory where resolv.conf will live */
                r = mkdir_safe_label("/run/systemd/resolve", 0755, uid, gid, MKDIR_WARN_MODE);
                if (r < 0)
                        return log_error_errno(r, "Could not create runtime directory: %m");

                /* Drop privileges, but keep three caps. Note that we drop two of those too, later on (see below) */
                r = drop_privileges(uid, gid,
                                    (UINT64_C(1) << CAP_NET_RAW)|          /* needed for SO_BINDTODEVICE */
                                    (UINT64_C(1) << CAP_NET_BIND_SERVICE)| /* needed to bind on port 53 */
                                    (UINT64_C(1) << CAP_SETPCAP)           /* needed in order to drop the caps later */);
                if (r < 0)
                        return log_error_errno(r, "Failed to drop privileges: %m");
        }

        r = manager_new(&m);
        if (r < 0)
                return log_error_errno(r, "Could not create manager: %m");

        r = manager_start(m);
        if (r < 0)
                return log_error_errno(r, "Failed to start manager: %m");

        /* Write finish default resolv.conf to avoid a dangling symlink */
        (void) manager_write_resolv_conf(m);

        (void) manager_check_resolv_conf(m);

        /* Let's drop the remaining caps now */
        r = capability_bounding_set_drop((UINT64_C(1) << CAP_NET_RAW), true);
        if (r < 0)
                return log_error_errno(r, "Failed to drop remaining caps: %m");

        notify_stop = notify_start(NOTIFY_READY, NOTIFY_STOPPING);

        r = sd_event_loop(m->event);
        if (r < 0)
                return log_error_errno(r, "Event loop failed: %m");

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
