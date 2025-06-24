/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/stat.h>
#include <unistd.h>

#include "sd-event.h"

#include "bus-log-control-api.h"
#include "bus-object.h"
#include "capability-util.h"
#include "daemon-util.h"
#include "main-func.h"
#include "mkdir-label.h"
#include "networkd-conf.h"
#include "networkd-manager.h"
#include "networkd-manager-bus.h"
#include "networkd-serialize.h"
#include "service-util.h"
#include "strv.h"
#include "user-util.h"

static int run(int argc, char *argv[]) {
        _cleanup_(manager_freep) Manager *m = NULL;
        _unused_ _cleanup_(notify_on_cleanup) const char *notify_message = NULL;
        int r;

        log_setup();

        r = service_parse_argv("systemd-networkd.service",
                               "Manage and configure network devices, create virtual network devices",
                               BUS_IMPLEMENTATIONS(&manager_object, &log_control_object),
                               argc, argv);
        if (r <= 0)
                return r;

        umask(0022);

        if (argc != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "This program takes no arguments.");

        /* Drop privileges, but only if we have been started as root. If we are not running as root we assume all
         * privileges are already dropped and we can't create our runtime directory. */
        if (geteuid() == 0) {
                const char *user = "systemd-network";
                uid_t uid;
                gid_t gid;

                r = get_user_creds(&user, &uid, &gid, NULL, NULL, 0);
                if (r < 0)
                        return log_error_errno(r, "Cannot resolve user name %s: %m", user);

                /* Create runtime directory. This is not necessary when networkd is
                 * started with "RuntimeDirectory=systemd/netif", or after
                 * systemd-tmpfiles-setup.service. */
                r = mkdir_safe_label("/run/systemd/netif", 0755, uid, gid, MKDIR_WARN_MODE);
                if (r < 0)
                        log_warning_errno(r, "Could not create runtime directory: %m");

                r = drop_privileges(uid, gid,
                                    (1ULL << CAP_NET_ADMIN) |
                                    (1ULL << CAP_NET_BIND_SERVICE) |
                                    (1ULL << CAP_NET_BROADCAST) |
                                    (1ULL << CAP_NET_RAW) |
                                    (1ULL << CAP_SYS_ADMIN) |
                                    (1ULL << CAP_BPF));
                if (r < 0)
                        return log_error_errno(r, "Failed to drop privileges: %m");
        }

        /* Always create the directories people can create inotify watches in. It is necessary to create the
         * following subdirectories after drop_privileges() to make them owned by systemd-network. */
        FOREACH_STRING(p,
                       "/run/systemd/netif/dhcp-server-lease/",
                       "/run/systemd/netif/leases/",
                       "/run/systemd/netif/links/") {
                r = mkdir_safe_label(p, 0755, UID_INVALID, GID_INVALID, MKDIR_WARN_MODE);
                if (r < 0)
                        log_warning_errno(r, "Could not create directory '%s': %m", p);
        }

        r = manager_new(&m, /* test_mode = */ false);
        if (r < 0)
                return log_error_errno(r, "Could not create manager: %m");

        r = manager_setup(m);
        if (r < 0)
                return log_error_errno(r, "Could not set up manager: %m");

        r = manager_parse_config_file(m);
        if (r < 0)
                log_warning_errno(r, "Failed to parse configuration file: %m");

        r = manager_load_config(m);
        if (r < 0)
                return log_error_errno(r, "Could not load configuration files: %m");

        r = manager_enumerate(m);
        if (r < 0)
                return r;

        r = manager_deserialize(m);
        if (r < 0)
                log_warning_errno(r, "Failed to deserialize the previous invocation, ignoring: %m");

        r = manager_start(m);
        if (r < 0)
                return log_error_errno(r, "Could not start manager: %m");

        notify_message = notify_start(NOTIFY_READY_MESSAGE, NOTIFY_STOPPING_MESSAGE);

        r = sd_event_loop(m->event);
        if (r < 0)
                return log_error_errno(r, "Event loop failed: %m");

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
