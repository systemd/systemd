/* SPDX-License-Identifier: LGPL-2.1+ */

#include <netinet/in.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "sd-daemon.h"
#include "sd-event.h"

#include "capability-util.h"
#include "daemon-util.h"
#include "main-func.h"
#include "mkdir.h"
#include "networkd-conf.h"
#include "networkd-manager.h"
#include "signal-util.h"
#include "user-util.h"

static int run(int argc, char *argv[]) {
        _cleanup_(notify_on_cleanup) const char *notify_message = NULL;
        _cleanup_(manager_freep) Manager *m = NULL;
        const char *user = "systemd-network";
        uid_t uid;
        gid_t gid;
        int r;

        log_setup_service();

        umask(0022);

        if (argc != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "This program takes no arguments.");

        r = get_user_creds(&user, &uid, &gid, NULL, NULL, 0);
        if (r < 0)
                return log_error_errno(r, "Cannot resolve user name %s: %m", user);

        /* Create runtime directory. This is not necessary when networkd is
         * started with "RuntimeDirectory=systemd/netif", or after
         * systemd-tmpfiles-setup.service. */
        r = mkdir_safe_label("/run/systemd/netif", 0755, uid, gid, MKDIR_WARN_MODE);
        if (r < 0)
                log_warning_errno(r, "Could not create runtime directory: %m");

        /* Drop privileges, but only if we have been started as root. If we are not running as root we assume all
         * privileges are already dropped. */
        if (geteuid() == 0) {
                r = drop_privileges(uid, gid,
                                    (1ULL << CAP_NET_ADMIN) |
                                    (1ULL << CAP_NET_BIND_SERVICE) |
                                    (1ULL << CAP_NET_BROADCAST) |
                                    (1ULL << CAP_NET_RAW));
                if (r < 0)
                        return log_error_errno(r, "Failed to drop privileges: %m");
        }

        /* Always create the directories people can create inotify watches in.
         * It is necessary to create the following subdirectories after drop_privileges()
         * to support old kernels not supporting AmbientCapabilities=. */
        r = mkdir_safe_label("/run/systemd/netif/links", 0755, uid, gid, MKDIR_WARN_MODE);
        if (r < 0)
                log_warning_errno(r, "Could not create runtime directory 'links': %m");

        r = mkdir_safe_label("/run/systemd/netif/leases", 0755, uid, gid, MKDIR_WARN_MODE);
        if (r < 0)
                log_warning_errno(r, "Could not create runtime directory 'leases': %m");

        r = mkdir_safe_label("/run/systemd/netif/lldp", 0755, uid, gid, MKDIR_WARN_MODE);
        if (r < 0)
                log_warning_errno(r, "Could not create runtime directory 'lldp': %m");

        assert_se(sigprocmask_many(SIG_BLOCK, NULL, SIGTERM, SIGINT, -1) >= 0);

        r = manager_new(&m);
        if (r < 0)
                return log_error_errno(r, "Could not create manager: %m");

        r = manager_connect_bus(m);
        if (r < 0)
                return log_error_errno(r, "Could not connect to bus: %m");

        r = manager_parse_config_file(m);
        if (r < 0)
                log_warning_errno(r, "Failed to parse configuration file: %m");

        r = manager_load_config(m);
        if (r < 0)
                return log_error_errno(r, "Could not load configuration files: %m");

        r = manager_rtnl_enumerate_links(m);
        if (r < 0)
                return log_error_errno(r, "Could not enumerate links: %m");

        r = manager_rtnl_enumerate_addresses(m);
        if (r < 0)
                return log_error_errno(r, "Could not enumerate addresses: %m");

        r = manager_rtnl_enumerate_neighbors(m);
        if (r < 0)
                return log_error_errno(r, "Could not enumerate neighbors: %m");

        r = manager_rtnl_enumerate_routes(m);
        if (r < 0)
                return log_error_errno(r, "Could not enumerate routes: %m");

        r = manager_rtnl_enumerate_rules(m);
        if (r < 0)
                return log_error_errno(r, "Could not enumerate rules: %m");

        r = manager_start(m);
        if (r < 0)
                return log_error_errno(r, "Could not start manager: %m");

        log_info("Enumeration completed");

        notify_message = notify_start(NOTIFY_READY, NOTIFY_STOPPING);

        r = sd_event_loop(m->event);
        if (r < 0)
                return log_error_errno(r, "Event loop failed: %m");

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
