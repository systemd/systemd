/* SPDX-License-Identifier: LGPL-2.1+ */

#include "sd-daemon.h"
#include "sd-event.h"

#include "capability-util.h"
#include "networkd-conf.h"
#include "networkd-manager.h"
#include "signal-util.h"
#include "user-util.h"

int main(int argc, char *argv[]) {
        _cleanup_(manager_freep) Manager *m = NULL;
        const char *user = "systemd-network";
        uid_t uid;
        gid_t gid;
        int r;

        log_set_target(LOG_TARGET_AUTO);
        log_parse_environment();
        log_open();

        umask(0022);

        if (argc != 1) {
                log_error("This program takes no arguments.");
                r = -EINVAL;
                goto out;
        }

        r = get_user_creds(&user, &uid, &gid, NULL, NULL);
        if (r < 0) {
                log_error_errno(r, "Cannot resolve user name %s: %m", user);
                goto out;
        }

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
                        goto out;
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
        if (r < 0) {
                log_error_errno(r, "Could not create manager: %m");
                goto out;
        }

        r = manager_connect_bus(m);
        if (r < 0) {
                log_error_errno(r, "Could not connect to bus: %m");
                goto out;
        }

        r = manager_parse_config_file(m);
        if (r < 0)
                log_warning_errno(r, "Failed to parse configuration file: %m");

        r = manager_load_config(m);
        if (r < 0) {
                log_error_errno(r, "Could not load configuration files: %m");
                goto out;
        }

        r = manager_rtnl_enumerate_links(m);
        if (r < 0) {
                log_error_errno(r, "Could not enumerate links: %m");
                goto out;
        }

        r = manager_rtnl_enumerate_addresses(m);
        if (r < 0) {
                log_error_errno(r, "Could not enumerate addresses: %m");
                goto out;
        }

        r = manager_rtnl_enumerate_routes(m);
        if (r < 0) {
                log_error_errno(r, "Could not enumerate routes: %m");
                goto out;
        }

        r = manager_rtnl_enumerate_rules(m);
        if (r < 0) {
                log_error_errno(r, "Could not enumerate rules: %m");
                goto out;
        }

        r = manager_start(m);
        if (r < 0) {
                log_error_errno(r, "Could not start manager: %m");
                goto out;
        }

        log_info("Enumeration completed");

        sd_notify(false,
                  "READY=1\n"
                  "STATUS=Processing requests...");

        r = sd_event_loop(m->event);
        if (r < 0) {
                log_error_errno(r, "Event loop failed: %m");
                goto out;
        }
out:
        sd_notify(false,
                  "STOPPING=1\n"
                  "STATUS=Shutting down...");

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
