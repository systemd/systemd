/* SPDX-License-Identifier: LGPL-2.1+ */

#include "sd-daemon.h"
#include "sd-event.h"

#include "capability-util.h"
#include "mkdir.h"
#include "resolved-conf.h"
#include "resolved-manager.h"
#include "resolved-resolv-conf.h"
#include "selinux-util.h"
#include "signal-util.h"
#include "user-util.h"

int main(int argc, char *argv[]) {
        _cleanup_(manager_freep) Manager *m = NULL;
        const char *user = "systemd-resolve";
        uid_t uid;
        gid_t gid;
        int r;

        log_set_target(LOG_TARGET_AUTO);
        log_parse_environment();
        log_open();

        if (argc != 1) {
                log_error("This program takes no arguments.");
                r = -EINVAL;
                goto finish;
        }

        umask(0022);

        r = mac_selinux_init();
        if (r < 0) {
                log_error_errno(r, "SELinux setup failed: %m");
                goto finish;
        }

        r = get_user_creds(&user, &uid, &gid, NULL, NULL);
        if (r < 0) {
                log_error_errno(r, "Cannot resolve user name %s: %m", user);
                goto finish;
        }

        /* Always create the directory where resolv.conf will live */
        r = mkdir_safe_label("/run/systemd/resolve", 0755, uid, gid, MKDIR_WARN_MODE);
        if (r < 0) {
                log_error_errno(r, "Could not create runtime directory: %m");
                goto finish;
        }

        /* Drop privileges, but only if we have been started as root. If we are not running as root we assume all
         * privileges are already dropped. */
        if (getuid() == 0) {
                r = symlink("../run/systemd/resolve/resolv.conf", "/etc/resolv.conf");
                if (r < 0 && errno != EEXIST)
                        log_warning_errno(errno,
                                          "Could not create /etc/resolv.conf symlink: %m");

                /* Drop privileges, but keep three caps. Note that we drop those too, later on (see below) */
                r = drop_privileges(uid, gid,
                                    (UINT64_C(1) << CAP_NET_RAW)|          /* needed for SO_BINDTODEVICE */
                                    (UINT64_C(1) << CAP_NET_BIND_SERVICE)| /* needed to bind on port 53 */
                                    (UINT64_C(1) << CAP_SETPCAP)           /* needed in order to drop the caps later */);
                if (r < 0)
                        goto finish;
        }

        assert_se(sigprocmask_many(SIG_BLOCK, NULL, SIGTERM, SIGINT, SIGUSR1, SIGUSR2, SIGRTMIN+1, -1) >= 0);

        r = manager_new(&m);
        if (r < 0) {
                log_error_errno(r, "Could not create manager: %m");
                goto finish;
        }

        r = manager_start(m);
        if (r < 0) {
                log_error_errno(r, "Failed to start manager: %m");
                goto finish;
        }

        /* Write finish default resolv.conf to avoid a dangling symlink */
        (void) manager_write_resolv_conf(m);

        /* Let's drop the remaining caps now */
        r = capability_bounding_set_drop(0, true);
        if (r < 0) {
                log_error_errno(r, "Failed to drop remaining caps: %m");
                goto finish;
        }

        sd_notify(false,
                  "READY=1\n"
                  "STATUS=Processing requests...");

        r = sd_event_loop(m->event);
        if (r < 0) {
                log_error_errno(r, "Event loop failed: %m");
                goto finish;
        }

        sd_event_get_exit_code(m->event, &r);

finish:
        sd_notify(false,
                  "STOPPING=1\n"
                  "STATUS=Shutting down...");

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
