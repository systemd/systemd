/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "sd-messages.h"

#include "errno-util.h"
#include "initrd-util.h"
#include "log.h"
#include "selinux-setup.h"
#include "selinux-util.h"
#include "string-util.h"
#include "time-util.h"

int mac_selinux_setup(bool *loaded_policy) {
        assert(loaded_policy);

#if HAVE_SELINUX
        int r;

        mac_selinux_disable_logging();

        /* Don't load policy in the initrd if we don't appear to have it.  For the real root, we check below
         * if we've already loaded policy, and return gracefully. */
        if (in_initrd() && access(selinux_path(), F_OK) < 0) {
                if (errno != ENOENT)
                        log_warning_errno(errno, "Unable to check if %s exists, assuming it does not: %m", selinux_path());

                return 0;
        }

        bool initialized = false;

        /* Already initialized by somebody else?
         *
         * Note: getcon_raw() can return 0, and still give us a NULL pointer if /proc/self/attr/current is
         * empty. SELinux guarantees this won't happen, but that file isn't specific to SELinux, and may be
         * provided by some other arbitrary LSM with different semantics. */
        _cleanup_freecon_ char *con = NULL;
        if (getcon_raw(&con) < 0)
                log_debug_errno(errno, "getcon_raw() failed, assuming SELinux is not initialized: %m");
        else if (con) {
                initialized = !streq(con, "kernel");
                log_debug("SELinux already initialized: %s", yes_no(initialized));
        }

        /* Make sure we have no fds open while loading the policy and transitioning */
        log_close();

        /* Now load the policy */
        usec_t before_load = now(CLOCK_MONOTONIC);
        int enforce = 0;
        if (selinux_init_load_policy(&enforce) == 0) { /* NB: Apparently doesn't set useful errno! */
                mac_selinux_retest();

                /* Transition to the new context */
                _cleanup_freecon_ char *label = NULL;
                r = mac_selinux_get_create_label_from_exe(SYSTEMD_BINARY_PATH, &label);
                if (r < 0) {
                        log_open();
                        log_warning_errno(r, "Failed to compute init label, ignoring: %m");
                } else {
                        r = RET_NERRNO(setcon_raw(label));
                        log_open();
                        if (r < 0)
                                log_warning_errno(r, "Failed to transition into init label '%s', ignoring: %m", label);
                        else
                                log_debug("Successfully switched to calculated init label '%s'.", label);
                }

                usec_t after_load = now(CLOCK_MONOTONIC);
                log_info("Successfully loaded SELinux policy in %s.",
                         FORMAT_TIMESPAN(after_load - before_load, 0));

                *loaded_policy = true;
        } else {
                log_open();

                if (enforce > 0) {
                        if (!initialized)
                                return log_struct_errno(LOG_EMERG, SYNTHETIC_ERRNO(EIO),
                                                        LOG_MESSAGE("Failed to load SELinux policy."),
                                                        LOG_MESSAGE_ID(SD_MESSAGE_SELINUX_FAILED_STR));

                        log_notice("Failed to load new SELinux policy. Continuing with old policy.");
                } else
                        log_debug("Unable to load SELinux policy. Ignoring.");
        }
#endif

        return 0;
}
