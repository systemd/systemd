/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stdio.h>
#include <unistd.h>

#if HAVE_SELINUX
#include <selinux/selinux.h>
#endif

#include "sd-messages.h"

#include "initrd-util.h"
#include "log.h"
#include "macro.h"
#include "selinux-setup.h"
#include "selinux-util.h"
#include "string-util.h"
#include "time-util.h"

#if HAVE_SELINUX
_printf_(2,3)
static int null_log(int type, const char *fmt, ...) {
        return 0;
}
#endif

int mac_selinux_setup(bool *loaded_policy) {

#if HAVE_SELINUX
        int enforce = 0;
        usec_t before_load, after_load;
        char *con;
        int r;
        bool initialized;

        assert(loaded_policy);

        /* Turn off all of SELinux' own logging, we want to do that */
        selinux_set_callback(SELINUX_CB_LOG, (const union selinux_callback) { .func_log = null_log });

        /* Don't load policy in the initrd if we don't appear to have it.  For the real root, we check below
         * if we've already loaded policy, and return gracefully. */
        if (in_initrd() && access(selinux_path(), F_OK) < 0)
                return 0;

        /* Already initialized by somebody else? */
        r = getcon_raw(&con);
        /* getcon_raw can return 0, and still give us a NULL pointer if /proc/self/attr/current is
         * empty. SELinux guarantees this won't happen, but that file isn't specific to SELinux, and may be
         * provided by some other arbitrary LSM with different semantics. */
        if (r == 0 && con) {
                initialized = !streq(con, "kernel");
                freecon(con);
        } else
                initialized = false;

        /* Make sure we have no fds open while loading the policy and
         * transitioning */
        log_close();

        /* Now load the policy */
        before_load = now(CLOCK_MONOTONIC);
        r = selinux_init_load_policy(&enforce);
        if (r == 0) {
                _cleanup_freecon_ char *label = NULL;

                mac_selinux_retest();

                /* Transition to the new context */
                r = mac_selinux_get_create_label_from_exe(SYSTEMD_BINARY_PATH, &label);
                if (r < 0 || !label) {
                        log_open();
                        log_error("Failed to compute init label, ignoring.");
                } else {
                        r = setcon_raw(label);

                        log_open();
                        if (r < 0)
                                log_error("Failed to transition into init label '%s', ignoring.", label);
                }

                after_load = now(CLOCK_MONOTONIC);

                log_info("Successfully loaded SELinux policy in %s.",
                         FORMAT_TIMESPAN(after_load - before_load, 0));

                *loaded_policy = true;

        } else {
                log_open();

                if (enforce > 0) {
                        if (!initialized)
                                return log_struct_errno(LOG_EMERG, SYNTHETIC_ERRNO(EIO),
                                                        LOG_MESSAGE("Failed to load SELinux policy :%m"),
                                                        "MESSAGE_ID=" SD_MESSAGE_SELINUX_FAILED_STR);

                        log_warning("Failed to load new SELinux policy. Continuing with old policy.");
                } else
                        log_debug("Unable to load SELinux policy. Ignoring.");
        }
#endif

        return 0;
}
