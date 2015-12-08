/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <errno.h>
#include <stdio.h>
#include <unistd.h>

#ifdef HAVE_SELINUX
#include <selinux/selinux.h>
#endif

#include "log.h"
#include "macro.h"
#include "selinux-setup.h"
#include "selinux-util.h"
#include "string-util.h"
#include "util.h"

#ifdef HAVE_SELINUX
_printf_(2,3)
static int null_log(int type, const char *fmt, ...) {
        return 0;
}
#endif

int mac_selinux_setup(bool *loaded_policy) {

#ifdef HAVE_SELINUX
        int enforce = 0;
        usec_t before_load, after_load;
        security_context_t con;
        int r;
        union selinux_callback cb;
        bool initialized = false;

        assert(loaded_policy);

        /* Turn off all of SELinux' own logging, we want to do that */
        cb.func_log = null_log;
        selinux_set_callback(SELINUX_CB_LOG, cb);

        /* Don't load policy in the initrd if we don't appear to have
         * it.  For the real root, we check below if we've already
         * loaded policy, and return gracefully.
         */
        if (in_initrd() && access(selinux_path(), F_OK) < 0)
                return 0;

        /* Already initialized by somebody else? */
        r = getcon_raw(&con);
        if (r == 0) {
                initialized = !streq(con, "kernel");
                freecon(con);
        }

        /* Make sure we have no fds open while loading the policy and
         * transitioning */
        log_close();

        /* Now load the policy */
        before_load = now(CLOCK_MONOTONIC);
        r = selinux_init_load_policy(&enforce);
        if (r == 0) {
                _cleanup_(mac_selinux_freep) char *label = NULL;
                char timespan[FORMAT_TIMESPAN_MAX];

                mac_selinux_retest();

                /* Transition to the new context */
                r = mac_selinux_get_create_label_from_exe(SYSTEMD_BINARY_PATH, &label);
                if (r < 0 || !label) {
                        log_open();
                        log_error("Failed to compute init label, ignoring.");
                } else {
                        r = setcon(label);

                        log_open();
                        if (r < 0)
                                log_error("Failed to transition into init label '%s', ignoring.", label);
                }

                after_load = now(CLOCK_MONOTONIC);

                log_info("Successfully loaded SELinux policy in %s.",
                         format_timespan(timespan, sizeof(timespan), after_load - before_load, 0));

                *loaded_policy = true;

        } else {
                log_open();

                if (enforce > 0) {
                        if (!initialized) {
                                log_emergency("Failed to load SELinux policy.");
                                return -EIO;
                        }

                        log_warning("Failed to load new SELinux policy. Continuing with old policy.");
                } else
                        log_debug("Unable to load SELinux policy. Ignoring.");
        }
#endif

        return 0;
}
