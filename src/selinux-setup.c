/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#ifdef HAVE_SELINUX
#include <selinux/selinux.h>
#endif

#include "selinux-setup.h"
#include "macro.h"
#include "util.h"
#include "log.h"

int selinux_setup(char *const argv[]) {
#ifdef HAVE_SELINUX
       int enforce = 0;
       usec_t n;
       security_context_t con;

       /* Already initialized? */
       if (getcon_raw(&con) == 0) {
               bool initialized;

               initialized = !streq(con, "kernel");
               freecon(con);

               if (initialized)
                       return 0;
       }

       /* Before we load the policy we create a flag file to ensure
        * that after the reexec we iterate through /run and /dev to
        * relabel things. */
       touch("/dev/.systemd-relabel-run-dev");

       n = now(CLOCK_MONOTONIC);
       if (selinux_init_load_policy(&enforce) == 0) {
               char buf[FORMAT_TIMESPAN_MAX];

               n = now(CLOCK_MONOTONIC) - n;
               log_info("Successfully loaded SELinux policy in %s, reexecuting.",
                         format_timespan(buf, sizeof(buf), n));

               /* FIXME: Ideally we'd just call setcon() here instead
                * of having to reexecute ourselves here. */

               execv(SYSTEMD_BINARY_PATH, argv);
               log_error("Failed to reexecute: %m");
               return -errno;

       } else {
               unlink("/dev/.systemd-relabel-run-dev");

               if (enforce > 0) {
                       log_full(LOG_ERR, "Failed to load SELinux policy.");
                       return -EIO;
               }
       }
#endif

       return 0;
}
