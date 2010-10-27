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

       /* Already initialized? */
       if (path_is_mount_point("/selinux") > 0)
               return 0;

       if (selinux_init_load_policy(&enforce) == 0) {
               log_info("Successfully loaded SELinux policy, reexecuting.");

               /* FIXME: Ideally we'd just call setcon() here instead
                * of having to reexecute ourselves here. */

               execv(SYSTEMD_BINARY_PATH, argv);
               log_error("Failed to reexecute: %m");
               return -errno;

       } else {
               log_full(enforce > 0 ? LOG_ERR : LOG_DEBUG, "Failed to load SELinux policy.");

               if (enforce > 0)
                       return -EIO;
       }
#endif

       return 0;
}
