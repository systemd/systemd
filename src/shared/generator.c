/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2014 Lennart Poettering

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

#include <string.h>
#include <unistd.h>

#include "util.h"
#include "special.h"
#include "mkdir.h"
#include "unit-name.h"
#include "generator.h"
#include "path-util.h"

int generator_write_fsck_deps(
                FILE *f,
                const char *dest,
                const char *what,
                const char *where,
                const char *fstype) {

        assert(f);
        assert(dest);
        assert(what);
        assert(where);

        if (!is_device_path(what)) {
                log_warning("Checking was requested for \"%s\", but it is not a device.", what);
                return 0;
        }

        if (!isempty(fstype) && !streq(fstype, "auto")) {
                int r;
                r = fsck_exists(fstype);
                if (r < 0) {
                        log_warning("Checking was requested for %s, but fsck.%s cannot be used: %s", what, fstype, strerror(-r));
                        /* treat missing check as essentially OK */
                        return r == -ENOENT ? 0 : r;
                }
        }

        if (streq(where, "/")) {
                char *lnk;

                lnk = strappenda(dest, "/" SPECIAL_LOCAL_FS_TARGET ".wants/systemd-fsck-root.service");

                mkdir_parents(lnk, 0755);
                if (symlink(SYSTEM_DATA_UNIT_PATH "/systemd-fsck-root.service", lnk) < 0) {
                        log_error("Failed to create symlink %s: %m", lnk);
                        return -errno;
                }

        } else {
                _cleanup_free_ char *fsck = NULL;

                fsck = unit_name_from_path_instance("systemd-fsck", what, ".service");
                if (!fsck)
                        return log_oom();

                fprintf(f,
                        "RequiresOverridable=%s\n"
                        "After=%s\n",
                        fsck,
                        fsck);
        }

        return 0;
}
