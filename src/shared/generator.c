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
#include "dropin.h"

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
                if (r == -ENOENT) {
                        /* treat missing check as essentially OK */
                        log_debug("Checking was requested for %s, but fsck.%s does not exist: %s", what, fstype, strerror(-r));
                        return 0;
                } else if (r < 0) {
                        log_warning("Checking was requested for %s, but fsck.%s cannot be used: %s", what, fstype, strerror(-r));
                        return r;
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

int generator_write_timeouts(const char *dir, const char *what, const char *where,
                             const char *opts, char **filtered) {

        /* Allow configuration how long we wait for a device that
         * backs a mount point to show up. This is useful to support
         * endless device timeouts for devices that show up only after
         * user input, like crypto devices. */

        _cleanup_free_ char *node = NULL, *unit = NULL, *t = NULL;
        char *start, *timeout;
        usec_t u;
        int r;
        size_t len;

        if ((start = mount_test_option(opts, "comment=systemd.device-timeout")))
                timeout = start + 31;
        else if ((start = mount_test_option(opts, "x-systemd.device-timeout")))
                timeout = start + 25;
        else {
                if (filtered) {
                        *filtered = strdup(opts ?: "");
                        if (!*filtered)
                                return log_oom();
                }

                return 0;
        }

        len = strcspn(timeout, ",;" WHITESPACE);
        t = strndup(timeout, len);
        if (!t)
                return -ENOMEM;

        if (filtered) {
                char *prefix, *postfix;

                prefix = strndupa(opts, start - opts - (start != opts));
                postfix = timeout + len + (start == opts && timeout[len] != '\0');
                *filtered = strjoin(prefix, *postfix ? postfix : NULL, NULL);
                if (!*filtered)
                        return log_oom();
        }

        r = parse_sec(t, &u);
        if (r < 0) {
                log_warning("Failed to parse timeout for %s, ignoring: %s",
                            where, timeout);
                return 0;
        }

        node = fstab_node_to_udev_node(what);
        if (!node)
                return log_oom();

        unit = unit_name_from_path(node, ".device");
        if (!unit)
                return -ENOMEM;

        return write_drop_in_format(dir, unit, 50, "device-timeout",
                                    "# Automatically generated by %s\n\n"
                                    "[Unit]\nJobTimeoutSec=%u",
                                    program_invocation_short_name,
                                    u / USEC_PER_SEC);
}
