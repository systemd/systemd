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

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/capability.h>
#include <sys/statvfs.h>
#include <fnmatch.h>

#include "sd-id128.h"
#include "util.h"
#include "condition.h"
#include "virt.h"
#include "path-util.h"
#include "fileio.h"
#include "unit.h"
#include "smack-util.h"
#include "apparmor-util.h"
#include "ima-util.h"
#include "selinux-util.h"

static bool condition_test_security(Condition *c) {
        assert(c);
        assert(c->parameter);
        assert(c->type == CONDITION_SECURITY);

        if (streq(c->parameter, "selinux"))
                return use_selinux() == !c->negate;
        if (streq(c->parameter, "apparmor"))
                return use_apparmor() == !c->negate;
        if (streq(c->parameter, "ima"))
                return use_ima() == !c->negate;
        if (streq(c->parameter, "smack"))
                return use_smack() == !c->negate;

        return c->negate;
}

static bool condition_test_capability(Condition *c) {
        _cleanup_fclose_ FILE *f = NULL;
        cap_value_t value;
        char line[LINE_MAX];
        unsigned long long capabilities = -1;

        assert(c);
        assert(c->parameter);
        assert(c->type == CONDITION_CAPABILITY);

        /* If it's an invalid capability, we don't have it */

        if (cap_from_name(c->parameter, &value) < 0)
                return c->negate;

        /* If it's a valid capability we default to assume
         * that we have it */

        f = fopen("/proc/self/status", "re");
        if (!f)
                return !c->negate;

        while (fgets(line, sizeof(line), f)) {
                truncate_nl(line);

                if (startswith(line, "CapBnd:")) {
                        (void) sscanf(line+7, "%llx", &capabilities);
                        break;
                }
        }

        return !!(capabilities & (1ULL << value)) == !c->negate;
}

static bool condition_test_needs_update(Condition *c) {
        const char *p;
        struct stat usr, other;

        assert(c);
        assert(c->parameter);
        assert(c->type == CONDITION_NEEDS_UPDATE);

        /* If the file system is read-only we shouldn't suggest an update */
        if (path_is_read_only_fs(c->parameter) > 0)
                return c->negate;

        /* Any other failure means we should allow the condition to be true,
         * so that we rather invoke too many update tools then too
         * few. */

        if (!path_is_absolute(c->parameter))
                return !c->negate;

        p = strappenda(c->parameter, "/.updated");
        if (lstat(p, &other) < 0)
                return !c->negate;

        if (lstat("/usr/", &usr) < 0)
                return !c->negate;

        return (usr.st_mtim.tv_sec > other.st_mtim.tv_sec ||
                (usr.st_mtim.tv_sec == other.st_mtim.tv_sec && usr.st_mtim.tv_nsec > other.st_mtim.tv_nsec)) == !c->negate;
}

static bool condition_test(Condition *c) {
        assert(c);

        switch(c->type) {

        case CONDITION_PATH_EXISTS:
                return (access(c->parameter, F_OK) >= 0) == !c->negate;

        case CONDITION_PATH_EXISTS_GLOB:
                return (glob_exists(c->parameter) > 0) == !c->negate;

        case CONDITION_PATH_IS_DIRECTORY: {
                struct stat st;

                if (stat(c->parameter, &st) < 0)
                        return c->negate;
                return S_ISDIR(st.st_mode) == !c->negate;
        }

        case CONDITION_PATH_IS_SYMBOLIC_LINK: {
                struct stat st;

                if (lstat(c->parameter, &st) < 0)
                        return c->negate;
                return S_ISLNK(st.st_mode) == !c->negate;
        }

        case CONDITION_PATH_IS_MOUNT_POINT:
                return (path_is_mount_point(c->parameter, true) > 0) == !c->negate;

        case CONDITION_PATH_IS_READ_WRITE:
                return (path_is_read_only_fs(c->parameter) > 0) == c->negate;

        case CONDITION_DIRECTORY_NOT_EMPTY: {
                int k;

                k = dir_is_empty(c->parameter);
                return !(k == -ENOENT || k > 0) == !c->negate;
        }

        case CONDITION_FILE_NOT_EMPTY: {
                struct stat st;

                if (stat(c->parameter, &st) < 0)
                        return c->negate;

                return (S_ISREG(st.st_mode) && st.st_size > 0) == !c->negate;
        }

        case CONDITION_FILE_IS_EXECUTABLE: {
                struct stat st;

                if (stat(c->parameter, &st) < 0)
                        return c->negate;

                return (S_ISREG(st.st_mode) && (st.st_mode & 0111)) == !c->negate;
        }

        case CONDITION_KERNEL_COMMAND_LINE:
                return condition_test_kernel_command_line(c);

        case CONDITION_VIRTUALIZATION:
                return condition_test_virtualization(c);

        case CONDITION_SECURITY:
                return condition_test_security(c);

        case CONDITION_CAPABILITY:
                return condition_test_capability(c);

        case CONDITION_HOST:
                return condition_test_host(c);

        case CONDITION_AC_POWER:
                return condition_test_ac_power(c);

        case CONDITION_ARCHITECTURE:
                return condition_test_architecture(c);

        case CONDITION_NEEDS_UPDATE:
                return condition_test_needs_update(c);

        case CONDITION_NULL:
                return !c->negate;

        default:
                assert_not_reached("Invalid condition type.");
        }
}

bool condition_test_list(const char *unit, Condition *first) {
        Condition *c;
        int triggered = -1;

        /* If the condition list is empty, then it is true */
        if (!first)
                return true;

        /* Otherwise, if all of the non-trigger conditions apply and
         * if any of the trigger conditions apply (unless there are
         * none) we return true */
        LIST_FOREACH(conditions, c, first) {
                bool b;

                b = condition_test(c);
                if (unit)
                        log_debug_unit(unit,
                                       "%s=%s%s%s %s for %s.",
                                       condition_type_to_string(c->type),
                                       c->trigger ? "|" : "",
                                       c->negate ? "!" : "",
                                       c->parameter,
                                       b ? "succeeded" : "failed",
                                       unit);
                c->state = b ? 1 : -1;

                if (!c->trigger && !b)
                        return false;

                if (c->trigger && triggered <= 0)
                        triggered = b;
        }

        return triggered != 0;
}
