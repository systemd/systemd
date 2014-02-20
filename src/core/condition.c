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

#include <systemd/sd-id128.h>
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

Condition* condition_new(ConditionType type, const char *parameter, bool trigger, bool negate) {
        Condition *c;

        assert(type < _CONDITION_TYPE_MAX);

        c = new0(Condition, 1);
        if (!c)
                return NULL;

        c->type = type;
        c->trigger = trigger;
        c->negate = negate;

        if (parameter) {
                c->parameter = strdup(parameter);
                if (!c->parameter) {
                        free(c);
                        return NULL;
                }
        }

        return c;
}

void condition_free(Condition *c) {
        assert(c);

        free(c->parameter);
        free(c);
}

void condition_free_list(Condition *first) {
        Condition *c, *n;

        LIST_FOREACH_SAFE(conditions, c, n, first)
                condition_free(c);
}

static bool condition_test_kernel_command_line(Condition *c) {
        char *line, *w, *state, *word = NULL;
        bool equal;
        int r;
        size_t l, pl;
        bool found = false;

        assert(c);
        assert(c->parameter);
        assert(c->type == CONDITION_KERNEL_COMMAND_LINE);

        r = proc_cmdline(&line);
        if (r < 0)
                log_warning("Failed to read /proc/cmdline, ignoring: %s", strerror(-r));
        if (r <= 0)
                return c->negate;

        equal = !!strchr(c->parameter, '=');
        pl = strlen(c->parameter);

        FOREACH_WORD_QUOTED(w, l, line, state) {

                free(word);
                word = strndup(w, l);
                if (!word)
                        break;

                if (equal) {
                        if (streq(word, c->parameter)) {
                                found = true;
                                break;
                        }
                } else {
                        if (startswith(word, c->parameter) && (word[pl] == '=' || word[pl] == 0)) {
                                found = true;
                                break;
                        }
                }

        }

        free(word);
        free(line);

        return found == !c->negate;
}

static bool condition_test_virtualization(Condition *c) {
        int b;
        Virtualization v;
        const char *id;

        assert(c);
        assert(c->parameter);
        assert(c->type == CONDITION_VIRTUALIZATION);

        v = detect_virtualization(&id);
        if (v < 0) {
                log_warning("Failed to detect virtualization, ignoring: %s", strerror(-v));
                return c->negate;
        }

        /* First, compare with yes/no */
        b = parse_boolean(c->parameter);

        if (v > 0 && b > 0)
                return !c->negate;

        if (v == 0 && b == 0)
                return !c->negate;

        /* Then, compare categorization */
        if (v == VIRTUALIZATION_VM && streq(c->parameter, "vm"))
                return !c->negate;

        if (v == VIRTUALIZATION_CONTAINER && streq(c->parameter, "container"))
                return !c->negate;

        /* Finally compare id */
        return (v > 0 && streq(c->parameter, id)) == !c->negate;
}

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
        cap_value_t value;
        FILE *f;
        char line[LINE_MAX];
        unsigned long long capabilities = (unsigned long long) -1;

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

        fclose(f);

        return !!(capabilities & (1ULL << value)) == !c->negate;
}

static bool condition_test_host(Condition *c) {
        sd_id128_t x, y;
        char *h;
        int r;
        bool b;

        assert(c);
        assert(c->parameter);
        assert(c->type == CONDITION_HOST);

        if (sd_id128_from_string(c->parameter, &x) >= 0) {

                r = sd_id128_get_machine(&y);
                if (r < 0)
                        return c->negate;

                return sd_id128_equal(x, y);
        }

        h = gethostname_malloc();
        if (!h)
                return c->negate;

        b = fnmatch(c->parameter, h, FNM_CASEFOLD) == 0;
        free(h);

        return b == !c->negate;
}

static bool condition_test_ac_power(Condition *c) {
        int r;

        assert(c);
        assert(c->parameter);
        assert(c->type == CONDITION_AC_POWER);

        r = parse_boolean(c->parameter);
        if (r < 0)
                return !c->negate;

        return ((on_ac_power() != 0) == !!r) == !c->negate;
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

void condition_dump(Condition *c, FILE *f, const char *prefix) {
        assert(c);
        assert(f);

        if (!prefix)
                prefix = "";

        fprintf(f,
                "%s\t%s: %s%s%s %s\n",
                prefix,
                condition_type_to_string(c->type),
                c->trigger ? "|" : "",
                c->negate ? "!" : "",
                c->parameter,
                c->state < 0 ? "failed" : c->state > 0 ? "succeeded" : "untested");
}

void condition_dump_list(Condition *first, FILE *f, const char *prefix) {
        Condition *c;

        LIST_FOREACH(conditions, c, first)
                condition_dump(c, f, prefix);
}

static const char* const condition_type_table[_CONDITION_TYPE_MAX] = {
        [CONDITION_PATH_EXISTS] = "ConditionPathExists",
        [CONDITION_PATH_EXISTS_GLOB] = "ConditionPathExistsGlob",
        [CONDITION_PATH_IS_DIRECTORY] = "ConditionPathIsDirectory",
        [CONDITION_PATH_IS_SYMBOLIC_LINK] = "ConditionPathIsSymbolicLink",
        [CONDITION_PATH_IS_MOUNT_POINT] = "ConditionPathIsMountPoint",
        [CONDITION_PATH_IS_READ_WRITE] = "ConditionPathIsReadWrite",
        [CONDITION_DIRECTORY_NOT_EMPTY] = "ConditionDirectoryNotEmpty",
        [CONDITION_FILE_NOT_EMPTY] = "ConditionFileNotEmpty",
        [CONDITION_FILE_IS_EXECUTABLE] = "ConditionFileIsExecutable",
        [CONDITION_KERNEL_COMMAND_LINE] = "ConditionKernelCommandLine",
        [CONDITION_VIRTUALIZATION] = "ConditionVirtualization",
        [CONDITION_SECURITY] = "ConditionSecurity",
        [CONDITION_CAPABILITY] = "ConditionCapability",
        [CONDITION_HOST] = "ConditionHost",
        [CONDITION_AC_POWER] = "ConditionACPower",
        [CONDITION_NULL] = "ConditionNull"
};

DEFINE_STRING_TABLE_LOOKUP(condition_type, ConditionType);
