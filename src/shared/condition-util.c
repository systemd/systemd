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
#include <sys/statvfs.h>
#include <fnmatch.h>

#include <systemd/sd-id128.h>
#include "util.h"
#include "condition-util.h"
#include "virt.h"
#include "path-util.h"
#include "fileio.h"
#include "unit.h"
#include "architecture.h"

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

bool condition_test_kernel_command_line(Condition *c) {
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

bool condition_test_virtualization(Condition *c) {
        int b, v;
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

bool condition_test_architecture(Condition *c) {
        Architecture a, b;

        assert(c);
        assert(c->parameter);
        assert(c->type == CONDITION_ARCHITECTURE);

        a = uname_architecture();
        if (a < 0)
                return c->negate;

        if (streq(c->parameter, "native"))
                b = native_architecture();
        else
                b = architecture_from_string(c->parameter);

        if (b < 0)
                return c->negate;

        return (a == b) == !c->negate;
}

bool condition_test_host(Condition *c) {
        _cleanup_free_ char *h = NULL;
        sd_id128_t x, y;
        int r;

        assert(c);
        assert(c->parameter);
        assert(c->type == CONDITION_HOST);

        if (sd_id128_from_string(c->parameter, &x) >= 0) {

                r = sd_id128_get_machine(&y);
                if (r < 0)
                        return c->negate;

                return sd_id128_equal(x, y) == !c->negate;
        }

        h = gethostname_malloc();
        if (!h)
                return c->negate;

        return (fnmatch(c->parameter, h, FNM_CASEFOLD) == 0) == !c->negate;
}

bool condition_test_ac_power(Condition *c) {
        int r;

        assert(c);
        assert(c->parameter);
        assert(c->type == CONDITION_AC_POWER);

        r = parse_boolean(c->parameter);
        if (r < 0)
                return !c->negate;

        return ((on_ac_power() != 0) == !!r) == !c->negate;
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
        [CONDITION_ARCHITECTURE] = "ConditionArchitecture",
        [CONDITION_NEEDS_UPDATE] = "ConditionNeedsUpdate",
        [CONDITION_NULL] = "ConditionNull"
};

DEFINE_STRING_TABLE_LOOKUP(condition_type, ConditionType);
