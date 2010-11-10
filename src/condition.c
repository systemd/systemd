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

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#include "util.h"
#include "condition.h"

Condition* condition_new(ConditionType type, const char *parameter, bool negate) {
        Condition *c;

        c = new0(Condition, 1);
        c->type = type;
        c->negate = negate;

        if (parameter)
                if (!(c->parameter = strdup(parameter))) {
                        free(c);
                        return NULL;
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

static bool test_kernel_command_line(const char *parameter) {
        char *line, *w, *state, *word = NULL;
        bool equal;
        int r;
        size_t l, pl;
        bool found = false;

        if ((r = read_one_line_file("/proc/cmdline", &line)) < 0) {
                log_warning("Failed to read /proc/cmdline, ignoring: %s", strerror(-r));
                return false;
        }

        equal = !!strchr(parameter, '=');
        pl = strlen(parameter);

        FOREACH_WORD_QUOTED(w, l, line, state) {

                free(word);
                if (!(word = strndup(w, l)))
                        break;

                if (equal) {
                        if (streq(word, parameter)) {
                                found = true;
                                break;
                        }
                } else {
                        if (startswith(word, parameter) && (word[pl] == '=' || word[pl] == 0)) {
                                found = true;
                                break;
                        }
                }

        }

        free(word);
        free(line);

        return found;
}

bool condition_test(Condition *c) {
        assert(c);

        switch(c->type) {

        case CONDITION_PATH_EXISTS:
                return (access(c->parameter, F_OK) >= 0) == !c->negate;

        case CONDITION_KERNEL_COMMAND_LINE:
                return !!test_kernel_command_line(c->parameter) == !c->negate;

        case CONDITION_NULL:
                return !c->negate;

        default:
                assert_not_reached("Invalid condition type.");
        }
}

bool condition_test_list(Condition *first) {
        Condition *c;

        /* If the condition list is empty, then it is true */
        if (!first)
                return true;

        /* Otherwise, if any of the conditions apply we return true */
        LIST_FOREACH(conditions, c, first)
                if (condition_test(c))
                        return true;

        return false;
}

void condition_dump(Condition *c, FILE *f, const char *prefix) {
        assert(c);
        assert(f);

        if (!prefix)
                prefix = "";

        fprintf(f,
                "%s%s: %s%s\n",
                prefix,
                condition_type_to_string(c->type),
                c->negate ? "!" : "",
                c->parameter);
}

void condition_dump_list(Condition *first, FILE *f, const char *prefix) {
        Condition *c;

        LIST_FOREACH(conditions, c, first)
                condition_dump(c, f, prefix);
}

static const char* const condition_type_table[_CONDITION_TYPE_MAX] = {
        [CONDITION_KERNEL_COMMAND_LINE] = "ConditionKernelCommandLine",
        [CONDITION_PATH_EXISTS] = "ConditionPathExists",
        [CONDITION_NULL] = "ConditionNull"
};

DEFINE_STRING_TABLE_LOOKUP(condition_type, ConditionType);
