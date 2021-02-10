/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "locale-util.h"
#include "sort-util.h"
#include "special.h"
#include "systemctl-list-dependencies.h"
#include "systemctl-util.h"
#include "systemctl.h"
#include "terminal-util.h"

static int list_dependencies_print(const char *name, int level, unsigned branches, bool last) {
        _cleanup_free_ char *n = NULL;
        size_t max_len = MAX(columns(),20u);
        size_t len = 0;

        if (!arg_plain) {

                for (int i = level - 1; i >= 0; i--) {
                        len += 2;
                        if (len > max_len - 3 && !arg_full) {
                                printf("%s...\n",max_len % 2 ? "" : " ");
                                return 0;
                        }
                        printf("%s", special_glyph(branches & (1 << i) ? SPECIAL_GLYPH_TREE_VERTICAL : SPECIAL_GLYPH_TREE_SPACE));
                }
                len += 2;

                if (len > max_len - 3 && !arg_full) {
                        printf("%s...\n",max_len % 2 ? "" : " ");
                        return 0;
                }

                printf("%s", special_glyph(last ? SPECIAL_GLYPH_TREE_RIGHT : SPECIAL_GLYPH_TREE_BRANCH));
        }

        if (arg_full) {
                printf("%s\n", name);
                return 0;
        }

        n = ellipsize(name, max_len-len, 100);
        if (!n)
                return log_oom();

        printf("%s\n", n);
        return 0;
}

static int list_dependencies_compare(char * const *a, char * const *b) {
        if (unit_name_to_type(*a) == UNIT_TARGET && unit_name_to_type(*b) != UNIT_TARGET)
                return 1;
        if (unit_name_to_type(*a) != UNIT_TARGET && unit_name_to_type(*b) == UNIT_TARGET)
                return -1;

        return strcasecmp(*a, *b);
}

static int list_dependencies_one(
                sd_bus *bus,
                const char *name,
                int level,
                char ***units,
                unsigned branches) {

        _cleanup_strv_free_ char **deps = NULL;
        char **c;
        int r;

        assert(bus);
        assert(name);
        assert(units);

        r = strv_extend(units, name);
        if (r < 0)
                return log_oom();

        r = unit_get_dependencies(bus, name, &deps);
        if (r < 0)
                return r;

        typesafe_qsort(deps, strv_length(deps), list_dependencies_compare);

        STRV_FOREACH(c, deps) {
                if (strv_contains(*units, *c)) {
                        if (!arg_plain) {
                                printf("  ");
                                r = list_dependencies_print("...", level + 1, (branches << 1) | (c[1] == NULL ? 0 : 1), 1);
                                if (r < 0)
                                        return r;
                        }
                        continue;
                }

                if (arg_plain)
                        printf("  ");
                else {
                        UnitActiveState active_state = _UNIT_ACTIVE_STATE_INVALID;
                        const char *on;

                        (void) get_state_one_unit(bus, *c, &active_state);

                        switch (active_state) {
                        case UNIT_ACTIVE:
                        case UNIT_RELOADING:
                        case UNIT_ACTIVATING:
                                on = ansi_highlight_green();
                                break;

                        case UNIT_INACTIVE:
                        case UNIT_DEACTIVATING:
                                on = ansi_normal();
                                break;

                        default:
                                on = ansi_highlight_red();
                                break;
                        }

                        printf("%s%s%s ", on, special_glyph(unit_active_state_to_glyph(active_state)), ansi_normal());
                }

                r = list_dependencies_print(*c, level, branches, c[1] == NULL);
                if (r < 0)
                        return r;

                if (arg_all || unit_name_to_type(*c) == UNIT_TARGET) {
                       r = list_dependencies_one(bus, *c, level + 1, units, (branches << 1) | (c[1] == NULL ? 0 : 1));
                       if (r < 0)
                               return r;
                }
        }

        if (!arg_plain)
                strv_remove(*units, name);

        return 0;
}

int list_dependencies(int argc, char *argv[], void *userdata) {
        _cleanup_strv_free_ char **units = NULL, **done = NULL;
        char **u, **patterns;
        sd_bus *bus;
        int r;

        r = acquire_bus(BUS_MANAGER, &bus);
        if (r < 0)
                return r;

        patterns = strv_skip(argv, 1);
        if (strv_isempty(patterns)) {
                units = strv_new(SPECIAL_DEFAULT_TARGET);
                if (!units)
                        return log_oom();
        } else {
                r = expand_unit_names(bus, patterns, NULL, &units, NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to expand names: %m");
        }

        (void) pager_open(arg_pager_flags);

        STRV_FOREACH(u, units) {
                if (u != units)
                        puts("");

                puts(*u);
                r = list_dependencies_one(bus, *u, 0, &done, 0);
                if (r < 0)
                        return r;
        }

        return 0;
}
