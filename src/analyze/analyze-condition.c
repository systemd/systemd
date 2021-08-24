/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>

#include "analyze-condition.h"
#include "analyze-verify.h"
#include "condition.h"
#include "conf-parser.h"
#include "load-fragment.h"
#include "service.h"

static bool starts_with_condition_type(const char *line) {
        assert(line);

        for (ConditionType t = 0; t < _CONDITION_TYPE_MAX; t++) {
                const char *name;

                name = condition_type_to_string(t);
                if (startswith(line, name))
                        return true;

                name = assert_type_to_string(t);
                if (startswith(line, name))
                        return true;
        }

        return false;
}

static int parse_condition(Unit *u, const char *line) {
        assert(u);
        assert(line);

        for (ConditionType t = 0; t < _CONDITION_TYPE_MAX; t++) {
                ConfigParserCallback callback;
                Condition **target;
                const char *p, *name;

                name = condition_type_to_string(t);
                p = startswith(line, name);
                if (p)
                        target = &u->conditions;
                else {
                        name = assert_type_to_string(t);
                        p = startswith(line, name);
                        if (!p)
                                continue;

                        target = &u->asserts;
                }

                p += strspn(p, WHITESPACE);

                if (*p != '=')
                        continue;
                p++;

                p += strspn(p, WHITESPACE);

                if (condition_takes_path(t))
                        callback = config_parse_unit_condition_path;
                else
                        callback = config_parse_unit_condition_string;

                return callback(NULL, "(cmdline)", 0, NULL, 0, name, t, p, target, u);
        }

        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Cannot parse \"%s\".", line);
}

_printf_(7, 8)
static int log_helper(void *userdata, int level, int error, const char *file, int line, const char *func, const char *format, ...) {
        Unit *u = userdata;
        va_list ap;
        int r;

        assert(u);

        /* "upgrade" debug messages */
        level = MIN(LOG_INFO, level);

        va_start(ap, format);
        r = log_object_internalv(level, error, file, line, func,
                                 NULL,
                                 u->id,
                                 NULL,
                                 NULL,
                                 format, ap);
        va_end(ap);

        return r;
}

int verify_conditions(char **lines, UnitFileScope scope, const char *root) {
        _cleanup_(manager_freep) Manager *m = NULL;
        _cleanup_free_ char *var = NULL;
        _cleanup_strv_free_ char **filenames = NULL;
        Unit *u;
        char **line;
        int r, q = 1;

        STRV_FOREACH(line, lines) {
                if (starts_with_condition_type(*line))
                        continue;

                if (unit_name_is_valid(*line, UNIT_NAME_ANY)) {
                        r = strv_extend(&filenames, *line);
                        if (r < 0)
                                return r;
                }
        }

        if (filenames) {
                r = verify_generate_path(&var, filenames);
                if (r < 0)
                        return log_error_errno(r, "Failed to generate unit load path: %m");

                assert_se(set_unit_path(var) >= 0);
        }

        r = manager_new(scope, MANAGER_TEST_RUN_MINIMAL, &m);
        if (r < 0)
                return log_error_errno(r, "Failed to initialize manager: %m");

        log_debug("Starting manager...");
        r = manager_startup(m, /* serialization= */ NULL, /* fds= */ NULL, root);
        if (r < 0)
                return r;

        r = unit_new_for_name(m, sizeof(Service), "test.service", &u);
        if (r < 0)
                return log_error_errno(r, "Failed to create test.service: %m");

        STRV_FOREACH(line, lines) {
                if (unit_name_is_valid(*line, UNIT_NAME_ANY)) {
                        _cleanup_free_ char *prepared = NULL;
                        Unit *unit;

                        r = verify_prepare_filename(*line, &prepared);
                        if (r < 0)
                                return log_error_errno(r, "Failed to prepare filename %s: %m", *line);

                        r = manager_load_startable_unit_or_warn(m, NULL, prepared, &unit);
                        if (r < 0)
                                return r;

                        if (unit->asserts)
                                LIST_JOIN(conditions, u->asserts, unit->asserts);
                        if (unit->conditions)
                                LIST_JOIN(conditions, u->conditions, unit->conditions);
                } else {
                        r = parse_condition(u, *line);
                        if (r < 0)
                                return r;
                }
        }

        r = condition_test_list(u->asserts, environ, assert_type_to_string, log_helper, u);
        if (u->asserts)
                log_notice("Asserts %s.", r > 0 ? "succeeded" : "failed");

        q = condition_test_list(u->conditions, environ, condition_type_to_string, log_helper, u);
        if (u->conditions)
                log_notice("Conditions %s.", q > 0 ? "succeeded" : "failed");

        return r > 0 && q > 0 ? 0 : -EIO;
}
