/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>

#include "analyze.h"
#include "analyze-condition.h"
#include "analyze-verify-util.h"
#include "condition.h"
#include "conf-parser.h"
#include "load-fragment.h"
#include "service.h"

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
        Unit *u = ASSERT_PTR(userdata);
        Manager *m = ASSERT_PTR(u->manager);
        va_list ap;
        int r;

        /* "upgrade" debug messages */
        level = MIN(LOG_INFO, level);

        va_start(ap, format);
        r = log_object_internalv(level, error, file, line, func,
                                 /* object_field = */ m->unit_log_field,
                                 /* object = */ u->id,
                                 /* extra_field = */ NULL,
                                 /* extra = */ NULL,
                                 format, ap);
        va_end(ap);

        return r;
}

static int verify_conditions(char **lines, RuntimeScope scope, const char *unit, const char *root) {
        _cleanup_(manager_freep) Manager *m = NULL;
        Unit *u;
        int r, q = 1;

        if (unit) {
                r = verify_set_unit_path(STRV_MAKE(unit));
                if (r < 0)
                        return log_error_errno(r, "Failed to set unit load path: %m");
        }

        r = manager_new(scope, MANAGER_TEST_RUN_MINIMAL|MANAGER_TEST_DONT_OPEN_EXECUTOR, &m);
        if (r < 0)
                return log_error_errno(r, "Failed to initialize manager: %m");

        log_debug("Starting manager...");
        r = manager_startup(m, /* serialization= */ NULL, /* fds= */ NULL, root);
        if (r < 0)
                return r;

        if (unit) {
                _cleanup_free_ char *prepared = NULL;

                r = verify_prepare_filename(unit, &prepared);
                if (r < 0)
                        return log_error_errno(r, "Failed to prepare filename %s: %m", unit);

                r = manager_load_startable_unit_or_warn(m, NULL, prepared, &u);
                if (r < 0)
                        return r;
        } else {
                r = unit_new_for_name(m, sizeof(Service), "test.service", &u);
                if (r < 0)
                        return log_error_errno(r, "Failed to create test.service: %m");

                STRV_FOREACH(line, lines) {
                        r = parse_condition(u, *line);
                        if (r < 0)
                                return r;
                }
        }

        condition_test_logger_t logger = arg_quiet ? NULL : log_helper;
        r = condition_test_list(u->asserts, environ, assert_type_to_string, logger, u);
        if (u->asserts)
                log_full(arg_quiet ? LOG_DEBUG : LOG_NOTICE, "Asserts %s.", r > 0 ? "succeeded" : "failed");

        q = condition_test_list(u->conditions, environ, condition_type_to_string, logger, u);
        if (u->conditions)
                log_full(arg_quiet ? LOG_DEBUG : LOG_NOTICE, "Conditions %s.", q > 0 ? "succeeded" : "failed");

        return r > 0 && q > 0 ? 0 : -EIO;
}

int verb_condition(int argc, char *argv[], void *userdata) {
        int r;

        r = verify_conditions(strv_skip(argv, 1), arg_runtime_scope, arg_unit, arg_root);
        if (r < 0)
                return r;

        return EXIT_SUCCESS;
}
