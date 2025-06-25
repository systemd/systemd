/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>
#include <unistd.h>

#include "analyze.h"
#include "analyze-condition.h"
#include "analyze-verify-util.h"
#include "condition.h"
#include "load-fragment.h"
#include "manager.h"
#include "service.h"
#include "string-util.h"
#include "strv.h"

static int parse_condition(Unit *u, const char *line) {
        assert(u);
        assert(line);

        line = skip_leading_chars(line, /* bad = */ NULL);

        const char *eq = strchr(line, '=');
        if (!eq)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Cannot parse \"%s\".", line);

        _cleanup_free_ char *type_string = strndup(line, eq - line);
        if (!type_string)
                return log_oom();

        delete_trailing_chars(type_string, /* bad = */ NULL);

        Condition **target;
        ConditionType type;
        if (startswith(type_string, "Condition")) {
                target = &u->conditions;
                type = condition_type_from_string(type_string);
        } else {
                target = &u->asserts;
                type = assert_type_from_string(type_string);
        }
        if (type < 0)
                return log_error_errno(type, "Cannot parse \"%s\".", line);

        const char *val = skip_leading_chars(eq + 1, /* bad = */ NULL);

        ConfigParserCallback callback;
        if (condition_takes_path(type))
                callback = config_parse_unit_condition_path;
        else
                callback = config_parse_unit_condition_string;

        return callback(/* unit = */ NULL,
                        /* filename = */ "(cmdline)",
                        /* line = */ 0,
                        /* section = */ NULL,
                        /* section_line = */ 0,
                        /* lvalue = */ type_string,
                        /* ltype = */ type,
                        /* rvalue = */ val,
                        /* data = */ target,
                        /* userdata = */ u);
}

_printf_(7, 8)
static int log_helper(void *userdata, int level, int error, const char *file, int line, const char *func, const char *format, ...) {
        Unit *u = ASSERT_PTR(userdata);
        va_list ap;
        int r;

        /* "upgrade" debug messages */
        level = MIN(LOG_INFO, level);

        va_start(ap, format);
        r = log_object_internalv(level, error, file, line, func,
                                 /* object_field = */ unit_log_field(u),
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
