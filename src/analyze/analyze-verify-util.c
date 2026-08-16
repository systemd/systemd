/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>
#include <unistd.h>

#include "sd-bus.h"
#include "sd-messages.h"

#include "all-units.h"
#include "alloc-util.h"
#include "analyze-verify-util.h"
#include "bus-error.h"
#include "dbus-unit.h"
#include "env-util.h"
#include "errno-util.h"
#include "log.h"
#include "manager.h"
#include "pager.h"
#include "path-util.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "unit-name.h"
#include "unit-serialize.h"

int verify_prepare_filename(const char *filename, const char *instance, char **ret) {
        _cleanup_free_ char *abspath = NULL, *name = NULL, *dir = NULL, *with_instance = NULL;
        char *c;
        int r;

        assert(filename);
        assert(ret);

        r = path_make_absolute_cwd(filename, &abspath);
        if (r < 0)
                return r;

        r = path_extract_filename(abspath, &name);
        if (r < 0)
                return r;

        if (!unit_name_is_valid(name, UNIT_NAME_ANY))
                return -EINVAL;

        if (unit_name_is_valid(name, UNIT_NAME_TEMPLATE)) {
                r = unit_name_replace_instance(name, instance, &with_instance);
                if (r < 0)
                        return r;
        }

        r = path_extract_directory(abspath, &dir);
        if (r < 0)
                return r;

        c = path_join(dir, with_instance ?: name);
        if (!c)
                return -ENOMEM;

        *ret = c;
        return 0;
}

static int find_unit_directory(const char *p, char **ret) {
        _cleanup_free_ char *a = NULL, *u = NULL, *t = NULL, *d = NULL;
        int r;

        assert(p);
        assert(ret);

        r = path_make_absolute_cwd(p, &a);
        if (r < 0)
                return r;

        if (access(a, F_OK) >= 0) {
                r = path_extract_directory(a, &d);
                if (r < 0)
                        return r;

                *ret = TAKE_PTR(d);
                return 0;
        }

        r = path_extract_filename(a, &u);
        if (r < 0)
                return r;

        if (!unit_name_is_valid(u, UNIT_NAME_INSTANCE))
                return -ENOENT;

        /* If the specified unit is an instance of a template unit, then let's try to find the template unit. */
        r = unit_name_template(u, &t);
        if (r < 0)
                return r;

        r = path_extract_directory(a, &d);
        if (r < 0)
                return r;

        free(a);
        a = path_join(d, t);
        if (!a)
                return -ENOMEM;

        if (access(a, F_OK) < 0)
                return -errno;

        *ret = TAKE_PTR(d);
        return 0;
}

int verify_set_unit_path(char * const *filenames) {
        _cleanup_strv_free_ char **ans = NULL;
        _cleanup_free_ char *joined = NULL;
        const char *old;
        int r;

        STRV_FOREACH(filename, filenames) {
                _cleanup_free_ char *t = NULL;

                r = find_unit_directory(*filename, &t);
                if (r == -ENOMEM)
                        return r;
                if (r < 0)
                        continue;

                r = strv_consume(&ans, TAKE_PTR(t));
                if (r < 0)
                        return r;
        }

        if (strv_isempty(ans))
                return 0;

        joined = strv_join(strv_uniq(ans), ":");
        if (!joined)
                return -ENOMEM;

        /* First, prepend our directories. Second, if some path was specified, use that, and
         * otherwise use the defaults. Any duplicates will be filtered out in path-lookup.c.
         * Treat explicit empty path to mean that nothing should be appended. */
        old = getenv("SYSTEMD_UNIT_PATH");
        if (!path_is_valid_search_path(old))
                return -EINVAL;

        if (!streq_ptr(old, "") &&
            !strextend_with_separator(&joined, ":", streq_ptr(old, ":") ? "" : strempty(old)))
                return -ENOMEM;

        return setenv_unit_path(joined);
}

static bool verify_error_is_fatal(int r) {
        return ERRNO_IS_NEG_RESOURCE(r) || r == -E2BIG;
}

typedef struct VerifyCallbackContext {
        VerifyUnitsResult *result;

        /* First error raised by a callback which cannot return errors through its source API. */
        int error;
} VerifyCallbackContext;

static void verify_diagnostic_done(VerifyDiagnostic *diagnostic) {
        if (!diagnostic)
                return;

        free(diagnostic->message);
        free(diagnostic->unit);
        free(diagnostic->configuration_file);
        free(diagnostic->message_id);

        *diagnostic = (VerifyDiagnostic) {};
}

void verify_units_result_done(VerifyUnitsResult *result) {
        if (!result)
                return;

        FOREACH_ARRAY(diagnostic, result->diagnostics, result->n_diagnostics)
                verify_diagnostic_done(diagnostic);

        free(result->diagnostics);
        *result = (VerifyUnitsResult) {};
}

static int verify_diagnostic_add(
                VerifyCallbackContext *context,
                int priority,
                const char *message,
                const char *unit,
                const char *configuration_file,
                unsigned configuration_line,
                const char *message_id) {

        _cleanup_(verify_diagnostic_done) VerifyDiagnostic diagnostic = {
                .priority = priority,
                .configuration_line = configuration_line,
        };

        assert(context);
        assert(context->result);
        assert(message);

        diagnostic.message = strdup(message);
        if (!diagnostic.message)
                return -ENOMEM;

        if (unit) {
                diagnostic.unit = strdup(unit);
                if (!diagnostic.unit)
                        return -ENOMEM;
        }

        if (configuration_file) {
                diagnostic.configuration_file = strdup(configuration_file);
                if (!diagnostic.configuration_file)
                        return -ENOMEM;
        }

        if (message_id) {
                diagnostic.message_id = strdup(message_id);
                if (!diagnostic.message_id)
                        return -ENOMEM;
        }

        if (!GREEDY_REALLOC(context->result->diagnostics, context->result->n_diagnostics + 1))
                return -ENOMEM;

        context->result->diagnostics[context->result->n_diagnostics++] = TAKE_STRUCT(diagnostic);
        return 1;
}

static void verify_manager_diagnostic_callback(const ManagerDiagnostic *record, void *userdata) {
        VerifyCallbackContext *context = ASSERT_PTR(userdata);
        int r;

        assert(record);

        if (context->error < 0)
                return;
        if (record->priority > LOG_INFO)
                return;

        r = verify_diagnostic_add(
                        context,
                        record->priority,
                        record->message,
                        record->unit,
                        record->configuration_file,
                        record->configuration_line,
                        record->message_id);
        if (r < 0)
                context->error = r;
}

static void verify_manager_diagnostic_callback_clearp(Manager **manager) {
        assert(manager);

        if (!*manager)
                return;

        (*manager)->test_run_diagnostic_callback = NULL;
        (*manager)->test_run_diagnostic_userdata = NULL;
}

static void verify_syntax_callback(const LogSyntaxRecord *record, void *userdata) {
        VerifyCallbackContext *context = ASSERT_PTR(userdata);
        int r;

        assert(record);

        if (context->error < 0)
                return;
        if (record->priority > LOG_INFO)
                return;

        r = verify_diagnostic_add(
                        context,
                        record->priority,
                        record->message,
                        record->unit,
                        record->config_file,
                        record->config_line,
                        SD_MESSAGE_INVALID_CONFIGURATION_STR);
        if (r < 0)
                context->error = r;
}

static int verify_callback_get_error(const VerifyCallbackContext *context) {
        assert(context);

        return context->error;
}

static bool verify_diagnostic_is_syntax_warning(const VerifyDiagnostic *diagnostic) {
        assert(diagnostic);

        return diagnostic->priority <= LOG_WARNING &&
                diagnostic->unit &&
                streq_ptr(diagnostic->message_id, SD_MESSAGE_INVALID_CONFIGURATION_STR);
}

static int verify_diagnostics_syntax_status(
                const VerifyUnitsResult *result,
                char * const *filenames,
                RecursiveErrors recursive_errors) {

        assert(result);

        if (IN_SET(recursive_errors, RECURSIVE_ERRORS_YES, RECURSIVE_ERRORS_NO)) {
                FOREACH_ARRAY(diagnostic, result->diagnostics, result->n_diagnostics)
                        if (verify_diagnostic_is_syntax_warning(diagnostic))
                                return -ENOTRECOVERABLE;

                return 0;
        }

        if (recursive_errors != RECURSIVE_ERRORS_ONE)
                return 0;

        STRV_FOREACH(filename, filenames) {
                _cleanup_free_ char *unit_file = NULL;
                int r;

                r = path_extract_filename(*filename, &unit_file);
                if (r < 0)
                        return log_error_errno(r, "Failed to extract file name from '%s': %m", *filename);

                FOREACH_ARRAY(diagnostic, result->diagnostics, result->n_diagnostics)
                        if (verify_diagnostic_is_syntax_warning(diagnostic) &&
                            streq(diagnostic->unit, unit_file))
                                return -ENOTRECOVERABLE;
        }

        return 0;
}

static int verify_socket(Unit *u) {
        Unit *service;
        int r;

        assert(u);

        if (u->type != UNIT_SOCKET)
                return 0;

        r = socket_load_service_unit(SOCKET(u), -1, &service);
        if (r < 0)
                return log_unit_error_errno(u, r, "service unit for the socket cannot be loaded: %m");

        if (service->load_state != UNIT_LOADED)
                return log_unit_error_errno(u, SYNTHETIC_ERRNO(ENOENT),
                                            "service %s not loaded, socket cannot be started.", service->id);

        log_unit_debug(u, "using service unit %s.", service->id);
        return 0;
}

int verify_executable(Unit *u, const ExecCommand *exec, const char *root) {
        int r;

        if (!exec)
                return 0;

        if (exec->flags & EXEC_COMMAND_IGNORE_FAILURE)
                return 0;

        r = find_executable_full(exec->path, root, NULL, false, NULL, NULL);
        if (r < 0)
                return log_unit_error_errno(u, r, "Command %s is not executable: %m", exec->path);

        return 0;
}

static int verify_executables(Unit *u, const char *root) {
        int r = 0, k;

        assert(u);

        if (u->type == UNIT_SERVICE)
                FOREACH_ELEMENT(i, SERVICE(u)->exec_command)
                        LIST_FOREACH(command, j, *i) {
                                k = verify_executable(u, j, root);
                                if (verify_error_is_fatal(k))
                                        return k;

                                RET_GATHER(r, k);
                        }

        if (u->type == UNIT_SOCKET)
                FOREACH_ELEMENT(i, SOCKET(u)->exec_command)
                        LIST_FOREACH(command, j, *i) {
                                k = verify_executable(u, j, root);
                                if (verify_error_is_fatal(k))
                                        return k;

                                RET_GATHER(r, k);
                        }

        return r;
}

static int verify_documentation(Unit *u, bool check_man) {
        int r = 0, k;

        STRV_FOREACH(p, u->documentation) {
                log_unit_debug(u, "Found documentation item: %s", *p);

                if (check_man && startswith(*p, "man:")) {
                        k = show_man_page(*p + 4, true);
                        if (k != 0) {
                                if (verify_error_is_fatal(k))
                                        return k;

                                if (k < 0)
                                        log_unit_error_errno(u, k, "Can't show %s: %m", *p + 4);
                                else {
                                        log_unit_error(u, "Command 'man %s' failed with code %d", *p + 4, k);
                                        k = -ENOEXEC;
                                }
                                if (r == 0)
                                        r = k;
                        }
                }
        }

        /* Check remote URLs? */

        return r;
}

static int verify_unit(Unit *u, bool check_man, const char *root, bool suppress_output) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int r, k;

        assert(u);

        if (!suppress_output && DEBUG_LOGGING)
                unit_dump(u, stdout, "\t");

        log_unit_debug(u, "Creating %s/start job", u->id);
        r = manager_add_job(u->manager, JOB_START, u, JOB_REPLACE, &error, /* ret= */ NULL);
        if (r < 0) {
                log_unit_error_errno(
                                u, r, "Failed to create %s/start: %s", u->id, bus_error_message(&error, r));
                if (verify_error_is_fatal(r))
                        return r;
        }

        k = verify_socket(u);
        if (verify_error_is_fatal(k))
                return k;
        RET_GATHER(r, k);

        k = verify_executables(u, root);
        if (verify_error_is_fatal(k))
                return k;
        RET_GATHER(r, k);

        k = verify_documentation(u, check_man);
        if (verify_error_is_fatal(k))
                return k;
        RET_GATHER(r, k);

        return r;
}

static int verify_load_startable_unit(
                Manager *m,
                const char *path,
                VerifyCallbackContext *context,
                Unit **ret,
                int *ret_status) {

        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        Unit *unit;
        int r, k;

        assert(m);
        assert(path);
        assert(context);
        assert(ret);
        assert(ret_status);

        r = manager_load_unit(m, /* name= */ NULL, path, &error, &unit);
        if (r < 0) {
                if (verify_error_is_fatal(r))
                        return r;

                const char *message = bus_error_message(&error, r);

                log_error_errno(r, "Failed to load unit file %s: %s", path, message);

                k = verify_diagnostic_add(
                                context,
                                LOG_ERR,
                                message,
                                last_path_component(path),
                                path,
                                0,
                                /* message_id= */ NULL);
                if (k < 0)
                        return k;

                *ret_status = r;
                return 0;
        }

        r = bus_unit_validate_load_state(unit, &error);
        if (r < 0) {
                if (verify_error_is_fatal(r))
                        return r;

                const char *message = bus_error_message(&error, r);

                log_error_errno(r, "%s", message);

                k = verify_diagnostic_add(
                                context,
                                LOG_ERR,
                                message,
                                unit->id,
                                unit->fragment_path ?: path,
                                0,
                                /* message_id= */ NULL);
                if (k < 0)
                        return k;

                *ret_status = r;
                return 0;
        }

        *ret = unit;
        *ret_status = 0;
        return 0;
}

static int verify_prepare_filename_and_report(
                const char *filename,
                const char *instance,
                VerifyCallbackContext *context,
                char **ret,
                int *ret_status) {

        _cleanup_free_ char *message = NULL;
        int r, k;

        assert(filename);
        assert(instance);
        assert(context);
        assert(ret);
        assert(ret_status);

        r = verify_prepare_filename(filename, instance, ret);
        if (r >= 0) {
                *ret_status = 0;
                return 0;
        }

        log_error_errno(r, "Failed to prepare filename %s: %m", filename);
        if (verify_error_is_fatal(r))
                return r;

        message = strjoin("Failed to prepare filename ", filename, ": ", STRERROR(r));
        if (!message)
                return -ENOMEM;

        k = verify_diagnostic_add(
                        context,
                        LOG_ERR,
                        message,
                        /* unit= */ NULL,
                        filename,
                        0,
                        /* message_id= */ NULL);
        if (k < 0)
                return k;

        *ret_status = r;
        return 0;
}

static int verify_units_internal(const VerifyUnitsParameters *parameters, VerifyUnitsResult *ret) {
        _cleanup_(verify_units_result_done) VerifyUnitsResult result = {};
        VerifyCallbackContext context = {
                .result = &result,
        };
        _cleanup_(manager_freep) Manager *m = NULL;
        _cleanup_(verify_manager_diagnostic_callback_clearp) Manager *diagnostic_manager = NULL;
        _cleanup_free_ char *saved_unit_path = NULL;
        _cleanup_free_ Unit **units = NULL;
        size_t n_filenames, count = 0;
        int r, k, status = 0;

        assert(parameters);
        assert(ret);

        n_filenames = strv_length(parameters->filenames);

        if (n_filenames == 0) {
                *ret = TAKE_STRUCT(result);
                return 0;
        }

        assert(parameters->instance);

        const ManagerTestRunFlags flags =
                MANAGER_TEST_RUN_MINIMAL |
                parameters->run_environment_generators * MANAGER_TEST_RUN_ENV_GENERATORS |
                MANAGER_TEST_DONT_OPEN_EXECUTOR |
                (parameters->recursive_errors == RECURSIVE_ERRORS_NO) *
                        MANAGER_TEST_RUN_IGNORE_DEPENDENCIES |
                parameters->run_unit_generators * MANAGER_TEST_RUN_GENERATORS;

        if (!parameters->lookup_path_override) {
                const char *unit_path = getenv("SYSTEMD_UNIT_PATH");

                if (unit_path) {
                        saved_unit_path = strdup(unit_path);
                        if (!saved_unit_path)
                                return log_oom();
                }

                r = verify_set_unit_path(parameters->filenames);
                if (r < 0)
                        return log_error_errno(r, "Failed to set unit load path: %m");
        }

        r = manager_new(parameters->runtime_scope, flags, &m);
        if (r < 0)
                log_error_errno(r, "Failed to initialize manager: %m");
        else {
                log_debug("Starting manager...");

                r = manager_startup(
                                m,
                                /* serialization= */ NULL,
                                /* fds= */ NULL,
                                /* named_listen_fds= */ NULL,
                                parameters->root);
        }

        if (!parameters->lookup_path_override) {
                k = set_unset_env("SYSTEMD_UNIT_PATH", saved_unit_path, /* overwrite= */ true);
                if (k < 0)
                        return log_error_errno(k, "Failed to restore unit load path: %m");
        }
        if (r < 0)
                return r;

        if (parameters->lookup_path_override) {
                _cleanup_strv_free_ char **search_path = NULL;

                search_path = strv_copy(parameters->lookup_path_override);
                if (!search_path)
                        return -ENOMEM;

                strv_free_and_replace(m->lookup_paths.search_path, search_path);
        }

        manager_clear_jobs(m);

        /* These callbacks are scoped to the temporary manager and syntax parser, so diagnostics and
         * their effect on the result do not depend on presentation through the ambient log target. */
        _unused_ _cleanup_(clear_log_syntax_callback) dummy_t syntax_callback_cleanup;
        set_log_syntax_callback(verify_syntax_callback, &context);
        assert(!m->test_run_diagnostic_callback);
        m->test_run_diagnostic_callback = verify_manager_diagnostic_callback;
        m->test_run_diagnostic_userdata = &context;
        diagnostic_manager = m;
        m->no_console_output = parameters->suppress_output;

        units = new(Unit*, n_filenames);
        if (!units)
                return -ENOMEM;

        log_debug("Loading requested units...");

        STRV_FOREACH(filename, parameters->filenames) {
                _cleanup_free_ char *prepared = NULL;
                int finding_status;

                log_debug("Handling %s...", *filename);

                k = verify_prepare_filename_and_report(
                                *filename,
                                parameters->instance,
                                &context,
                                &prepared,
                                &finding_status);
                if (k < 0)
                        return k;

                if (finding_status < 0) {
                        RET_GATHER(status, finding_status);
                        continue;
                }

                k = verify_load_startable_unit(
                                m,
                                prepared,
                                &context,
                                &units[count],
                                &finding_status);
                if (k < 0)
                        return k;

                k = verify_callback_get_error(&context);
                if (k < 0)
                        return k;

                if (finding_status < 0) {
                        RET_GATHER(status, finding_status);
                        continue;
                }

                count++;
        }

        FOREACH_ARRAY(i, units, count) {
                k = verify_unit(
                                *i,
                                parameters->check_man,
                                parameters->root,
                                parameters->suppress_output);

                r = verify_callback_get_error(&context);
                if (r < 0)
                        return r;

                if (k < 0) {
                        if (verify_error_is_fatal(k))
                                return k;

                        RET_GATHER(status, k);
                }
        }

        if (status == 0) {
                k = verify_diagnostics_syntax_status(
                                &result,
                                parameters->filenames,
                                parameters->recursive_errors);
                if (k < 0) {
                        if (verify_error_is_fatal(k))
                                return k;

                        status = k;
                }
        }

        result.legacy_status = status;
        *ret = TAKE_STRUCT(result);
        return 0;
}

int verify_units(const VerifyUnitsParameters *parameters, VerifyUnitsResult *ret) {
        LogTarget saved_target;
        int r;

        assert(parameters);
        assert(ret);

        if (!parameters->suppress_output)
                return verify_units_internal(parameters, ret);

        saved_target = log_get_target();
        log_set_target(LOG_TARGET_NULL);
        r = verify_units_internal(parameters, ret);
        log_set_target(saved_target);

        return r;
}

static const char* const recursive_errors_table[_RECURSIVE_ERRORS_MAX] = {
        [RECURSIVE_ERRORS_NO]  = "no",
        [RECURSIVE_ERRORS_YES] = "yes",
        [RECURSIVE_ERRORS_ONE] = "one",
};

DEFINE_STRING_TABLE_LOOKUP(recursive_errors, RecursiveErrors);
