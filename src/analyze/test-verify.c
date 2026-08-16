/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>

#include "sd-messages.h"

#include "analyze-verify-util.h"
#include "execute.h"
#include "fileio.h"
#include "path-util.h"
#include "rm-rf.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"
#include "tmpfile-util.h"

TEST(verify_nonexistent) {
        /* Negative cases */
        assert_se(verify_executable(NULL, &(ExecCommand) {.flags = EXEC_COMMAND_IGNORE_FAILURE, .path = (char*) "/non/existent"}, NULL) == 0);
        assert_se(verify_executable(NULL, &(ExecCommand) {.path = (char*) "/non/existent"}, NULL) < 0);

        /* Ordinary cases */
        assert_se(verify_executable(NULL, &(ExecCommand) {.path = (char*) "/bin/echo"}, NULL) == 0);
        assert_se(verify_executable(NULL, &(ExecCommand) {.flags = EXEC_COMMAND_IGNORE_FAILURE, .path = (char*) "/bin/echo"}, NULL) == 0);
}

static void test_verify_set_unit_path_one(const char *old, const char *expected) {
        _cleanup_(rm_rf_physical_and_freep) char *tmp = NULL;
        _cleanup_free_ char *unit = NULL;
        char *unit_paths[2];

        ASSERT_OK(mkdtemp_malloc("/tmp/test-verify.XXXXXX", &tmp));
        unit = ASSERT_NOT_NULL(path_join(tmp, "test.service"));
        ASSERT_OK(write_string_file(unit, "[Unit]\nDescription=test\n", WRITE_STRING_FILE_CREATE));

        if (old)
                ASSERT_OK_ERRNO(setenv("SYSTEMD_UNIT_PATH", old, 1));
        else
                ASSERT_OK_ERRNO(unsetenv("SYSTEMD_UNIT_PATH"));

        unit_paths[0] = unit;
        unit_paths[1] = NULL;

        if (expected) {
                ASSERT_OK(verify_set_unit_path(unit_paths));
                ASSERT_STREQ(getenv("SYSTEMD_UNIT_PATH"), strjoina(tmp, expected));
        } else
                ASSERT_ERROR(verify_set_unit_path(unit_paths), EINVAL);
}

TEST(verify_set_unit_path) {
        _cleanup_free_ char *old_saved = getenv("SYSTEMD_UNIT_PATH") ? strdup(getenv("SYSTEMD_UNIT_PATH")) : NULL;
        ASSERT_TRUE(old_saved || !getenv("SYSTEMD_UNIT_PATH"));

        test_verify_set_unit_path_one(/* old= */ NULL, ":");
        test_verify_set_unit_path_one("", "");
        test_verify_set_unit_path_one(":", ":");
        test_verify_set_unit_path_one("/foo:", ":/foo:");
        test_verify_set_unit_path_one(":foo", /* expected= */ NULL);
        test_verify_set_unit_path_one("/foo::/bar", /* expected= */ NULL);

        if (old_saved)
                ASSERT_OK_ERRNO(setenv("SYSTEMD_UNIT_PATH", old_saved, 1));
        else
                ASSERT_OK_ERRNO(unsetenv("SYSTEMD_UNIT_PATH"));
}

TEST(verify_units_restores_unit_path) {
        _cleanup_(rm_rf_physical_and_freep) char *tmp = NULL;
        _cleanup_free_ char *first = NULL, *second = NULL;
        const bool had_unit_path = getenv("SYSTEMD_UNIT_PATH");
        _cleanup_free_ char *old_unit_path = had_unit_path ? strdup(getenv("SYSTEMD_UNIT_PATH")) : NULL;
        char *filenames[2] = {};
        char *filename;
        int r;

        ASSERT_TRUE(old_unit_path || !had_unit_path);
        ASSERT_OK(mkdtemp_malloc("/tmp/test-verify-restore.XXXXXX", &tmp));
        first = ASSERT_NOT_NULL(path_join(tmp, "first.service"));
        second = ASSERT_NOT_NULL(path_join(tmp, "second.service"));
        ASSERT_OK(write_string_file(first, "[Unit]\n", WRITE_STRING_FILE_CREATE));
        ASSERT_OK(write_string_file(second, "[Unit]\n", WRITE_STRING_FILE_CREATE));

        ASSERT_OK_ERRNO(setenv("SYSTEMD_UNIT_PATH", ":", /* overwrite= */ true));

        VerifyUnitsParameters parameters = {
                .filenames = filenames,
                .runtime_scope = RUNTIME_SCOPE_SYSTEM,
                .recursive_errors = RECURSIVE_ERRORS_NO,
                .instance = "test_instance",
                .suppress_output = true,
        };

        FOREACH_ARGUMENT(filename, first, second) {
                _cleanup_(verify_units_result_done) VerifyUnitsResult result = {};

                filenames[0] = filename;
                r = verify_units(&parameters, &result);
                ASSERT_STREQ(getenv("SYSTEMD_UNIT_PATH"), ":");
                if (manager_errno_skip_test(r)) {
                        log_notice_errno(r, "Skipping test, manager startup failed: %m");
                        break;
                }
                ASSERT_OK(r);
        }

        if (had_unit_path)
                ASSERT_OK_ERRNO(setenv("SYSTEMD_UNIT_PATH", old_unit_path, /* overwrite= */ true));
        else
                ASSERT_OK_ERRNO(unsetenv("SYSTEMD_UNIT_PATH"));
}

TEST(verify_units_empty) {
        _cleanup_(verify_units_result_done) VerifyUnitsResult result = {};

        ASSERT_OK(verify_units(&(VerifyUnitsParameters) {}, &result));
        ASSERT_OK(result.legacy_status);
        ASSERT_EQ(result.n_diagnostics, 0u);
}

static VerifyDiagnostic* find_diagnostic(
                VerifyUnitsResult *result,
                const char *unit,
                const char *configuration_file,
                const char *message_id) {

        FOREACH_ARRAY(diagnostic, result->diagnostics, result->n_diagnostics)
                if (streq_ptr(diagnostic->unit, unit) &&
                    streq_ptr(diagnostic->configuration_file, configuration_file) &&
                    streq_ptr(diagnostic->message_id, message_id))
                        return diagnostic;

        return NULL;
}

static VerifyDiagnostic* find_diagnostic_by_message_id(
                VerifyUnitsResult *result,
                const char *message_id) {

        FOREACH_ARRAY(diagnostic, result->diagnostics, result->n_diagnostics)
                if (streq_ptr(diagnostic->message_id, message_id))
                        return diagnostic;

        return NULL;
}

TEST(verify_units_result) {
        _cleanup_(verify_units_result_done) VerifyUnitsResult result = {};
        _cleanup_(rm_rf_physical_and_freep) char *tmp = NULL;
        _cleanup_free_ char *bad = NULL, *invalid = NULL, *load_error = NULL, *missing = NULL, *parse = NULL;
        char *filenames[3];
        int r;

        ASSERT_OK(mkdtemp_malloc("/tmp/test-verify.XXXXXX", &tmp));
        bad = ASSERT_NOT_NULL(path_join(tmp, "bad.service"));
        invalid = ASSERT_NOT_NULL(path_join(tmp, "invalid"));
        load_error = ASSERT_NOT_NULL(path_join(tmp, "load-error.service"));
        missing = ASSERT_NOT_NULL(path_join(tmp, "missing.service"));
        parse = ASSERT_NOT_NULL(path_join(tmp, "parse.service"));
        ASSERT_OK(write_string_file(
                        bad,
                        "[Unit]\nUnknownSetting=yes\n[Service]\nExecStart=/bin/true\n",
                        WRITE_STRING_FILE_CREATE));
        ASSERT_OK(write_string_file(load_error, "[Service]\n", WRITE_STRING_FILE_CREATE));
        ASSERT_OK(write_string_file(
                        parse,
                        "[Service]\nRemainAfterExit=invalid\nExecStart=/bin/true\n",
                        WRITE_STRING_FILE_CREATE));

        VerifyUnitsParameters parameters = {
                .filenames = filenames,
                .runtime_scope = RUNTIME_SCOPE_SYSTEM,
                .recursive_errors = _RECURSIVE_ERRORS_INVALID,
                .instance = "test_instance",
                .suppress_output = true,
        };

        filenames[0] = bad;
        filenames[1] = NULL;
        filenames[2] = NULL;

        r = verify_units(&parameters, &result);
        if (manager_errno_skip_test(r)) {
                log_notice_errno(r, "Skipping test, manager startup failed: %m");
                return;
        }
        ASSERT_OK(r);
        ASSERT_EQ(result.legacy_status, 0);

        VerifyDiagnostic *diagnostic = ASSERT_NOT_NULL(find_diagnostic(
                        &result, "bad.service", bad, SD_MESSAGE_INVALID_CONFIGURATION_STR));
        ASSERT_STREQ(diagnostic->configuration_file, bad);
        ASSERT_EQ(diagnostic->configuration_line, 2u);

        verify_units_result_done(&result);
        parameters.recursive_errors = RECURSIVE_ERRORS_NO;
        ASSERT_OK(verify_units(&parameters, &result));
        ASSERT_ERROR(result.legacy_status, ENOTRECOVERABLE);

        /* Diagnostics and recursive error handling must not depend on the selected log verbosity. The
         * unknown-key path is gated by log_syntax_enabled(), while parse errors call log_syntax_internal()
         * directly, so keep both cases covered. */
        int old_max_level = log_set_max_level(LOG_ERR);

        verify_units_result_done(&result);
        parameters.suppress_output = false;
        ASSERT_OK(verify_units(&parameters, &result));
        ASSERT_ERROR(result.legacy_status, ENOTRECOVERABLE);
        ASSERT_NOT_NULL(find_diagnostic(
                        &result, "bad.service", bad, SD_MESSAGE_INVALID_CONFIGURATION_STR));

        verify_units_result_done(&result);
        filenames[0] = parse;
        ASSERT_OK(verify_units(&parameters, &result));
        ASSERT_ERROR(result.legacy_status, ENOTRECOVERABLE);
        ASSERT_NOT_NULL(find_diagnostic(
                        &result, "parse.service", parse, SD_MESSAGE_INVALID_CONFIGURATION_STR));

        log_set_max_level(old_max_level);
        parameters.suppress_output = true;

        verify_units_result_done(&result);
        filenames[0] = load_error;
        ASSERT_OK(verify_units(&parameters, &result));
        ASSERT_LT(result.legacy_status, 0);
        diagnostic = ASSERT_NOT_NULL(find_diagnostic(
                        &result, "load-error.service", load_error, /* message_id= */ NULL));
        ASSERT_STREQ(diagnostic->configuration_file, load_error);

        verify_units_result_done(&result);
        filenames[0] = missing;
        ASSERT_OK(verify_units(&parameters, &result));
        ASSERT_LT(result.legacy_status, 0);
        diagnostic = ASSERT_NOT_NULL(find_diagnostic(
                        &result, "missing.service", missing, /* message_id= */ NULL));
        ASSERT_STREQ(diagnostic->configuration_file, missing);

        verify_units_result_done(&result);
        filenames[0] = invalid;
        ASSERT_OK(verify_units(&parameters, &result));
        ASSERT_ERROR(result.legacy_status, EINVAL);
        diagnostic = ASSERT_NOT_NULL(find_diagnostic(
                        &result, /* unit= */ NULL, invalid, /* message_id= */ NULL));
        ASSERT_STREQ(diagnostic->configuration_file, invalid);
}

TEST(verify_units_cycles) {
        _cleanup_(verify_units_result_done) VerifyUnitsResult result = {};
        _cleanup_free_ char *unit_dir = NULL, *unbreakable = NULL, *breakable = NULL;
        VerifyDiagnostic *diagnostic;
        char *filenames[2];
        int r;

        ASSERT_OK(get_testdata_dir("test-engine", &unit_dir));
        unbreakable = ASSERT_NOT_NULL(path_join(unit_dir, "d.service"));
        breakable = ASSERT_NOT_NULL(path_join(unit_dir, "e.service"));

        VerifyUnitsParameters parameters = {
                .filenames = filenames,
                .runtime_scope = RUNTIME_SCOPE_SYSTEM,
                .recursive_errors = RECURSIVE_ERRORS_YES,
                .instance = "test_instance",
                .suppress_output = true,
        };

        filenames[0] = unbreakable;
        filenames[1] = NULL;

        r = verify_units(&parameters, &result);
        if (manager_errno_skip_test(r)) {
                log_notice_errno(r, "Skipping test, manager startup failed: %m");
                return;
        }
        ASSERT_OK(r);
        ASSERT_LT(result.legacy_status, 0);
        diagnostic = ASSERT_NOT_NULL(find_diagnostic_by_message_id(
                        &result, SD_MESSAGE_UNIT_ORDERING_CYCLE_STR));
        ASSERT_NOT_NULL(diagnostic->unit);
        ASSERT_TRUE(STR_IN_SET(diagnostic->unit, "a.service", "b.service", "d.service"));
        diagnostic = ASSERT_NOT_NULL(find_diagnostic_by_message_id(
                        &result, SD_MESSAGE_CANT_BREAK_ORDERING_CYCLE_STR));
        ASSERT_NOT_NULL(diagnostic->unit);
        ASSERT_TRUE(STR_IN_SET(diagnostic->unit, "a.service", "b.service", "d.service"));

        verify_units_result_done(&result);
        filenames[0] = breakable;

        ASSERT_OK(verify_units(&parameters, &result));
        ASSERT_OK(result.legacy_status);
        diagnostic = ASSERT_NOT_NULL(find_diagnostic_by_message_id(
                        &result, SD_MESSAGE_UNIT_ORDERING_CYCLE_STR));
        ASSERT_NOT_NULL(diagnostic->unit);
        ASSERT_TRUE(STR_IN_SET(diagnostic->unit, "a.service", "b.service", "e.service"));
        diagnostic = ASSERT_NOT_NULL(find_diagnostic_by_message_id(
                        &result, SD_MESSAGE_DELETING_JOB_BECAUSE_ORDERING_CYCLE_STR));
        ASSERT_NOT_NULL(diagnostic->unit);
        ASSERT_TRUE(STR_IN_SET(diagnostic->unit, "a.service", "b.service", "e.service"));
}

TEST(verify_units_manager_diagnostics) {
        _cleanup_(verify_units_result_done) VerifyUnitsResult result = {};
        _cleanup_(rm_rf_physical_and_freep) char *tmp = NULL;
        _cleanup_free_ char *service = NULL;
        char *filenames[2];
        int r;

        ASSERT_OK(mkdtemp_malloc("/tmp/test-verify-diagnostics.XXXXXX", &tmp));
        service = ASSERT_NOT_NULL(path_join(tmp, "diagnostics.service"));
        ASSERT_OK(write_string_file(
                        service,
                        "[Service]\n"
                        "Type=oneshot\n"
                        "RuntimeMaxSec=1s\n"
                        "User=unsafe@name\n"
                        "User=nobody\n"
                        "ExecStart=true\n",
                        WRITE_STRING_FILE_CREATE));

        VerifyUnitsParameters parameters = {
                .filenames = filenames,
                .runtime_scope = RUNTIME_SCOPE_SYSTEM,
                .recursive_errors = RECURSIVE_ERRORS_YES,
                .instance = "test_instance",
                .suppress_output = true,
        };

        filenames[0] = service;
        filenames[1] = NULL;

        r = verify_units(&parameters, &result);
        if (manager_errno_skip_test(r)) {
                log_notice_errno(r, "Skipping test, manager startup failed: %m");
                return;
        }
        ASSERT_OK(r);
        ASSERT_OK(result.legacy_status);

        bool found = false;
        FOREACH_ARRAY(diagnostic, result.diagnostics, result.n_diagnostics)
                if (streq_ptr(diagnostic->unit, "diagnostics.service") &&
                    strstr(diagnostic->message, "RuntimeMaxSec=")) {
                        found = true;
                        break;
                }
        ASSERT_TRUE(found);
        ASSERT_NOT_NULL(find_diagnostic(
                        &result, "diagnostics.service", service,
                        SD_MESSAGE_UNSAFE_USER_NAME_STR));
        ASSERT_NOT_NULL(find_diagnostic(
                        &result,
                        "diagnostics.service",
                        service,
                        SD_MESSAGE_NOBODY_USER_UNSUITABLE_STR));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
