/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>

#include "sd-messages.h"

#include "analyze-verify-util.h"
#include "env-util.h"
#include "execute.h"
#include "fileio.h"
#include "iovec-util.h"
#include "manager.h"
#include "path-util.h"
#include "rm-rf.h"
#include "string-util.h"
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

static void test_verify_build_unit_path_one(const char *old, const char *expected) {
        _cleanup_(rm_rf_physical_and_freep) char *tmp = NULL;
        _cleanup_free_ char *unit = NULL, *unit_path = NULL;
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
                ASSERT_OK(verify_build_unit_path(unit_paths, &unit_path));
                ASSERT_STREQ(unit_path, strjoina(tmp, expected));
        } else
                ASSERT_ERROR(verify_build_unit_path(unit_paths, &unit_path), EINVAL);

        ASSERT_TRUE(streq_ptr(getenv("SYSTEMD_UNIT_PATH"), old));
}

TEST(verify_build_unit_path) {
        _cleanup_free_ char *old_saved = getenv("SYSTEMD_UNIT_PATH") ? strdup(getenv("SYSTEMD_UNIT_PATH")) : NULL;
        ASSERT_TRUE(old_saved || !getenv("SYSTEMD_UNIT_PATH"));

        test_verify_build_unit_path_one(NULL, ":");
        test_verify_build_unit_path_one("", "");
        test_verify_build_unit_path_one(":", ":");
        test_verify_build_unit_path_one("/foo:", ":/foo:");
        test_verify_build_unit_path_one(":foo", NULL);
        test_verify_build_unit_path_one("/foo::/bar", NULL);

        if (old_saved)
                ASSERT_OK_ERRNO(setenv("SYSTEMD_UNIT_PATH", old_saved, 1));
        else
                ASSERT_OK_ERRNO(unsetenv("SYSTEMD_UNIT_PATH"));
}

TEST(manager_unit_path_override) {
        RuntimeScope scope;

        FOREACH_ARGUMENT(scope, RUNTIME_SCOPE_SYSTEM, RUNTIME_SCOPE_USER) {
                _cleanup_(manager_freep) Manager *m = NULL;

                ASSERT_OK(manager_new(scope, MANAGER_TEST_RUN_MINIMAL|MANAGER_TEST_DONT_OPEN_EXECUTOR, &m));
                ASSERT_OK(manager_set_unit_path_override(m, "/tmp/unit-path"));
                ASSERT_STREQ(m->unit_path_override, "/tmp/unit-path");

                if (scope == RUNTIME_SCOPE_USER)
                        ASSERT_STREQ(strv_env_get(m->transient_environment, "SYSTEMD_UNIT_PATH"), "/tmp/unit-path");
                else
                        ASSERT_NULL(strv_env_get(m->transient_environment, "SYSTEMD_UNIT_PATH"));
        }
}

TEST(verify_diagnostics_plain_log_record) {
        _cleanup_(verify_diagnostics_done) VerifyDiagnostics diagnostics = {};
        const char message[] = {
                'p', 'l', 'a', 'i', 'n', ' ', 'u', 'n', 'i', 't', ' ', 'i', 's', 's', 'u', 'e',
        };
        const char bad_message[] = "bad\0message";
        LogRecord record = {
                .type = LOG_RECORD_PLAIN,
                .priority = LOG_WARNING,
                .message = message,
                .message_size = sizeof(message),
                .prefix = "not unit metadata",
                .object_field = "UNIT=",
                .object = "plain.service",
        };

        ASSERT_OK_POSITIVE(verify_diagnostics_add_log_record(&diagnostics, &record));
        ASSERT_EQ(diagnostics.n_items, 1u);
        ASSERT_EQ(diagnostics.items[0].priority, LOG_WARNING);
        ASSERT_STREQ(diagnostics.items[0].message, "plain unit issue");
        ASSERT_STREQ(diagnostics.items[0].unit, "plain.service");
        ASSERT_NULL(diagnostics.items[0].configuration_file);
        ASSERT_EQ(diagnostics.items[0].configuration_line, 0u);
        ASSERT_NULL(diagnostics.items[0].message_id);

        record.object_field = "USER_UNIT=";
        record.object = "user.service";
        ASSERT_OK_POSITIVE(verify_diagnostics_add_log_record(&diagnostics, &record));
        ASSERT_EQ(diagnostics.n_items, 2u);
        ASSERT_STREQ(diagnostics.items[1].unit, "user.service");

        record.object_field = NULL;
        ASSERT_OK_ZERO(verify_diagnostics_add_log_record(&diagnostics, &record));
        ASSERT_EQ(diagnostics.n_items, 2u);

        record.object_field = "UNIT=";
        record.priority = LOG_DEBUG;
        ASSERT_OK_ZERO(verify_diagnostics_add_log_record(&diagnostics, &record));
        ASSERT_EQ(diagnostics.n_items, 2u);

        record.priority = LOG_WARNING;
        record.object_field = "UNIT=";
        record.message = bad_message;
        record.message_size = sizeof(bad_message) - 1;
        ASSERT_OK_ZERO(verify_diagnostics_add_log_record(&diagnostics, &record));
        ASSERT_EQ(diagnostics.n_items, 2u);
}

TEST(verify_diagnostics_structured_log_record) {
        _cleanup_(verify_diagnostics_done) VerifyDiagnostics diagnostics = {};
        struct iovec fields[] = {
                IOVEC_MAKE_STRING("MESSAGE_ID=" SD_MESSAGE_INVALID_CONFIGURATION_STR),
                IOVEC_MAKE_STRING("CONFIG_LINE=7"),
                IOVEC_MAKE_STRING("MESSAGE=bad=setting\nsecond line"),
                IOVEC_MAKE_STRING("CONFIG_FILE=/tmp/plain.service\nCONFIG_LINE=999"),
                IOVEC_MAKE_STRING("UNIT=plain.service"),
        };
        LogRecord record = {
                .type = LOG_RECORD_STRUCTURED,
                .priority = LOG_WARNING,
                .message = "ignored summary",
                .message_size = STRLEN("ignored summary"),
                .fields = fields,
                .n_fields = ELEMENTSOF(fields),
        };

        ASSERT_OK_POSITIVE(verify_diagnostics_add_log_record(&diagnostics, &record));
        ASSERT_EQ(diagnostics.n_items, 1u);
        ASSERT_EQ(diagnostics.items[0].priority, LOG_WARNING);
        ASSERT_STREQ(diagnostics.items[0].message, "bad=setting\nsecond line");
        ASSERT_STREQ(diagnostics.items[0].unit, "plain.service");
        ASSERT_STREQ(diagnostics.items[0].configuration_file, "/tmp/plain.service\nCONFIG_LINE=999");
        ASSERT_EQ(diagnostics.items[0].configuration_line, 7u);
        ASSERT_STREQ(diagnostics.items[0].message_id, SD_MESSAGE_INVALID_CONFIGURATION_STR);
}

TEST(verify_diagnostics_structured_filtering) {
        _cleanup_(verify_diagnostics_done) VerifyDiagnostics diagnostics = {};
        const char bad_file[] = "CONFIG_FILE=bad\0file";
        struct iovec ignored_fields[] = {
                IOVEC_MAKE_STRING("MESSAGE_ID=00000000000000000000000000000000"),
                IOVEC_MAKE_STRING("MESSAGE=ignored"),
                IOVEC_MAKE_STRING("UNIT=ignored.service"),
        };
        struct iovec malformed_fields[] = {
                IOVEC_MAKE_STRING("MESSAGE_ID=" SD_MESSAGE_INVALID_CONFIGURATION_STR),
                IOVEC_MAKE_STRING("MESSAGE=malformed metadata"),
                IOVEC_MAKE_STRING("USER_UNIT=user.service"),
                IOVEC_MAKE_STRING("USER_UNIT=user.service"),
                IOVEC_MAKE_STRING("CONFIG_LINE=18446744073709551616"),
                IOVEC_MAKE(bad_file, sizeof(bad_file) - 1),
        };
        struct iovec cycle_fields[] = {
                IOVEC_MAKE_STRING("MESSAGE_ID=" SD_MESSAGE_UNIT_ORDERING_CYCLE_STR),
                IOVEC_MAKE_STRING("MESSAGE=cycle"),
                IOVEC_MAKE_STRING("UNIT=a.service\nUNIT=b.service"),
        };
        struct iovec conflicting_id_fields[] = {
                IOVEC_MAKE_STRING("MESSAGE_ID=" SD_MESSAGE_INVALID_CONFIGURATION_STR),
                IOVEC_MAKE_STRING("MESSAGE_ID=00000000000000000000000000000000"),
                IOVEC_MAKE_STRING("MESSAGE=conflicting ID"),
        };
        struct iovec conflicting_id_fields_reverse[] = {
                IOVEC_MAKE_STRING("MESSAGE_ID=00000000000000000000000000000000"),
                IOVEC_MAKE_STRING("MESSAGE_ID=" SD_MESSAGE_INVALID_CONFIGURATION_STR),
                IOVEC_MAKE_STRING("MESSAGE=conflicting ID"),
        };
        struct iovec conflicting_source_fields[] = {
                IOVEC_MAKE_STRING("MESSAGE_ID=" SD_MESSAGE_INVALID_CONFIGURATION_STR),
                IOVEC_MAKE_STRING("MESSAGE=conflicting source"),
                IOVEC_MAKE_STRING("CONFIG_FILE=/tmp/one"),
                IOVEC_MAKE_STRING("CONFIG_FILE=/tmp/two"),
                IOVEC_MAKE_STRING("CONFIG_LINE=0"),
                IOVEC_MAKE_STRING("CONFIG_LINE=7"),
        };
        struct iovec conflicting_message_fields[] = {
                IOVEC_MAKE_STRING("MESSAGE_ID=" SD_MESSAGE_INVALID_CONFIGURATION_STR),
                IOVEC_MAKE_STRING("MESSAGE=first"),
                IOVEC_MAKE_STRING("MESSAGE=second"),
        };
        struct iovec unsafe_user_fields[] = {
                IOVEC_MAKE_STRING("MESSAGE_ID=" SD_MESSAGE_UNSAFE_USER_NAME_STR),
                IOVEC_MAKE_STRING("MESSAGE=unsafe user name"),
        };
        struct iovec nobody_user_fields[] = {
                IOVEC_MAKE_STRING("MESSAGE_ID=" SD_MESSAGE_NOBODY_USER_UNSUITABLE_STR),
                IOVEC_MAKE_STRING("MESSAGE=nobody is unsuitable"),
                IOVEC_MAKE_STRING("UNIT=nobody.service"),
                IOVEC_MAKE_STRING("CONFIG_FILE=/tmp/nobody.service"),
                IOVEC_MAKE_STRING("CONFIG_LINE=3"),
        };
        LogRecord record = {
                .type = LOG_RECORD_STRUCTURED,
                .priority = LOG_ERR,
                .fields = ignored_fields,
                .n_fields = ELEMENTSOF(ignored_fields),
        };

        ASSERT_OK_ZERO(verify_diagnostics_add_log_record(&diagnostics, &record));
        ASSERT_EQ(diagnostics.n_items, 0u);

        record.fields = malformed_fields;
        record.n_fields = ELEMENTSOF(malformed_fields);
        ASSERT_OK_POSITIVE(verify_diagnostics_add_log_record(&diagnostics, &record));
        ASSERT_EQ(diagnostics.n_items, 1u);
        ASSERT_STREQ(diagnostics.items[0].message, "malformed metadata");
        ASSERT_STREQ(diagnostics.items[0].unit, "user.service");
        ASSERT_NULL(diagnostics.items[0].configuration_file);
        ASSERT_EQ(diagnostics.items[0].configuration_line, 0u);

        record.priority = LOG_DEBUG;
        ASSERT_OK_ZERO(verify_diagnostics_add_log_record(&diagnostics, &record));
        ASSERT_EQ(diagnostics.n_items, 1u);
        record.priority = LOG_ERR;

        record.fields = conflicting_id_fields;
        record.n_fields = ELEMENTSOF(conflicting_id_fields);
        ASSERT_OK_ZERO(verify_diagnostics_add_log_record(&diagnostics, &record));
        record.fields = conflicting_id_fields_reverse;
        record.n_fields = ELEMENTSOF(conflicting_id_fields_reverse);
        ASSERT_OK_ZERO(verify_diagnostics_add_log_record(&diagnostics, &record));
        ASSERT_EQ(diagnostics.n_items, 1u);

        record.fields = conflicting_source_fields;
        record.n_fields = ELEMENTSOF(conflicting_source_fields);
        ASSERT_OK_POSITIVE(verify_diagnostics_add_log_record(&diagnostics, &record));
        ASSERT_EQ(diagnostics.n_items, 2u);
        ASSERT_NULL(diagnostics.items[1].configuration_file);
        ASSERT_EQ(diagnostics.items[1].configuration_line, 0u);

        record.fields = conflicting_message_fields;
        record.n_fields = ELEMENTSOF(conflicting_message_fields);
        ASSERT_OK_ZERO(verify_diagnostics_add_log_record(&diagnostics, &record));
        ASSERT_EQ(diagnostics.n_items, 2u);

        record.fields = cycle_fields;
        record.n_fields = ELEMENTSOF(cycle_fields);
        ASSERT_OK_POSITIVE(verify_diagnostics_add_log_record(&diagnostics, &record));
        ASSERT_EQ(diagnostics.n_items, 3u);
        ASSERT_STREQ(diagnostics.items[2].message, "cycle");
        ASSERT_NULL(diagnostics.items[2].unit);
        ASSERT_STREQ(diagnostics.items[2].message_id, SD_MESSAGE_UNIT_ORDERING_CYCLE_STR);

        record.fields = unsafe_user_fields;
        record.n_fields = ELEMENTSOF(unsafe_user_fields);
        ASSERT_OK_POSITIVE(verify_diagnostics_add_log_record(&diagnostics, &record));
        ASSERT_EQ(diagnostics.n_items, 4u);
        ASSERT_NULL(diagnostics.items[3].unit);
        ASSERT_STREQ(diagnostics.items[3].message_id, SD_MESSAGE_UNSAFE_USER_NAME_STR);

        record.fields = nobody_user_fields;
        record.n_fields = ELEMENTSOF(nobody_user_fields);
        ASSERT_OK_POSITIVE(verify_diagnostics_add_log_record(&diagnostics, &record));
        ASSERT_EQ(diagnostics.n_items, 5u);
        ASSERT_STREQ(diagnostics.items[4].unit, "nobody.service");
        ASSERT_STREQ(diagnostics.items[4].configuration_file, "/tmp/nobody.service");
        ASSERT_EQ(diagnostics.items[4].configuration_line, 3u);
        ASSERT_STREQ(diagnostics.items[4].message_id, SD_MESSAGE_NOBODY_USER_UNSUITABLE_STR);
}

TEST(verify_units_empty) {
        _cleanup_(verify_units_result_done) VerifyUnitsResult result = {};
        const VerifyUnitsParameters parameters = {
                .runtime_scope = RUNTIME_SCOPE_SYSTEM,
                .recursive_errors = RECURSIVE_ERRORS_YES,
                .instance = "test_instance",
        };

        ASSERT_OK(verify_units(&parameters, &result));
        ASSERT_EQ(result.legacy_status, 0);
        ASSERT_EQ(result.diagnostics.n_items, 0u);
}

static VerifyDiagnostic* find_diagnostic(
                VerifyUnitsResult *result,
                const char *unit,
                const char *configuration_file,
                const char *message_id) {

        FOREACH_ARRAY(diagnostic, result->diagnostics.items, result->diagnostics.n_items)
                if (streq_ptr(diagnostic->unit, unit) &&
                    streq_ptr(diagnostic->configuration_file, configuration_file) &&
                    streq_ptr(diagnostic->message_id, message_id))
                        return diagnostic;

        return NULL;
}

TEST(verify_units_result) {
        _cleanup_(verify_units_result_done) VerifyUnitsResult result = {};
        _cleanup_(rm_rf_physical_and_freep) char *tmp = NULL;
        _cleanup_free_ char *bad = NULL, *invalid = NULL, *load_error = NULL, *missing = NULL, *parse = NULL;
        char *filenames[2];
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
         * unknown-key path is gated by log_level_enabled(), while parse errors call log_syntax_internal()
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

DEFINE_TEST_MAIN(LOG_DEBUG);
