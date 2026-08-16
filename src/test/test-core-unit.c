/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-messages.h"

#include "alloc-util.h"
#include "escape.h"
#include "load-fragment.h"
#include "manager.h"
#include "strv.h"
#include "tests.h"
#include "unit.h"

static void test_unit_escape_setting_one(
                const char *s,
                const char *expected_exec_env,
                const char *expected_exec,
                const char *expected_c) {

        _cleanup_free_ char *a = NULL, *b = NULL, *c = NULL, *d = NULL,
                *s_esc = NULL, *a_esc = NULL, *b_esc = NULL, *c_esc = NULL, *d_esc = NULL;
        const char *t;

        if (!expected_exec_env)
                expected_exec_env = s;
        if (!expected_exec)
                expected_exec = expected_exec_env;
        if (!expected_c)
                expected_c = expected_exec;
        assert_se(s_esc = cescape(s));

        assert_se(t = unit_escape_setting(s, 0, &a));
        assert_se(a_esc = cescape(t));
        log_debug("%s: [%s] → [%s]", __func__, s_esc, a_esc);
        ASSERT_NULL(a);
        assert_se(t == s);

        assert_se(t = unit_escape_setting(s, UNIT_ESCAPE_EXEC_SYNTAX_ENV, &b));
        assert_se(b_esc = cescape(t));
        log_debug("%s: [%s] → [%s]", __func__, s_esc, b_esc);
        assert_se(b == NULL || streq(b, t));
        ASSERT_STREQ(t, expected_exec_env);

        assert_se(t = unit_escape_setting(s, UNIT_ESCAPE_EXEC_SYNTAX, &c));
        assert_se(c_esc = cescape(t));
        log_debug("%s: [%s] → [%s]", __func__, s_esc, c_esc);
        assert_se(c == NULL || streq(c, t));
        ASSERT_STREQ(t, expected_exec);

        assert_se(t = unit_escape_setting(s, UNIT_ESCAPE_C, &d));
        assert_se(d_esc = cescape(t));
        log_debug("%s: [%s] → [%s]", __func__, s_esc, d_esc);
        assert_se(d == NULL || streq(d, t));
        ASSERT_STREQ(t, expected_c);
}

TEST(unit_escape_setting) {
        test_unit_escape_setting_one("/sbin/sbash", NULL, NULL, NULL);
        test_unit_escape_setting_one("$", "$$", "$", "$");
        test_unit_escape_setting_one("$$", "$$$$", "$$", "$$");
        test_unit_escape_setting_one("'", "'", NULL, "\\'");
        test_unit_escape_setting_one("\"", "\\\"", NULL, NULL);
        test_unit_escape_setting_one("\t", "\\t", NULL, NULL);
        test_unit_escape_setting_one(" ", NULL, NULL, NULL);
        test_unit_escape_setting_one("$;'\"\t\n", "$$;'\\\"\\t\\n", "$;'\\\"\\t\\n", "$;\\'\\\"\\t\\n");
}

static void test_unit_concat_strv_one(
                char **s,
                const char *expected_none,
                const char *expected_exec_env,
                const char *expected_exec,
                const char *expected_c) {

        _cleanup_free_ char *a = NULL, *b = NULL, *c = NULL, *d = NULL,
                *s_ser = NULL, *s_esc = NULL, *a_esc = NULL, *b_esc = NULL, *c_esc = NULL, *d_esc = NULL;

        assert_se(s_ser = strv_join(s, "_"));
        assert_se(s_esc = cescape(s_ser));
        if (!expected_exec_env)
                expected_exec_env = expected_none;
        if (!expected_exec)
                expected_exec = expected_none;
        if (!expected_c)
                expected_c = expected_none;

        assert_se(a = unit_concat_strv(s, 0));
        assert_se(a_esc = cescape(a));
        log_debug("%s: [%s] → [%s]", __func__, s_esc, a_esc);
        ASSERT_STREQ(a, expected_none);

        assert_se(b = unit_concat_strv(s, UNIT_ESCAPE_EXEC_SYNTAX_ENV));
        assert_se(b_esc = cescape(b));
        log_debug("%s: [%s] → [%s]", __func__, s_esc, b_esc);
        ASSERT_STREQ(b, expected_exec_env);

        assert_se(c = unit_concat_strv(s, UNIT_ESCAPE_EXEC_SYNTAX));
        assert_se(c_esc = cescape(c));
        log_debug("%s: [%s] → [%s]", __func__, s_esc, c_esc);
        ASSERT_STREQ(c, expected_exec);

        assert_se(d = unit_concat_strv(s, UNIT_ESCAPE_C));
        assert_se(d_esc = cescape(d));
        log_debug("%s: [%s] → [%s]", __func__, s_esc, d_esc);
        ASSERT_STREQ(d, expected_c);
}

TEST(unit_concat_strv) {
        test_unit_concat_strv_one(STRV_MAKE("a", "b", "c"),
                                  "\"a\" \"b\" \"c\"",
                                  NULL,
                                  NULL,
                                  NULL);
        test_unit_concat_strv_one(STRV_MAKE("a", " ", "$", "$$", ""),
                                  "\"a\" \" \" \"$\" \"$$\" \"\"",
                                  "\"a\" \" \" \"$$\" \"$$$$\" \"\"",
                                  NULL,
                                  NULL);
        test_unit_concat_strv_one(STRV_MAKE("\n", " ", "\t"),
                                  "\"\n\" \" \" \"\t\"",
                                  "\"\\n\" \" \" \"\\t\"",
                                  "\"\\n\" \" \" \"\\t\"",
                                  "\"\\n\" \" \" \"\\t\"");
}

typedef struct TestManagerDiagnosticState {
        Manager *manager;
        size_t n_calls;
        int priority;
        int callback_error;
        char message[LINE_MAX];
        const char *unit;
        const char *configuration_file;
        unsigned configuration_line;
        const char *message_id;
} TestManagerDiagnosticState;

static int test_manager_diagnostic_callback(const ManagerDiagnostic *record, void *userdata) {
        TestManagerDiagnosticState *state = ASSERT_PTR(userdata);

        assert(record);

        state->n_calls++;
        state->priority = record->priority;
        state->unit = record->unit;
        state->configuration_file = record->configuration_file;
        state->configuration_line = record->configuration_line;
        state->message_id = record->message_id;
        (void) snprintf(state->message, sizeof state->message, "%s", record->message);

        /* A callback may itself log. Such nested records must not recursively invoke the callback. */
        (void) manager_dispatch_test_run_diagnostic(state->manager, record);

        return state->callback_error;
}

TEST(manager_diagnostic) {
        _cleanup_free_ char *configured_user = NULL;
        char unit_id[] = "diagnostic.service";
        Manager manager = {
                .runtime_scope = RUNTIME_SCOPE_SYSTEM,
                .test_run_flags = MANAGER_TEST_RUN_MINIMAL,
        };
        Unit unit = {
                .manager = &manager,
                .id = unit_id,
        };
        TestManagerDiagnosticState state = {
                .manager = &manager,
        };

        manager_set_test_run_diagnostic_callback(&manager, test_manager_diagnostic_callback, &state);

        int old_max_level = log_set_max_level(LOG_ERR);

        ASSERT_OK_ZERO(config_parse_user_group_compat(
                        unit_id,
                        "/tmp/diagnostic.service",
                        7,
                        "Service",
                        1,
                        "User",
                        0,
                        "unsafe@name",
                        &configured_user,
                        &unit));
        ASSERT_EQ(state.n_calls, 1U);
        ASSERT_EQ(state.priority, LOG_NOTICE);
        ASSERT_STREQ(state.message,
                     "Accepting user/group name 'unsafe@name', which does not match strict user/group name rules.");
        ASSERT_NULL(state.unit);
        ASSERT_NULL(state.configuration_file);
        ASSERT_EQ(state.configuration_line, 0U);
        ASSERT_STREQ(state.message_id, SD_MESSAGE_UNSAFE_USER_NAME_STR);

        ASSERT_OK_ZERO(config_parse_user_group_compat(
                        unit_id,
                        "/tmp/diagnostic.service",
                        9,
                        "Service",
                        1,
                        "User",
                        0,
                        NOBODY_USER_NAME,
                        &configured_user,
                        &unit));
        ASSERT_EQ(state.n_calls, 2U);
        ASSERT_EQ(state.priority, LOG_NOTICE);
        ASSERT_STREQ(state.message,
                     "/tmp/diagnostic.service:9: Special user nobody configured, this is not safe!");
        ASSERT_STREQ(state.unit, unit_id);
        ASSERT_STREQ(state.configuration_file, "/tmp/diagnostic.service");
        ASSERT_EQ(state.configuration_line, 9U);
        ASSERT_STREQ(state.message_id, SD_MESSAGE_NOBODY_USER_UNSUITABLE_STR);

        ASSERT_OK_ZERO(log_unit_internal(
                        &unit, LOG_INFO, 0, PROJECT_FILE, __LINE__, __func__, "Test message %u", 7U));
        ASSERT_EQ(state.n_calls, 3U);
        ASSERT_EQ(state.priority, LOG_INFO);
        ASSERT_STREQ(state.message, "Test message 7");
        ASSERT_STREQ(state.unit, unit_id);

        ASSERT_OK_ZERO(log_unit_internal(
                        &unit,
                        LOG_INFO,
                        0,
                        PROJECT_FILE,
                        __LINE__,
                        __func__,
                        "Line one\n\nLine two\rLine three"));
        ASSERT_EQ(state.n_calls, 6U);
        ASSERT_STREQ(state.message, "Line three");

        ASSERT_OK_ZERO(log_unit_internal(
                        &unit, LOG_DEBUG, 0, PROJECT_FILE, __LINE__, __func__, "Debug message"));
        ASSERT_EQ(state.n_calls, 6U);

        state.callback_error = -E2BIG;
        ASSERT_ERROR(
                        log_unit_internal(
                                &unit,
                                LOG_WARNING,
                                SYNTHETIC_ERRNO(EINVAL),
                                PROJECT_FILE,
                                __LINE__,
                                __func__,
                                "Warning message"),
                        EINVAL);
        ASSERT_EQ(state.n_calls, 7U);
        ASSERT_ERROR(manager_get_test_run_diagnostic_error(&manager), E2BIG);

        manager_record_test_run_diagnostic_error(&manager, -ENOMEM);
        ASSERT_ERROR(manager_get_test_run_diagnostic_error(&manager), E2BIG);

        ASSERT_ERROR(
                        log_unit_internal(
                                &unit,
                                LOG_INFO,
                                SYNTHETIC_ERRNO(ENOENT),
                                PROJECT_FILE,
                                __LINE__,
                                __func__,
                                "Ignored after callback failure"),
                        ENOENT);
        ASSERT_EQ(state.n_calls, 7U);

        manager_clear_test_run_diagnostic_callback(&manager);
        ASSERT_NULL(manager.test_run_diagnostic_callback);
        ASSERT_NULL(manager.test_run_diagnostic_userdata);

        log_set_max_level(old_max_level);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
