/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "escape.h"
#include "manager.h"
#include "rm-rf.h"
#include "service.h"
#include "strv.h"
#include "tests.h"
#include "time-util.h"
#include "timer.h"
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
        ASSERT_NOT_NULL(s_esc = cescape(s));

        ASSERT_NOT_NULL(t = unit_escape_setting(s, /* flags= */ 0, &a));
        ASSERT_NOT_NULL(a_esc = cescape(t));
        log_debug("%s: [%s] → [%s]", __func__, s_esc, a_esc);
        ASSERT_NULL(a);
        ASSERT_PTR_EQ(t, s);

        ASSERT_NOT_NULL(t = unit_escape_setting(s, UNIT_ESCAPE_EXEC_SYNTAX_ENV, &b));
        ASSERT_NOT_NULL(b_esc = cescape(t));
        log_debug("%s: [%s] → [%s]", __func__, s_esc, b_esc);
        ASSERT_TRUE(b == NULL || streq(b, t));
        ASSERT_STREQ(t, expected_exec_env);

        ASSERT_NOT_NULL(t = unit_escape_setting(s, UNIT_ESCAPE_EXEC_SYNTAX, &c));
        ASSERT_NOT_NULL(c_esc = cescape(t));
        log_debug("%s: [%s] → [%s]", __func__, s_esc, c_esc);
        ASSERT_TRUE(c == NULL || streq(c, t));
        ASSERT_STREQ(t, expected_exec);

        ASSERT_NOT_NULL(t = unit_escape_setting(s, UNIT_ESCAPE_C, &d));
        ASSERT_NOT_NULL(d_esc = cescape(t));
        log_debug("%s: [%s] → [%s]", __func__, s_esc, d_esc);
        ASSERT_TRUE(d == NULL || streq(d, t));
        ASSERT_STREQ(t, expected_c);
}

TEST(unit_escape_setting) {
        test_unit_escape_setting_one("/sbin/sbash", /* expected_exec_env= */ NULL, /* expected_exec= */ NULL, /* expected_c= */ NULL);
        test_unit_escape_setting_one("$", "$$", "$", "$");
        test_unit_escape_setting_one("$$", "$$$$", "$$", "$$");
        test_unit_escape_setting_one("'", "'", /* expected_exec= */ NULL, "\\'");
        test_unit_escape_setting_one("\"", "\\\"", /* expected_exec= */ NULL, /* expected_c= */ NULL);
        test_unit_escape_setting_one("\t", "\\t", /* expected_exec= */ NULL, /* expected_c= */ NULL);
        test_unit_escape_setting_one(" ", /* expected_exec_env= */ NULL, /* expected_exec= */ NULL, /* expected_c= */ NULL);
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

        ASSERT_NOT_NULL(s_ser = strv_join(s, "_"));
        ASSERT_NOT_NULL(s_esc = cescape(s_ser));
        if (!expected_exec_env)
                expected_exec_env = expected_none;
        if (!expected_exec)
                expected_exec = expected_none;
        if (!expected_c)
                expected_c = expected_none;

        ASSERT_NOT_NULL(a = unit_concat_strv(s, /* flags= */ 0));
        ASSERT_NOT_NULL(a_esc = cescape(a));
        log_debug("%s: [%s] → [%s]", __func__, s_esc, a_esc);
        ASSERT_STREQ(a, expected_none);

        ASSERT_NOT_NULL(b = unit_concat_strv(s, UNIT_ESCAPE_EXEC_SYNTAX_ENV));
        ASSERT_NOT_NULL(b_esc = cescape(b));
        log_debug("%s: [%s] → [%s]", __func__, s_esc, b_esc);
        ASSERT_STREQ(b, expected_exec_env);

        ASSERT_NOT_NULL(c = unit_concat_strv(s, UNIT_ESCAPE_EXEC_SYNTAX));
        ASSERT_NOT_NULL(c_esc = cescape(c));
        log_debug("%s: [%s] → [%s]", __func__, s_esc, c_esc);
        ASSERT_STREQ(c, expected_exec);

        ASSERT_NOT_NULL(d = unit_concat_strv(s, UNIT_ESCAPE_C));
        ASSERT_NOT_NULL(d_esc = cescape(d));
        log_debug("%s: [%s] → [%s]", __func__, s_esc, d_esc);
        ASSERT_STREQ(d, expected_c);
}

TEST(unit_concat_strv) {
        test_unit_concat_strv_one(STRV_MAKE("a", "b", "c"),
                                  "\"a\" \"b\" \"c\"",
                                  /* expected_exec_env= */ NULL,
                                  /* expected_exec= */ NULL,
                                  /* expected_c= */ NULL);
        test_unit_concat_strv_one(STRV_MAKE("a", " ", "$", "$$", ""),
                                  "\"a\" \" \" \"$\" \"$$\" \"\"",
                                  "\"a\" \" \" \"$$\" \"$$$$\" \"\"",
                                  /* expected_exec= */ NULL,
                                  /* expected_c= */ NULL);
        test_unit_concat_strv_one(STRV_MAKE("\n", " ", "\t"),
                                  "\"\n\" \" \" \"\t\"",
                                  "\"\\n\" \" \" \"\\t\"",
                                  "\"\\n\" \" \" \"\\t\"",
                                  "\"\\n\" \" \" \"\\t\"");
}

TEST(service_restart_backoff_enabled) {
        ASSERT_TRUE(service_restart_backoff_enabled(10 * USEC_PER_SEC, 160 * USEC_PER_SEC, 4));
        ASSERT_FALSE(service_restart_backoff_enabled(10 * USEC_PER_SEC, 160 * USEC_PER_SEC, /* restart_steps= */ 0));
        ASSERT_FALSE(service_restart_backoff_enabled(/* restart_usec= */ 0, 160 * USEC_PER_SEC, 4));
        ASSERT_FALSE(service_restart_backoff_enabled(10 * USEC_PER_SEC, USEC_INFINITY, 4));
        ASSERT_FALSE(service_restart_backoff_enabled(160 * USEC_PER_SEC, 160 * USEC_PER_SEC, 4));
}

TEST(service_restart_usec_nth) {
        static const usec_t expected[] = { 10, 20, 40, 80, 160, 160, 160 };

        for (unsigned n = 1; n <= ELEMENTSOF(expected); n++)
                ASSERT_EQ(service_restart_usec_nth(10 * USEC_PER_SEC, 160 * USEC_PER_SEC, 4, n),
                          expected[n - 1] * USEC_PER_SEC);

        ASSERT_EQ(service_restart_usec_nth(1 * USEC_PER_SEC, 64 * USEC_PER_SEC, 6, 6), 32 * USEC_PER_SEC);
        ASSERT_EQ(service_restart_usec_nth(5 * USEC_PER_SEC, 60 * USEC_PER_SEC, 3, 2), 11447142u);

        ASSERT_EQ(service_restart_usec_nth(10 * USEC_PER_SEC, 160 * USEC_PER_SEC, /* restart_steps= */ 0, 3), 10 * USEC_PER_SEC);
        ASSERT_EQ(service_restart_usec_nth(10 * USEC_PER_SEC, USEC_INFINITY, 4, 3), 10 * USEC_PER_SEC);
        ASSERT_EQ(service_restart_usec_nth(/* restart_usec= */ 0, 160 * USEC_PER_SEC, 4, 3), 0u);
        ASSERT_EQ(service_restart_usec_nth(160 * USEC_PER_SEC, 160 * USEC_PER_SEC, 4, 3), 160 * USEC_PER_SEC);
}

TEST(timer_coldplug) {
        _cleanup_(rm_rf_physical_and_freep) char *runtime_dir = NULL;
        _cleanup_(manager_freep) Manager *m = NULL;
        _cleanup_(unit_freep) Unit *service = NULL;

        ASSERT_NOT_NULL(runtime_dir = setup_fake_runtime_dir());
        ASSERT_OK(manager_new(RUNTIME_SCOPE_USER, MANAGER_TEST_RUN_MINIMAL|MANAGER_TEST_DONT_OPEN_EXECUTOR, &m));
        m->n_reloading = 1;

        ASSERT_OK(unit_new_for_name(m, sizeof(Service), "coldplug.service", &service));
        service->load_state = UNIT_LOADED;

        FOREACH_ELEMENT(state, ((const TimerState[]) { TIMER_WAITING, TIMER_ELAPSED })) {
                _cleanup_(unit_freep) Unit *u = NULL;
                TimerValue *v;

                ASSERT_OK(unit_new_for_name(m, sizeof(Timer), "coldplug.timer", &u));
                u->load_state = UNIT_LOADED;
                ASSERT_OK(unit_add_dependency(u, UNIT_TRIGGERS, service, /* add_reference= */ true, UNIT_DEPENDENCY_FILE));

                Timer *t = TIMER(u);
                t->deserialized_state = *state;
                /* Keep an already fired OnActiveSec= timer waiting for a separate trigger. */
                t->on_clock_change = *state == TIMER_WAITING;
                dual_timestamp_now(&t->last_trigger);
                u->inactive_exit_timestamp = (dual_timestamp) { .monotonic = 1 };

                ASSERT_NOT_NULL(v = new0(TimerValue, 1));
                v->base = TIMER_ACTIVE;
                v->value = 1;
                LIST_PREPEND(value, t->values, v);

                ASSERT_OK(unit_coldplug(u));
                ASSERT_EQ(t->state, *state);
                ASSERT_TRUE(v->disabled);
                ASSERT_NULL(t->monotonic_event_source);
        }

        /* A pending OnActiveSec= trigger must retain its original deadline across reloads. */
        _cleanup_(unit_freep) Unit *u = NULL;
        TimerValue *v;

        ASSERT_OK(unit_new_for_name(m, sizeof(Timer), "pending.timer", &u));
        u->load_state = UNIT_LOADED;
        u->inactive_exit_timestamp = (dual_timestamp) { .monotonic = now(CLOCK_MONOTONIC) };
        ASSERT_OK(unit_add_dependency(u, UNIT_TRIGGERS, service, /* add_reference= */ true, UNIT_DEPENDENCY_FILE));

        Timer *t = TIMER(u);
        t->deserialized_state = TIMER_WAITING;
        ASSERT_NOT_NULL(v = new0(TimerValue, 1));
        v->base = TIMER_ACTIVE;
        v->value = USEC_PER_HOUR;
        LIST_PREPEND(value, t->values, v);

        ASSERT_OK(unit_coldplug(u));
        ASSERT_EQ(t->state, TIMER_WAITING);
        ASSERT_EQ(t->next_elapse_monotonic_or_boottime, u->inactive_exit_timestamp.monotonic + USEC_PER_HOUR);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
