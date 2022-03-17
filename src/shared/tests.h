/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

#include "sd-daemon.h"

#include "macro.h"
#include "static-destruct.h"
#include "util.h"

static inline bool manager_errno_skip_test(int r) {
        return IN_SET(abs(r),
                      EPERM,
                      EACCES,
                      EADDRINUSE,
                      EHOSTDOWN,
                      ENOENT,
                      ENOMEDIUM /* cannot determine cgroup */
        );
}

char* setup_fake_runtime_dir(void);
int enter_cgroup_subroot(char **ret_cgroup);
int enter_cgroup_root(char **ret_cgroup);
int get_testdata_dir(const char *suffix, char **ret);
const char* get_catalog_dir(void);
bool slow_tests_enabled(void);
void test_setup_logging(int level);
int log_tests_skipped(const char *message);
int log_tests_skipped_errno(int r, const char *message);

int write_tmpfile(char *pattern, const char *contents);

bool have_namespaces(void);

/* We use the small but non-trivial limit here */
#define CAN_MEMLOCK_SIZE (512 * 1024U)
bool can_memlock(void);

#define TEST_REQ_RUNNING_SYSTEMD(x)                                 \
        if (sd_booted() > 0) {                                      \
                x;                                                  \
        } else {                                                    \
                printf("systemd not booted, skipping '%s'\n", #x);   \
        }

/* Provide a convenient way to check if we're running in CI. */
const char *ci_environment(void);

typedef struct TestFunc {
        union f {
                void (*void_func)(void);
                int (*int_func)(void);
        } f;
        const char * const name;
        bool has_ret:1;
        bool sd_booted:1;
} TestFunc;

/* See static-destruct.h for an explanation of how this works. */
#define REGISTER_TEST(func, ...)                                                                        \
        _Pragma("GCC diagnostic ignored \"-Wattributes\"")                                              \
        _section_("SYSTEMD_TEST_TABLE") _alignptr_ _used_ _retain_ _variable_no_sanitize_address_       \
        static const TestFunc UNIQ_T(static_test_table_entry, UNIQ) = {                                 \
                .f = (union f) &(func),                                                                 \
                .name = STRINGIFY(func),                                                                \
                .has_ret = __builtin_types_compatible_p(typeof((union f){}.int_func), typeof(&(func))), \
                ##__VA_ARGS__                                                                           \
        }

extern const TestFunc _weak_ __start_SYSTEMD_TEST_TABLE[];
extern const TestFunc _weak_ __stop_SYSTEMD_TEST_TABLE[];

#define TEST(name, ...)                            \
        static void test_##name(void);             \
        REGISTER_TEST(test_##name, ##__VA_ARGS__); \
        static void test_##name(void)

#define TEST_RET(name, ...)                        \
        static int test_##name(void);              \
        REGISTER_TEST(test_##name, ##__VA_ARGS__); \
        static int test_##name(void)

static inline int run_test_table(void) {
        int r = EXIT_SUCCESS;

        if (!__start_SYSTEMD_TEST_TABLE)
                return r;

        const TestFunc *t = ALIGN_TO_PTR(__start_SYSTEMD_TEST_TABLE, sizeof(TestFunc*));
        while (t < __stop_SYSTEMD_TEST_TABLE) {

                if (t->sd_booted && sd_booted() <= 0) {
                        log_info("/* systemd not booted, skipping %s */", t->name);
                        if (t->has_ret && r == EXIT_SUCCESS)
                                r = EXIT_TEST_SKIP;
                } else {
                        log_info("/* %s */", t->name);

                        if (t->has_ret) {
                                int r2 = t->f.int_func();
                                if (r == EXIT_SUCCESS)
                                        r = r2;
                        } else
                                t->f.void_func();
                }

                t = ALIGN_TO_PTR(t + 1, sizeof(TestFunc*));
        }

        return r;
}

#define DEFINE_TEST_MAIN_FULL(log_level, intro, outro)    \
        int main(int argc, char *argv[]) {                \
                int (*_intro)(void) = intro;              \
                int (*_outro)(void) = outro;              \
                int _r, _q;                               \
                test_setup_logging(log_level);            \
                save_argc_argv(argc, argv);               \
                _r = _intro ? _intro() : EXIT_SUCCESS;    \
                if (_r == EXIT_SUCCESS)                   \
                        _r = run_test_table();            \
                _q = _outro ? _outro() : EXIT_SUCCESS;    \
                static_destruct();                        \
                if (_r < 0)                               \
                        return EXIT_FAILURE;              \
                if (_r != EXIT_SUCCESS)                   \
                        return _r;                        \
                if (_q < 0)                               \
                        return EXIT_FAILURE;              \
                return _q;                                \
        }

#define DEFINE_TEST_MAIN_WITH_INTRO(log_level, intro)   \
        DEFINE_TEST_MAIN_FULL(log_level, intro, NULL)
#define DEFINE_TEST_MAIN(log_level)                     \
        DEFINE_TEST_MAIN_FULL(log_level, NULL, NULL)
