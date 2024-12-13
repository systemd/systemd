/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <sys/prctl.h>
#include <unistd.h>

#include "sd-daemon.h"

#include "argv-util.h"
#include "errno-util.h"
#include "macro.h"
#include "process-util.h"
#include "rlimit-util.h"
#include "signal-util.h"
#include "static-destruct.h"
#include "strv.h"

static inline void log_set_assert_return_is_criticalp(bool *p) {
        log_set_assert_return_is_critical(*p);
}

#define _SAVE_ASSERT_RETURN_IS_CRITICAL(b)                              \
        _unused_ _cleanup_(log_set_assert_return_is_criticalp) bool b = \
                log_get_assert_return_is_critical()

#define SAVE_ASSERT_RETURN_IS_CRITICAL                          \
        _SAVE_ASSERT_RETURN_IS_CRITICAL(UNIQ_T(saved, UNIQ))

#define ASSERT_RETURN_IS_CRITICAL(b, expr)                              \
        ({                                                              \
                SAVE_ASSERT_RETURN_IS_CRITICAL;                         \
                log_set_assert_return_is_critical(b);                   \
                expr;                                                   \
        })

#define ASSERT_RETURN_EXPECTED(expr) ASSERT_RETURN_IS_CRITICAL(false, expr)
#define ASSERT_RETURN_EXPECTED_SE(expr) ASSERT_RETURN_EXPECTED(assert_se(expr));

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

#define log_tests_skipped(fmt, ...)                                     \
        ({                                                              \
                log_notice("%s: " fmt ", skipping tests.",              \
                           program_invocation_short_name,               \
                           ##__VA_ARGS__);                              \
                EXIT_TEST_SKIP;                                         \
        })

#define log_tests_skipped_errno(error, fmt, ...)                        \
        ({                                                              \
                log_notice_errno(error,                                 \
                                 "%s: " fmt ", skipping tests: %m",     \
                                 program_invocation_short_name,         \
                                 ##__VA_ARGS__);                        \
                EXIT_TEST_SKIP;                                         \
        })

int write_tmpfile(char *pattern, const char *contents);

bool have_namespaces(void);
bool userns_has_single_user(void);

/* We use the small but non-trivial limit here */
#define CAN_MEMLOCK_SIZE (512 * 1024U)
bool can_memlock(void);

/* Define void* buffer and size_t length variables from a hex string. */
#define DEFINE_HEX_PTR(name, hex)                                       \
        _cleanup_free_ void *name = NULL;                               \
        size_t name##_len = 0;                                          \
        assert_se(unhexmem_full(hex, strlen_ptr(hex), false, &name, &name##_len) >= 0);

#define TEST_REQ_RUNNING_SYSTEMD(x)                                 \
        if (sd_booted() > 0) {                                      \
                x;                                                  \
        } else {                                                    \
                printf("systemd not booted, skipping '%s'\n", #x);   \
        }

/* Provide a convenient way to check if we're running in CI. */
const char* ci_environment(void);

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

#define TEST_LOG_FUNC() \
        log_info("/* %s() */", __func__)

static inline int run_test_table(void) {
        _cleanup_strv_free_ char **tests = NULL;
        int r = EXIT_SUCCESS;
        bool ran = false;
        const char *e;

        if (!__start_SYSTEMD_TEST_TABLE)
                return r;

        e = getenv("TESTFUNCS");
        if (e) {
                r = strv_split_full(&tests, e, ":", EXTRACT_DONT_COALESCE_SEPARATORS);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse $TESTFUNCS: %m");
        }

        for (const TestFunc *t = ALIGN_PTR(__start_SYSTEMD_TEST_TABLE);
             t + 1 <= __stop_SYSTEMD_TEST_TABLE;
             t = ALIGN_PTR(t + 1)) {

                if (tests && !strv_contains(tests, t->name))
                        continue;

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

                ran = true;
        }

        if (!ran)
                return log_error_errno(SYNTHETIC_ERRNO(ENXIO), "No matching tests found.");

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

#define DECIMAL_STR_FMT(x) _Generic((x),        \
        char: "%c",                             \
        bool: "%d",                             \
        unsigned char: "%d",                    \
        short: "%hd",                           \
        unsigned short: "%hu",                  \
        int: "%d",                              \
        unsigned: "%u",                         \
        long: "%ld",                            \
        unsigned long: "%lu",                   \
        long long: "%lld",                      \
        unsigned long long: "%llu")

#define ASSERT_OK(expr)                                                                                         \
        ({                                                                                                      \
                typeof(expr) _result = (expr);                                                                  \
                if (_result < 0) {                                                                              \
                        log_error_errno(_result, "%s:%i: Assertion failed: expected \"%s\" to succeed, but got error: %m", \
                                        PROJECT_FILE, __LINE__, #expr);                                         \
                        abort();                                                                                \
                }                                                                                               \
         })

/* For functions that return a boolean on success and a negative errno on failure. */
#define ASSERT_OK_POSITIVE(expr)                                                                                \
        ({                                                                                                      \
                typeof(expr) _result = (expr);                                                                  \
                if (_result < 0) {                                                                              \
                        log_error_errno(_result, "%s:%i: Assertion failed: expected \"%s\" to succeed, but got error: %m", \
                                        PROJECT_FILE, __LINE__, #expr);                                         \
                        abort();                                                                                \
                }                                                                                               \
                if (_result == 0) {                                                                             \
                        log_error("%s:%i: Assertion failed: expected \"%s\" to be positive, but it is zero.",   \
                                  PROJECT_FILE, __LINE__, #expr);                                               \
                        abort();                                                                                \
                }                                                                                               \
         })

#define ASSERT_OK_ZERO(expr)                                                                                    \
        ({                                                                                                      \
                typeof(expr) _result = (expr);                                                                  \
                if (_result < 0) {                                                                              \
                        log_error_errno(_result, "%s:%i: Assertion failed: expected \"%s\" to succeed, but got error: %m", \
                                        PROJECT_FILE, __LINE__, #expr);                                         \
                        abort();                                                                                \
                }                                                                                               \
                if (_result != 0) {                                                                             \
                        char _sexpr[DECIMAL_STR_MAX(typeof(expr))];                                             \
                        xsprintf(_sexpr, DECIMAL_STR_FMT(_result), _result);                                    \
                        log_error("%s:%i: Assertion failed: expected \"%s\" to be zero, but it is %s.",         \
                                  PROJECT_FILE, __LINE__, #expr, _sexpr);                                       \
                        abort();                                                                                \
                }                                                                                               \
         })

#define ASSERT_OK_EQ(expr1, expr2)                                                                              \
        ({                                                                                                      \
                typeof(expr1) _expr1 = (expr1);                                                                 \
                typeof(expr2) _expr2 = (expr2);                                                                 \
                if (_expr1 < 0) {                                                                               \
                        log_error_errno(_expr1, "%s:%i: Assertion failed: expected \"%s\" to succeed, but got error: %m", \
                                        PROJECT_FILE, __LINE__, #expr1);                                        \
                        abort();                                                                                \
                }                                                                                               \
                if (_expr1 != _expr2) {                                                                         \
                        char _sexpr1[DECIMAL_STR_MAX(typeof(expr1))];                                           \
                        char _sexpr2[DECIMAL_STR_MAX(typeof(expr2))];                                           \
                        xsprintf(_sexpr1, DECIMAL_STR_FMT(_expr1), _expr1);                                     \
                        xsprintf(_sexpr2, DECIMAL_STR_FMT(_expr2), _expr2);                                     \
                        log_error("%s:%i: Assertion failed: expected \"%s == %s\", got %s != %s",               \
                                  PROJECT_FILE, __LINE__, #expr1, #expr2, _sexpr1, _sexpr2);                    \
                        abort();                                                                                \
                }                                                                                               \
        })

#define ASSERT_OK_ERRNO(expr)                                                                                   \
        ({                                                                                                      \
                typeof(expr) _result = (expr);                                                                  \
                if (_result < 0) {                                                                              \
                        log_error_errno(errno, "%s:%i: Assertion failed: expected \"%s\" to succeed, but got error: %m", \
                                        PROJECT_FILE, __LINE__, #expr);                                         \
                        abort();                                                                                \
                }                                                                                               \
        })

#define ASSERT_OK_ZERO_ERRNO(expr)                                                                              \
        ({                                                                                                      \
                typeof(expr) _result = (expr);                                                                  \
                if (_result < 0) {                                                                              \
                        log_error_errno(errno, "%s:%i: Assertion failed: expected \"%s\" to succeed, but got error: %m", \
                                        PROJECT_FILE, __LINE__, #expr);                                         \
                        abort();                                                                                \
                }                                                                                               \
                if (_result != 0) {                                                                             \
                        char _sexpr[DECIMAL_STR_MAX(typeof(expr))];                                             \
                        xsprintf(_sexpr, DECIMAL_STR_FMT(_result), _result);                                    \
                        log_error("%s:%i: Assertion failed: expected \"%s\" to be zero, but it is %s.",         \
                                  PROJECT_FILE, __LINE__, #expr, _sexpr);                                       \
                        abort();                                                                                \
                }                                                                                               \
        })

#define ASSERT_OK_EQ_ERRNO(expr1, expr2)                                                                        \
        ({                                                                                                      \
                typeof(expr1) _expr1 = (expr1);                                                                 \
                typeof(expr2) _expr2 = (expr2);                                                                 \
                if (_expr1 < 0) {                                                                               \
                        log_error_errno(errno, "%s:%i: Assertion failed: expected \"%s\" to succeed, but got error: %m", \
                                        PROJECT_FILE, __LINE__, #expr1);                                        \
                        abort();                                                                                \
                }                                                                                               \
                if (_expr1 != _expr2) {                                                                         \
                        char _sexpr1[DECIMAL_STR_MAX(typeof(expr1))];                                           \
                        char _sexpr2[DECIMAL_STR_MAX(typeof(expr2))];                                           \
                        xsprintf(_sexpr1, DECIMAL_STR_FMT(_expr1), _expr1);                                     \
                        xsprintf(_sexpr2, DECIMAL_STR_FMT(_expr2), _expr2);                                     \
                        log_error("%s:%i: Assertion failed: expected \"%s == %s\", but %s != %s",               \
                                  PROJECT_FILE, __LINE__, #expr1, #expr2, _sexpr1, _sexpr2);                    \
                        abort();                                                                                \
                }                                                                                               \
        })

#define ASSERT_FAIL(expr)                                                                                       \
        ({                                                                                                      \
                typeof(expr) _result = (expr);                                                                  \
                if (_result >= 0) {                                                                             \
                        log_error_errno(_result, "%s:%i: Assertion failed: expected \"%s\" to fail, but it succeeded", \
                                        PROJECT_FILE, __LINE__, #expr);                                         \
                        abort();                                                                                \
                }                                                                                               \
        })

#define ASSERT_ERROR(expr1, expr2)                                                                              \
        ({                                                                                                      \
                int _expr1 = (expr1);                                                                           \
                int _expr2 = (expr2);                                                                           \
                if (_expr1 >= 0) {                                                                              \
                        log_error("%s:%i: Assertion failed: expected \"%s\" to fail with error \"%s\", but it succeeded", \
                                  PROJECT_FILE, __LINE__, #expr1, STRERROR(_expr2));                            \
                        abort();                                                                                \
                } else if (-_expr1 != _expr2) {                                                                  \
                        log_error_errno(_expr1, "%s:%i: Assertion failed: expected \"%s\" to fail with error \"%s\", but got the following error: %m", \
                                        PROJECT_FILE, __LINE__, #expr1, STRERROR(_expr2));                      \
                        abort();                                                                                \
                }                                                                                               \
        })

#define ASSERT_ERROR_ERRNO(expr1, expr2)                                                                        \
        ({                                                                                                      \
                int _expr1 = (expr1);                                                                           \
                int _expr2 = (expr2);                                                                           \
                if (_expr1 >= 0) {                                                                              \
                        log_error("%s:%i: Assertion failed: expected \"%s\" to fail with error \"%s\", but it succeeded", \
                                  PROJECT_FILE, __LINE__, #expr1, STRERROR(_expr2));                            \
                        abort();                                                                                \
                } else if (errno != _expr2) {                                                                   \
                        log_error_errno(errno, "%s:%i: Assertion failed: expected \"%s\" to fail with error \"%s\", but got the following error: %m", \
                                        PROJECT_FILE, __LINE__, #expr1, STRERROR(errno));                       \
                        abort();                                                                                \
                }                                                                                               \
        })

#define ASSERT_TRUE(expr)                                                                                       \
        ({                                                                                                      \
                if (!(expr)) {                                                                                  \
                        log_error("%s:%i: Assertion failed: expected \"%s\" to be true",                        \
                                  PROJECT_FILE, __LINE__, #expr);                                               \
                        abort();                                                                                \
                }                                                                                               \
        })

#define ASSERT_FALSE(expr)                                                                                      \
        ({                                                                                                      \
                if ((expr)) {                                                                                   \
                        log_error("%s:%i: Assertion failed: expected \"%s\" to be false",                       \
                                  PROJECT_FILE, __LINE__, #expr);                                               \
                        abort();                                                                                \
                }                                                                                               \
        })

#define ASSERT_NULL(expr)                                                                                       \
        ({                                                                                                      \
                typeof(expr) _result = (expr);                                                                  \
                if (_result != NULL) {                                                                          \
                        log_error("%s:%i: Assertion failed: expected \"%s\" to be NULL, got \"%p\" != NULL",    \
                                  PROJECT_FILE, __LINE__, #expr, _result);                                      \
                        abort();                                                                                \
                }                                                                                               \
        })

#define ASSERT_NOT_NULL(expr)                                                                                   \
        ({                                                                                                      \
                if ((expr) == NULL) {                                                                           \
                        log_error("%s:%i: Assertion failed: expected \"%s\" to be not NULL",                    \
                                  PROJECT_FILE, __LINE__, #expr);                                               \
                        abort();                                                                                \
                }                                                                                               \
        })

#define ASSERT_STREQ(expr1, expr2)                                                                              \
        ({                                                                                                      \
                const char *_expr1 = (expr1), *_expr2 = (expr2);                                                \
                if (!streq_ptr(_expr1, _expr2)) {                                                               \
                        log_error("%s:%i: Assertion failed: expected \"%s == %s\", got \"%s != %s\"",           \
                                  PROJECT_FILE, __LINE__, #expr1, #expr2, strnull(_expr1), strnull(_expr2));    \
                        abort();                                                                                \
                }                                                                                               \
        })

/* DECIMAL_STR_FMT() uses _Generic which cannot be used in string concatenation so we have to format the
 * input into strings first and then format those into the final assertion message. */

#define ASSERT_EQ(expr1, expr2)                                                                                 \
        ({                                                                                                      \
                typeof(expr1) _expr1 = (expr1);                                                                 \
                typeof(expr2) _expr2 = (expr2);                                                                 \
                if (_expr1 != _expr2) {                                                                         \
                        char _sexpr1[DECIMAL_STR_MAX(typeof(expr1))];                                           \
                        char _sexpr2[DECIMAL_STR_MAX(typeof(expr2))];                                           \
                        xsprintf(_sexpr1, DECIMAL_STR_FMT(_expr1), _expr1);                                     \
                        xsprintf(_sexpr2, DECIMAL_STR_FMT(_expr2), _expr2);                                     \
                        log_error("%s:%i: Assertion failed: expected \"%s == %s\", but %s != %s",               \
                                  PROJECT_FILE, __LINE__, #expr1, #expr2, _sexpr1, _sexpr2);                    \
                        abort();                                                                                \
                }                                                                                               \
        })

#define ASSERT_GE(expr1, expr2)                                                                                 \
        ({                                                                                                      \
                typeof(expr1) _expr1 = (expr1);                                                                 \
                typeof(expr2) _expr2 = (expr2);                                                                 \
                if (_expr1 < _expr2) {                                                                          \
                        char _sexpr1[DECIMAL_STR_MAX(typeof(expr1))];                                           \
                        char _sexpr2[DECIMAL_STR_MAX(typeof(expr2))];                                           \
                        xsprintf(_sexpr1, DECIMAL_STR_FMT(_expr1), _expr1);                                     \
                        xsprintf(_sexpr2, DECIMAL_STR_FMT(_expr2), _expr2);                                     \
                        log_error("%s:%i: Assertion failed: expected \"%s >= %s\", but %s < %s",                \
                                  PROJECT_FILE, __LINE__, #expr1, #expr2, _sexpr1, _sexpr2);                    \
                        abort();                                                                                \
                }                                                                                               \
        })

#define ASSERT_LE(expr1, expr2)                                                                                 \
        ({                                                                                                      \
                typeof(expr1) _expr1 = (expr1);                                                                 \
                typeof(expr2) _expr2 = (expr2);                                                                 \
                if (_expr1 > _expr2) {                                                                          \
                        char _sexpr1[DECIMAL_STR_MAX(typeof(expr1))];                                           \
                        char _sexpr2[DECIMAL_STR_MAX(typeof(expr2))];                                           \
                        xsprintf(_sexpr1, DECIMAL_STR_FMT(_expr1), _expr1);                                     \
                        xsprintf(_sexpr2, DECIMAL_STR_FMT(_expr2), _expr2);                                     \
                        log_error("%s:%i: Assertion failed: expected \"%s <= %s\", but %s > %s",                \
                                  PROJECT_FILE, __LINE__, #expr1, #expr2, _sexpr1, _sexpr2);                    \
                        abort();                                                                                \
                }                                                                                               \
        })

#define ASSERT_NE(expr1, expr2)                                                                                 \
        ({                                                                                                      \
                typeof(expr1) _expr1 = (expr1);                                                                 \
                typeof(expr2) _expr2 = (expr2);                                                                 \
                if (_expr1 == _expr2) {                                                                         \
                        char _sexpr1[DECIMAL_STR_MAX(typeof(expr1))];                                           \
                        char _sexpr2[DECIMAL_STR_MAX(typeof(expr2))];                                           \
                        xsprintf(_sexpr1, DECIMAL_STR_FMT(_expr1), _expr1);                                     \
                        xsprintf(_sexpr2, DECIMAL_STR_FMT(_expr2), _expr2);                                     \
                        log_error("%s:%i: Assertion failed: expected \"%s != %s\", but %s == %s",               \
                                  PROJECT_FILE, __LINE__, #expr1, #expr2, _sexpr1, _sexpr2);                    \
                        abort();                                                                                \
                }                                                                                               \
        })

#define ASSERT_GT(expr1, expr2)                                                                                 \
        ({                                                                                                      \
                typeof(expr1) _expr1 = (expr1);                                                                 \
                typeof(expr2) _expr2 = (expr2);                                                                 \
                if (!(_expr1 > _expr2)) {                                                                       \
                        char _sexpr1[DECIMAL_STR_MAX(typeof(expr1))];                                           \
                        char _sexpr2[DECIMAL_STR_MAX(typeof(expr2))];                                           \
                        xsprintf(_sexpr1, DECIMAL_STR_FMT(_expr1), _expr1);                                     \
                        xsprintf(_sexpr2, DECIMAL_STR_FMT(_expr2), _expr2);                                     \
                        log_error("%s:%i: Assertion failed: expected \"%s > %s\", but %s <= %s",                \
                                  PROJECT_FILE, __LINE__, #expr1, #expr2, _sexpr1, _sexpr2);                    \
                        abort();                                                                                \
                }                                                                                               \
        })

#define ASSERT_LT(expr1, expr2)                                                                                 \
        ({                                                                                                      \
                typeof(expr1) _expr1 = (expr1);                                                                 \
                typeof(expr2) _expr2 = (expr2);                                                                 \
                if (!(_expr1 < _expr2)) {                                                                       \
                        char _sexpr1[DECIMAL_STR_MAX(typeof(expr1))];                                           \
                        char _sexpr2[DECIMAL_STR_MAX(typeof(expr2))];                                           \
                        xsprintf(_sexpr1, DECIMAL_STR_FMT(_expr1), _expr1);                                     \
                        xsprintf(_sexpr2, DECIMAL_STR_FMT(_expr2), _expr2);                                     \
                        log_error("%s:%i: Assertion failed: expected \"%s < %s\", but %s >= %s",                \
                                  PROJECT_FILE, __LINE__, #expr1, #expr2, _sexpr1, _sexpr2);                    \
                        abort();                                                                                \
                }                                                                                               \
        })

#define ASSERT_SIGNAL(expr, signal)                                                                             \
        ({                                                                                                      \
                ASSERT_TRUE(SIGNAL_VALID(signal));                                                              \
                siginfo_t _siginfo = {};                                                                        \
                int _pid = fork();                                                                              \
                ASSERT_OK(_pid);                                                                                \
                if (_pid == 0) {                                                                                \
                        /* Speed things up by never even attempting to generate a coredump */                   \
                        (void) prctl(PR_SET_DUMPABLE, 0);                                                       \
                        /* But still set an rlimit just in case */                                              \
                        (void) setrlimit(RLIMIT_CORE, &RLIMIT_MAKE_CONST(0));                                   \
                        expr;                                                                                   \
                        _exit(EXIT_SUCCESS);                                                                    \
                }                                                                                               \
                (void) wait_for_terminate(_pid, &_siginfo);                                                     \
                if (_siginfo.si_status != signal) {                                                             \
                        log_error("%s:%i: Assertion failed: \"%s\" died with signal %s, but %s was expected",   \
                                  PROJECT_FILE, __LINE__, #expr, signal_to_string(_siginfo.si_status),          \
                                  signal_to_string(signal));                                                    \
                        abort();                                                                                \
                }                                                                                               \
        })

#define ASSERT_EQ_ID128(expr1, expr2)                                                                           \
        ({                                                                                                      \
                typeof(expr1) _expr1 = (expr1);                                                                 \
                typeof(expr2) _expr2 = (expr2);                                                                 \
                if (!sd_id128_equal(_expr1, _expr2)) {                                                          \
                        log_error("%s:%i: Assertion failed: \"%s == %s\", but %s != %s",                        \
                                  PROJECT_FILE, __LINE__,                                                       \
                                  #expr1, #expr2,                                                               \
                                  SD_ID128_TO_STRING(_expr1), SD_ID128_TO_STRING(_expr2));                      \
                        abort();                                                                                \
                }                                                                                               \
        })

#define ASSERT_NE_ID128(expr1, expr2)                                                                           \
        ({                                                                                                      \
                typeof(expr1) _expr1 = (expr1);                                                                 \
                typeof(expr2) _expr2 = (expr2);                                                                 \
                if (sd_id128_equal(_expr1, _expr2)) {                                                           \
                        log_error("%s:%i: Assertion failed: \"%s != %s\", but %s == %s",                        \
                                  PROJECT_FILE, __LINE__,                                                       \
                                  #expr1, #expr2,                                                               \
                                  SD_ID128_TO_STRING(_expr1), SD_ID128_TO_STRING(_expr2));                      \
                        abort();                                                                                \
                }                                                                                               \
        })

#define EFI_GUID_Fmt "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x"
#define EFI_GUID_Arg(guid) (guid).Data1, (guid).Data2, (guid).Data3,                           \
                           (guid).Data4[0], (guid).Data4[1], (guid).Data4[2], (guid).Data4[3], \
                           (guid).Data4[4], (guid).Data4[5], (guid).Data4[6], (guid).Data4[7]  \

#define ASSERT_EQ_EFI_GUID(expr1, expr2)                                                                        \
        ({                                                                                                      \
                typeof(expr1) _expr1 = (expr1);                                                                 \
                typeof(expr2) _expr2 = (expr2);                                                                 \
                if (!efi_guid_equal(_expr1, _expr2)) {                                                          \
                        log_error("%s:%i: Assertion failed: expected \"%s == %s\", but " EFI_GUID_Fmt           \
                                  " != " EFI_GUID_Fmt,                                                          \
                                  PROJECT_FILE, __LINE__,                                                       \
                                  #expr1, #expr2,                                                               \
                                  EFI_GUID_Arg(*_expr1), EFI_GUID_Arg(*_expr2));                                \
                        abort();                                                                                \
                }                                                                                               \
        })
