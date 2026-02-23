/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <unistd.h>

#include "errno-list.h"
#include "shared-forward.h"
#include "log.h"
#include "log-assert-critical.h"
#include "static-destruct.h"            /* IWYU pragma: keep */
#include "signal-util.h"                /* IWYU pragma: keep */
#include "stdio-util.h"
#include "string-util.h"                /* IWYU pragma: keep */

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
        return IN_SET(ABS(r),
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

int define_hex_ptr_internal(const char *hex, void **name, size_t *name_len);

/* Define void* buffer and size_t length variables from a hex string. */
#define DEFINE_HEX_PTR(name, hex)                                       \
        _cleanup_free_ void *name = NULL;                               \
        size_t name##_len = 0;                                          \
        ASSERT_OK(define_hex_ptr_internal(hex, &name, &name##_len))

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

int run_test_table(const TestFunc *start, const TestFunc *end);

void test_prepare(int argc, char *argv[], int log_level);

#define DEFINE_TEST_MAIN_FULL(log_level, intro, outro)    \
        int main(int argc, char *argv[]) {                \
                int (*_intro)(void) = intro;              \
                int (*_outro)(void) = outro;              \
                int _r, _q;                               \
                test_prepare(argc, argv, log_level);      \
                _r = _intro ? _intro() : EXIT_SUCCESS;    \
                if (_r == EXIT_SUCCESS)                   \
                        _r = run_test_table(__start_SYSTEMD_TEST_TABLE, __stop_SYSTEMD_TEST_TABLE); \
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

_noreturn_ void log_test_failed_internal(const char *file, int line, const char *func, const char *format, ...) _printf_(4,5);

#define log_test_failed(format, ...) \
        log_test_failed_internal(PROJECT_FILE, __LINE__, __func__, "%s:%i: Assertion failed: " format, PROJECT_FILE, __LINE__, ##__VA_ARGS__)

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

#ifdef __COVERITY__
#  define ASSERT_OK(expr)                                                                                       \
        ({                                                                                                      \
                typeof(expr) _result = (expr);                                                                  \
                __coverity_check__(_result >= 0);                                                               \
                _result;                                                                                        \
        })
#else
#  define ASSERT_OK(expr)                                                                                       \
        ({                                                                                                      \
                typeof(expr) _result = (expr);                                                                  \
                if (_result < 0)                                                                                \
                        log_test_failed("Expected \"%s\" to succeed, but got error: %"PRIiMAX"/%s",             \
                                        #expr, (intmax_t) _result, ERRNO_NAME(_result));                        \
                _result;                                                                                        \
         })
#endif

#ifdef __COVERITY__
#  define ASSERT_OK_OR(expr, ...)                                                                               \
        ({                                                                                                      \
                typeof(expr) _result = (expr);                                                                  \
                __coverity_check__(_result >= 0 || IN_SET(_result, 0, __VA_ARGS__);                             \
                _result;                                                                                        \
        })
#else
#  define ASSERT_OK_OR(expr, ...)                                                                               \
        ({                                                                                                      \
                typeof(expr) _result = (expr);                                                                  \
                if (_result < 0 && !IN_SET(_result, 0, __VA_ARGS__))                                            \
                        log_test_failed("\"%s\" failed with unexpected error: %"PRIiMAX"/%s",                   \
                                        #expr, (intmax_t) _result, ERRNO_NAME(_result));                        \
                _result;                                                                                        \
         })
#endif

/* For functions that return a boolean on success and a negative errno on failure. */
#ifdef __COVERITY__
#  define ASSERT_OK_POSITIVE(expr)                                                                              \
        ({                                                                                                      \
                typeof(expr) _result = (expr);                                                                  \
                __coverity_check__(_result > 0);                                                                \
                _result;                                                                                        \
        })
#else
#  define ASSERT_OK_POSITIVE(expr)                                                                              \
        ({                                                                                                      \
                typeof(expr) _result = (expr);                                                                  \
                if (_result < 0)                                                                                \
                        log_test_failed("Expected \"%s\" to succeed, but got error: %"PRIiMAX"/%s",             \
                                        #expr, (intmax_t) _result, ERRNO_NAME(_result));                        \
                if (_result == 0)                                                                               \
                        log_test_failed("Expected \"%s\" to be positive, but it is zero.", #expr);              \
                _result;                                                                                        \
         })
#endif

#ifdef __COVERITY__
#  define ASSERT_OK_ZERO(expr)                                                                                  \
        ({                                                                                                      \
                typeof(expr) _result = (expr);                                                                  \
                __coverity_check__(_result == 0);                                                               \
                _result;                                                                                        \
        })
#else
#  define ASSERT_OK_ZERO(expr)                                                                                  \
        ({                                                                                                      \
                typeof(expr) _result = (expr);                                                                  \
                if (_result < 0)                                                                                \
                        log_test_failed("Expected \"%s\" to succeed, but got error: %"PRIiMAX"/%s",             \
                                        #expr, (intmax_t) _result, ERRNO_NAME(_result));                        \
                if (_result != 0)                                                                               \
                        log_test_failed("Expected \"%s\" to be zero, but it is %"PRIiMAX".",                    \
                                        #expr, (intmax_t) _result);                                             \
                _result;                                                                                        \
         })
#endif

#ifdef __COVERITY__
#  define ASSERT_OK_EQ(expr1, expr2)                                                                            \
        ({                                                                                                      \
                typeof(expr1) _expr1 = (expr1);                                                                 \
                typeof(expr2) _expr2 = (expr2);                                                                 \
                __coverity_check__(_expr1 == _expr2);                                                           \
                _expr1;                                                                                         \
        })
#else
#  define ASSERT_OK_EQ(expr1, expr2)                                                                            \
        ({                                                                                                      \
                typeof(expr1) _expr1 = (expr1);                                                                 \
                typeof(expr2) _expr2 = (expr2);                                                                 \
                if (_expr1 < 0)                                                                                 \
                        log_test_failed("Expected \"%s\" to succeed, but got error: %"PRIiMAX"/%s",             \
                                        #expr1, (intmax_t) _expr1, ERRNO_NAME(_expr1));                         \
                if (_expr1 != _expr2)                                                                           \
                        log_test_failed("Expected \"%s == %s\", got %"PRIiMAX" != %"PRIiMAX,                    \
                                        #expr1, #expr2, (intmax_t) _expr1, (intmax_t) _expr2);                  \
                _expr1;                                                                                         \
        })
#endif

#ifdef __COVERITY__
#  define ASSERT_OK_NE(expr1, expr2)                                                                            \
        ({                                                                                                      \
                typeof(expr1) _expr1 = (expr1);                                                                 \
                typeof(expr2) _expr2 = (expr2);                                                                 \
                __coverity_check__(_expr1 != _expr2);                                                           \
                _expr1;                                                                                         \
        })
#else
#  define ASSERT_OK_NE(expr1, expr2)                                                                            \
        ({                                                                                                      \
                typeof(expr1) _expr1 = (expr1);                                                                 \
                typeof(expr2) _expr2 = (expr2);                                                                 \
                if (_expr1 < 0)                                                                                 \
                        log_test_failed("Expected \"%s\" to succeed, but got error: %"PRIiMAX"/%s",             \
                                        #expr1, (intmax_t) _expr1, ERRNO_NAME(_expr1));                         \
                if (_expr1 == _expr2)                                                                           \
                        log_test_failed("Expected \"%s != %s\", got %"PRIiMAX" != %"PRIiMAX,                    \
                                        #expr1, #expr2, (intmax_t) _expr1, (intmax_t) _expr2);                  \
                _expr1;                                                                                         \
        })
#endif

/* For functions that return a boolean on success and set errno on failure. */
#ifdef __COVERITY__
#  define ASSERT_OK_ERRNO(expr)                                                                                 \
        ({                                                                                                      \
                typeof(expr) _result = (expr);                                                                  \
                __coverity_check__(_result >= 0);                                                               \
                _result;                                                                                        \
        })
#else
#  define ASSERT_OK_ERRNO(expr)                                                                                 \
        ({                                                                                                      \
                typeof(expr) _result = (expr);                                                                  \
                if (_result < 0)                                                                                \
                        log_test_failed("Expected \"%s\" to succeed, but got errno: %d/%s",                     \
                                        #expr, errno, ERRNO_NAME(errno));                                       \
                _result;                                                                                        \
        })
#endif

#ifdef __COVERITY__
#  define ASSERT_OK_ZERO_ERRNO(expr)                                                                            \
        ({                                                                                                      \
                typeof(expr) _result = (expr);                                                                  \
                __coverity_check__(_result == 0);                                                               \
                _result;                                                                                        \
        })
#else
#  define ASSERT_OK_ZERO_ERRNO(expr)                                                                            \
        ({                                                                                                      \
                typeof(expr) _result = (expr);                                                                  \
                if (_result < 0)                                                                                \
                        log_test_failed("Expected \"%s\" to succeed, but got errno: %d/%s",                     \
                                        #expr, errno, ERRNO_NAME(errno));                                       \
                if (_result != 0)                                                                               \
                        log_test_failed("Expected \"%s\" to be zero, but it is %"PRIiMAX".",                    \
                                        #expr, (intmax_t) _result);                                             \
                _result;                                                                                        \
        })
#endif

#ifdef __COVERITY__
#  define ASSERT_OK_EQ_ERRNO(expr1, expr2)                                                                      \
        ({                                                                                                      \
                typeof(expr1) _expr1 = (expr1);                                                                 \
                typeof(expr2) _expr2 = (expr2);                                                                 \
                __coverity_check__(_expr1 == _expr2);                                                           \
                _expr1;                                                                                         \
        })
#else
#  define ASSERT_OK_EQ_ERRNO(expr1, expr2)                                                                      \
        ({                                                                                                      \
                typeof(expr1) _expr1 = (expr1);                                                                 \
                typeof(expr2) _expr2 = (expr2);                                                                 \
                if (_expr1 < 0)                                                                                 \
                        log_test_failed("Expected \"%s\" to succeed, but got errno: %d/%s",                     \
                                        #expr1, errno, ERRNO_NAME(errno));                                      \
                if (_expr1 != _expr2)                                                                           \
                        log_test_failed("Expected \"%s == %s\", but %"PRIiMAX" != %"PRIiMAX,                    \
                                        #expr1, #expr2, (intmax_t) _expr1, (intmax_t) _expr2);                  \
                _expr1;                                                                                         \
        })
#endif

#ifdef __COVERITY__
#  define ASSERT_FAIL(expr)                                                                                     \
        ({                                                                                                      \
                typeof(expr) _result = (expr);                                                                  \
                __coverity_check__(_result < 0);                                                                \
                _result;                                                                                        \
        })
#else
#  define ASSERT_FAIL(expr)                                                                                     \
        ({                                                                                                      \
                typeof(expr) _result = (expr);                                                                  \
                if (_result >= 0)                                                                               \
                        log_test_failed("Expected \"%s\" to fail, but it succeeded.", #expr);                   \
                _result;                                                                                        \
        })
#endif

#ifdef __COVERITY__
#  define ASSERT_ERROR(expr1, expr2)                                                                            \
        ({                                                                                                      \
                int _expr1 = (expr1);                                                                           \
                int _expr2 = (expr2);                                                                           \
                __coverity_check__((_expr1) == -(_expr2));                                                      \
                _expr1;                                                                                         \
        })
#else
#  define ASSERT_ERROR(expr1, expr2)                                                                            \
        ({                                                                                                      \
                int _expr1 = (expr1);                                                                           \
                int _expr2 = (expr2);                                                                           \
                if (_expr1 >= 0)                                                                                \
                        log_test_failed("Expected \"%s\" to fail with error %d/%s, but it succeeded",           \
                                        #expr1, -_expr2, ERRNO_NAME(_expr2));                                   \
                else if (-_expr1 != _expr2)                                                                     \
                        log_test_failed("Expected \"%s\" to fail with error %d/%s, but got %d/%s",              \
                                        #expr1, -_expr2, ERRNO_NAME(_expr2), _expr1, ERRNO_NAME(_expr1));       \
                _expr1;                                                                                         \
        })
#endif

#ifdef __COVERITY__
#  define ASSERT_ERROR_ERRNO(expr1, expr2)                                                                      \
        ({                                                                                                      \
                int _expr1 = (expr1);                                                                           \
                int _expr2 = (expr2);                                                                           \
                __coverity_check__(_expr1 < 0 && errno == _expr2);                                              \
                _expr1;                                                                                         \
        })
#else
#  define ASSERT_ERROR_ERRNO(expr1, expr2)                                                                      \
        ({                                                                                                      \
                int _expr1 = (expr1);                                                                           \
                int _expr2 = (expr2);                                                                           \
                if (_expr1 >= 0)                                                                                \
                        log_test_failed("Expected \"%s\" to fail with errno %d/%s, but it succeeded",           \
                                        #expr1, _expr2, ERRNO_NAME(_expr2));                                    \
                else if (errno != _expr2)                                                                       \
                        log_test_failed("Expected \"%s\" to fail with errno %d/%s, but got %d/%s",              \
                                        #expr1, _expr2, ERRNO_NAME(_expr2), errno, ERRNO_NAME(errno));          \
                _expr1;                                                                                         \
        })
#endif

#ifdef __COVERITY__
#  define ASSERT_TRUE(expr) __coverity_check__(!!(expr))
#else
#  define ASSERT_TRUE(expr)                                                                                     \
        ({                                                                                                      \
                if (!(expr))                                                                                    \
                        log_test_failed("Expected \"%s\" to be true", #expr);                                   \
        })
#endif

#ifdef __COVERITY__
#  define ASSERT_FALSE(expr) __coverity_check__(!(expr))
#else
#  define ASSERT_FALSE(expr)                                                                                    \
        ({                                                                                                      \
                if ((expr))                                                                                     \
                        log_test_failed("Expected \"%s\" to be false", #expr);                                  \
        })
#endif

#ifdef __COVERITY__
#  define ASSERT_NULL(expr) __coverity_check__((expr) == NULL)
#else
#  define ASSERT_NULL(expr)                                                                                     \
        ({                                                                                                      \
                typeof(expr) _result = (expr);                                                                  \
                if (_result != NULL)                                                                            \
                        log_test_failed("Expected \"%s\" to be NULL, got \"%p\" != NULL", #expr, _result);      \
        })
#endif

#ifdef __COVERITY__
#  define ASSERT_NOT_NULL(expr) __coverity_check__((expr) != NULL)
#else
#  define ASSERT_NOT_NULL(expr)                                                                                 \
        ({                                                                                                      \
                typeof(expr) _result = (expr);                                                                  \
                if (_result == NULL)                                                                            \
                        log_test_failed("Expected \"%s\" to be not NULL", #expr);                               \
                _result;                                                                                        \
        })
#endif

#ifdef __COVERITY__
#  define ASSERT_STREQ(expr1, expr2) __coverity_check__(streq_ptr((expr1), (expr2)))
#else
#  define ASSERT_STREQ(expr1, expr2)                                                                            \
        ({                                                                                                      \
                const char *_expr1 = (expr1), *_expr2 = (expr2);                                                \
                if (!streq_ptr(_expr1, _expr2))                                                                 \
                        log_test_failed("Expected \"%s == %s\", got \"%s != %s\"",                              \
                                        #expr1, #expr2, strnull(_expr1), strnull(_expr2));                      \
        })
#endif

#ifdef __COVERITY__
#  define ASSERT_NOT_STREQ(expr1, expr2) __coverity_check__(!streq_ptr((expr1), (expr2)))
#else
#  define ASSERT_NOT_STREQ(expr1, expr2)                                                                        \
        ({                                                                                                      \
                const char *_expr1 = (expr1), *_expr2 = (expr2);                                                \
                if (streq_ptr(_expr1, _expr2))                                                                  \
                        log_test_failed("Expected \"%s != %s\", got \"%s == %s\"",                              \
                                        #expr1, #expr2, strnull(_expr1), strnull(_expr2));                      \
        })
#endif

#ifdef __COVERITY__
#  define ASSERT_STRNEQ(expr1, expr2, n) __coverity_check__(strneq_ptr((expr1), (expr2), (n)))
#else
#  define ASSERT_STRNEQ(expr1, expr2, n)                                                                        \
        ({                                                                                                      \
                const char *_expr1 = (expr1), *_expr2 = (expr2);                                                \
                size_t _n = (n);                                                                                \
                if (!strneq_ptr(_expr1, _expr2, _n))                                                            \
                        log_test_failed("Expected \"%s == %s\", got \"%s != %s\" (first %zu characters)",       \
                                        #expr1, #expr2, strnull(_expr1), strnull(_expr2), _n);                  \
        })
#endif

#ifdef __COVERITY__
#  define ASSERT_PTR_EQ(expr1, expr2) __coverity_check__((expr1) == (expr2))
#else
#  define ASSERT_PTR_EQ(expr1, expr2)                                                                           \
        ({                                                                                                      \
                const void *_expr1 = (expr1), *_expr2 = (expr2);                                                \
                if (_expr1 != _expr2)                                                                           \
                        log_test_failed("Expected \"%s == %s\", got \"0x%p != 0x%p\"",                          \
                                        #expr1, #expr2, _expr1, _expr2);                                        \
        })
#endif

/* DECIMAL_STR_FMT() uses _Generic which cannot be used in string concatenation so we have to format the
 * input into strings first and then format those into the final assertion message. */

#ifdef __COVERITY__
#  define ASSERT_EQ(expr1, expr2) __coverity_check__((expr1) == (expr2))
#else
#  define ASSERT_EQ(expr1, expr2)                                                                               \
        ({                                                                                                      \
                typeof(expr1) _expr1 = (expr1);                                                                 \
                typeof(expr2) _expr2 = (expr2);                                                                 \
                if (_expr1 != _expr2) {                                                                         \
                        char _sexpr1[DECIMAL_STR_MAX(typeof(expr1))];                                           \
                        char _sexpr2[DECIMAL_STR_MAX(typeof(expr2))];                                           \
                        xsprintf(_sexpr1, DECIMAL_STR_FMT(_expr1), _expr1);                                     \
                        xsprintf(_sexpr2, DECIMAL_STR_FMT(_expr2), _expr2);                                     \
                        log_test_failed("Expected \"%s == %s\", but %s != %s",                                  \
                                        #expr1, #expr2, _sexpr1, _sexpr2);                                      \
                }                                                                                               \
        })
#endif

#ifdef __COVERITY__
#  define ASSERT_GE(expr1, expr2) __coverity_check__((expr1) >= (expr2))
#else
#  define ASSERT_GE(expr1, expr2)                                                                               \
        ({                                                                                                      \
                typeof(expr1) _expr1 = (expr1);                                                                 \
                typeof(expr2) _expr2 = (expr2);                                                                 \
                if (_expr1 < _expr2) {                                                                          \
                        char _sexpr1[DECIMAL_STR_MAX(typeof(expr1))];                                           \
                        char _sexpr2[DECIMAL_STR_MAX(typeof(expr2))];                                           \
                        xsprintf(_sexpr1, DECIMAL_STR_FMT(_expr1), _expr1);                                     \
                        xsprintf(_sexpr2, DECIMAL_STR_FMT(_expr2), _expr2);                                     \
                        log_test_failed("Expected \"%s >= %s\", but %s < %s",                                   \
                                        #expr1, #expr2, _sexpr1, _sexpr2);                                      \
                }                                                                                               \
        })
#endif

#ifdef __COVERITY__
#  define ASSERT_LE(expr1, expr2) __coverity_check__((expr1) <= (expr2))
#else
#  define ASSERT_LE(expr1, expr2)                                                                               \
        ({                                                                                                      \
                typeof(expr1) _expr1 = (expr1);                                                                 \
                typeof(expr2) _expr2 = (expr2);                                                                 \
                if (_expr1 > _expr2) {                                                                          \
                        char _sexpr1[DECIMAL_STR_MAX(typeof(expr1))];                                           \
                        char _sexpr2[DECIMAL_STR_MAX(typeof(expr2))];                                           \
                        xsprintf(_sexpr1, DECIMAL_STR_FMT(_expr1), _expr1);                                     \
                        xsprintf(_sexpr2, DECIMAL_STR_FMT(_expr2), _expr2);                                     \
                        log_test_failed("Expected \"%s <= %s\", but %s > %s",                                   \
                                        #expr1, #expr2, _sexpr1, _sexpr2);                                      \
                }                                                                                               \
        })
#endif

#ifdef __COVERITY__
# define ASSERT_NE(expr1, expr2) __coverity_check__((expr1) != (expr2))
#else
#  define ASSERT_NE(expr1, expr2)                                                                               \
        ({                                                                                                      \
                typeof(expr1) _expr1 = (expr1);                                                                 \
                typeof(expr2) _expr2 = (expr2);                                                                 \
                if (_expr1 == _expr2) {                                                                         \
                        char _sexpr1[DECIMAL_STR_MAX(typeof(expr1))];                                           \
                        char _sexpr2[DECIMAL_STR_MAX(typeof(expr2))];                                           \
                        xsprintf(_sexpr1, DECIMAL_STR_FMT(_expr1), _expr1);                                     \
                        xsprintf(_sexpr2, DECIMAL_STR_FMT(_expr2), _expr2);                                     \
                        log_test_failed("Expected \"%s != %s\", but %s == %s",                                  \
                                        #expr1, #expr2, _sexpr1, _sexpr2);                                      \
                }                                                                                               \
        })
#endif

#ifdef __COVERITY__
#  define ASSERT_GT(expr1, expr2) __coverity_check__((expr1) > (expr2))
#else
#  define ASSERT_GT(expr1, expr2)                                                                               \
        ({                                                                                                      \
                typeof(expr1) _expr1 = (expr1);                                                                 \
                typeof(expr2) _expr2 = (expr2);                                                                 \
                if (!(_expr1 > _expr2)) {                                                                       \
                        char _sexpr1[DECIMAL_STR_MAX(typeof(expr1))];                                           \
                        char _sexpr2[DECIMAL_STR_MAX(typeof(expr2))];                                           \
                        xsprintf(_sexpr1, DECIMAL_STR_FMT(_expr1), _expr1);                                     \
                        xsprintf(_sexpr2, DECIMAL_STR_FMT(_expr2), _expr2);                                     \
                        log_test_failed("Expected \"%s > %s\", but %s <= %s",                                   \
                                        #expr1, #expr2, _sexpr1, _sexpr2);                                      \
                }                                                                                               \
        })
#endif

#ifdef __COVERITY__
#  define ASSERT_LT(expr1, expr2) __coverity_check__((expr1) < (expr2))
#else
#  define ASSERT_LT(expr1, expr2)                                                                               \
        ({                                                                                                      \
                typeof(expr1) _expr1 = (expr1);                                                                 \
                typeof(expr2) _expr2 = (expr2);                                                                 \
                if (!(_expr1 < _expr2)) {                                                                       \
                        char _sexpr1[DECIMAL_STR_MAX(typeof(expr1))];                                           \
                        char _sexpr2[DECIMAL_STR_MAX(typeof(expr2))];                                           \
                        xsprintf(_sexpr1, DECIMAL_STR_FMT(_expr1), _expr1);                                     \
                        xsprintf(_sexpr2, DECIMAL_STR_FMT(_expr2), _expr2);                                     \
                        log_test_failed("Expected \"%s < %s\", but %s >= %s",                                   \
                                        #expr1, #expr2, _sexpr1, _sexpr2);                                      \
                }                                                                                               \
        })
#endif

enum {
        ASSERT_SIGNAL_FORK_CHILD  = 0, /* We are in the child process */
        ASSERT_SIGNAL_FORK_PARENT = 1, /* We are in the parent process */
};

int assert_signal_internal(int *ret_signal);

#ifdef __COVERITY__
#  define ASSERT_SIGNAL(expr, signal) __coverity_check__(((expr), false))
#else
#  define ASSERT_SIGNAL(expr, signal) __ASSERT_SIGNAL(UNIQ, expr, signal)
#  define __ASSERT_SIGNAL(uniq, expr, sgnl)                                                                     \
        ({                                                                                                      \
                ASSERT_TRUE(SIGNAL_VALID(sgnl));                                                                \
                int UNIQ_T(_status, uniq);                                                                      \
                int UNIQ_T(_path, uniq) = assert_signal_internal(&UNIQ_T(_status, uniq));                       \
                ASSERT_OK_ERRNO(UNIQ_T(_path, uniq));                                                           \
                if (UNIQ_T(_path, uniq) == ASSERT_SIGNAL_FORK_CHILD) {                                          \
                        (void) signal(sgnl, SIG_DFL);                                                           \
                        expr;                                                                                   \
                        _exit(EXIT_SUCCESS);                                                                    \
                }                                                                                               \
                ASSERT_EQ(UNIQ_T(_path, uniq), ASSERT_SIGNAL_FORK_PARENT);                                      \
                if (UNIQ_T(_status, uniq) != sgnl)                                                              \
                        log_test_failed("\"%s\" died with signal %s, but %s was expected",                      \
                                        #expr, signal_to_string(UNIQ_T(_status, uniq)),                         \
                                                                       signal_to_string(sgnl));                 \
        })
#endif

#ifdef __COVERITY__
#  define ASSERT_EQ_ID128(expr1, expr2) __coverity_check__(sd_id128_equal((expr1), (expr2)))
#else
#  define ASSERT_EQ_ID128(expr1, expr2)                                                                         \
        ({                                                                                                      \
                typeof(expr1) _expr1 = (expr1);                                                                 \
                typeof(expr2) _expr2 = (expr2);                                                                 \
                if (!sd_id128_equal(_expr1, _expr2))                                                            \
                        log_test_failed("\"%s == %s\", but %s != %s",                                           \
                                        #expr1, #expr2,                                                         \
                                        SD_ID128_TO_STRING(_expr1), SD_ID128_TO_STRING(_expr2));                \
        })
#endif

#ifdef __COVERITY__
#  define ASSERT_NE_ID128(expr1, expr2) __coverity_check__(!sd_id128_equal((expr1), (expr2)))
#else
#  define ASSERT_NE_ID128(expr1, expr2)                                                                         \
        ({                                                                                                      \
                typeof(expr1) _expr1 = (expr1);                                                                 \
                typeof(expr2) _expr2 = (expr2);                                                                 \
                if (sd_id128_equal(_expr1, _expr2))                                                             \
                        log_test_failed("\"%s != %s\", but %s == %s",                                           \
                                        #expr1, #expr2,                                                         \
                                        SD_ID128_TO_STRING(_expr1), SD_ID128_TO_STRING(_expr2));                \
        })
#endif

#define EFI_GUID_Fmt "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x"
#define EFI_GUID_Arg(guid) (guid).Data1, (guid).Data2, (guid).Data3,                           \
                           (guid).Data4[0], (guid).Data4[1], (guid).Data4[2], (guid).Data4[3], \
                           (guid).Data4[4], (guid).Data4[5], (guid).Data4[6], (guid).Data4[7]  \

#ifdef __COVERITY__
#  define ASSERT_EQ_EFI_GUID(expr1, expr2) __coverity_check__(efi_guid_equal((expr1), (expr2)))
#else
#  define ASSERT_EQ_EFI_GUID(expr1, expr2)                                                                      \
        ({                                                                                                      \
                typeof(expr1) _expr1 = (expr1);                                                                 \
                typeof(expr2) _expr2 = (expr2);                                                                 \
                if (!efi_guid_equal(_expr1, _expr2))                                                            \
                        log_test_failed("Expected \"%s == %s\", but " EFI_GUID_Fmt                              \
                                        " != " EFI_GUID_Fmt,                                                    \
                                        #expr1, #expr2,                                                         \
                                        EFI_GUID_Arg(*_expr1), EFI_GUID_Arg(*_expr2));                          \
        })
#endif
