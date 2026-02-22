/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "format-util.h"
#include "iovec-util.h"
#include "iovec-wrapper.h"
#include "log.h"
#include "log-context.h"
#include "process-util.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"

#define X10(x) x x x x x x x x x x
#define X100(x) X10(X10(x))
#define X1000(x) X100(X10(x))

TEST(synthetic_errno) {
        ASSERT_TRUE(IS_SYNTHETIC_ERRNO(SYNTHETIC_ERRNO(EINVAL)));
        ASSERT_TRUE(IS_SYNTHETIC_ERRNO(SYNTHETIC_ERRNO(-EINVAL)));
        assert_cc(!IS_SYNTHETIC_ERRNO(EINVAL));
        assert_cc(!IS_SYNTHETIC_ERRNO(-EINVAL));
        ASSERT_TRUE(IS_SYNTHETIC_ERRNO(SYNTHETIC_ERRNO(0)));
        assert_cc(!IS_SYNTHETIC_ERRNO(0));
        ASSERT_EQ(ERRNO_VALUE(EINVAL), EINVAL);
        ASSERT_EQ(ERRNO_VALUE(SYNTHETIC_ERRNO(-EINVAL)), EINVAL);

        ASSERT_ERROR(log_info_errno(SYNTHETIC_ERRNO(EUCLEAN), "foo"), EUCLEAN);
}

static int fail_with_EINVAL(void) {
        assert_return(false, -EINVAL);
        return 0;
}

TEST(assert_return_is_critical) {
        SAVE_ASSERT_RETURN_IS_CRITICAL;

        log_set_assert_return_is_critical(false);
        ASSERT_ERROR(fail_with_EINVAL(), EINVAL);

        log_set_assert_return_is_critical(true);
        ASSERT_RETURN_IS_CRITICAL(false, ASSERT_ERROR(fail_with_EINVAL(), EINVAL));
        ASSERT_TRUE(log_get_assert_return_is_critical());
        ASSERT_RETURN_EXPECTED(ASSERT_ERROR(fail_with_EINVAL(), EINVAL));
        ASSERT_TRUE(log_get_assert_return_is_critical());
        ASSERT_RETURN_EXPECTED_SE(fail_with_EINVAL() == -EINVAL);
        ASSERT_TRUE(log_get_assert_return_is_critical());
}

TEST(file) {
        log_info("__FILE__: %s", __FILE__);
        log_info("RELATIVE_SOURCE_PATH: %s", RELATIVE_SOURCE_PATH);
        log_info("PROJECT_FILE: %s", PROJECT_FILE);

        ASSERT_NOT_NULL(startswith(__FILE__, RELATIVE_SOURCE_PATH "/"));
}

static void test_log_once_impl(void) {
        log_once(LOG_INFO, "This should be logged in LOG_INFO at first, then in LOG_DEBUG later.");
        log_once(LOG_DEBUG, "This should be logged only once in LOG_DEBUG.");
        ASSERT_ERROR(log_once_errno(LOG_INFO, SYNTHETIC_ERRNO(ENOANO),
                                 "This should be logged with errno in LOG_INFO at first, then in LOG_DEBUG later: %m"),
                     ENOANO);
        ASSERT_ERROR(log_once_errno(LOG_DEBUG, SYNTHETIC_ERRNO(EBADMSG),
                                    "This should be logged only once with errno in LOG_DEBUG: %m"),
                     EBADMSG);
}

TEST(log_once) {
        for (unsigned i = 0; i < 4; i++)
                test_log_once_impl();
}

_sentinel_
static void test_log_format_iovec_sentinel(
                char * const *expected,
                const char *format,
                ...) {

        size_t iovec_len = 20, n = 0;
        struct iovec *iovec = newa(struct iovec, iovec_len);
        va_list ap;

        log_debug("/* %s(%s) */", __func__, strnull(format));

        char **v = STRV_MAKE("SYSLOG_FACILITY=3",
                             "SYSLOG_IDENTIFIER=systemd-journald",
                             "_TRANSPORT=driver",
                             "PRIORITY=6");
        size_t m = strv_length(v);

        STRV_FOREACH(s, v)
                iovec[n++] = IOVEC_MAKE_STRING(*s);

        ASSERT_EQ(n, m);

        va_start(ap, format);
        DISABLE_WARNING_FORMAT_NONLITERAL;
        ASSERT_OK(log_format_iovec(iovec, iovec_len, &n, /* newline_separator= */ false, ENOANO, format, ap));
        REENABLE_WARNING;
        va_end(ap);

        ASSERT_EQ(n, m + strv_length(expected));

        for (size_t i = 0; i < n; i++)
                if (i < m)
                        ASSERT_EQ(iovec_memcmp(&iovec[i], &IOVEC_MAKE_STRING(v[i])), 0);
                else {
                        ASSERT_EQ(iovec_memcmp(&iovec[i], &IOVEC_MAKE_STRING(expected[i - m])), 0);
                        free(iovec[i].iov_base);
                }

        n = m;

        va_start(ap, format);
        DISABLE_WARNING_FORMAT_NONLITERAL;
        ASSERT_OK(log_format_iovec(iovec, iovec_len, &n, /* newline_separator= */ true, ENOANO, format, ap));
        REENABLE_WARNING;
        va_end(ap);

        ASSERT_EQ(n, m + strv_length(expected) * 2);

        for (size_t i = 0; i < n; i++)
                if (i < m)
                        ASSERT_EQ(iovec_memcmp(&iovec[i], &IOVEC_MAKE_STRING(v[i])), 0);
                else if ((i - m) % 2 == 0) {
                        ASSERT_EQ(iovec_memcmp(&iovec[i], &IOVEC_MAKE_STRING(expected[(i - m) / 2])), 0);
                        free(iovec[i].iov_base);
                } else
                        ASSERT_EQ(iovec_memcmp(&iovec[i], &IOVEC_MAKE_STRING("\n")), 0);
}

#define test_log_format_iovec_one(...)                 \
        test_log_format_iovec_sentinel(__VA_ARGS__, NULL)

TEST(log_format_iovec) {
        test_log_format_iovec_one(NULL, NULL);
        test_log_format_iovec_one(STRV_MAKE("MESSAGE=hoge"),
                                  LOG_MESSAGE("hoge"));
        test_log_format_iovec_one(STRV_MAKE("MESSAGE=hoge: 10"),
                                  LOG_MESSAGE("hoge: %i", 10));
        test_log_format_iovec_one(STRV_MAKE("MESSAGE=hoge: 10-a", "HOGEHOGE=100-string", "FOOFOO=4-3"),
                                  LOG_MESSAGE("hoge: %i-%c", 10, 'a'),
                                  LOG_ITEM("HOGEHOGE=%zu-%s", (size_t) 100, "string"),
                                  LOG_ITEM("FOOFOO=%hu-%llu", (unsigned short) 4, (long long unsigned) 3));
}

static void test_log_struct(void) {
        log_struct(LOG_INFO,
                   "MESSAGE=Waldo PID="PID_FMT" (no errno)", getpid_cached(),
                   "SERVICE=piepapo");

        /* The same as above, just using LOG_MESSAGE() and LOG_ITEM(), which is generally recommended */
        log_struct(LOG_INFO,
                   LOG_MESSAGE("Waldo PID="PID_FMT" (no errno)", getpid_cached()),
                   LOG_ITEM("SERVICE=piepapo"));

        log_struct_errno(LOG_INFO, EILSEQ,
                         LOG_MESSAGE("Waldo PID="PID_FMT": %m (normal)", getpid_cached()),
                         LOG_ITEM("SERVICE=piepapo"));

        log_struct_errno(LOG_INFO, SYNTHETIC_ERRNO(EILSEQ),
                         LOG_MESSAGE("Waldo PID="PID_FMT": %m (synthetic)", getpid_cached()),
                         LOG_ITEM("SERVICE=piepapo"));

        log_struct(LOG_INFO,
                   LOG_MESSAGE("Foobar PID="PID_FMT, getpid_cached()),
                   LOG_ITEM("FORMAT_STR_TEST=1=%i A=%c 2=%hi 3=%li 4=%lli 1=%p foo=%s 2.5=%g 3.5=%g 4.5=%Lg",
                            (int) 1, 'A', (short) 2, (long) 3, (long long) 4, (void*) 1, "foo", (float) 2.5f, (double) 3.5, (long double) 4.5),
                   LOG_ITEM("SUFFIX=GOT IT"));
}

static void test_long_lines(void) {
        log_object_internal(LOG_NOTICE,
                            EUCLEAN,
                            X1000("abcd_") ".txt",
                            1000000,
                            X1000("fff") "unc",
                            "OBJECT=",
                            X1000("obj_") "ect",
                            "EXTRA=",
                            X1000("ext_") "tra",
                            "asdfasdf %s asdfasdfa", "foobar");
}

static void test_log_syntax(void) {
        ASSERT_ERROR(log_syntax("unit", LOG_ERR, "filename", 10, EINVAL, "EINVAL: %s: %m", "hogehoge"), EINVAL);
        ASSERT_ERROR(log_syntax("unit", LOG_ERR, "filename", 10, -ENOENT, "ENOENT: %s: %m", "hogehoge"), ENOENT);
        ASSERT_ERROR(log_syntax("unit", LOG_ERR, "filename", 10, SYNTHETIC_ERRNO(ENOTTY), "ENOTTY: %s: %m", "hogehoge"), ENOTTY);
}

static void test_log_context(void) {
        {
                char **strv = STRV_MAKE("FIRST=abc", "SECOND=qrs");

                LOG_CONTEXT_PUSH("THIRD=pfs");
                LOG_CONTEXT_PUSH("FOURTH=def");
                LOG_CONTEXT_PUSH_STRV(strv);
                LOG_CONTEXT_PUSH_STRV(strv);

                /* Test that the log context was set up correctly. The strv we pushed twice should only
                 * result in one log context which is reused. */
                ASSERT_EQ(log_context_num_contexts(), 3U);
                ASSERT_EQ(log_context_num_fields(), 4U);

                /* Test that everything still works with modifications to the log context. */
                test_log_struct();
                test_long_lines();
                test_log_syntax();

                {
                        LOG_CONTEXT_PUSH("FIFTH=123");
                        LOG_CONTEXT_PUSH_STRV(strv);

                        /* Check that our nested fields got added correctly. */
                        ASSERT_EQ(log_context_num_contexts(), 4U);
                        ASSERT_EQ(log_context_num_fields(), 5U);

                        /* Test that everything still works in a nested block. */
                        test_log_struct();
                        test_long_lines();
                        test_log_syntax();
                }

                /* Check that only the fields from the nested block got removed. */
                ASSERT_EQ(log_context_num_contexts(), 3U);
                ASSERT_EQ(log_context_num_fields(), 4U);
        }

        ASSERT_EQ(log_context_num_contexts(), 0U);
        ASSERT_EQ(log_context_num_fields(), 0U);

        {
                _cleanup_(log_context_unrefp) LogContext *ctx = NULL;

                char **strv = STRV_MAKE("SIXTH=ijn", "SEVENTH=PRP");
                ASSERT_NOT_NULL(ctx = log_context_new_strv(strv, /* owned= */ false));

                ASSERT_EQ(log_context_num_contexts(), 1U);
                ASSERT_EQ(log_context_num_fields(), 2U);

                /* Test that everything still works with a manually configured log context. */
                test_log_struct();
                test_long_lines();
                test_log_syntax();
        }

        {
                char **strv = NULL;

                ASSERT_NOT_NULL(strv = strv_new("ABC", "DEF"));
                LOG_CONTEXT_CONSUME_STRV(strv);

                ASSERT_EQ(log_context_num_contexts(), 1U);
                ASSERT_EQ(log_context_num_fields(), 2U);
        }

        {
                /* Test that everything still works with a mixed strv and iov. */
                struct iovec iov[] = {
                        IOVEC_MAKE_STRING("ABC=def"),
                        IOVEC_MAKE_STRING("GHI=jkl"),
                };
                _cleanup_free_ struct iovec_wrapper *iovw = NULL;
                ASSERT_NOT_NULL(iovw = iovw_new());
                ASSERT_OK(iovw_consume(iovw, strdup("MNO=pqr"), STRLEN("MNO=pqr") + 1));

                LOG_CONTEXT_PUSH_IOV(iov, ELEMENTSOF(iov));
                LOG_CONTEXT_PUSH_IOV(iov, ELEMENTSOF(iov));
                LOG_CONTEXT_CONSUME_IOV(iovw->iovec, iovw->count);
                LOG_CONTEXT_PUSH("STU=vwx");

                ASSERT_EQ(log_context_num_contexts(), 3U);
                ASSERT_EQ(log_context_num_fields(), 4U);

                test_log_struct();
                test_long_lines();
                test_log_syntax();
        }

        {
                LOG_CONTEXT_PUSH_KEY_VALUE("ABC=", "QED");
                LOG_CONTEXT_PUSH_KEY_VALUE("ABC=", "QED");
                ASSERT_EQ(log_context_num_contexts(), 1U);
                ASSERT_EQ(log_context_num_fields(), 1U);

                test_log_struct();
                test_long_lines();
                test_log_syntax();
        }

        ASSERT_EQ(log_context_num_contexts(), 0U);
        ASSERT_EQ(log_context_num_fields(), 0U);
}

static void test_log_prefix(void) {
        {
                LOG_SET_PREFIX("ABC");

                test_log_struct();
                test_long_lines();
                test_log_syntax();

                {
                        LOG_SET_PREFIX("QED");

                        test_log_struct();
                        test_long_lines();
                        test_log_syntax();
                }

                test_log_struct();
                test_long_lines();
                test_log_syntax();
        }

        test_log_struct();
        test_long_lines();
        test_log_syntax();
}

TEST(log_target) {
        for (int target = 0; target < _LOG_TARGET_MAX; target++) {
                log_set_target(target);
                log_open();

                test_log_struct();
                test_long_lines();
                test_log_syntax();
                test_log_context();
                test_log_prefix();
        }
}

DEFINE_TEST_MAIN(LOG_DEBUG);
