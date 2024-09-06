/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stddef.h>
#include <unistd.h>

#include "format-util.h"
#include "io-util.h"
#include "iovec-util.h"
#include "iovec-wrapper.h"
#include "log.h"
#include "process-util.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"

#define X10(x) x x x x x x x x x x
#define X100(x) X10(X10(x))
#define X1000(x) X100(X10(x))

static int fail_with_EINVAL(void) {
        assert_return(false, -EINVAL);
        return 0;
}

static void test_assert_return_is_critical(void) {
        SAVE_ASSERT_RETURN_IS_CRITICAL;

        log_set_assert_return_is_critical(false);
        assert_se(fail_with_EINVAL() == -EINVAL);

        log_set_assert_return_is_critical(true);
        ASSERT_RETURN_IS_CRITICAL(false, assert_se(fail_with_EINVAL() == -EINVAL));
        assert_se(log_get_assert_return_is_critical() == true);
        ASSERT_RETURN_EXPECTED(assert_se(fail_with_EINVAL() == -EINVAL));
        assert_se(log_get_assert_return_is_critical() == true);
        ASSERT_RETURN_EXPECTED_SE(fail_with_EINVAL() == -EINVAL);
        assert_se(log_get_assert_return_is_critical() == true);
}

static void test_file(void) {
        log_info("__FILE__: %s", __FILE__);
        log_info("RELATIVE_SOURCE_PATH: %s", RELATIVE_SOURCE_PATH);
        log_info("PROJECT_FILE: %s", PROJECT_FILE);

        assert_se(startswith(__FILE__, RELATIVE_SOURCE_PATH "/"));
}

static void test_log_struct(void) {
        log_struct(LOG_INFO,
                   "MESSAGE=Waldo PID="PID_FMT" (no errno)", getpid_cached(),
                   "SERVICE=piepapo");

        /* The same as above, just using LOG_MESSAGE(), which is generally recommended */
        log_struct(LOG_INFO,
                   LOG_MESSAGE("Waldo PID="PID_FMT" (no errno)", getpid_cached()),
                   "SERVICE=piepapo");

        log_struct_errno(LOG_INFO, EILSEQ,
                         LOG_MESSAGE("Waldo PID="PID_FMT": %m (normal)", getpid_cached()),
                         "SERVICE=piepapo");

        log_struct_errno(LOG_INFO, SYNTHETIC_ERRNO(EILSEQ),
                         LOG_MESSAGE("Waldo PID="PID_FMT": %m (synthetic)", getpid_cached()),
                         "SERVICE=piepapo");

        log_struct(LOG_INFO,
                   LOG_MESSAGE("Foobar PID="PID_FMT, getpid_cached()),
                   "FORMAT_STR_TEST=1=%i A=%c 2=%hi 3=%li 4=%lli 1=%p foo=%s 2.5=%g 3.5=%g 4.5=%Lg",
                   (int) 1, 'A', (short) 2, (long int) 3, (long long int) 4, (void*) 1, "foo", (float) 2.5f, (double) 3.5, (long double) 4.5,
                   "SUFFIX=GOT IT");
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
        assert_se(log_syntax("unit", LOG_ERR, "filename", 10, EINVAL, "EINVAL: %s: %m", "hogehoge") == -EINVAL);
        assert_se(log_syntax("unit", LOG_ERR, "filename", 10, -ENOENT, "ENOENT: %s: %m", "hogehoge") == -ENOENT);
        assert_se(log_syntax("unit", LOG_ERR, "filename", 10, SYNTHETIC_ERRNO(ENOTTY), "ENOTTY: %s: %m", "hogehoge") == -ENOTTY);
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
                assert_se(log_context_num_contexts() == 3);
                assert_se(log_context_num_fields() == 4);

                /* Test that everything still works with modifications to the log context. */
                test_log_struct();
                test_long_lines();
                test_log_syntax();

                {
                        LOG_CONTEXT_PUSH("FIFTH=123");
                        LOG_CONTEXT_PUSH_STRV(strv);

                        /* Check that our nested fields got added correctly. */
                        assert_se(log_context_num_contexts() == 4);
                        assert_se(log_context_num_fields() == 5);

                        /* Test that everything still works in a nested block. */
                        test_log_struct();
                        test_long_lines();
                        test_log_syntax();
                }

                /* Check that only the fields from the nested block got removed. */
                assert_se(log_context_num_contexts() == 3);
                assert_se(log_context_num_fields() == 4);
        }

        assert_se(log_context_num_contexts() == 0);
        assert_se(log_context_num_fields() == 0);

        {
                _cleanup_(log_context_unrefp) LogContext *ctx = NULL;

                char **strv = STRV_MAKE("SIXTH=ijn", "SEVENTH=PRP");
                assert_se(ctx = log_context_new_strv(strv, /*owned=*/ false));

                assert_se(log_context_num_contexts() == 1);
                assert_se(log_context_num_fields() == 2);

                /* Test that everything still works with a manually configured log context. */
                test_log_struct();
                test_long_lines();
                test_log_syntax();
        }

        {
                char **strv = NULL;

                assert_se(strv = strv_new("ABC", "DEF"));
                LOG_CONTEXT_CONSUME_STRV(strv);

                assert_se(log_context_num_contexts() == 1);
                assert_se(log_context_num_fields() == 2);
        }

        {
                /* Test that everything still works with a mixed strv and iov. */
                struct iovec iov[] = {
                        IOVEC_MAKE_STRING("ABC=def"),
                        IOVEC_MAKE_STRING("GHI=jkl"),
                };
                _cleanup_free_ struct iovec_wrapper *iovw = iovw_new();
                assert_se(iovw);
                assert_se(iovw_consume(iovw, strdup("MNO=pqr"), STRLEN("MNO=pqr") + 1) == 0);

                LOG_CONTEXT_PUSH_IOV(iov, ELEMENTSOF(iov));
                LOG_CONTEXT_PUSH_IOV(iov, ELEMENTSOF(iov));
                LOG_CONTEXT_CONSUME_IOV(iovw->iovec, iovw->count);
                LOG_CONTEXT_PUSH("STU=vwx");

                assert_se(log_context_num_contexts() == 3);
                assert_se(log_context_num_fields() == 4);

                test_log_struct();
                test_long_lines();
                test_log_syntax();
        }

        {
                LOG_CONTEXT_PUSH_KEY_VALUE("ABC=", "QED");
                LOG_CONTEXT_PUSH_KEY_VALUE("ABC=", "QED");
                assert_se(log_context_num_contexts() == 1);
                assert_se(log_context_num_fields() == 1);

                test_log_struct();
                test_long_lines();
                test_log_syntax();
        }

        assert_se(log_context_num_contexts() == 0);
        assert_se(log_context_num_fields() == 0);
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

int main(int argc, char* argv[]) {
        test_setup_logging(LOG_DEBUG);

        ASSERT_TRUE(IS_SYNTHETIC_ERRNO(SYNTHETIC_ERRNO(EINVAL)));
        ASSERT_TRUE(IS_SYNTHETIC_ERRNO(SYNTHETIC_ERRNO(-EINVAL)));
        assert_cc(!IS_SYNTHETIC_ERRNO(EINVAL));
        assert_cc(!IS_SYNTHETIC_ERRNO(-EINVAL));
        ASSERT_TRUE(IS_SYNTHETIC_ERRNO(SYNTHETIC_ERRNO(0)));
        assert_cc(!IS_SYNTHETIC_ERRNO(0));
        ASSERT_EQ(ERRNO_VALUE(EINVAL), EINVAL);
        ASSERT_EQ(ERRNO_VALUE(SYNTHETIC_ERRNO(-EINVAL)), EINVAL);

        test_assert_return_is_critical();
        test_file();

        assert_se(log_info_errno(SYNTHETIC_ERRNO(EUCLEAN), "foo") == -EUCLEAN);

        for (int target = 0; target < _LOG_TARGET_MAX; target++) {
                log_set_target(target);
                log_open();

                test_log_struct();
                test_long_lines();
                test_log_syntax();
                test_log_context();
                test_log_prefix();
        }

        return 0;
}
