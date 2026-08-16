/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "format-util.h"
#include "fd-util.h"
#include "io-util.h"
#include "iovec-util.h"
#include "iovec-wrapper.h"
#include "log.h"
#include "log-context.h"
#include "memfd-util.h"
#include "process-util.h"
#include "sd-messages.h"
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
                        ASSERT_TRUE(iovec_equal(&iovec[i], &IOVEC_MAKE_STRING(v[i])));
                else {
                        ASSERT_TRUE(iovec_equal(&iovec[i], &IOVEC_MAKE_STRING(expected[i - m])));
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
                        ASSERT_TRUE(iovec_equal(&iovec[i], &IOVEC_MAKE_STRING(v[i])));
                else if ((i - m) % 2 == 0) {
                        ASSERT_TRUE(iovec_equal(&iovec[i], &IOVEC_MAKE_STRING(expected[(i - m) / 2])));
                        free(iovec[i].iov_base);
                } else
                        ASSERT_TRUE(iovec_equal(&iovec[i], &IOVEC_MAKE_STRING("\n")));
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

TEST(log_struct_iovec_many_fields) {
        LogTarget old_target = log_get_target();
        struct iovec iovec[1024];

        log_set_target(LOG_TARGET_JOURNAL);
        log_open();
        if (log_on_console()) {
                log_set_target(old_target);
                log_open();
                return (void) log_tests_skipped("journal socket is not available");
        }

        iovec[0] = IOVEC_MAKE_STRING("MESSAGE=many fields");
        for (size_t i = 1; i < ELEMENTSOF(iovec); i++)
                iovec[i] = IOVEC_MAKE_STRING("FIELD=value");

        ASSERT_OK(log_struct_iovec(LOG_INFO, iovec, ELEMENTSOF(iovec)));

        log_set_target(old_target);
        log_open();
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
                struct iovec_wrapper iovw = {};
                ASSERT_OK(iovw_consume(&iovw, strdup("MNO=pqr"), STRLEN("MNO=pqr") + 1));

                LOG_CONTEXT_PUSH_IOV(iov, ELEMENTSOF(iov));
                LOG_CONTEXT_PUSH_IOV(iov, ELEMENTSOF(iov));
                LOG_CONTEXT_CONSUME_IOV(iovw.iovec, iovw.count);
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

typedef struct ObservedLogRecord {
        LogRecordType type;
        int priority;
        char *message;
        size_t message_size;
        char *prefix;
        char *object_field;
        char *object;
        char *extra_field;
        char *extra;
        struct iovec_wrapper fields;
} ObservedLogRecord;

typedef struct LogObserverTestContext {
        ObservedLogRecord records[8];
        size_t n_records;
        unsigned n_callbacks;
        int callback_error;
        bool recurse;
} LogObserverTestContext;

static void observed_log_record_done(ObservedLogRecord *record) {
        assert(record);

        free(record->message);
        free(record->prefix);
        free(record->object_field);
        free(record->object);
        free(record->extra_field);
        free(record->extra);
        iovw_done_free(&record->fields);
}

static void log_observer_test_context_done(LogObserverTestContext *ctx) {
        assert(ctx);

        FOREACH_ARRAY(record, ctx->records, ctx->n_records)
                observed_log_record_done(record);
}

static int log_observer_test_callback(const LogRecord *record, void *userdata) {
        LogObserverTestContext *ctx = userdata;
        int r;

        assert(ctx);

        ctx->n_callbacks++;

        if (ctx->recurse)
                log_notice("This recursive message must not be observed.");

        if (ctx->callback_error < 0)
                return ctx->callback_error;

        if (ctx->n_records >= ELEMENTSOF(ctx->records))
                return -E2BIG;

        ObservedLogRecord *stored = &ctx->records[ctx->n_records];
        *stored = (ObservedLogRecord) {
                .type = record->type,
                .priority = record->priority,
                .message_size = record->message_size,
        };

        if (record->message) {
                stored->message = memdup_suffix0(record->message, record->message_size);
                if (!stored->message)
                        goto oom;
        }

        r = strdup_to(&stored->prefix, record->prefix);
        if (r < 0)
                goto fail;
        r = strdup_to(&stored->object_field, record->object_field);
        if (r < 0)
                goto fail;
        r = strdup_to(&stored->object, record->object);
        if (r < 0)
                goto fail;
        r = strdup_to(&stored->extra_field, record->extra_field);
        if (r < 0)
                goto fail;
        r = strdup_to(&stored->extra, record->extra);
        if (r < 0)
                goto fail;

        FOREACH_ARRAY(field, record->fields, record->n_fields) {
                r = iovw_extend_iov_full(&stored->fields, /* accept_zero= */ true, field);
                if (r < 0)
                        goto fail;
        }

        ctx->n_records++;
        return 0;

oom:
        r = -ENOMEM;
fail:
        observed_log_record_done(stored);
        *stored = (ObservedLogRecord) {};
        return r;
}

static bool observed_log_record_has_field(const ObservedLogRecord *record, const char *field) {
        assert(record);
        assert(field);

        FOREACH_ARRAY(iovec, record->fields.iovec, record->fields.count)
                if (iovec_equal(iovec, &IOVEC_MAKE_STRING(field)))
                        return true;

        return false;
}

TEST(log_observer_records) {
        LogObserverTestContext ctx = {};
        LogTarget old_target = log_get_target();
        int old_max_level = log_set_max_level(LOG_NULL);

        log_set_target(LOG_TARGET_NULL);

        LogObserver *observer = log_observer_new(
                        LOG_NOTICE, /* flags= */ 0, log_observer_test_callback, &ctx);
        ASSERT_NOT_NULL(observer);

        ASSERT_ERROR(log_notice_errno(EUCLEAN, "plain record: %m"), EUCLEAN);
        ASSERT_ERROR(log_object_internal(
                             LOG_WARNING, ENOENT,
                             PROJECT_FILE, __LINE__, __func__,
                             "UNIT=", "object.service",
                             "EXTRA=", "extra",
                             "object record"),
                     ENOENT);
        ASSERT_OK(log_struct(
                          LOG_ERR,
                          LOG_MESSAGE("structured record %i", 42),
                          LOG_MESSAGE_ID(SD_MESSAGE_INVALID_CONFIGURATION_STR),
                          LOG_ITEM("UNIT=%s", "structured.service")));

        const struct iovec iovec[] = {
                IOVEC_MAKE_STRING("MESSAGE=iovec record"),
                IOVEC_MAKE_STRING("USER_UNIT=iovec.service"),
        };
        ASSERT_OK(log_struct_iovec(LOG_WARNING, iovec, ELEMENTSOF(iovec)));
        ASSERT_ERROR(log_syntax(
                             "syntax.service", LOG_WARNING, "/tmp/syntax.service", 23, EINVAL,
                             "syntax record"),
                     EINVAL);

        ASSERT_OK(log_observer_get_error(observer));
        observer = log_observer_free(observer);
        log_set_target(old_target);
        log_set_max_level(old_max_level);

        ASSERT_EQ(ctx.n_callbacks, 5U);
        ASSERT_EQ(ctx.n_records, 5U);

        ASSERT_EQ(ctx.records[0].type, LOG_RECORD_PLAIN);
        ASSERT_EQ(ctx.records[0].priority, LOG_NOTICE);
        ASSERT_TRUE(startswith(ctx.records[0].message, "plain record:"));

        ASSERT_EQ(ctx.records[1].type, LOG_RECORD_PLAIN);
        ASSERT_EQ(ctx.records[1].priority, LOG_WARNING);
        ASSERT_STREQ(ctx.records[1].message, "object record");
        ASSERT_STREQ(ctx.records[1].prefix, "object.service");
        ASSERT_STREQ(ctx.records[1].object_field, "UNIT=");
        ASSERT_STREQ(ctx.records[1].object, "object.service");
        ASSERT_STREQ(ctx.records[1].extra_field, "EXTRA=");
        ASSERT_STREQ(ctx.records[1].extra, "extra");

        ASSERT_EQ(ctx.records[2].type, LOG_RECORD_STRUCTURED);
        ASSERT_EQ(ctx.records[2].priority, LOG_ERR);
        ASSERT_STREQ(ctx.records[2].message, "structured record 42");
        ASSERT_TRUE(observed_log_record_has_field(
                            &ctx.records[2], "MESSAGE_ID=" SD_MESSAGE_INVALID_CONFIGURATION_STR));
        ASSERT_TRUE(observed_log_record_has_field(&ctx.records[2], "UNIT=structured.service"));

        ASSERT_EQ(ctx.records[3].type, LOG_RECORD_STRUCTURED);
        ASSERT_EQ(ctx.records[3].priority, LOG_WARNING);
        ASSERT_STREQ(ctx.records[3].message, "iovec record");
        ASSERT_TRUE(observed_log_record_has_field(&ctx.records[3], "USER_UNIT=iovec.service"));

        ASSERT_EQ(ctx.records[4].type, LOG_RECORD_STRUCTURED);
        ASSERT_EQ(ctx.records[4].priority, LOG_WARNING);
        ASSERT_TRUE(observed_log_record_has_field(&ctx.records[4], "CONFIG_FILE=/tmp/syntax.service"));
        ASSERT_TRUE(observed_log_record_has_field(&ctx.records[4], "CONFIG_LINE=23"));
        ASSERT_TRUE(observed_log_record_has_field(&ctx.records[4], "USER_UNIT=syntax.service"));

        log_observer_test_context_done(&ctx);
}

TEST(log_observer_nested) {
        LogObserverTestContext outer_ctx = {}, inner_ctx = {};
        LogTarget old_target = log_get_target();
        int old_max_level = log_set_max_level(LOG_NULL);

        log_set_target(LOG_TARGET_NULL);

        LogObserver *outer = log_observer_new(
                        LOG_NOTICE, /* flags= */ 0, log_observer_test_callback, &outer_ctx);
        ASSERT_NOT_NULL(outer);

        log_notice("outer before");

        LogObserver *inner = log_observer_new(
                        LOG_NOTICE, /* flags= */ 0, log_observer_test_callback, &inner_ctx);
        ASSERT_NOT_NULL(inner);
        log_notice("inner");
        inner = log_observer_free(inner);

        log_notice("outer after");
        outer = log_observer_free(outer);
        log_notice("outside");

        log_set_target(old_target);
        log_set_max_level(old_max_level);

        ASSERT_EQ(outer_ctx.n_records, 2U);
        ASSERT_STREQ(outer_ctx.records[0].message, "outer before");
        ASSERT_STREQ(outer_ctx.records[1].message, "outer after");
        ASSERT_EQ(inner_ctx.n_records, 1U);
        ASSERT_STREQ(inner_ctx.records[0].message, "inner");

        log_observer_test_context_done(&outer_ctx);
        log_observer_test_context_done(&inner_ctx);
}

TEST(log_observer_filtering_and_error) {
        LogObserverTestContext ctx = {
                .callback_error = -ENOMEM,
                .recurse = true,
        };
        LogTarget old_target = log_get_target();
        int old_max_level = log_set_max_level(LOG_NULL);

        log_set_target(LOG_TARGET_NULL);

        LogObserver *observer = log_observer_new(
                        LOG_WARNING, /* flags= */ 0, log_observer_test_callback, &ctx);
        ASSERT_NOT_NULL(observer);

        ASSERT_TRUE(log_level_enabled(LOG_ERR));
        ASSERT_FALSE(log_level_enabled(LOG_NOTICE));
        ASSERT_ERROR(log_error_errno(EUCLEAN, "captured error"), EUCLEAN);
        log_warning("callback is no longer invoked");
        log_notice("outside the observer's severity ceiling");

        ASSERT_ERROR(log_observer_get_error(observer), ENOMEM);
        observer = log_observer_free(observer);
        log_set_target(old_target);
        log_set_max_level(old_max_level);

        ASSERT_EQ(ctx.n_callbacks, 1U);
        ASSERT_EQ(ctx.n_records, 0U);
}

static int run_log_observer_suppression_test(void) {
        _cleanup_close_ int memfd = memfd_new("log-observer-suppression-test");
        assert_se(memfd >= 0);

        int r = pidref_safe_fork_full(
                        "(log-observer-suppression-test)",
                        (const int[3]) { -EBADF, -EBADF, memfd },
                        /* except_fds= */ NULL,
                        /* n_except_fds= */ 0,
                        FORK_WAIT|FORK_LOG|FORK_REARRANGE_STDIO,
                        /* ret= */ NULL);
        assert_se(r >= 0);

        if (r == 0) {
                LogObserverTestContext ctx = {
                        .callback_error = -ENOMEM,
                };

                log_close();
                log_set_target_and_open(LOG_TARGET_CONSOLE);
                log_set_max_level(LOG_NOTICE);

                log_notice("visible before");

                LogObserver *observer = log_observer_new(
                                LOG_NOTICE, LOG_OBSERVER_SUPPRESS, log_observer_test_callback, &ctx);
                assert_se(observer);
                log_notice("hidden plain");
                log_struct(LOG_WARNING, LOG_MESSAGE("hidden structured"));
                observer = log_observer_free(observer);

                log_notice("visible after");
                _exit(0);
        }

        assert_se(lseek(memfd, 0, SEEK_SET) == 0);
        return TAKE_FD(memfd);
}

TEST(log_observer_suppression) {
        _cleanup_close_ int fd = run_log_observer_suppression_test();
        char buffer[4096];
        ssize_t n;

        ASSERT_OK_POSITIVE(n = loop_read(fd, buffer, sizeof(buffer) - 1, /* do_poll= */ false));
        buffer[n] = 0;

        ASSERT_NOT_NULL(strstr(buffer, "visible before"));
        ASSERT_NOT_NULL(strstr(buffer, "visible after"));
        ASSERT_NULL(strstr(buffer, "hidden plain"));
        ASSERT_NULL(strstr(buffer, "hidden structured"));
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
