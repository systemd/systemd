/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/resource.h>
#include <unistd.h>
#if HAVE_VALGRIND_VALGRIND_H
#include <valgrind/valgrind.h>
#endif

#include "alloc-util.h"
#include "capability-util.h"
#include "process-util.h"
#include "rlimit-util.h"
#include "string-util.h"
#include "tests.h"
#include "time-util.h"
#include "user-util.h"

static void test_rlimit_parse_format_one(int resource, const char *string, rlim_t soft, rlim_t hard, int ret, const char *formatted) {
        _cleanup_free_ char *f = NULL;
        struct rlimit rl = {
                .rlim_cur = 4711,
                .rlim_max = 4712,
        }, rl2 = {
                .rlim_cur = 4713,
                .rlim_max = 4714
        };

        ASSERT_EQ(rlimit_parse(resource, string, &rl), ret);
        if (ret < 0)
                return;

        ASSERT_EQ(rl.rlim_cur, soft);
        ASSERT_EQ(rl.rlim_max, hard);

        ASSERT_OK(rlimit_format(&rl, &f));
        ASSERT_STREQ(formatted, f);

        ASSERT_OK(rlimit_parse(resource, formatted, &rl2));
        ASSERT_EQ(memcmp(&rl, &rl2, sizeof(struct rlimit)), 0);
}

TEST(rlimit_parse_format) {
        test_rlimit_parse_format_one(RLIMIT_NOFILE, "4:5", 4, 5, /* ret= */ 0, "4:5");
        test_rlimit_parse_format_one(RLIMIT_NOFILE, "6", 6, 6, /* ret= */ 0, "6");
        test_rlimit_parse_format_one(RLIMIT_NOFILE, "infinity", RLIM_INFINITY, RLIM_INFINITY, /* ret= */ 0, "infinity");
        test_rlimit_parse_format_one(RLIMIT_NOFILE, "infinity:infinity", RLIM_INFINITY, RLIM_INFINITY, /* ret= */ 0, "infinity");
        test_rlimit_parse_format_one(RLIMIT_NOFILE, "8:infinity", 8, RLIM_INFINITY, /* ret= */ 0, "8:infinity");
        test_rlimit_parse_format_one(RLIMIT_CPU, "25min:13h", (25*USEC_PER_MINUTE) / USEC_PER_SEC, (13*USEC_PER_HOUR) / USEC_PER_SEC, /* ret= */ 0, "1500:46800");
        test_rlimit_parse_format_one(RLIMIT_NOFILE, "", /* soft= */ 0, /* hard= */ 0, -EINVAL, /* formatted= */ NULL);
        test_rlimit_parse_format_one(RLIMIT_NOFILE, "5:4", /* soft= */ 0, /* hard= */ 0, -EILSEQ, /* formatted= */ NULL);
        test_rlimit_parse_format_one(RLIMIT_NOFILE, "5:4:3", /* soft= */ 0, /* hard= */ 0, -EINVAL, /* formatted= */ NULL);
        test_rlimit_parse_format_one(RLIMIT_NICE, "20", 20, 20, /* ret= */ 0, "20");
        test_rlimit_parse_format_one(RLIMIT_NICE, "40", 40, 40, /* ret= */ 0, "40");
        test_rlimit_parse_format_one(RLIMIT_NICE, "41", 41, 41, -ERANGE, "41");
        test_rlimit_parse_format_one(RLIMIT_NICE, "0", /* soft= */ 0, /* hard= */ 0, /* ret= */ 0, "0");
        test_rlimit_parse_format_one(RLIMIT_NICE, "-7", 27, 27, /* ret= */ 0, "27");
        test_rlimit_parse_format_one(RLIMIT_NICE, "-20", 40, 40, /* ret= */ 0, "40");
        test_rlimit_parse_format_one(RLIMIT_NICE, "-21", 41, 41, -ERANGE, "41");
        test_rlimit_parse_format_one(RLIMIT_NICE, "-0", 20, 20, /* ret= */ 0, "20");
        test_rlimit_parse_format_one(RLIMIT_NICE, "+7", 13, 13, /* ret= */ 0, "13");
        test_rlimit_parse_format_one(RLIMIT_NICE, "+19", 1, 1, /* ret= */ 0, "1");
        test_rlimit_parse_format_one(RLIMIT_NICE, "+20", /* soft= */ 0, /* hard= */ 0, -ERANGE, "0");
        test_rlimit_parse_format_one(RLIMIT_NICE, "+0", 20, 20, /* ret= */ 0, "20");
        test_rlimit_parse_format_one(RLIMIT_NICE, "+0", 20, 20, /* ret= */ 0, "20");
        test_rlimit_parse_format_one(RLIMIT_RTTIME, "25min:13h", 25*USEC_PER_MINUTE, 13*USEC_PER_HOUR, /* ret= */ 0, "1500000000:46800000000");
        test_rlimit_parse_format_one(RLIMIT_RTTIME, "infinity", RLIM_INFINITY, RLIM_INFINITY, /* ret= */ 0, "infinity");
}

TEST(rlimit_from_string) {
        ASSERT_EQ(rlimit_from_string("NOFILE"), RLIMIT_NOFILE);
        ASSERT_ERROR(rlimit_from_string("LimitNOFILE"), EINVAL);
        ASSERT_ERROR(rlimit_from_string("RLIMIT_NOFILE"), EINVAL);
        ASSERT_ERROR(rlimit_from_string("xxxNOFILE"), EINVAL);
        ASSERT_ERROR(rlimit_from_string("DefaultLimitNOFILE"), EINVAL);
}

TEST(rlimit_from_string_harder) {
        ASSERT_EQ(rlimit_from_string_harder("NOFILE"), RLIMIT_NOFILE);
        ASSERT_EQ(rlimit_from_string_harder("LimitNOFILE"), RLIMIT_NOFILE);
        ASSERT_EQ(rlimit_from_string_harder("RLIMIT_NOFILE"), RLIMIT_NOFILE);
        ASSERT_ERROR(rlimit_from_string_harder("xxxNOFILE"), EINVAL);
        ASSERT_ERROR(rlimit_from_string_harder("DefaultLimitNOFILE"), EINVAL);
}

TEST(rlimit_to_string_all) {
        for (int i = 0; i < _RLIMIT_MAX; i++) {
                _cleanup_free_ char *prefixed = NULL;
                const char *p;

                ASSERT_NOT_NULL(p = rlimit_to_string(i));
                log_info("%i = %s", i, p);

                ASSERT_EQ(rlimit_from_string(p), i);
                ASSERT_EQ(rlimit_from_string_harder(p), i);

                ASSERT_NOT_NULL(prefixed = strjoin("Limit", p));

                ASSERT_FAIL(rlimit_from_string(prefixed));
                ASSERT_EQ(rlimit_from_string_harder(prefixed), i);

                prefixed = mfree(prefixed);
                ASSERT_NOT_NULL(prefixed = strjoin("RLIMIT_", p));

                ASSERT_FAIL(rlimit_from_string(prefixed));
                ASSERT_EQ(rlimit_from_string_harder(prefixed), i);
        }
}

TEST(setrlimit) {
        struct rlimit old, new, high;
        struct rlimit err = {
                .rlim_cur = 10,
                .rlim_max = 5,
        };

        ASSERT_OK_ZERO(drop_capability(CAP_SYS_RESOURCE));

        ASSERT_OK_ZERO_ERRNO(getrlimit(RLIMIT_NOFILE, &old));
        new.rlim_cur = MIN(5U, old.rlim_max);
        new.rlim_max = old.rlim_max;
        ASSERT_OK_ERRNO(setrlimit(RLIMIT_NOFILE, &new));

        ASSERT_STREQ(rlimit_to_string(RLIMIT_NOFILE), "NOFILE");
        ASSERT_NULL(rlimit_to_string(-1));

        ASSERT_OK_ZERO_ERRNO(getrlimit(RLIMIT_NOFILE, &old));
        ASSERT_OK_ZERO(setrlimit_closest(RLIMIT_NOFILE, &old));
        ASSERT_OK_ZERO_ERRNO(getrlimit(RLIMIT_NOFILE, &new));
        ASSERT_EQ(old.rlim_cur, new.rlim_cur);
        ASSERT_EQ(old.rlim_max, new.rlim_max);

        ASSERT_OK_ZERO_ERRNO(getrlimit(RLIMIT_NOFILE, &old));
        high = RLIMIT_MAKE_CONST(old.rlim_max == RLIM_INFINITY ? old.rlim_max : old.rlim_max + 1);
        ASSERT_OK_ZERO(setrlimit_closest(RLIMIT_NOFILE, &high));
        ASSERT_OK_ZERO_ERRNO(getrlimit(RLIMIT_NOFILE, &new));
        ASSERT_EQ(new.rlim_max, old.rlim_max);
        ASSERT_EQ(new.rlim_cur, new.rlim_max);

        ASSERT_OK_ZERO_ERRNO(getrlimit(RLIMIT_NOFILE, &old));
        ASSERT_ERROR(setrlimit_closest(RLIMIT_NOFILE, &err), EINVAL);
        ASSERT_OK_ZERO_ERRNO(getrlimit(RLIMIT_NOFILE, &new));
        ASSERT_EQ(old.rlim_cur, new.rlim_cur);
        ASSERT_EQ(old.rlim_max, new.rlim_max);
}

TEST(pid_getrlimit) {
        int r;

        /* We fork off a child and read the parent's resource limit from there (i.e. our own), and compare
         * with what getrlimit() gives us */

        for (int resource = 0; resource < _RLIMIT_MAX; resource++) {
                struct rlimit direct;

                ASSERT_OK_ERRNO(getrlimit(resource, &direct));

                /* We fork off a child so that getrlimit() doesn't work anymore */
                r = pidref_safe_fork(
                                "(getrlimit)",
                                FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGKILL|FORK_LOG|FORK_WAIT,
                                /* ret= */ NULL);
                ASSERT_OK(r);

                if (r == 0) {
                        struct rlimit indirect;
                        /* child */

                        /* Drop privs, so that prlimit() doesn't work anymore */
                        (void) setresgid(GID_NOBODY, GID_NOBODY, GID_NOBODY);
                        (void) setresuid(UID_NOBODY, UID_NOBODY, UID_NOBODY);

                        ASSERT_OK(pid_getrlimit(getppid(), resource, &indirect));

#if HAVE_VALGRIND_VALGRIND_H
                        /* Valgrind fakes some changes in RLIMIT_NOFILE getrlimit() returns, work around that */
                        if (RUNNING_ON_VALGRIND && resource == RLIMIT_NOFILE) {
                                log_info("Skipping pid_getrlimit() check for RLIMIT_NOFILE, running in valgrind");
                                _exit(EXIT_SUCCESS);
                        }
#endif

                        ASSERT_EQ(direct.rlim_cur, indirect.rlim_cur);
                        ASSERT_EQ(direct.rlim_max, indirect.rlim_max);

                        _exit(EXIT_SUCCESS);
                }
        }
}

DEFINE_TEST_MAIN(LOG_INFO);
