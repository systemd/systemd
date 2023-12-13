/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/resource.h>
#if HAVE_VALGRIND_VALGRIND_H
#include <valgrind/valgrind.h>
#endif

#include "alloc-util.h"
#include "capability-util.h"
#include "macro.h"
#include "missing_resource.h"
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

        assert_se(rlimit_parse(resource, string, &rl) == ret);
        if (ret < 0)
                return;

        assert_se(rl.rlim_cur == soft);
        assert_se(rl.rlim_max == hard);

        assert_se(rlimit_format(&rl, &f) >= 0);
        assert_se(streq(formatted, f));

        assert_se(rlimit_parse(resource, formatted, &rl2) >= 0);
        assert_se(memcmp(&rl, &rl2, sizeof(struct rlimit)) == 0);
}

TEST(rlimit_parse_format) {
        test_rlimit_parse_format_one(RLIMIT_NOFILE, "4:5", 4, 5, 0, "4:5");
        test_rlimit_parse_format_one(RLIMIT_NOFILE, "6", 6, 6, 0, "6");
        test_rlimit_parse_format_one(RLIMIT_NOFILE, "infinity", RLIM_INFINITY, RLIM_INFINITY, 0, "infinity");
        test_rlimit_parse_format_one(RLIMIT_NOFILE, "infinity:infinity", RLIM_INFINITY, RLIM_INFINITY, 0, "infinity");
        test_rlimit_parse_format_one(RLIMIT_NOFILE, "8:infinity", 8, RLIM_INFINITY, 0, "8:infinity");
        test_rlimit_parse_format_one(RLIMIT_CPU, "25min:13h", (25*USEC_PER_MINUTE) / USEC_PER_SEC, (13*USEC_PER_HOUR) / USEC_PER_SEC, 0, "1500:46800");
        test_rlimit_parse_format_one(RLIMIT_NOFILE, "", 0, 0, -EINVAL, NULL);
        test_rlimit_parse_format_one(RLIMIT_NOFILE, "5:4", 0, 0, -EILSEQ, NULL);
        test_rlimit_parse_format_one(RLIMIT_NOFILE, "5:4:3", 0, 0, -EINVAL, NULL);
        test_rlimit_parse_format_one(RLIMIT_NICE, "20", 20, 20, 0, "20");
        test_rlimit_parse_format_one(RLIMIT_NICE, "40", 40, 40, 0, "40");
        test_rlimit_parse_format_one(RLIMIT_NICE, "41", 41, 41, -ERANGE, "41");
        test_rlimit_parse_format_one(RLIMIT_NICE, "0", 0, 0, 0, "0");
        test_rlimit_parse_format_one(RLIMIT_NICE, "-7", 27, 27, 0, "27");
        test_rlimit_parse_format_one(RLIMIT_NICE, "-20", 40, 40, 0, "40");
        test_rlimit_parse_format_one(RLIMIT_NICE, "-21", 41, 41, -ERANGE, "41");
        test_rlimit_parse_format_one(RLIMIT_NICE, "-0", 20, 20, 0, "20");
        test_rlimit_parse_format_one(RLIMIT_NICE, "+7", 13, 13, 0, "13");
        test_rlimit_parse_format_one(RLIMIT_NICE, "+19", 1, 1, 0, "1");
        test_rlimit_parse_format_one(RLIMIT_NICE, "+20", 0, 0, -ERANGE, "0");
        test_rlimit_parse_format_one(RLIMIT_NICE, "+0", 20, 20, 0, "20");
}

TEST(rlimit_from_string) {
        assert_se(rlimit_from_string("NOFILE") == RLIMIT_NOFILE);
        assert_se(rlimit_from_string("LimitNOFILE") == -EINVAL);
        assert_se(rlimit_from_string("RLIMIT_NOFILE") == -EINVAL);
        assert_se(rlimit_from_string("xxxNOFILE") == -EINVAL);
        assert_se(rlimit_from_string("DefaultLimitNOFILE") == -EINVAL);
}

TEST(rlimit_from_string_harder) {
        assert_se(rlimit_from_string_harder("NOFILE") == RLIMIT_NOFILE);
        assert_se(rlimit_from_string_harder("LimitNOFILE") == RLIMIT_NOFILE);
        assert_se(rlimit_from_string_harder("RLIMIT_NOFILE") == RLIMIT_NOFILE);
        assert_se(rlimit_from_string_harder("xxxNOFILE") == -EINVAL);
        assert_se(rlimit_from_string_harder("DefaultLimitNOFILE") == -EINVAL);
}

TEST(rlimit_to_string_all) {
        for (int i = 0; i < _RLIMIT_MAX; i++) {
                _cleanup_free_ char *prefixed = NULL;
                const char *p;

                assert_se(p = rlimit_to_string(i));
                log_info("%i = %s", i, p);

                assert_se(rlimit_from_string(p) == i);
                assert_se(rlimit_from_string_harder(p) == i);

                assert_se(prefixed = strjoin("Limit", p));

                assert_se(rlimit_from_string(prefixed) < 0);
                assert_se(rlimit_from_string_harder(prefixed) == i);

                prefixed = mfree(prefixed);
                assert_se(prefixed = strjoin("RLIMIT_", p));

                assert_se(rlimit_from_string(prefixed) < 0);
                assert_se(rlimit_from_string_harder(prefixed) == i);
        }
}

TEST(setrlimit) {
        struct rlimit old, new, high;
        struct rlimit err = {
                .rlim_cur = 10,
                .rlim_max = 5,
        };

        assert_se(drop_capability(CAP_SYS_RESOURCE) == 0);

        assert_se(getrlimit(RLIMIT_NOFILE, &old) == 0);
        new.rlim_cur = MIN(5U, old.rlim_max);
        new.rlim_max = old.rlim_max;
        assert_se(setrlimit(RLIMIT_NOFILE, &new) >= 0);

        assert_se(streq_ptr(rlimit_to_string(RLIMIT_NOFILE), "NOFILE"));
        assert_se(rlimit_to_string(-1) == NULL);

        assert_se(getrlimit(RLIMIT_NOFILE, &old) == 0);
        assert_se(setrlimit_closest(RLIMIT_NOFILE, &old) == 0);
        assert_se(getrlimit(RLIMIT_NOFILE, &new) == 0);
        assert_se(old.rlim_cur == new.rlim_cur);
        assert_se(old.rlim_max == new.rlim_max);

        assert_se(getrlimit(RLIMIT_NOFILE, &old) == 0);
        high = RLIMIT_MAKE_CONST(old.rlim_max == RLIM_INFINITY ? old.rlim_max : old.rlim_max + 1);
        assert_se(setrlimit_closest(RLIMIT_NOFILE, &high) == 0);
        assert_se(getrlimit(RLIMIT_NOFILE, &new) == 0);
        assert_se(new.rlim_max == old.rlim_max);
        assert_se(new.rlim_cur == new.rlim_max);

        assert_se(getrlimit(RLIMIT_NOFILE, &old) == 0);
        assert_se(setrlimit_closest(RLIMIT_NOFILE, &err) == -EINVAL);
        assert_se(getrlimit(RLIMIT_NOFILE, &new) == 0);
        assert_se(old.rlim_cur == new.rlim_cur);
        assert_se(old.rlim_max == new.rlim_max);
}

TEST(pid_getrlimit) {
        int r;

        /* We fork off a child and read the parent's resource limit from there (i.e. our own), and compare
         * with what getrlimit() gives us */

        for (int resource = 0; resource < _RLIMIT_MAX; resource++) {
                struct rlimit direct;

                assert_se(getrlimit(resource, &direct) >= 0);

                /* We fork off a child so that getrlimit() doesn't work anymore */
                r = safe_fork("(getrlimit)", FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGKILL|FORK_LOG|FORK_WAIT, /* ret_pid= */ NULL);
                assert_se(r >= 0);

                if (r == 0) {
                        struct rlimit indirect;
                        /* child */

                        /* Drop privs, so that prlimit() doesn't work anymore */
                        (void) setresgid(GID_NOBODY, GID_NOBODY, GID_NOBODY);
                        (void) setresuid(UID_NOBODY, UID_NOBODY, UID_NOBODY);

                        assert_se(pid_getrlimit(getppid(), resource, &indirect) >= 0);

#ifdef HAVE_VALGRIND_VALGRIND_H
                        /* Valgrind fakes some changes in RLIMIT_NOFILE getrlimit() returns, work around that */
                        if (RUNNING_ON_VALGRIND && resource == RLIMIT_NOFILE) {
                                log_info("Skipping pid_getrlimit() check for RLIMIT_NOFILE, running in valgrind");
                                _exit(EXIT_SUCCESS);
                        }
#endif

                        assert_se(direct.rlim_cur == indirect.rlim_cur);
                        assert_se(direct.rlim_max == indirect.rlim_max);

                        _exit(EXIT_SUCCESS);
                }
        }
}

DEFINE_TEST_MAIN(LOG_INFO);
