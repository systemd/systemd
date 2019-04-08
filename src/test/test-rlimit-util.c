/* SPDX-License-Identifier: LGPL-2.1+ */

#include <sys/resource.h>

#include "alloc-util.h"
#include "capability-util.h"
#include "macro.h"
#include "missing.h"
#include "rlimit-util.h"
#include "string-util.h"
#include "time-util.h"

static void test_rlimit_parse_format(int resource, const char *string, rlim_t soft, rlim_t hard, int ret, const char *formatted) {
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

int main(int argc, char *argv[]) {
        struct rlimit old, new, high;
        struct rlimit err = {
                .rlim_cur = 10,
                .rlim_max = 5,
        };
        int i;

        log_parse_environment();
        log_open();

        assert_se(drop_capability(CAP_SYS_RESOURCE) == 0);

        assert_se(getrlimit(RLIMIT_NOFILE, &old) == 0);
        new.rlim_cur = MIN(5U, old.rlim_max);
        new.rlim_max = old.rlim_max;
        assert_se(setrlimit(RLIMIT_NOFILE, &new) >= 0);

        assert_se(rlimit_from_string("NOFILE") == RLIMIT_NOFILE);
        assert_se(rlimit_from_string("LimitNOFILE") == -1);
        assert_se(rlimit_from_string("RLIMIT_NOFILE") == -1);
        assert_se(rlimit_from_string("xxxNOFILE") == -1);
        assert_se(rlimit_from_string("DefaultLimitNOFILE") == -1);

        assert_se(rlimit_from_string_harder("NOFILE") == RLIMIT_NOFILE);
        assert_se(rlimit_from_string_harder("LimitNOFILE") == RLIMIT_NOFILE);
        assert_se(rlimit_from_string_harder("RLIMIT_NOFILE") == RLIMIT_NOFILE);
        assert_se(rlimit_from_string_harder("xxxNOFILE") == -1);
        assert_se(rlimit_from_string_harder("DefaultLimitNOFILE") == -1);

        for (i = 0; i < _RLIMIT_MAX; i++) {
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

        test_rlimit_parse_format(RLIMIT_NOFILE, "4:5", 4, 5, 0, "4:5");
        test_rlimit_parse_format(RLIMIT_NOFILE, "6", 6, 6, 0, "6");
        test_rlimit_parse_format(RLIMIT_NOFILE, "infinity", RLIM_INFINITY, RLIM_INFINITY, 0, "infinity");
        test_rlimit_parse_format(RLIMIT_NOFILE, "infinity:infinity", RLIM_INFINITY, RLIM_INFINITY, 0, "infinity");
        test_rlimit_parse_format(RLIMIT_NOFILE, "8:infinity", 8, RLIM_INFINITY, 0, "8:infinity");
        test_rlimit_parse_format(RLIMIT_CPU, "25min:13h", (25*USEC_PER_MINUTE) / USEC_PER_SEC, (13*USEC_PER_HOUR) / USEC_PER_SEC, 0, "1500:46800");
        test_rlimit_parse_format(RLIMIT_NOFILE, "", 0, 0, -EINVAL, NULL);
        test_rlimit_parse_format(RLIMIT_NOFILE, "5:4", 0, 0, -EILSEQ, NULL);
        test_rlimit_parse_format(RLIMIT_NOFILE, "5:4:3", 0, 0, -EINVAL, NULL);
        test_rlimit_parse_format(RLIMIT_NICE, "20", 20, 20, 0, "20");
        test_rlimit_parse_format(RLIMIT_NICE, "40", 40, 40, 0, "40");
        test_rlimit_parse_format(RLIMIT_NICE, "41", 41, 41, -ERANGE, "41");
        test_rlimit_parse_format(RLIMIT_NICE, "0", 0, 0, 0, "0");
        test_rlimit_parse_format(RLIMIT_NICE, "-7", 27, 27, 0, "27");
        test_rlimit_parse_format(RLIMIT_NICE, "-20", 40, 40, 0, "40");
        test_rlimit_parse_format(RLIMIT_NICE, "-21", 41, 41, -ERANGE, "41");
        test_rlimit_parse_format(RLIMIT_NICE, "-0", 20, 20, 0, "20");
        test_rlimit_parse_format(RLIMIT_NICE, "+7", 13, 13, 0, "13");
        test_rlimit_parse_format(RLIMIT_NICE, "+19", 1, 1, 0, "1");
        test_rlimit_parse_format(RLIMIT_NICE, "+20", 0, 0, -ERANGE, "0");
        test_rlimit_parse_format(RLIMIT_NICE, "+0", 20, 20, 0, "20");

        return 0;
}
