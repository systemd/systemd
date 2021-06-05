/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "strv.h"
#include "sysctl-util.h"
#include "tests.h"

static const char* cases[] = {
        "a.b.c", "a/b/c",
        "a/b/c", "a/b/c",
        "a/b.c/d", "a/b.c/d",
        "a.b/c.d", "a/b.c/d",

        "net.ipv4.conf.enp3s0/200.forwarding", "net/ipv4/conf/enp3s0.200/forwarding",
        "net/ipv4/conf/enp3s0.200/forwarding", "net/ipv4/conf/enp3s0.200/forwarding",

        "a...b...c", "a/b/c",
        "a///b///c", "a/b/c",
        ".a...b...c", "a/b/c",
        "/a///b///c", "a/b/c",
        NULL,
};

static void test_sysctl_normalize(void) {
        log_info("/* %s */", __func__);

        const char **s, **expected;
        STRV_FOREACH_PAIR(s, expected, cases) {
                _cleanup_free_ char *t;

                assert_se(t = strdup(*s));
                assert_se(sysctl_normalize(t) == t);

                log_info("\"%s\" → \"%s\", expected \"%s\"", *s, t, *expected);
                assert_se(streq(t, *expected));
        }
}

int main(int argc, char *argv[]) {
        test_setup_logging(LOG_INFO);

        test_sysctl_normalize();

        return 0;
}
