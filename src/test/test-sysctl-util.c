/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-id128.h"

#include "errno-util.h"
#include "hostname-util.h"
#include "strv.h"
#include "sysctl-util.h"
#include "tests.h"

static const char* const cases[] = {
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
        STRV_FOREACH_PAIR(s, expected, (const char**) cases) {
                _cleanup_free_ char *t;

                assert_se(t = strdup(*s));
                assert_se(sysctl_normalize(t) == t);

                log_info("\"%s\" → \"%s\", expected \"%s\"", *s, t, *expected);
                assert_se(streq(t, *expected));
        }
}

static void test_sysctl_read(void) {
        _cleanup_free_ char *s = NULL, *h = NULL;
        sd_id128_t a, b;
        int r;

        assert_se(sysctl_read("kernel/random/boot_id", &s) >= 0);
        assert_se(sd_id128_from_string(s, &a) >= 0);
        assert_se(sd_id128_get_boot(&b) >= 0);
        assert_se(sd_id128_equal(a, b));
        s = mfree(s);

        assert_se(sysctl_read_ip_property(AF_INET, "lo", "forwarding", &s));
        assert_se(STR_IN_SET(s, "0", "1"));

        r = sysctl_write_ip_property(AF_INET, "lo", "forwarding", s);
        assert_se(r >= 0 || ERRNO_IS_PRIVILEGE(r) || r == -EROFS);
        s = mfree(s);

        assert_se(sysctl_read_ip_property(AF_INET, NULL, "ip_forward", &s));
        assert_se(STR_IN_SET(s, "0", "1"));

        r = sysctl_write_ip_property(AF_INET, NULL, "ip_forward", s);
        assert_se(r >= 0 || ERRNO_IS_PRIVILEGE(r) || r == -EROFS);
        s = mfree(s);

        assert_se(sysctl_read("kernel/hostname", &s) >= 0);
        assert_se(gethostname_full(GET_HOSTNAME_ALLOW_NONE|GET_HOSTNAME_ALLOW_LOCALHOST, &h) >= 0);
        assert_se(streq(s, h));

        r = sysctl_write("kernel/hostname", s);
        assert_se(r >= 0 || ERRNO_IS_PRIVILEGE(r) || r == -EROFS);
}

int main(int argc, char *argv[]) {
        test_setup_logging(LOG_INFO);

        test_sysctl_normalize();
        test_sysctl_read();

        return 0;
}
