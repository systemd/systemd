/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/utsname.h>

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

TEST(sysctl_normalize) {
        STRV_FOREACH_PAIR(s, expected, cases) {
                _cleanup_free_ char *t;

                assert_se(t = strdup(*s));
                assert_se(sysctl_normalize(t) == t);

                log_info("\"%s\" → \"%s\", expected \"%s\"", *s, t, *expected);
                assert_se(streq(t, *expected));
        }
}

TEST(sysctl_read) {
        _cleanup_free_ char *s = NULL;
        struct utsname u;
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
        assert_se(uname(&u) >= 0);
        assert_se(streq_ptr(s, u.nodename));

        r = sysctl_write("kernel/hostname", s);
        assert_se(r >= 0 || ERRNO_IS_PRIVILEGE(r) || r == -EROFS);
}

DEFINE_TEST_MAIN(LOG_INFO);
