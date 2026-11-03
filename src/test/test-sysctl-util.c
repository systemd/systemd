/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/socket.h>
#include <sys/utsname.h>

#include "sd-id128.h"

#include "errno-util.h"
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

                ASSERT_NOT_NULL(t = strdup(*s));
                ASSERT_PTR_EQ(sysctl_normalize(t), t);

                log_info("\"%s\" → \"%s\", expected \"%s\"", *s, t, *expected);
                ASSERT_STREQ(t, *expected);
        }
}

TEST(sysctl_read) {
        _cleanup_free_ char *s = NULL;
        struct utsname u;
        sd_id128_t a, b;
        int r;

        ASSERT_OK(sysctl_read("kernel/random/boot_id", &s));
        ASSERT_OK(sd_id128_from_string(s, &a));
        ASSERT_OK(sd_id128_get_boot(&b));
        ASSERT_EQ_ID128(a, b);
        s = mfree(s);

        ASSERT_OK_POSITIVE(sysctl_read_ip_property(AF_INET, "lo", "forwarding", &s));
        ASSERT_TRUE(STR_IN_SET(s, "0", "1"));

        r = sysctl_write_ip_property(AF_INET, "lo", "forwarding", s, /* shadow= */ NULL);
        ASSERT_TRUE(r >= 0 || ERRNO_IS_NEG_FS_WRITE_REFUSED(r));
        s = mfree(s);

        ASSERT_OK_POSITIVE(sysctl_read_ip_property(AF_INET, /* ifname= */ NULL, "ip_forward", &s));
        ASSERT_TRUE(STR_IN_SET(s, "0", "1"));

        r = sysctl_write_ip_property(AF_INET, /* ifname= */ NULL, "ip_forward", s, /* shadow= */ NULL);
        ASSERT_TRUE(r >= 0 || ERRNO_IS_NEG_FS_WRITE_REFUSED(r));
        s = mfree(s);

        ASSERT_OK(sysctl_read("kernel/hostname", &s));
        ASSERT_OK_ERRNO(uname(&u));
        ASSERT_STREQ(s, u.nodename);

        r = sysctl_write("kernel/hostname", s);
        ASSERT_TRUE(r >= 0 || ERRNO_IS_NEG_FS_WRITE_REFUSED(r));
}

TEST(sysctl_read_int) {
        unsigned u;
        uint32_t u32;
        uint64_t u64;
        unsigned long lu;
        int i;

        ASSERT_OK(sysctl_read_int("kernel/pid_max", &i));
        ASSERT_GT(i, 0);
        ASSERT_OK(sysctl_read_unsigned("kernel/pid_max", &u));
        ASSERT_EQ(u, (unsigned) i);
        ASSERT_OK(sysctl_read_uint32("kernel/pid_max", &u32));
        ASSERT_EQ(u32, (uint32_t) i);
        ASSERT_OK(sysctl_read_uint64("kernel/pid_max", &u64));
        ASSERT_EQ(u64, (uint64_t) i);
        ASSERT_OK(sysctl_read_lu("kernel/pid_max", &lu));
        ASSERT_EQ(lu, (unsigned long) i);

        ASSERT_ERROR(sysctl_read_int("kernel/random/boot_id", &i), EINVAL);
        ASSERT_ERROR(sysctl_read_unsigned("kernel/random/boot_id", &u), EINVAL);
        ASSERT_ERROR(sysctl_read_uint64("kernel/random/boot_id", &u64), EINVAL);
        ASSERT_ERROR(sysctl_read_lu("kernel/random/boot_id", &lu), EINVAL);
        ASSERT_ERROR(sysctl_read_int("kernel/this-does-not-exist", &i), ENOENT);
        ASSERT_ERROR(sysctl_read_unsigned("kernel/this-does-not-exist", &u), ENOENT);
        ASSERT_ERROR(sysctl_read_uint64("kernel/this-does-not-exist", &u64), ENOENT);
        ASSERT_ERROR(sysctl_read_lu("kernel/this-does-not-exist", &lu), ENOENT);
}

DEFINE_TEST_MAIN(LOG_INFO);
