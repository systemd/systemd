/* SPDX-License-Identifier: LGPL-2.1+ */

#include "alloc-util.h"
#include "tests.h"
#include "socket-netlink.h"
#include "string-util.h"

static void test_socket_address_parse_one(const char *in, int ret, int family, const char *expected) {
        SocketAddress a;
        _cleanup_free_ char *out = NULL;
        int r;

        r = socket_address_parse(&a, in);
        if (r >= 0)
                assert_se(socket_address_print(&a, &out) >= 0);

        log_info("\"%s\" → %s → \"%s\" (expect \"%s\")", in,
                 r >= 0 ? "✓" : "✗", empty_to_dash(out), r >= 0 ? expected ?: in : "-");
        assert_se(r == ret);
        if (r >= 0) {
                assert_se(a.sockaddr.sa.sa_family == family);
                assert_se(streq(out, expected ?: in));
        }
}

static void test_socket_address_parse(void) {
        log_info("/* %s */", __func__);

        test_socket_address_parse_one("junk", -EINVAL, 0, NULL);
        test_socket_address_parse_one("192.168.1.1", -EINVAL, 0, NULL);
        test_socket_address_parse_one(".168.1.1", -EINVAL, 0, NULL);
        test_socket_address_parse_one("989.168.1.1", -EINVAL, 0, NULL);
        test_socket_address_parse_one("192.168.1.1:65536", -ERANGE, 0, NULL);
        test_socket_address_parse_one("192.168.1.1:0", -EINVAL, 0, NULL);
        test_socket_address_parse_one("0", -EINVAL, 0, NULL);
        test_socket_address_parse_one("65536", -ERANGE, 0, NULL);

        const int default_family = socket_ipv6_is_supported() ? AF_INET6 : AF_INET;

        test_socket_address_parse_one("65535", 0, default_family, "[::]:65535");

        /* The checks below will pass even if ipv6 is disabled in
         * kernel. The underlying glibc's inet_pton() is just a string
         * parser and doesn't make any syscalls. */

        test_socket_address_parse_one("[::1]", -EINVAL, 0, NULL);
        test_socket_address_parse_one("[::1]8888", -EINVAL, 0, NULL);
        test_socket_address_parse_one("::1", -EINVAL, 0, NULL);
        test_socket_address_parse_one("[::1]:0", -EINVAL, 0, NULL);
        test_socket_address_parse_one("[::1]:65536", -ERANGE, 0, NULL);
        test_socket_address_parse_one("[a:b:1]:8888", -EINVAL, 0, NULL);

        test_socket_address_parse_one("8888", 0, default_family, "[::]:8888");
        test_socket_address_parse_one("[2001:0db8:0000:85a3:0000:0000:ac1f:8001]:8888", 0, AF_INET6,
                                      "[2001:db8:0:85a3::ac1f:8001]:8888");
        test_socket_address_parse_one("[::1]:8888", 0, AF_INET6, NULL);
        test_socket_address_parse_one("192.168.1.254:8888", 0, AF_INET, NULL);
        test_socket_address_parse_one("/foo/bar", 0, AF_UNIX, NULL);
        test_socket_address_parse_one("/", 0, AF_UNIX, NULL);
        test_socket_address_parse_one("@abstract", 0, AF_UNIX, NULL);

        {
                char aaa[SUN_PATH_LEN + 1] = "@";

                memset(aaa + 1, 'a', SUN_PATH_LEN - 1);
                char_array_0(aaa);

                test_socket_address_parse_one(aaa, -EINVAL, 0, NULL);

                aaa[SUN_PATH_LEN - 1] = '\0';
                test_socket_address_parse_one(aaa, 0, AF_UNIX, NULL);
        }

        test_socket_address_parse_one("vsock:2:1234", 0, AF_VSOCK, NULL);
        test_socket_address_parse_one("vsock::1234", 0, AF_VSOCK, NULL);
        test_socket_address_parse_one("vsock:2:1234x", -EINVAL, 0, NULL);
        test_socket_address_parse_one("vsock:2x:1234", -EINVAL, 0, NULL);
        test_socket_address_parse_one("vsock:2", -EINVAL, 0, NULL);
}

static void test_socket_address_parse_netlink(void) {
        SocketAddress a;

        log_info("/* %s */", __func__);

        assert_se(socket_address_parse_netlink(&a, "junk") < 0);
        assert_se(socket_address_parse_netlink(&a, "") < 0);

        assert_se(socket_address_parse_netlink(&a, "route") >= 0);
        assert_se(a.sockaddr.nl.nl_family == AF_NETLINK);
        assert_se(a.sockaddr.nl.nl_groups == 0);
        assert_se(a.protocol == NETLINK_ROUTE);
        assert_se(socket_address_parse_netlink(&a, "route") >= 0);
        assert_se(socket_address_parse_netlink(&a, "route 10") >= 0);
        assert_se(a.sockaddr.nl.nl_family == AF_NETLINK);
        assert_se(a.sockaddr.nl.nl_groups == 10);
        assert_se(a.protocol == NETLINK_ROUTE);

        /* With spaces and tabs */
        assert_se(socket_address_parse_netlink(&a, " kobject-uevent ") >= 0);
        assert_se(a.sockaddr.nl.nl_family == AF_NETLINK);
        assert_se(a.sockaddr.nl.nl_groups == 0);
        assert_se(a.protocol == NETLINK_KOBJECT_UEVENT);
        assert_se(socket_address_parse_netlink(&a, " \t kobject-uevent \t 10") >= 0);
        assert_se(a.sockaddr.nl.nl_family == AF_NETLINK);
        assert_se(a.sockaddr.nl.nl_groups == 10);
        assert_se(a.protocol == NETLINK_KOBJECT_UEVENT);
        assert_se(socket_address_parse_netlink(&a, "kobject-uevent\t10") >= 0);
        assert_se(a.sockaddr.nl.nl_family == AF_NETLINK);
        assert_se(a.sockaddr.nl.nl_groups == 10);
        assert_se(a.protocol == NETLINK_KOBJECT_UEVENT);

        /* trailing space is not supported */
        assert_se(socket_address_parse_netlink(&a, "kobject-uevent\t10 ") < 0);

        /* Group must be unsigned */
        assert_se(socket_address_parse_netlink(&a, "kobject-uevent -1") < 0);

        /* oss-fuzz #6884 */
        assert_se(socket_address_parse_netlink(&a, "\xff") < 0);
}

static void test_socket_address_equal(void) {
        SocketAddress a, b;

        log_info("/* %s */", __func__);

        assert_se(socket_address_parse(&a, "192.168.1.1:8888") >= 0);
        assert_se(socket_address_parse(&b, "192.168.1.1:888") >= 0);
        assert_se(!socket_address_equal(&a, &b));

        assert_se(socket_address_parse(&a, "192.168.1.1:8888") >= 0);
        assert_se(socket_address_parse(&b, "192.16.1.1:8888") >= 0);
        assert_se(!socket_address_equal(&a, &b));

        assert_se(socket_address_parse(&a, "192.168.1.1:8888") >= 0);
        assert_se(socket_address_parse(&b, "8888") >= 0);
        assert_se(!socket_address_equal(&a, &b));

        assert_se(socket_address_parse(&a, "192.168.1.1:8888") >= 0);
        assert_se(socket_address_parse(&b, "/foo/bar/") >= 0);
        assert_se(!socket_address_equal(&a, &b));

        assert_se(socket_address_parse(&a, "192.168.1.1:8888") >= 0);
        assert_se(socket_address_parse(&b, "192.168.1.1:8888") >= 0);
        assert_se(socket_address_equal(&a, &b));

        assert_se(socket_address_parse(&a, "/foo/bar") >= 0);
        assert_se(socket_address_parse(&b, "/foo/bar") >= 0);
        assert_se(socket_address_equal(&a, &b));

        assert_se(socket_address_parse(&a, "[::1]:8888") >= 0);
        assert_se(socket_address_parse(&b, "[::1]:8888") >= 0);
        assert_se(socket_address_equal(&a, &b));

        assert_se(socket_address_parse(&a, "@abstract") >= 0);
        assert_se(socket_address_parse(&b, "@abstract") >= 0);
        assert_se(socket_address_equal(&a, &b));

        assert_se(socket_address_parse_netlink(&a, "firewall") >= 0);
        assert_se(socket_address_parse_netlink(&b, "firewall") >= 0);
        assert_se(socket_address_equal(&a, &b));

        assert_se(socket_address_parse(&a, "vsock:2:1234") >= 0);
        assert_se(socket_address_parse(&b, "vsock:2:1234") >= 0);
        assert_se(socket_address_equal(&a, &b));
        assert_se(socket_address_parse(&b, "vsock:2:1235") >= 0);
        assert_se(!socket_address_equal(&a, &b));
        assert_se(socket_address_parse(&b, "vsock:3:1234") >= 0);
        assert_se(!socket_address_equal(&a, &b));
}

static void test_socket_address_get_path(void) {
        SocketAddress a;

        log_info("/* %s */", __func__);

        assert_se(socket_address_parse(&a, "192.168.1.1:8888") >= 0);
        assert_se(!socket_address_get_path(&a));

        assert_se(socket_address_parse(&a, "@abstract") >= 0);
        assert_se(!socket_address_get_path(&a));

        assert_se(socket_address_parse(&a, "[::1]:8888") >= 0);
        assert_se(!socket_address_get_path(&a));

        assert_se(socket_address_parse(&a, "/foo/bar") >= 0);
        assert_se(streq(socket_address_get_path(&a), "/foo/bar"));

        assert_se(socket_address_parse(&a, "vsock:2:1234") >= 0);
        assert_se(!socket_address_get_path(&a));
}

static void test_socket_address_is(void) {
        SocketAddress a;

        log_info("/* %s */", __func__);

        assert_se(socket_address_parse(&a, "192.168.1.1:8888") >= 0);
        assert_se(socket_address_is(&a, "192.168.1.1:8888", SOCK_STREAM));
        assert_se(!socket_address_is(&a, "route", SOCK_STREAM));
        assert_se(!socket_address_is(&a, "192.168.1.1:8888", SOCK_RAW));
}

static void test_socket_address_is_netlink(void) {
        SocketAddress a;

        log_info("/* %s */", __func__);

        assert_se(socket_address_parse_netlink(&a, "route 10") >= 0);
        assert_se(socket_address_is_netlink(&a, "route 10"));
        assert_se(!socket_address_is_netlink(&a, "192.168.1.1:8888"));
        assert_se(!socket_address_is_netlink(&a, "route 1"));
}

int main(int argc, char *argv[]) {
        test_setup_logging(LOG_DEBUG);

        test_socket_address_parse();
        test_socket_address_parse_netlink();
        test_socket_address_equal();
        test_socket_address_get_path();
        test_socket_address_is();
        test_socket_address_is_netlink();

        return 0;
}
