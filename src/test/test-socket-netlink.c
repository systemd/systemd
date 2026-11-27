/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <sys/eventfd.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "format-util.h"
#include "missing-network.h"
#include "process-util.h"
#include "socket-netlink.h"
#include "socket-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"

static void test_socket_address_parse_one(const char *in, int ret, int family, const char *expected) {
        SocketAddress a;
        _cleanup_free_ char *out = NULL;
        int r;

        r = socket_address_parse(&a, in);
        if (r >= 0) {
                r = socket_address_print(&a, &out);
                if (r < 0)
                        log_error_errno(r, "Printing failed for \"%s\": %m", in);
                ASSERT_OK(r);
                ASSERT_EQ(a.type, 0);
        }

        log_info("\"%s\" → %s %d → \"%s\" (expect %d / \"%s\")",
                 in,
                 r >= 0 ? "✓" : "✗", r,
                 empty_to_dash(out),
                 ret,
                 ret >= 0 ? expected ?: in : "-");
        ASSERT_EQ(r, ret);
        if (r >= 0) {
                ASSERT_EQ(a.sockaddr.sa.sa_family, family);
                ASSERT_STREQ(out, expected ?: in);
        }
}

TEST(socket_address_parse) {
        test_socket_address_parse_one("junk", -EINVAL, /* family= */ 0, /* expected= */ NULL);
        test_socket_address_parse_one("192.168.1.1", -EINVAL, /* family= */ 0, /* expected= */ NULL);
        test_socket_address_parse_one(".168.1.1", -EINVAL, /* family= */ 0, /* expected= */ NULL);
        test_socket_address_parse_one("989.168.1.1", -EINVAL, /* family= */ 0, /* expected= */ NULL);
        test_socket_address_parse_one("192.168.1.1:65536", -ERANGE, /* family= */ 0, /* expected= */ NULL);
        test_socket_address_parse_one("192.168.1.1:0", -EINVAL, /* family= */ 0, /* expected= */ NULL);
        test_socket_address_parse_one("0", -EINVAL, /* family= */ 0, /* expected= */ NULL);
        test_socket_address_parse_one("65536", -ERANGE, /* family= */ 0, /* expected= */ NULL);

        const int default_family = socket_ipv6_is_supported() ? AF_INET6 : AF_INET;

        test_socket_address_parse_one("65535", /* ret= */ 0, default_family,
                                      default_family == AF_INET6 ? "[::]:65535": "0.0.0.0:65535");

        /* The checks below will pass even if ipv6 is disabled in
         * kernel. The underlying glibc's inet_pton() is just a string
         * parser and doesn't make any syscalls. */

        test_socket_address_parse_one("[::1]", -EINVAL, /* family= */ 0, /* expected= */ NULL);
        test_socket_address_parse_one("[::1]8888", -EINVAL, /* family= */ 0, /* expected= */ NULL);
        test_socket_address_parse_one("::1", -EINVAL, /* family= */ 0, /* expected= */ NULL);
        test_socket_address_parse_one("[::1]:0", -EINVAL, /* family= */ 0, /* expected= */ NULL);
        test_socket_address_parse_one("[::1]:65536", -ERANGE, /* family= */ 0, /* expected= */ NULL);
        test_socket_address_parse_one("[a:b:1]:8888", -EINVAL, /* family= */ 0, /* expected= */ NULL);
        test_socket_address_parse_one("[::1]%lo:1234", -EINVAL, /* family= */ 0, /* expected= */ NULL);
        test_socket_address_parse_one("[::1]%lo:0", -EINVAL, /* family= */ 0, /* expected= */ NULL);
        test_socket_address_parse_one("[::1]%lo", -EINVAL, /* family= */ 0, /* expected= */ NULL);
        test_socket_address_parse_one("[::1]%lo%lo:1234", -EINVAL, /* family= */ 0, /* expected= */ NULL);
        test_socket_address_parse_one("[::1]% lo:1234", -EINVAL, /* family= */ 0, /* expected= */ NULL);

        test_socket_address_parse_one("8888", /* ret= */ 0, default_family,
                                      default_family == AF_INET6 ? "[::]:8888": "0.0.0.0:8888");
        test_socket_address_parse_one("[2001:0db8:0000:85a3:0000:0000:ac1f:8001]:8888", /* ret= */ 0, AF_INET6,
                                      "[2001:db8:0:85a3::ac1f:8001]:8888");
        test_socket_address_parse_one("[::1]:8888", /* ret= */ 0, AF_INET6, /* expected= */ NULL);
        test_socket_address_parse_one("[::1]:1234%lo", /* ret= */ 0, AF_INET6, /* expected= */ NULL);
        test_socket_address_parse_one("[::1]:0%lo", -EINVAL, /* family= */ 0, /* expected= */ NULL);
        test_socket_address_parse_one("[::1]%lo", -EINVAL, /* family= */ 0, /* expected= */ NULL);
        test_socket_address_parse_one("[::1]:1234%lo%lo", -EINVAL, /* family= */ 0, /* expected= */ NULL);
        test_socket_address_parse_one("[::1]:1234%xxxxasdf", -ENODEV, /* family= */ 0, /* expected= */ NULL);
        test_socket_address_parse_one("192.168.1.254:8888", /* ret= */ 0, AF_INET, /* expected= */ NULL);
        test_socket_address_parse_one("/foo/bar", /* ret= */ 0, AF_UNIX, /* expected= */ NULL);
        test_socket_address_parse_one("/", -EINVAL, /* family= */ 0, /* expected= */ NULL);
        test_socket_address_parse_one("@abstract", /* ret= */ 0, AF_UNIX, /* expected= */ NULL);

        {
                char aaa[SUN_PATH_LEN + 1] = "@";

                memset(aaa + 1, 'a', SUN_PATH_LEN - 1);
                char_array_0(aaa);

                test_socket_address_parse_one(aaa, -EINVAL, /* family= */ 0, /* expected= */ NULL);

                aaa[SUN_PATH_LEN - 1] = '\0';
                test_socket_address_parse_one(aaa, /* ret= */ 0, AF_UNIX, /* expected= */ NULL);
        }

        test_socket_address_parse_one("vsock:2:1234", /* ret= */ 0, AF_VSOCK, /* expected= */ NULL);
        test_socket_address_parse_one("vsock::1234", /* ret= */ 0, AF_VSOCK, /* expected= */ NULL);
        test_socket_address_parse_one("vsock:2:1234x", -EINVAL, /* family= */ 0, /* expected= */ NULL);
        test_socket_address_parse_one("vsock:2x:1234", -EINVAL, /* family= */ 0, /* expected= */ NULL);
        test_socket_address_parse_one("vsock:2", -EINVAL, /* family= */ 0, /* expected= */ NULL);
}

TEST(socket_address_parse_netlink) {
        SocketAddress a;

        ASSERT_FAIL(socket_address_parse_netlink(&a, "junk"));
        ASSERT_FAIL(socket_address_parse_netlink(&a, ""));

        ASSERT_OK(socket_address_parse_netlink(&a, "route"));
        ASSERT_EQ(a.sockaddr.nl.nl_family, AF_NETLINK);
        ASSERT_EQ(a.sockaddr.nl.nl_groups, 0U);
        ASSERT_EQ(a.protocol, NETLINK_ROUTE);
        ASSERT_OK(socket_address_parse_netlink(&a, "route"));
        ASSERT_OK(socket_address_parse_netlink(&a, "route 10"));
        ASSERT_EQ(a.sockaddr.nl.nl_family, AF_NETLINK);
        ASSERT_EQ(a.sockaddr.nl.nl_groups, 10U);
        ASSERT_EQ(a.protocol, NETLINK_ROUTE);

        /* With spaces and tabs */
        ASSERT_OK(socket_address_parse_netlink(&a, " kobject-uevent "));
        ASSERT_EQ(a.sockaddr.nl.nl_family, AF_NETLINK);
        ASSERT_EQ(a.sockaddr.nl.nl_groups, 0U);
        ASSERT_EQ(a.protocol, NETLINK_KOBJECT_UEVENT);
        ASSERT_OK(socket_address_parse_netlink(&a, " \t kobject-uevent \t 10"));
        ASSERT_EQ(a.sockaddr.nl.nl_family, AF_NETLINK);
        ASSERT_EQ(a.sockaddr.nl.nl_groups, 10U);
        ASSERT_EQ(a.protocol, NETLINK_KOBJECT_UEVENT);
        ASSERT_OK(socket_address_parse_netlink(&a, "kobject-uevent\t10"));
        ASSERT_EQ(a.sockaddr.nl.nl_family, AF_NETLINK);
        ASSERT_EQ(a.sockaddr.nl.nl_groups, 10U);
        ASSERT_EQ(a.protocol, NETLINK_KOBJECT_UEVENT);

        /* trailing space is not supported */
        ASSERT_FAIL(socket_address_parse_netlink(&a, "kobject-uevent\t10 "));

        /* Group must be unsigned */
        ASSERT_FAIL(socket_address_parse_netlink(&a, "kobject-uevent -1"));

        /* oss-fuzz #6884 */
        ASSERT_FAIL(socket_address_parse_netlink(&a, "\xff"));
}

TEST(socket_address_equal) {
        SocketAddress a, b;

        ASSERT_OK(socket_address_parse(&a, "192.168.1.1:8888"));
        ASSERT_OK(socket_address_parse(&b, "192.168.1.1:888"));
        ASSERT_FALSE(socket_address_equal(&a, &b));

        ASSERT_OK(socket_address_parse(&a, "192.168.1.1:8888"));
        ASSERT_OK(socket_address_parse(&b, "192.16.1.1:8888"));
        ASSERT_FALSE(socket_address_equal(&a, &b));

        ASSERT_OK(socket_address_parse(&a, "192.168.1.1:8888"));
        ASSERT_OK(socket_address_parse(&b, "8888"));
        ASSERT_FALSE(socket_address_equal(&a, &b));

        ASSERT_OK(socket_address_parse(&a, "192.168.1.1:8888"));
        ASSERT_OK(socket_address_parse(&b, "/foo/bar/"));
        ASSERT_FALSE(socket_address_equal(&a, &b));

        ASSERT_OK(socket_address_parse(&a, "192.168.1.1:8888"));
        ASSERT_OK(socket_address_parse(&b, "192.168.1.1:8888"));
        ASSERT_TRUE(socket_address_equal(&a, &b));

        ASSERT_OK(socket_address_parse(&a, "/foo/bar"));
        ASSERT_OK(socket_address_parse(&b, "/foo/bar"));
        ASSERT_TRUE(socket_address_equal(&a, &b));

        ASSERT_OK(socket_address_parse(&a, "[::1]:8888"));
        ASSERT_OK(socket_address_parse(&b, "[::1]:8888"));
        ASSERT_TRUE(socket_address_equal(&a, &b));

        ASSERT_OK(socket_address_parse(&a, "@abstract"));
        ASSERT_OK(socket_address_parse(&b, "@abstract"));
        ASSERT_TRUE(socket_address_equal(&a, &b));

        ASSERT_OK(socket_address_parse_netlink(&a, "firewall"));
        ASSERT_OK(socket_address_parse_netlink(&b, "firewall"));
        ASSERT_TRUE(socket_address_equal(&a, &b));

        ASSERT_OK(socket_address_parse(&a, "vsock:2:1234"));
        ASSERT_OK(socket_address_parse(&b, "vsock:2:1234"));
        ASSERT_TRUE(socket_address_equal(&a, &b));
        ASSERT_OK(socket_address_parse(&b, "vsock:2:1235"));
        ASSERT_FALSE(socket_address_equal(&a, &b));
        ASSERT_OK(socket_address_parse(&b, "vsock:3:1234"));
        ASSERT_FALSE(socket_address_equal(&a, &b));
}

TEST(socket_address_get_path) {
        SocketAddress a;

        ASSERT_OK(socket_address_parse(&a, "192.168.1.1:8888"));
        ASSERT_NULL(socket_address_get_path(&a));

        ASSERT_OK(socket_address_parse(&a, "@abstract"));
        ASSERT_NULL(socket_address_get_path(&a));

        ASSERT_OK(socket_address_parse(&a, "[::1]:8888"));
        ASSERT_NULL(socket_address_get_path(&a));

        ASSERT_OK(socket_address_parse(&a, "/foo/bar"));
        ASSERT_STREQ(socket_address_get_path(&a), "/foo/bar");

        ASSERT_OK(socket_address_parse(&a, "vsock:2:1234"));
        ASSERT_NULL(socket_address_get_path(&a));
}

TEST(socket_address_is) {
        SocketAddress a;

        ASSERT_OK(socket_address_parse(&a, "192.168.1.1:8888"));
        ASSERT_TRUE(socket_address_is(&a, "192.168.1.1:8888", /* type= */ 0 /* unspecified yet */));
        ASSERT_FALSE(socket_address_is(&a, "route", /* type= */ 0));
        ASSERT_FALSE(socket_address_is(&a, "route", SOCK_STREAM));
        ASSERT_FALSE(socket_address_is(&a, "192.168.1.1:8888", SOCK_RAW));
        ASSERT_FALSE(socket_address_is(&a, "192.168.1.1:8888", SOCK_STREAM));
        a.type = SOCK_STREAM;
        ASSERT_TRUE(socket_address_is(&a, "192.168.1.1:8888", SOCK_STREAM));
}

TEST(socket_address_is_netlink) {
        SocketAddress a;

        ASSERT_OK(socket_address_parse_netlink(&a, "route 10"));
        ASSERT_TRUE(socket_address_is_netlink(&a, "route 10"));
        ASSERT_FALSE(socket_address_is_netlink(&a, "192.168.1.1:8888"));
        ASSERT_FALSE(socket_address_is_netlink(&a, "route 1"));
}

static void test_in_addr_ifindex_to_string_one(int f, const char *a, int ifindex, const char *b) {
        _cleanup_free_ char *r = NULL;
        union in_addr_union ua, uuaa;
        int ff, ifindex2;

        ASSERT_OK(in_addr_from_string(f, a, &ua));
        ASSERT_OK(in_addr_ifindex_to_string(f, &ua, ifindex, &r));
        printf("test_in_addr_ifindex_to_string_one: %s == %s\n", b, r);
        ASSERT_STREQ(b, r);

        ASSERT_OK(in_addr_ifindex_from_string_auto(b, &ff, &uuaa, &ifindex2));
        ASSERT_EQ(ff, f);
        ASSERT_OK_POSITIVE(in_addr_equal(f, &ua, &uuaa));
        ASSERT_TRUE(ifindex2 == ifindex || ifindex2 == 0);
}

TEST(in_addr_ifindex_to_string) {
        test_in_addr_ifindex_to_string_one(AF_INET, "192.168.0.1", 7, "192.168.0.1");
        test_in_addr_ifindex_to_string_one(AF_INET, "10.11.12.13", 9, "10.11.12.13");
        test_in_addr_ifindex_to_string_one(AF_INET6, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", 10, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
        test_in_addr_ifindex_to_string_one(AF_INET6, "::1", 11, "::1");
        test_in_addr_ifindex_to_string_one(AF_INET6, "fe80::", LOOPBACK_IFINDEX, "fe80::%1");
        test_in_addr_ifindex_to_string_one(AF_INET6, "fe80::", /* ifindex= */ 0, "fe80::");
        test_in_addr_ifindex_to_string_one(AF_INET6, "fe80::14", /* ifindex= */ 0, "fe80::14");
        test_in_addr_ifindex_to_string_one(AF_INET6, "fe80::15", -7, "fe80::15");
        test_in_addr_ifindex_to_string_one(AF_INET6, "fe80::16", LOOPBACK_IFINDEX, "fe80::16%1");
}

TEST(in_addr_ifindex_from_string_auto) {
        int family, ifindex;
        union in_addr_union ua;

        /* Most in_addr_ifindex_from_string_auto() invocations have already been tested above, but let's test some more */

        ASSERT_OK(in_addr_ifindex_from_string_auto("fe80::17", &family, &ua, &ifindex));
        ASSERT_EQ(family, AF_INET6);
        ASSERT_EQ(ifindex, 0);

        ASSERT_OK(in_addr_ifindex_from_string_auto("fe80::18%1", &family, &ua, &ifindex));
        ASSERT_EQ(family, AF_INET6);
        ASSERT_EQ(ifindex, 1);

        ASSERT_OK(in_addr_ifindex_from_string_auto("fe80::18%lo", &family, &ua, &ifindex));
        ASSERT_EQ(family, AF_INET6);
        ASSERT_EQ(ifindex, LOOPBACK_IFINDEX);

        ASSERT_ERROR(in_addr_ifindex_from_string_auto("fe80::19%thisinterfacecantexist", &family, &ua, &ifindex), ENODEV);
}

static void test_in_addr_ifindex_name_from_string_auto_one(const char *a, const char *expected) {
        int family, ifindex;
        union in_addr_union ua;
        _cleanup_free_ char *server_name = NULL;

        ASSERT_OK(in_addr_ifindex_name_from_string_auto(a, &family, &ua, &ifindex, &server_name));
        ASSERT_STREQ(server_name, expected);
}

TEST(in_addr_ifindex_name_from_string_auto) {
        test_in_addr_ifindex_name_from_string_auto_one("192.168.0.1", /* expected= */ NULL);
        test_in_addr_ifindex_name_from_string_auto_one("192.168.0.1#test.com", "test.com");
        test_in_addr_ifindex_name_from_string_auto_one("fe80::18%1", /* expected= */ NULL);
        test_in_addr_ifindex_name_from_string_auto_one("fe80::18%1#another.test.com", "another.test.com");
}

static void test_in_addr_port_ifindex_name_from_string_auto_one(const char *str, int family, uint16_t port, int ifindex,
                                                                const char *server_name, const char *str_repr) {
        union in_addr_union a;
        uint16_t p;
        int f, i;
        char *fake;

        log_info("%s: %s", __func__, str);

        {
                _cleanup_free_ char *name = NULL, *x = NULL;
                ASSERT_OK_ZERO(in_addr_port_ifindex_name_from_string_auto(str, &f, &a, &p, &i, &name));
                ASSERT_EQ(family, f);
                ASSERT_EQ(port, p);
                ASSERT_EQ(ifindex, i);
                ASSERT_STREQ(server_name, name);
                ASSERT_OK(in_addr_port_ifindex_name_to_string(f, &a, p, i, name, &x));
                ASSERT_STREQ(str_repr ?: str, x);
        }

        if (port > 0)
                ASSERT_ERROR(in_addr_port_ifindex_name_from_string_auto(str, &f, &a, /* ret_port= */ NULL, &i, &fake), EINVAL);
        else {
                _cleanup_free_ char *name = NULL, *x = NULL;
                ASSERT_OK_ZERO(in_addr_port_ifindex_name_from_string_auto(str, &f, &a, /* ret_port= */ NULL, &i, &name));
                ASSERT_EQ(family, f);
                ASSERT_EQ(ifindex, i);
                ASSERT_STREQ(server_name, name);
                ASSERT_OK(in_addr_port_ifindex_name_to_string(f, &a, /* port= */ 0, i, name, &x));
                ASSERT_STREQ(str_repr ?: str, x);
        }

        if (ifindex > 0)
                ASSERT_ERROR(in_addr_port_ifindex_name_from_string_auto(str, &f, &a, &p, /* ret_ifindex= */ NULL, &fake), EINVAL);
        else {
                _cleanup_free_ char *name = NULL, *x = NULL;
                ASSERT_OK_ZERO(in_addr_port_ifindex_name_from_string_auto(str, &f, &a, &p, /* ret_ifindex= */ NULL, &name));
                ASSERT_EQ(family, f);
                ASSERT_EQ(port, p);
                ASSERT_STREQ(server_name, name);
                ASSERT_OK(in_addr_port_ifindex_name_to_string(f, &a, p, /* ifindex= */ 0, name, &x));
                ASSERT_STREQ(str_repr ?: str, x);
        }

        if (server_name)
                ASSERT_ERROR(in_addr_port_ifindex_name_from_string_auto(str, &f, &a, &p, &i, /* ret_server_name= */ NULL), EINVAL);
        else {
                _cleanup_free_ char *x = NULL;
                ASSERT_OK_ZERO(in_addr_port_ifindex_name_from_string_auto(str, &f, &a, &p, &i, /* ret_server_name= */ NULL));
                ASSERT_EQ(family, f);
                ASSERT_EQ(port, p);
                ASSERT_EQ(ifindex, i);
                ASSERT_OK(in_addr_port_ifindex_name_to_string(f, &a, p, i, /* server_name= */ NULL, &x));
                ASSERT_STREQ(str_repr ?: str, x);
        }
}

TEST(in_addr_port_ifindex_name_from_string_auto) {
        test_in_addr_port_ifindex_name_from_string_auto_one("192.168.0.1", AF_INET, /* port= */ 0, /* ifindex= */ 0, /* server_name= */ NULL, /* str_repr= */ NULL);
        test_in_addr_port_ifindex_name_from_string_auto_one("192.168.0.1#test.com", AF_INET, /* port= */ 0, /* ifindex= */ 0, "test.com", /* str_repr= */ NULL);
        test_in_addr_port_ifindex_name_from_string_auto_one("192.168.0.1:53", AF_INET, 53, /* ifindex= */ 0, /* server_name= */ NULL, /* str_repr= */ NULL);
        test_in_addr_port_ifindex_name_from_string_auto_one("192.168.0.1:53#example.com", AF_INET, 53, /* ifindex= */ 0, "example.com", /* str_repr= */ NULL);
        test_in_addr_port_ifindex_name_from_string_auto_one("fe80::18", AF_INET6, /* port= */ 0, /* ifindex= */ 0, /* server_name= */ NULL, /* str_repr= */ NULL);
        test_in_addr_port_ifindex_name_from_string_auto_one("fe80::18#hoge.com", AF_INET6, /* port= */ 0, /* ifindex= */ 0, "hoge.com", /* str_repr= */ NULL);
        test_in_addr_port_ifindex_name_from_string_auto_one("fe80::18%1", AF_INET6, /* port= */ 0, 1, /* server_name= */ NULL, /* str_repr= */ NULL);
        test_in_addr_port_ifindex_name_from_string_auto_one("fe80::18%lo", AF_INET6, /* port= */ 0, 1, /* server_name= */ NULL, "fe80::18%1");
        test_in_addr_port_ifindex_name_from_string_auto_one("[fe80::18]:53", AF_INET6, 53, /* ifindex= */ 0, /* server_name= */ NULL, /* str_repr= */ NULL);
        test_in_addr_port_ifindex_name_from_string_auto_one("[fe80::18]:53%1", AF_INET6, 53, 1, /* server_name= */ NULL, /* str_repr= */ NULL);
        test_in_addr_port_ifindex_name_from_string_auto_one("[fe80::18]:53%lo", AF_INET6, 53, 1, /* server_name= */ NULL, "[fe80::18]:53%1");
        test_in_addr_port_ifindex_name_from_string_auto_one("fe80::18%1#hoge.com", AF_INET6, /* port= */ 0, 1, "hoge.com", /* str_repr= */ NULL);
        test_in_addr_port_ifindex_name_from_string_auto_one("[fe80::18]:53#hoge.com", AF_INET6, 53, /* ifindex= */ 0, "hoge.com", /* str_repr= */ NULL);
        test_in_addr_port_ifindex_name_from_string_auto_one("[fe80::18]:53%1", AF_INET6, 53, 1, /* server_name= */ NULL, /* str_repr= */ NULL);
        test_in_addr_port_ifindex_name_from_string_auto_one("[fe80::18]:53%1#hoge.com", AF_INET6, 53, 1, "hoge.com", /* str_repr= */ NULL);
        test_in_addr_port_ifindex_name_from_string_auto_one("[fe80::18]:53%lo", AF_INET6, 53, 1, /* server_name= */ NULL, "[fe80::18]:53%1");
        test_in_addr_port_ifindex_name_from_string_auto_one("[fe80::18]:53%lo#hoge.com", AF_INET6, 53, 1, "hoge.com", "[fe80::18]:53%1#hoge.com");
}

static void test_in_addr_full_new_from_uri_one(
                const char *str,
                const char *scheme,
                int family,
                const char *address,
                uint16_t port,
                int ifindex,
                const char *server_name,
                const char *path,
                const char *query,
                char **params,
                const char *str_repr) {

        _cleanup_(in_addr_full_freep) struct in_addr_full *a = NULL;
        union in_addr_union u;

        log_info("/* %s(%s) */", __func__, str);

        ASSERT_OK(in_addr_full_new_from_uri(str, &a));
        ASSERT_STREQ(a->scheme, scheme);
        ASSERT_EQ(a->family, family);
        ASSERT_OK(in_addr_from_string(family, address, &u));
        ASSERT_TRUE(in_addr_equal(family, &a->address, &u));
        ASSERT_EQ(a->port, port);
        ASSERT_EQ(a->ifindex, ifindex);
        ASSERT_STREQ(a->server_name, server_name);
        ASSERT_STREQ(a->path, path);
        ASSERT_STREQ(a->query, query);
        ASSERT_TRUE(strv_equal(a->params, params));
        ASSERT_STREQ(in_addr_full_to_string(a), str_repr ?: str);
}

TEST(in_addr_full_new_from_uri) {
        test_in_addr_full_new_from_uri_one("dns://192.168.0.1", "dns", AF_INET, "192.168.0.1", /* port= */ 0, /* ifindex= */ 0,
                                           /* server_name= */ NULL, /* path= */ NULL, /* query= */ NULL, /* params= */ NULL, /* str_repr= */ NULL);
        test_in_addr_full_new_from_uri_one("dns://192.168.0.1:5353", "dns", AF_INET, "192.168.0.1", 5353, /* ifindex= */ 0,
                                           /* server_name= */ NULL, /* path= */ NULL, /* query= */ NULL, /* params= */ NULL, /* str_repr= */ NULL);
        /* Scheme is case insensitive, an empty path is dropped */
        test_in_addr_full_new_from_uri_one("DNSS://192.168.0.1/", "dnss", AF_INET, "192.168.0.1", /* port= */ 0, /* ifindex= */ 0,
                                           /* server_name= */ NULL, /* path= */ NULL, /* query= */ NULL, /* params= */ NULL, "dnss://192.168.0.1");
        test_in_addr_full_new_from_uri_one("dnss://[2001:db8::1]", "dnss", AF_INET6, "2001:db8::1", /* port= */ 0, /* ifindex= */ 0,
                                           /* server_name= */ NULL, /* path= */ NULL, /* query= */ NULL, /* params= */ NULL, /* str_repr= */ NULL);
        test_in_addr_full_new_from_uri_one("dnss://2001:db8::1", "dnss", AF_INET6, "2001:db8::1", /* port= */ 0, /* ifindex= */ 0,
                                           /* server_name= */ NULL, /* path= */ NULL, /* query= */ NULL, /* params= */ NULL, "dnss://[2001:db8::1]");
        test_in_addr_full_new_from_uri_one("dnss://[2001:db8::1]:853", "dnss", AF_INET6, "2001:db8::1", 853, /* ifindex= */ 0,
                                           /* server_name= */ NULL, /* path= */ NULL, /* query= */ NULL, /* params= */ NULL, /* str_repr= */ NULL);
        test_in_addr_full_new_from_uri_one("dnss://1.1.1.1#name=one.one.one.one", "dnss", AF_INET, "1.1.1.1", /* port= */ 0, /* ifindex= */ 0,
                                           "one.one.one.one", /* path= */ NULL, /* query= */ NULL, /* params= */ NULL, /* str_repr= */ NULL);
        /* name= and ifname= are written first, then the other parameters in their given order */
        test_in_addr_full_new_from_uri_one("dnss://[fe80::1]:8853#downgrade=5353&ifname=lo&name=example.com", "dnss", AF_INET6, "fe80::1", 8853, 1,
                                           "example.com", /* path= */ NULL, /* query= */ NULL, STRV_MAKE("downgrade=5353"),
                                           "dnss://[fe80::1]:8853#name=example.com&ifname=1&downgrade=5353");
        /* A bare key reads as an empty value, and is written back as a bare key */
        test_in_addr_full_new_from_uri_one("dnss://1.1.1.1#downgrade", "dnss", AF_INET, "1.1.1.1", /* port= */ 0, /* ifindex= */ 0,
                                           /* server_name= */ NULL, /* path= */ NULL, /* query= */ NULL, STRV_MAKE("downgrade="), /* str_repr= */ NULL);
        test_in_addr_full_new_from_uri_one("dnss://1.1.1.1#downgrade=", "dnss", AF_INET, "1.1.1.1", /* port= */ 0, /* ifindex= */ 0,
                                           /* server_name= */ NULL, /* path= */ NULL, /* query= */ NULL, STRV_MAKE("downgrade="), "dnss://1.1.1.1#downgrade");
        /* Path and query are kept for the caller to check; '/' and '?' may appear in later parts */
        test_in_addr_full_new_from_uri_one("https://1.1.1.1/dns-query?dns=x/y#a=b?c", "https", AF_INET, "1.1.1.1", /* port= */ 0, /* ifindex= */ 0,
                                           /* server_name= */ NULL, "dns-query", "dns=x/y", STRV_MAKE("a=b?c"), /* str_repr= */ NULL);

        _cleanup_(in_addr_full_freep) struct in_addr_full *a = NULL;

        /* in_addr_full_new_from_string() accepts both forms */
        ASSERT_OK(in_addr_full_new_from_string("dnss://192.168.0.1:853#downgrade", &a));
        ASSERT_STREQ(a->scheme, "dnss");
        ASSERT_EQ(a->port, 853);
        ASSERT_STREQ(in_addr_full_to_string(a), "dnss://192.168.0.1:853#downgrade");
        a = in_addr_full_free(a);
        ASSERT_OK(in_addr_full_new_from_string("192.168.0.1:853#example.com", &a));
        ASSERT_NULL(a->scheme);
        ASSERT_STREQ(a->server_name, "example.com");
        a = in_addr_full_free(a);
        ASSERT_ERROR(in_addr_full_new_from_string("dns://example.com", &a), EINVAL);

        /* Not in URI form */
        ASSERT_ERROR(in_addr_full_new_from_uri("192.168.0.1", &a), EPROTONOSUPPORT);
        ASSERT_ERROR(in_addr_full_new_from_uri("192.168.0.1#dns://x", &a), EPROTONOSUPPORT);
        /* Separators only, at the very start, found by fuzz-network-parser */
        ASSERT_ERROR(in_addr_full_new_from_uri("", &a), EPROTONOSUPPORT);
        ASSERT_ERROR(in_addr_full_new_from_uri("#", &a), EPROTONOSUPPORT);
        ASSERT_ERROR(in_addr_full_new_from_uri("?", &a), EPROTONOSUPPORT);
        ASSERT_ERROR(in_addr_full_new_from_uri("?#", &a), EPROTONOSUPPORT);
        ASSERT_ERROR(in_addr_full_new_from_uri("/", &a), EPROTONOSUPPORT);
        ASSERT_ERROR(in_addr_full_new_from_string("#", &a), EINVAL);

        /* Invalid schemes */
        ASSERT_ERROR(in_addr_full_new_from_uri("://192.168.0.1", &a), EINVAL);
        ASSERT_ERROR(in_addr_full_new_from_uri("://", &a), EINVAL);
        ASSERT_ERROR(in_addr_full_new_from_uri("1dns://192.168.0.1", &a), EINVAL);
        ASSERT_ERROR(in_addr_full_new_from_uri("d_s://192.168.0.1", &a), EINVAL);

        /* Invalid authorities: missing, host names, userinfo, legacy '%' and '#' */
        ASSERT_ERROR(in_addr_full_new_from_uri("dns://", &a), EINVAL);
        ASSERT_ERROR(in_addr_full_new_from_uri("dns:///dns-query", &a), EINVAL);
        ASSERT_ERROR(in_addr_full_new_from_uri("dns://example.com", &a), EINVAL);
        ASSERT_ERROR(in_addr_full_new_from_uri("dns://user@192.168.0.1", &a), EINVAL);
        ASSERT_ERROR(in_addr_full_new_from_uri("dns://[fe80::1]:53%lo", &a), EINVAL);
        ASSERT_ERROR(in_addr_full_new_from_uri("dns://[]", &a), EINVAL);

        /* Invalid fragments: duplicate keys, invalid keys, invalid interface names */
        ASSERT_ERROR(in_addr_full_new_from_uri("dns://192.168.0.1#name=a&name=b", &a), EINVAL);
        ASSERT_ERROR(in_addr_full_new_from_uri("dns://192.168.0.1#na-me=a", &a), EINVAL);
        ASSERT_ERROR(in_addr_full_new_from_uri("dns://192.168.0.1#=a", &a), EINVAL);
        ASSERT_ERROR(in_addr_full_new_from_uri("dns://192.168.0.1#ifname=", &a), EINVAL);
        ASSERT_ERROR(in_addr_full_new_from_uri("dns://192.168.0.1#ifname=a/b", &a), EINVAL);

        ASSERT_NULL(a);
}

TEST(netns_get_nsid) {
        uint32_t u;
        int r;

        r = ASSERT_OK_OR(netns_get_nsid(-EBADF, &u), -ENODATA);
        if (r == -ENODATA)
                log_info("Our network namespace has no NSID assigned.");
        else
                log_info("Our NSID is %" PRIu32, u);
}

TEST(af_unix_get_qlen) {
        int r;
        _cleanup_close_ int unix_fd = ASSERT_FD(socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0));
        ASSERT_OK(socket_autobind(unix_fd, /* ret_name= */ NULL));
        ASSERT_OK_ERRNO(listen(unix_fd, 123));

        uint32_t q;
        r = af_unix_get_qlen(unix_fd, &q);
        if (r == -ENOENT)
                return (void) log_tests_skipped("CONFIG_UNIX_DIAG disabled");
        ASSERT_OK(r);
        ASSERT_EQ(q, 0U);

        _cleanup_close_ int conn_fd = ASSERT_FD(socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0));
        union sockaddr_union sa;
        socklen_t salen = sizeof(sa);
        ASSERT_OK_ERRNO(getsockname(unix_fd, &sa.sa, &salen));
        ASSERT_OK(connect(conn_fd, &sa.sa, salen));

        ASSERT_OK(af_unix_get_qlen(unix_fd, &q));
        ASSERT_EQ(q, 1U);

        _cleanup_close_ int conn2_fd = ASSERT_FD(socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0));
        ASSERT_OK(connect(conn2_fd, &sa.sa, salen));

        ASSERT_OK(af_unix_get_qlen(unix_fd, &q));
        ASSERT_EQ(q, 2U);

        _cleanup_close_ int efd = ASSERT_FD(eventfd(0, EFD_CLOEXEC));
        ASSERT_ERROR(af_unix_get_qlen(efd, &q), ENOTSOCK);
}

TEST(make_socket_fd_cloexec) {
        char address[STRLEN("@test-socket-netlink-") + DECIMAL_STR_MAX(pid_t) + 1];

        xsprintf(address, "@test-socket-netlink-" PID_FMT, getpid_cached());

        /* SOCK_CLOEXEC is implied, whether requested or not */
        _cleanup_close_ int fd = ASSERT_OK(make_socket_fd(LOG_DEBUG, address, SOCK_STREAM, /* flags= */ 0));
        int fl = ASSERT_OK_ERRNO(fcntl(fd, F_GETFD));
        ASSERT_TRUE(FLAGS_SET(fl, FD_CLOEXEC));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
