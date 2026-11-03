/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "argv-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "hashmap.h"
#include "log.h"
#include "resolved-etc-hosts.h"
#include "set.h"
#include "strv.h"
#include "tests.h"
#include "tmpfile-util.h"

TEST(parse_etc_hosts_system) {
        _cleanup_fclose_ FILE *f = NULL;

        f = fopen("/etc/hosts", "re");
        if (!f) {
                ASSERT_EQ(errno, ENOENT);
                return;
        }

        _cleanup_(etc_hosts_clear) EtcHosts hosts = {};
        ASSERT_OK_ZERO(etc_hosts_parse(&hosts, f));
}

#define in_addr_4(_address_str)                                       \
        (&(struct in_addr_data) { .family = AF_INET, .address.in = { .s_addr = inet_addr(_address_str) } })

#define in_addr_6(...)                                           \
        (&(struct in_addr_data) { .family = AF_INET6, .address.in6 = { .s6_addr = __VA_ARGS__ } })

#define has_4(_set, _address_str)                                       \
        set_contains(_set, in_addr_4(_address_str))

#define has_6(_set, ...)                                           \
        set_contains(_set, in_addr_6(__VA_ARGS__))

TEST(parse_etc_hosts) {
        _cleanup_(unlink_tempfilep) char
                t[] = "/tmp/test-resolved-etc-hosts.XXXXXX";

        int fd;
        _cleanup_fclose_ FILE *f = NULL;

        fd = ASSERT_OK(mkostemp_safe(t));

        f = ASSERT_NOT_NULL(fdopen(fd, "r+"));
        fputs("1.2.3.4 some.where\n"
              "1.2.3.5 some.where\n"
              "1.2.3.6 dash dash-dash.where-dash\n"
              "1.2.3.7 bad-dash- -bad-dash -bad-dash.bad-\n"
              "1.2.3.8\n"
              "1.2.3.9 before.comment # within.comment\n"
              "1.2.3.10 before.comment#within.comment2\n"
              "1.2.3.11 before.comment# within.comment3\n"
              "1.2.3.12 before.comment#\n"
              "1.2.3 short.address\n"
              "1.2.3.4.5 long.address\n"
              "1::2::3 multi.colon\n"

              "::0 some.where some.other\n"
              "0.0.0.0 deny.listed\n"
              "::5\t\t\t \tsome.where\tsome.other foobar.foo.foo\t\t\t\n"
              "        \n", f);
        ASSERT_OK(fflush_and_check(f));
        rewind(f);

        _cleanup_(etc_hosts_clear) EtcHosts hosts = {};
        ASSERT_OK_ZERO(etc_hosts_parse(&hosts, f));

        EtcHostsItemByName *bn;
        ASSERT_NOT_NULL(bn = hashmap_get(hosts.by_name, "some.where"));
        ASSERT_EQ(set_size(bn->addresses), 3U);
        ASSERT_TRUE(has_4(bn->addresses, "1.2.3.4"));
        ASSERT_TRUE(has_4(bn->addresses, "1.2.3.5"));
        ASSERT_TRUE(has_6(bn->addresses, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5}));

        ASSERT_NOT_NULL(bn = hashmap_get(hosts.by_name, "dash"));
        ASSERT_EQ(set_size(bn->addresses), 1U);
        ASSERT_TRUE(has_4(bn->addresses, "1.2.3.6"));

        ASSERT_NOT_NULL(bn = hashmap_get(hosts.by_name, "dash-dash.where-dash"));
        ASSERT_EQ(set_size(bn->addresses), 1U);
        ASSERT_TRUE(has_4(bn->addresses, "1.2.3.6"));

        /* See https://tools.ietf.org/html/rfc1035#section-2.3.1 */
        FOREACH_STRING(s, "bad-dash-", "-bad-dash", "-bad-dash.bad-")
                ASSERT_FALSE(hashmap_contains(hosts.by_name, s));

        ASSERT_NOT_NULL(bn = hashmap_get(hosts.by_name, "before.comment"));
        ASSERT_EQ(set_size(bn->addresses), 4U);
        ASSERT_TRUE(has_4(bn->addresses, "1.2.3.9"));
        ASSERT_TRUE(has_4(bn->addresses, "1.2.3.10"));
        ASSERT_TRUE(has_4(bn->addresses, "1.2.3.11"));
        ASSERT_TRUE(has_4(bn->addresses, "1.2.3.12"));

        ASSERT_FALSE(hashmap_contains(hosts.by_name, "within.comment"));
        ASSERT_FALSE(hashmap_contains(hosts.by_name, "within.comment2"));
        ASSERT_FALSE(hashmap_contains(hosts.by_name, "within.comment3"));
        ASSERT_FALSE(hashmap_contains(hosts.by_name, "#"));

        ASSERT_FALSE(hashmap_contains(hosts.by_name, "short.address"));
        ASSERT_FALSE(hashmap_contains(hosts.by_name, "long.address"));
        ASSERT_FALSE(hashmap_contains(hosts.by_name, "multi.colon"));
        ASSERT_FALSE(set_contains(hosts.no_address, "short.address"));
        ASSERT_FALSE(set_contains(hosts.no_address, "long.address"));
        ASSERT_FALSE(set_contains(hosts.no_address, "multi.colon"));

        ASSERT_NOT_NULL(bn = hashmap_get(hosts.by_name, "some.other"));
        ASSERT_EQ(set_size(bn->addresses), 1U);
        ASSERT_TRUE(has_6(bn->addresses, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5}));

        EtcHostsItemByAddress *ba;
        ASSERT_NOT_NULL(ba = hashmap_get(hosts.by_address, in_addr_4("1.2.3.6")));
        ASSERT_EQ(set_size(ba->names), 2U);
        ASSERT_TRUE(set_contains(ba->names, "dash"));
        ASSERT_TRUE(set_contains(ba->names, "dash-dash.where-dash"));
        ASSERT_STREQ(ba->canonical_name, "dash");

        ASSERT_NOT_NULL(ba = hashmap_get(hosts.by_address, in_addr_6({0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5})));
        ASSERT_EQ(set_size(ba->names), 3U);
        ASSERT_TRUE(set_contains(ba->names, "some.where"));
        ASSERT_TRUE(set_contains(ba->names, "some.other"));
        ASSERT_TRUE(set_contains(ba->names, "foobar.foo.foo"));
        ASSERT_STREQ(ba->canonical_name, "some.where");

        ASSERT_TRUE(set_contains(hosts.no_address, "some.where"));
        ASSERT_TRUE(set_contains(hosts.no_address, "some.other"));
        ASSERT_TRUE(set_contains(hosts.no_address, "deny.listed"));
        ASSERT_FALSE(set_contains(hosts.no_address, "foobar.foo.foo"));
}

static void test_parse_file_one(const char *fname) {
        _cleanup_(etc_hosts_clear) EtcHosts hosts = {};
        _cleanup_fclose_ FILE *f = NULL;

        log_info("/* %s(\"%s\") */", __func__, fname);

        ASSERT_NOT_NULL(f = fopen(fname, "re"));
        ASSERT_OK_ZERO(etc_hosts_parse(&hosts, f));
}

TEST(parse_file) {
        for (int i = 1; i < saved_argc; i++)
                test_parse_file_one(saved_argv[i]);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
