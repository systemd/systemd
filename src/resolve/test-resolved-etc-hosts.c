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
                assert_se(errno == ENOENT);
                return;
        }

        _cleanup_(etc_hosts_clear) EtcHosts hosts = {};
        assert_se(etc_hosts_parse(&hosts, f) == 0);
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

        fd = mkostemp_safe(t);
        assert_se(fd >= 0);

        f = fdopen(fd, "r+");
        assert_se(f);
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
        assert_se(fflush_and_check(f) >= 0);
        rewind(f);

        _cleanup_(etc_hosts_clear) EtcHosts hosts = {};
        assert_se(etc_hosts_parse(&hosts, f) == 0);

        EtcHostsItemByName *bn;
        assert_se(bn = hashmap_get(hosts.by_name, "some.where"));
        assert_se(set_size(bn->addresses) == 3);
        assert_se(has_4(bn->addresses, "1.2.3.4"));
        assert_se(has_4(bn->addresses, "1.2.3.5"));
        assert_se(has_6(bn->addresses, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5}));

        assert_se(bn = hashmap_get(hosts.by_name, "dash"));
        assert_se(set_size(bn->addresses) == 1);
        assert_se(has_4(bn->addresses, "1.2.3.6"));

        assert_se(bn = hashmap_get(hosts.by_name, "dash-dash.where-dash"));
        assert_se(set_size(bn->addresses) == 1);
        assert_se(has_4(bn->addresses, "1.2.3.6"));

        /* See https://tools.ietf.org/html/rfc1035#section-2.3.1 */
        FOREACH_STRING(s, "bad-dash-", "-bad-dash", "-bad-dash.bad-")
                assert_se(!hashmap_get(hosts.by_name, s));

        assert_se(bn = hashmap_get(hosts.by_name, "before.comment"));
        assert_se(set_size(bn->addresses) == 4);
        assert_se(has_4(bn->addresses, "1.2.3.9"));
        assert_se(has_4(bn->addresses, "1.2.3.10"));
        assert_se(has_4(bn->addresses, "1.2.3.11"));
        assert_se(has_4(bn->addresses, "1.2.3.12"));

        assert_se(!hashmap_get(hosts.by_name, "within.comment"));
        assert_se(!hashmap_get(hosts.by_name, "within.comment2"));
        assert_se(!hashmap_get(hosts.by_name, "within.comment3"));
        assert_se(!hashmap_get(hosts.by_name, "#"));

        assert_se(!hashmap_get(hosts.by_name, "short.address"));
        assert_se(!hashmap_get(hosts.by_name, "long.address"));
        assert_se(!hashmap_get(hosts.by_name, "multi.colon"));
        assert_se(!set_contains(hosts.no_address, "short.address"));
        assert_se(!set_contains(hosts.no_address, "long.address"));
        assert_se(!set_contains(hosts.no_address, "multi.colon"));

        assert_se(bn = hashmap_get(hosts.by_name, "some.other"));
        assert_se(set_size(bn->addresses) == 1);
        assert_se(has_6(bn->addresses, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5}));

        EtcHostsItemByAddress *ba;
        assert_se(ba = hashmap_get(hosts.by_address, in_addr_4("1.2.3.6")));
        assert_se(set_size(ba->names) == 2);
        assert_se(set_contains(ba->names, "dash"));
        assert_se(set_contains(ba->names, "dash-dash.where-dash"));
        assert_se(streq(ba->canonical_name, "dash"));

        assert_se(ba = hashmap_get(hosts.by_address, in_addr_6({0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5})));
        assert_se(set_size(ba->names) == 3);
        assert_se(set_contains(ba->names, "some.where"));
        assert_se(set_contains(ba->names, "some.other"));
        assert_se(set_contains(ba->names, "foobar.foo.foo"));
        assert_se(streq(ba->canonical_name, "some.where"));

        assert_se( set_contains(hosts.no_address, "some.where"));
        assert_se( set_contains(hosts.no_address, "some.other"));
        assert_se( set_contains(hosts.no_address, "deny.listed"));
        assert_se(!set_contains(hosts.no_address, "foobar.foo.foo"));
}

static void test_parse_file_one(const char *fname) {
        _cleanup_(etc_hosts_clear) EtcHosts hosts = {};
        _cleanup_fclose_ FILE *f = NULL;

        log_info("/* %s(\"%s\") */", __func__, fname);

        assert_se(f = fopen(fname, "re"));
        assert_se(etc_hosts_parse(&hosts, f) == 0);
}

TEST(parse_file) {
        for (int i = 1; i < saved_argc; i++)
                test_parse_file_one(saved_argv[i]);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
