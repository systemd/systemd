/* SPDX-License-Identifier: LGPL-2.1+ */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "log.h"
#include "resolved-etc-hosts.h"
#include "strv.h"
#include "tests.h"
#include "tmpfile-util.h"

static void test_parse_etc_hosts_system(void) {
        _cleanup_fclose_ FILE *f = NULL;

        log_info("/* %s */", __func__);

        f = fopen("/etc/hosts", "re");
        if (!f) {
                assert_se(errno == ENOENT);
                return;
        }

        _cleanup_(etc_hosts_free) EtcHosts hosts = {};
        assert_se(etc_hosts_parse(&hosts, f) == 0);
}

#define address_equal_4(_addr, _address)                                \
        ((_addr)->family == AF_INET &&                                  \
         !memcmp(&(_addr)->address.in, &(struct in_addr) { .s_addr = (_address) }, 4))

#define address_equal_6(_addr, ...)                                     \
        ((_addr)->family == AF_INET6 &&                                 \
         !memcmp(&(_addr)->address.in6, &(struct in6_addr) { .s6_addr = __VA_ARGS__}, 16) )

static void test_parse_etc_hosts(void) {
        _cleanup_(unlink_tempfilep) char
                t[] = "/tmp/test-resolved-etc-hosts.XXXXXX";

        log_info("/* %s */", __func__);

        int fd;
        _cleanup_fclose_ FILE *f;
        const char *s;

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
              "0.0.0.0 black.listed\n"
              "::5\t\t\t \tsome.where\tsome.other foobar.foo.foo\t\t\t\n"
              "        \n", f);
        assert_se(fflush_and_check(f) >= 0);
        rewind(f);

        _cleanup_(etc_hosts_free) EtcHosts hosts = {};
        assert_se(etc_hosts_parse(&hosts, f) == 0);

        EtcHostsItemByName *bn;
        assert_se(bn = hashmap_get(hosts.by_name, "some.where"));
        assert_se(bn->n_addresses == 3);
        assert_se(bn->n_allocated >= 3);
        assert_se(address_equal_4(bn->addresses[0], inet_addr("1.2.3.4")));
        assert_se(address_equal_4(bn->addresses[1], inet_addr("1.2.3.5")));
        assert_se(address_equal_6(bn->addresses[2], {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5}));

        assert_se(bn = hashmap_get(hosts.by_name, "dash"));
        assert_se(bn->n_addresses == 1);
        assert_se(bn->n_allocated >= 1);
        assert_se(address_equal_4(bn->addresses[0], inet_addr("1.2.3.6")));

        assert_se(bn = hashmap_get(hosts.by_name, "dash-dash.where-dash"));
        assert_se(bn->n_addresses == 1);
        assert_se(bn->n_allocated >= 1);
        assert_se(address_equal_4(bn->addresses[0], inet_addr("1.2.3.6")));

        /* See https://tools.ietf.org/html/rfc1035#section-2.3.1 */
        FOREACH_STRING(s, "bad-dash-", "-bad-dash", "-bad-dash.bad-")
                assert_se(!hashmap_get(hosts.by_name, s));

        assert_se(bn = hashmap_get(hosts.by_name, "before.comment"));
        assert_se(bn->n_addresses == 4);
        assert_se(bn->n_allocated >= 4);
        assert_se(address_equal_4(bn->addresses[0], inet_addr("1.2.3.9")));
        assert_se(address_equal_4(bn->addresses[1], inet_addr("1.2.3.10")));
        assert_se(address_equal_4(bn->addresses[2], inet_addr("1.2.3.11")));
        assert_se(address_equal_4(bn->addresses[3], inet_addr("1.2.3.12")));

        assert(!hashmap_get(hosts.by_name, "within.comment"));
        assert(!hashmap_get(hosts.by_name, "within.comment2"));
        assert(!hashmap_get(hosts.by_name, "within.comment3"));
        assert(!hashmap_get(hosts.by_name, "#"));

        assert(!hashmap_get(hosts.by_name, "short.address"));
        assert(!hashmap_get(hosts.by_name, "long.address"));
        assert(!hashmap_get(hosts.by_name, "multi.colon"));
        assert_se(!set_contains(hosts.no_address, "short.address"));
        assert_se(!set_contains(hosts.no_address, "long.address"));
        assert_se(!set_contains(hosts.no_address, "multi.colon"));

        assert_se(bn = hashmap_get(hosts.by_name, "some.other"));
        assert_se(bn->n_addresses == 1);
        assert_se(bn->n_allocated >= 1);
        assert_se(address_equal_6(bn->addresses[0], {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5}));

        assert_se( set_contains(hosts.no_address, "some.where"));
        assert_se( set_contains(hosts.no_address, "some.other"));
        assert_se( set_contains(hosts.no_address, "black.listed"));
        assert_se(!set_contains(hosts.no_address, "foobar.foo.foo"));
}

static void test_parse_file(const char *fname) {
        _cleanup_(etc_hosts_free) EtcHosts hosts = {};
        _cleanup_fclose_ FILE *f;

        log_info("/* %s(\"%s\") */", __func__, fname);

        assert_se(f = fopen(fname, "re"));
        assert_se(etc_hosts_parse(&hosts, f) == 0);
}

int main(int argc, char **argv) {
        test_setup_logging(LOG_DEBUG);

        if (argc == 1) {
                test_parse_etc_hosts_system();
                test_parse_etc_hosts();
        } else
                test_parse_file(argv[1]);

        return 0;
}
