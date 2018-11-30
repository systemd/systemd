/* SPDX-License-Identifier: LGPL-2.1+ */

#include "fd-util.h"
#include "fs-util.h"
#include "log.h"
#include "resolved-etc-hosts.h"
#include "tmpfile-util.h"

static void test_parse_etc_hosts_system(void) {
        _cleanup_fclose_ FILE *f = NULL;

        f = fopen("/etc/hosts", "re");
        if (!f) {
                assert_se(errno == -ENOENT);
                return;
        }

        _cleanup_(etc_hosts_free) EtcHosts hosts = {};
        assert_se(etc_hosts_parse(&hosts, f) == 0);
}

static void test_parse_etc_hosts(const char *fname) {
        _cleanup_(unlink_tempfilep) char
                t[] = "/tmp/test-resolved-etc-hosts.XXXXXX";

        int fd;
        _cleanup_fclose_ FILE *f;

        if (fname) {
                f = fopen(fname, "re");
                assert_se(f);
        } else {
                fd = mkostemp_safe(t);
                assert_se(fd >= 0);

                f = fdopen(fd, "r+");
                assert_se(f);
                fputs("1.2.3.4 some.where\n", f);
                fputs("1.2.3.5 some.where\n", f);
                fputs("::0 some.where some.other\n", f);
                fputs("0.0.0.0 black.listed\n", f);
                fputs("::5 some.where some.other foobar.foo.foo\n", f);
                fputs("        \n", f);
                fflush(f);
                rewind(f);
        }

        _cleanup_(etc_hosts_free) EtcHosts hosts = {};
        assert_se(etc_hosts_parse(&hosts, f) == 0);

        if (fname)
                return;

        EtcHostsItemByName *bn;
        assert_se(bn = hashmap_get(hosts.by_name, "some.where"));
        assert_se(bn->n_addresses == 3);
        assert_se(bn->n_allocated >= 3);

        assert_se(bn->addresses[0]->family == AF_INET);
        assert_se(memcmp(&bn->addresses[0]->address.in,
                         &(struct in_addr) { .s_addr = htobe32(0x01020304) }, 4) == 0);
        assert_se(bn->addresses[1]->family == AF_INET);
        assert_se(memcmp(&bn->addresses[1]->address.in,
                         &(struct in_addr) { .s_addr = htobe32(0x01020305) }, 4) == 0);
        assert_se(bn->addresses[2]->family == AF_INET6);
        assert_se(memcmp(&bn->addresses[2]->address.in6,
                         &(struct in6_addr) { .s6_addr = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5} }, 16 ) == 0);

        assert_se(bn = hashmap_get(hosts.by_name, "some.other"));
        assert_se(bn->n_addresses == 1);
        assert_se(bn->n_allocated >= 1);
        assert_se(bn->addresses[0]->family == AF_INET6);
        assert_se(memcmp(&bn->addresses[0]->address.in6,
                         &(struct in6_addr) { .s6_addr = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5} }, 16 ) == 0);

        assert_se( set_contains(hosts.no_address, "some.where"));
        assert_se( set_contains(hosts.no_address, "some.other"));
        assert_se( set_contains(hosts.no_address, "black.listed"));
        assert_se(!set_contains(hosts.no_address, "foobar.foo.foo"));
}

int main(int argc, char **argv) {
        log_set_max_level(LOG_DEBUG);
        log_parse_environment();
        log_open();

        if (argc == 1)
                test_parse_etc_hosts_system();
        test_parse_etc_hosts(argv[1]);

        return 0;
}
