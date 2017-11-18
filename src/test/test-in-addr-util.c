/* SPDX-License-Identifier: LGPL-2.1+ */
/***
  This file is part of systemd

  Copyright 2017 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <netinet/in.h>

#include "in-addr-util.h"

static void test_in_addr_prefix_from_string(const char *p, int family, int ret, const union in_addr_union *u, unsigned char prefixlen) {
        union in_addr_union q;
        unsigned char l;
        int r;

        r = in_addr_prefix_from_string(p, family, &q, &l);
        assert_se(r == ret);

        if (r >= 0) {
                int f;

                assert_se(in_addr_equal(family, &q, u));
                assert_se(l == prefixlen);

                r = in_addr_prefix_from_string_auto(p, &f, &q, &l);
                assert_se(r >= 0);

                assert_se(f == family);
                assert_se(in_addr_equal(family, &q, u));
                assert_se(l == prefixlen);
        }
}

int main(int argc, char *argv[]) {
        test_in_addr_prefix_from_string("", AF_INET, -EINVAL, NULL, 0);
        test_in_addr_prefix_from_string("/", AF_INET, -EINVAL, NULL, 0);
        test_in_addr_prefix_from_string("/8", AF_INET, -EINVAL, NULL, 0);
        test_in_addr_prefix_from_string("1.2.3.4", AF_INET, 0, &(union in_addr_union) { .in = (struct in_addr) { .s_addr = htobe32(0x01020304) } }, 32);
        test_in_addr_prefix_from_string("1.2.3.4/0", AF_INET, 0, &(union in_addr_union) { .in = (struct in_addr) { .s_addr = htobe32(0x01020304) } }, 0);
        test_in_addr_prefix_from_string("1.2.3.4/1", AF_INET, 0, &(union in_addr_union) { .in = (struct in_addr) { .s_addr = htobe32(0x01020304) } }, 1);
        test_in_addr_prefix_from_string("1.2.3.4/2", AF_INET, 0, &(union in_addr_union) { .in = (struct in_addr) { .s_addr = htobe32(0x01020304) } }, 2);
        test_in_addr_prefix_from_string("1.2.3.4/32", AF_INET, 0, &(union in_addr_union) { .in = (struct in_addr) { .s_addr = htobe32(0x01020304) } }, 32);
        test_in_addr_prefix_from_string("1.2.3.4/33", AF_INET, -ERANGE, NULL, 0);
        test_in_addr_prefix_from_string("1.2.3.4/-1", AF_INET, -ERANGE, NULL, 0);
        test_in_addr_prefix_from_string("::1", AF_INET, -EINVAL, NULL, 0);

        test_in_addr_prefix_from_string("", AF_INET6, -EINVAL, NULL, 0);
        test_in_addr_prefix_from_string("/", AF_INET6, -EINVAL, NULL, 0);
        test_in_addr_prefix_from_string("/8", AF_INET6, -EINVAL, NULL, 0);
        test_in_addr_prefix_from_string("::1", AF_INET6, 0, &(union in_addr_union) { .in6 = IN6ADDR_LOOPBACK_INIT }, 128);
        test_in_addr_prefix_from_string("::1/0", AF_INET6, 0, &(union in_addr_union) { .in6 = IN6ADDR_LOOPBACK_INIT }, 0);
        test_in_addr_prefix_from_string("::1/1", AF_INET6, 0, &(union in_addr_union) { .in6 = IN6ADDR_LOOPBACK_INIT }, 1);
        test_in_addr_prefix_from_string("::1/2", AF_INET6, 0, &(union in_addr_union) { .in6 = IN6ADDR_LOOPBACK_INIT }, 2);
        test_in_addr_prefix_from_string("::1/32", AF_INET6, 0, &(union in_addr_union) { .in6 = IN6ADDR_LOOPBACK_INIT }, 32);
        test_in_addr_prefix_from_string("::1/33", AF_INET6, 0, &(union in_addr_union) { .in6 = IN6ADDR_LOOPBACK_INIT }, 33);
        test_in_addr_prefix_from_string("::1/64", AF_INET6, 0, &(union in_addr_union) { .in6 = IN6ADDR_LOOPBACK_INIT }, 64);
        test_in_addr_prefix_from_string("::1/128", AF_INET6, 0, &(union in_addr_union) { .in6 = IN6ADDR_LOOPBACK_INIT }, 128);
        test_in_addr_prefix_from_string("::1/129", AF_INET6, -ERANGE, NULL, 0);
        test_in_addr_prefix_from_string("::1/-1", AF_INET6, -ERANGE, NULL, 0);

        return 0;
}
