/***
  This file is part of systemd

  Copyright 2013 Zbigniew Jędrzejewski-Szmek

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

#include "dns-type.h"
#include "test-tables.h"

int main(int argc, char **argv) {
        uint16_t i;

        test_table_sparse(dns_type, DNS_TYPE);

        log_info("/* DNS_TYPE */");
        for (i = 0; i < _DNS_TYPE_MAX; i++) {
                const char *s;

                s = dns_type_to_string(i);
                assert_se(s == NULL || strlen(s) < _DNS_TYPE_STRING_MAX);

                if (s)
                        log_info("%-*s %s%s%s%s%s%s%s%s",
                                 (int) _DNS_TYPE_STRING_MAX - 1, s,
                                 dns_type_is_pseudo(i) ? "pseudo " : "",
                                 dns_type_is_valid_query(i) ? "valid_query " : "",
                                 dns_type_is_valid_rr(i) ? "is_valid_rr " : "",
                                 dns_type_may_redirect(i) ? "may_redirect " : "",
                                 dns_type_is_dnssec(i) ? "dnssec " : "",
                                 dns_type_is_obsolete(i) ? "obsolete " : "",
                                 dns_type_may_wildcard(i) ? "wildcard " : "",
                                 dns_type_apex_only(i) ? "apex_only " : "");
        }

        log_info("/* DNS_CLASS */");
        for (i = 0; i < _DNS_CLASS_MAX; i++) {
                const char *s;

                s = dns_class_to_string(i);
                assert_se(s == NULL || strlen(s) < _DNS_CLASS_STRING_MAX);

                if (s)
                        log_info("%-*s %s%s",
                                 (int) _DNS_CLASS_STRING_MAX - 1, s,
                                 dns_class_is_pseudo(i) ? "is_pseudo " : "",
                                 dns_class_is_valid_rr(i) ? "is_valid_rr " : "");
        }

        return EXIT_SUCCESS;
}
