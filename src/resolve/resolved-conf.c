/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2014 Tom Gundersen <teg@jklm.no>

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

#include "conf-parser.h"

#include "resolved-conf.h"

int manager_parse_dns_server(Manager *m, DnsServerType type, const char *string) {
        const char *word, *state;
        size_t length;
        DnsServer *first;
        int r;

        assert(m);
        assert(string);

        first = type == DNS_SERVER_FALLBACK ? m->fallback_dns_servers : m->dns_servers;

        FOREACH_WORD_QUOTED(word, length, string, state) {
                char buffer[length+1];
                int family;
                union in_addr_union addr;
                bool found = false;
                DnsServer *s;

                memcpy(buffer, word, length);
                buffer[length] = 0;

                r = in_addr_from_string_auto(buffer, &family, &addr);
                if (r < 0) {
                        log_warning("Ignoring invalid DNS address '%s'", buffer);
                        continue;
                }

                /* Filter out duplicates */
                LIST_FOREACH(servers, s, first)
                        if (s->family == family && in_addr_equal(family, &s->address, &addr)) {
                                found = true;
                                break;
                        }

                if (found)
                        continue;

                r = dns_server_new(m, NULL, type, NULL, family, &addr);
                if (r < 0)
                        return r;
        }

        return 0;
}

int config_parse_dnsv(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        Manager *m = userdata;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(m);

        if (isempty(rvalue))
                /* Empty assignment means clear the list */
                manager_flush_dns_servers(m, ltype);
        else {
                /* Otherwise add to the list */
                r = manager_parse_dns_server(m, ltype, rvalue);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, -r, "Failed to parse DNS server string '%s'. Ignoring.", rvalue);
                        return 0;
                }
        }

        /* If we have a manual setting, then we stop reading
         * /etc/resolv.conf */
        if (ltype == DNS_SERVER_SYSTEM)
                m->read_resolv_conf = false;

        return 0;
}

int config_parse_support(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        Support support, *v = data;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        support = support_from_string(rvalue);
        if (support < 0) {
                r = parse_boolean(rvalue);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, -r, "Failed to parse support level '%s'. Ignoring.", rvalue);
                        return 0;
                }

                support = r ? SUPPORT_YES : SUPPORT_NO;
        }

        *v = support;
        return 0;
}

int manager_parse_config_file(Manager *m) {
        assert(m);

        return config_parse_many("/etc/systemd/resolved.conf",
                                 CONF_DIRS_NULSTR("systemd/resolved.conf"),
                                 "Resolve\0",
                                 config_item_perf_lookup, resolved_gperf_lookup,
                                 false, m);
}
