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

#include "alloc-util.h"
#include "conf-parser.h"
#include "def.h"
#include "extract-word.h"
#include "parse-util.h"
#include "resolved-conf.h"
#include "string-util.h"

int manager_add_dns_server_by_string(Manager *m, DnsServerType type, const char *word) {
        union in_addr_union address;
        int family, r;
        DnsServer *s;

        assert(m);
        assert(word);

        r = in_addr_from_string_auto(word, &family, &address);
        if (r < 0)
                return r;

        /* Filter out duplicates */
        s = manager_find_dns_server(m, type, family, &address);
        if (s) {
                /*
                 * Drop the marker. This is used to find the servers
                 * that ceased to exist, see
                 * manager_mark_dns_servers() and
                 * manager_flush_marked_dns_servers().
                 */
                s->marked = false;
                return 0;
        }

        return dns_server_new(m, NULL, type, NULL, family, &address);
}

int manager_parse_dns_server_string_and_warn(Manager *m, DnsServerType type, const char *string) {
        int r;

        assert(m);
        assert(string);

        for(;;) {
                _cleanup_free_ char *word = NULL;

                r = extract_first_word(&string, &word, NULL, 0);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                r = manager_add_dns_server_by_string(m, type, word);
                if (r < 0) {
                        log_warning_errno(r, "Failed to add DNS server address '%s', ignoring.", word);
                        continue;
                }
        }

        return 0;
}

int config_parse_dns_servers(
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
                /* Otherwise, add to the list */
                r = manager_parse_dns_server_string_and_warn(m, ltype, rvalue);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r, "Failed to parse DNS server string '%s'. Ignoring.", rvalue);
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
                        log_syntax(unit, LOG_ERR, filename, line, r, "Failed to parse support level '%s'. Ignoring.", rvalue);
                        return 0;
                }

                support = r ? SUPPORT_YES : SUPPORT_NO;
        }

        *v = support;
        return 0;
}

int manager_parse_config_file(Manager *m) {
        assert(m);

        return config_parse_many(PKGSYSCONFDIR "/resolved.conf",
                                 CONF_PATHS_NULSTR("systemd/resolved.conf.d"),
                                 "Resolve\0",
                                 config_item_perf_lookup, resolved_gperf_lookup,
                                 false, m);
}
