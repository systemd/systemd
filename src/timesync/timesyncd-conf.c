/* SPDX-License-Identifier: LGPL-2.1+ */
/***
  This file is part of systemd.

  Copyright 2014 Kay Sievers, Lennart Poettering

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
#include "def.h"
#include "extract-word.h"
#include "string-util.h"
#include "timesyncd-conf.h"
#include "timesyncd-manager.h"
#include "timesyncd-server.h"

int manager_parse_server_string(Manager *m, ServerType type, const char *string) {
        ServerName *first;
        int r;

        assert(m);
        assert(string);

        first = type == SERVER_FALLBACK ? m->fallback_servers : m->system_servers;

        if (type == SERVER_FALLBACK)
                 m->have_fallbacks = true;

        for (;;) {
                _cleanup_free_ char *word = NULL;
                bool found = false;
                ServerName *n;

                r = extract_first_word(&string, &word, NULL, 0);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse timesyncd server syntax \"%s\": %m", string);
                if (r == 0)
                        break;

                /* Filter out duplicates */
                LIST_FOREACH(names, n, first)
                        if (streq_ptr(n->string, word)) {
                                found = true;
                                break;
                        }

                if (found)
                        continue;

                r = server_name_new(m, NULL, type, word);
                if (r < 0)
                        return r;
        }

        return 0;
}

int manager_parse_fallback_string(Manager *m, const char *string) {
        if (m->have_fallbacks)
                return 0;

        return manager_parse_server_string(m, SERVER_FALLBACK, string);
}

int config_parse_servers(
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

        if (isempty(rvalue))
                manager_flush_server_names(m, ltype);
        else {
                r = manager_parse_server_string(m, ltype, rvalue);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r, "Failed to parse NTP server string '%s'. Ignoring.", rvalue);
                        return 0;
                }
        }

        return 0;
}

int manager_parse_config_file(Manager *m) {
        int r;

        assert(m);

        r = config_parse_many_nulstr(PKGSYSCONFDIR "/timesyncd.conf",
                                     CONF_PATHS_NULSTR("systemd/timesyncd.conf.d"),
                                     "Time\0",
                                     config_item_perf_lookup, timesyncd_gperf_lookup,
                                     CONFIG_PARSE_WARN, m);
        if (r < 0)
                return r;

        if (m->poll_interval_min_usec < 16 * USEC_PER_SEC) {
                log_warning("Invalid PollIntervalMinSec=. Using default value.");
                m->poll_interval_min_usec = NTP_POLL_INTERVAL_MIN_USEC;
        }

        if (m->poll_interval_max_usec < m->poll_interval_min_usec) {
                log_warning("PollIntervalMaxSec= is smaller than PollIntervalMinSec=. Using default value.");
                m->poll_interval_max_usec = MAX(NTP_POLL_INTERVAL_MAX_USEC, m->poll_interval_min_usec * 32);
        }

        return r;
}
