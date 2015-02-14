/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

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


#include "timesyncd-manager.h"
#include "timesyncd-server.h"
#include "timesyncd-conf.h"

int manager_parse_server_string(Manager *m, ServerType type, const char *string) {
        const char *word, *state;
        size_t length;
        ServerName *first;
        int r;

        assert(m);
        assert(string);

        first = type == SERVER_FALLBACK ? m->fallback_servers : m->system_servers;

        FOREACH_WORD_QUOTED(word, length, string, state) {
                char buffer[length+1];
                bool found = false;
                ServerName *n;

                memcpy(buffer, word, length);
                buffer[length] = 0;

                /* Filter out duplicates */
                LIST_FOREACH(names, n, first)
                        if (streq_ptr(n->string, buffer)) {
                                found = true;
                                break;
                        }

                if (found)
                        continue;

                r = server_name_new(m, NULL, type, buffer);
                if (r < 0)
                        return r;
        }

        return 0;
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
                        log_syntax(unit, LOG_ERR, filename, line, -r, "Failed to parse NTP server string '%s'. Ignoring.", rvalue);
                        return 0;
                }
        }

        return 0;
}

int manager_parse_config_file(Manager *m) {
        assert(m);

        return config_parse_many("/etc/systemd/timesyncd.conf",
                                 CONF_DIRS_NULSTR("systemd/timesyncd.conf"),
                                 "Time\0",
                                 config_item_perf_lookup, timesyncd_gperf_lookup,
                                 false, m);
}
