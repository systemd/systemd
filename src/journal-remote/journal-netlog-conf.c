/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2015 Susant Sahani

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

#include "in-addr-util.h"
#include "journal-netlog-conf.h"

int config_parse_netlog_remote_address(const char *unit,
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
        assert(data);

        r = socket_address_parse(&m->address, rvalue);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, -r,
                           "Failed to parse address value, ignoring: %s", rvalue);
                return 0;
        }

        return 0;
}

int manager_parse_config_file(Manager *m) {
        assert(m);

        return config_parse_many("/etc/systemd/journal-netlogd.conf",
                                 CONF_DIRS_NULSTR("systemd/journal-netlogd.conf"),
                                 "Network\0",
                                 config_item_perf_lookup, journal_netlog_gperf_lookup,
                                 false, m);
}
