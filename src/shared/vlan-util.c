/***
  This file is part of systemd.

  Copyright 2016 Lennart Poettering

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
#include "parse-util.h"
#include "string-util.h"
#include "vlan-util.h"

int parse_vlanid(const char *p, uint16_t *ret) {
        uint16_t id;
        int r;

        r = safe_atou16(p, &id);
        if (r < 0)
                return r;
        if (!vlanid_is_valid(id))
                return -ERANGE;

        *ret = id;
        return 0;
}

int config_parse_default_port_vlanid(
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
        uint16_t *id = data;

        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (streq(rvalue, "none")) {
                *id = 0;
                return 0;
        }

        return config_parse_vlanid(unit, filename, line, section, section_line,
                                   lvalue, ltype, rvalue, data, userdata);
}

int config_parse_vlanid(
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

        uint16_t *id = data;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = parse_vlanid(rvalue, id);
        if (r == -ERANGE) {
                log_syntax(unit, LOG_ERR, filename, line, r, "VLAN identifier outside of valid range 0…4094, ignoring: %s", rvalue);
                return 0;
        }
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to parse VLAN identifier value, ignoring: %s", rvalue);
                return 0;
        }

        return 0;
}
