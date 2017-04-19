/***
  This file is part of systemd.

  Copyright 2014 Vinay Kulkarni <kulkarniv@vmware.com>

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

#include <ctype.h>

#include "conf-parser.h"
#include "def.h"
#include "dhcp-identifier.h"
#include "extract-word.h"
#include "hexdecoct.h"
#include "networkd-conf.h"
#include "networkd-network.h"
#include "string-table.h"

int manager_parse_config_file(Manager *m) {
        assert(m);

        return config_parse_many_nulstr(PKGSYSCONFDIR "/networkd.conf",
                                        CONF_PATHS_NULSTR("systemd/networkd.conf.d"),
                                        "DHCP\0",
                                        config_item_perf_lookup, networkd_gperf_lookup,
                                        false, m);
}

static const char* const duid_type_table[_DUID_TYPE_MAX] = {
        [DUID_TYPE_LLT]  = "link-layer-time",
        [DUID_TYPE_EN]   = "vendor",
        [DUID_TYPE_LL]   = "link-layer",
        [DUID_TYPE_UUID] = "uuid",
};
DEFINE_PRIVATE_STRING_TABLE_LOOKUP_FROM_STRING(duid_type, DUIDType);
DEFINE_CONFIG_PARSE_ENUM(config_parse_duid_type, duid_type, DUIDType, "Failed to parse DUID type");

int config_parse_duid_rawdata(
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

        DUID *ret = data;
        uint8_t raw_data[MAX_DUID_LEN];
        unsigned count = 0;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(ret);

        /* RawData contains DUID in format "NN:NN:NN..." */
        for (;;) {
                int n1, n2, len, r;
                uint32_t byte;
                _cleanup_free_ char *cbyte = NULL;

                r = extract_first_word(&rvalue, &cbyte, ":", 0);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r, "Failed to read DUID, ignoring assignment: %s.", rvalue);
                        return 0;
                }
                if (r == 0)
                        break;
                if (count >= MAX_DUID_LEN) {
                        log_syntax(unit, LOG_ERR, filename, line, 0, "Max DUID length exceeded, ignoring assignment: %s.", rvalue);
                        return 0;
                }

                len = strlen(cbyte);
                if (len != 1 && len != 2) {
                        log_syntax(unit, LOG_ERR, filename, line, 0, "Invalid length - DUID byte: %s, ignoring assignment: %s.", cbyte, rvalue);
                        return 0;
                }
                n1 = unhexchar(cbyte[0]);
                if (len == 2)
                        n2 = unhexchar(cbyte[1]);
                else
                        n2 = 0;

                if (n1 < 0 || n2 < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, 0, "Invalid DUID byte: %s. Ignoring assignment: %s.", cbyte, rvalue);
                        return 0;
                }

                byte = ((uint8_t) n1 << (4 * (len-1))) | (uint8_t) n2;
                raw_data[count++] = byte;
        }

        assert_cc(sizeof(raw_data) == sizeof(ret->raw_data));
        memcpy(ret->raw_data, raw_data, count);
        ret->raw_data_len = count;
        return 0;
}
