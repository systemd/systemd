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

#include <ctype.h>

#include "conf-parser.h"
#include "def.h"
#include "dhcp-identifier.h"
#include "networkd-conf.h"
#include "string-table.h"

int manager_parse_config_file(Manager *m) {
        assert(m);

        return config_parse_many(PKGSYSCONFDIR "/networkd.conf",
                                 CONF_PATHS_NULSTR("systemd/networkd.conf.d"),
                                 "DUID\0",
                                 config_item_perf_lookup, networkd_gperf_lookup,
                                 false, m);
}

static const char* const dhcp_duid_type_table[_DHCP_DUID_TYPE_MAX] = {
        [DHCP_DUID_TYPE_RAW]  = "raw",
        [DHCP_DUID_TYPE_LLT]  = "link-layer-time",
        [DHCP_DUID_TYPE_EN]   = "vendor",
        [DHCP_DUID_TYPE_LL]   = "link-layer",
        [DHCP_DUID_TYPE_UUID] = "uuid"
};
DEFINE_PRIVATE_STRING_TABLE_LOOKUP_FROM_STRING(dhcp_duid_type, DHCPDUIDType);
DEFINE_CONFIG_PARSE_ENUM(config_parse_dhcp_duid_type, dhcp_duid_type, DHCPDUIDType, "Failed to parse DHCP DUID type");

int config_parse_dhcp_duid_raw(
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
        int r;
        long byte;
        char *cbyte, *pnext;
        const char *pduid = (const char *)rvalue;
        size_t count = 0, duid_len = 0;
        Manager *m = userdata;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(m);
        assert(m->dhcp_duid_type != _DHCP_DUID_TYPE_INVALID);

        switch (m->dhcp_duid_type) {
        case DHCP_DUID_TYPE_LLT:
                /* RawData contains DUID-LLT link-layer address (offset 6) */
                duid_len = 6;
                break;
        case DHCP_DUID_TYPE_EN:
                /* RawData contains DUID-EN identifier (offset 4) */
                duid_len = 4;
                break;
        case DHCP_DUID_TYPE_LL:
                /* RawData contains DUID-LL link-layer address (offset 2) */
                duid_len = 2;
                break;
        case DHCP_DUID_TYPE_UUID:
                /* RawData specifies UUID (offset 0) - fall thru */
        case DHCP_DUID_TYPE_RAW:
                /* First two bytes of RawData is DUID Type - fall thru */
        default:
                break;
        }

        if (m->dhcp_duid_type != DHCP_DUID_TYPE_RAW)
                m->dhcp_duid.type = htobe16(m->dhcp_duid_type);

        /* RawData contains DUID in format " NN:NN:NN... " */
        while (true) {
                r = extract_first_word(&pduid, &cbyte, ":", 0);
                if (r < 0) {
                        log_error("Failed to read DUID.");
                        return -EINVAL;
                }
                if (r == 0)
                        break;
                if (duid_len >= MAX_DUID_LEN) {
                        log_error("DUID length exceeds maximum length.");
                        return -EINVAL;
                }

                errno = 0;
                byte = strtol(cbyte, &pnext, 16);
                if ((errno == ERANGE && (byte == LONG_MAX || byte == LONG_MIN))
                    || (errno != 0 && byte == 0) || (cbyte == pnext)) {
                        log_error("Invalid DUID byte: %s.", cbyte);
                        return -EINVAL; 
                }

                /* If DHCP_DUID_TYPE_RAW, first two bytes holds DUID Type */
                if ((m->dhcp_duid_type == DHCP_DUID_TYPE_RAW) && (count < 2)) {
                        m->dhcp_duid.type |= (byte << (8 * count));
                        count++;
                        continue;
                }

                m->dhcp_duid.raw.data[duid_len++] = byte;
        }

        m->dhcp_duid_len = sizeof(m->dhcp_duid.type) + duid_len;

        return 0;
}
