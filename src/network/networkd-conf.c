/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

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

static const char* const duid_type_table[_DUID_TYPE_MAX] = {
        [DUID_TYPE_RAW]  = "raw",
        [DUID_TYPE_LLT]  = "link-layer-time",
        [DUID_TYPE_EN]   = "vendor",
        [DUID_TYPE_LL]   = "link-layer",
        [DUID_TYPE_UUID] = "uuid"
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
        int r;
        long byte;
        char *cbyte, *pnext;
        const char *pduid = rvalue;
        size_t count = 0, duid_index = 0;
        Manager *m;
        Network *n;
        DUIDType *duid_type;
        uint16_t *dhcp_duid_type;
        size_t *dhcp_duid_len;
        uint8_t *dhcp_duid;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(userdata);

        if (ltype == DUID_CONFIG_SOURCE_GLOBAL) {
                m = userdata;
                duid_type = &m->duid_type;
                dhcp_duid_type = &m->dhcp_duid_type;
                dhcp_duid_len = &m->dhcp_duid_len;
                dhcp_duid = m->dhcp_duid;
        } else {
                /* DUID_CONFIG_SOURCE_NETWORK */
                n = userdata;
                duid_type = &n->duid_type;
                dhcp_duid_type = &n->dhcp_duid_type;
                dhcp_duid_len = &n->dhcp_duid_len;
                dhcp_duid = n->dhcp_duid;
        }

        if (*duid_type == _DUID_TYPE_INVALID)
                *duid_type = DUID_TYPE_RAW;

        switch (*duid_type) {
        case DUID_TYPE_LLT:
                /* RawData contains DUID-LLT link-layer address (offset 6) */
                duid_index = 6;
                break;
        case DUID_TYPE_EN:
                /* RawData contains DUID-EN identifier (offset 4) */
                duid_index = 4;
                break;
        case DUID_TYPE_LL:
                /* RawData contains DUID-LL link-layer address (offset 2) */
                duid_index = 2;
                break;
        case DUID_TYPE_UUID:
                /* RawData specifies UUID (offset 0) - fall thru */
        case DUID_TYPE_RAW:
                /* First two bytes of RawData is DUID Type - fall thru */
        default:
                break;
        }

        if (*duid_type != DUID_TYPE_RAW)
                *dhcp_duid_type = (uint16_t)(*duid_type);

        /* RawData contains DUID in format " NN:NN:NN... " */
        while (true) {
                r = extract_first_word(&pduid, &cbyte, ":", 0);
                if (r < 0) {
                        log_error("Failed to read DUID.");
                        return -EINVAL;
                }
                if (r == 0)
                        break;
                if (duid_index >= MAX_DUID_LEN) {
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

                /* If DUID_TYPE_RAW, first two bytes hold DHCP DUID type code */
                if ((*duid_type == DUID_TYPE_RAW) && (count < 2)) {
                        *dhcp_duid_type |= (byte << (8 * (1 - count)));
                        count++;
                        continue;
                }

                dhcp_duid[duid_index++] = byte;
        }

        *dhcp_duid_len = duid_index;

        return 0;
}
