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
#include "hexdecoct.h"
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
        int r, n1, n2, byte;
        char *cbyte;
        const char *pduid = rvalue;
        Manager *m = userdata;
        Network *n = userdata;
        DUIDType duidtype;
        uint16_t dhcp_duid_type = 0;
        uint8_t dhcp_duid[MAX_DUID_LEN];
        size_t len, count = 0, duid_start_offset = 0, dhcp_duid_len = 0;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(userdata);

        duidtype = (ltype == DUID_CONFIG_SOURCE_GLOBAL) ? m->duid_type
                                                        : n->duid_type;

        if (duidtype == _DUID_TYPE_INVALID)
                duidtype = DUID_TYPE_RAW;

        switch (duidtype) {
        case DUID_TYPE_LLT:
                /* RawData contains DUID-LLT link-layer address (offset 6) */
                duid_start_offset = 6;
                break;
        case DUID_TYPE_EN:
                /* RawData contains DUID-EN identifier (offset 4) */
                duid_start_offset = 4;
                break;
        case DUID_TYPE_LL:
                /* RawData contains DUID-LL link-layer address (offset 2) */
                duid_start_offset = 2;
                break;
        case DUID_TYPE_UUID:
                /* RawData specifies UUID (offset 0) - fall thru */
        case DUID_TYPE_RAW:
                /* First two bytes of RawData is DUID Type - fall thru */
        default:
                break;
        }

        if (duidtype != DUID_TYPE_RAW)
                dhcp_duid_type = (uint16_t)duidtype;

        /* RawData contains DUID in format " NN:NN:NN... " */
        for (;;) {
                r = extract_first_word(&pduid, &cbyte, ":", 0);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r,
                                   "Failed to read DUID, ignoring assignment: %s.", rvalue);
                        goto exit;
                }
                if (r == 0)
                        break;
                if ((duid_start_offset + dhcp_duid_len) >= MAX_DUID_LEN) {
                        log_syntax(unit, LOG_ERR, filename, line, 0,
                                   "Max DUID length exceeded, ignoring assignment: %s.", rvalue);
                        goto exit;
                }

                len = strlen(cbyte);
                if ((len == 0) || (len > 2)) {
                        log_syntax(unit, LOG_ERR, filename, line, 0,
                                   "Invalid length - DUID byte: %s, ignoring assignment: %s.", cbyte, rvalue);
                        goto exit;
                }
                n2 = 0;
                n1 = unhexchar(cbyte[0]);
                if (len == 2)
                        n2 = unhexchar(cbyte[1]);
                if ((n1 < 0) || (n2 < 0)) {
                        log_syntax(unit, LOG_ERR, filename, line, 0,
                                   "Invalid DUID byte: %s. Ignoring assignment: %s.", cbyte, rvalue);
                        goto exit;
                }
                byte = (n1 << (4 * (len-1))) | n2;

                /* If DUID_TYPE_RAW, first two bytes hold DHCP DUID type code */
                if ((duidtype == DUID_TYPE_RAW) && (count < 2)) {
                        dhcp_duid_type |= (byte << (8 * (1 - count)));
                        count++;
                        continue;
                }

                dhcp_duid[duid_start_offset + dhcp_duid_len] = byte;
                dhcp_duid_len++;
        }

        if (ltype == DUID_CONFIG_SOURCE_GLOBAL) {
                m->duid_type = duidtype;
                m->dhcp_duid_type = dhcp_duid_type;
                m->dhcp_duid_len = dhcp_duid_len;
                memcpy(&m->dhcp_duid[duid_start_offset], dhcp_duid, dhcp_duid_len);
        } else {
                /* DUID_CONFIG_SOURCE_NETWORK */
                n->duid_type = duidtype;
                n->dhcp_duid_type = dhcp_duid_type;
                n->dhcp_duid_len = dhcp_duid_len;
                memcpy(&n->dhcp_duid[duid_start_offset], dhcp_duid, dhcp_duid_len);
        }

exit:
        return 0;
}
