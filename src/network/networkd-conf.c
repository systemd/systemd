/* SPDX-License-Identifier: LGPL-2.1+ */
/***
  Copyright © 2014 Vinay Kulkarni <kulkarniv@vmware.com>
 ***/

#include <ctype.h>

#include "conf-parser.h"
#include "def.h"
#include "dhcp-identifier.h"
#include "extract-word.h"
#include "hexdecoct.h"
#include "networkd-conf.h"
#include "networkd-manager.h"
#include "networkd-network.h"
#include "networkd-speed-meter.h"
#include "string-table.h"

int manager_parse_config_file(Manager *m) {
        int r;

        assert(m);

        r = config_parse_many_nulstr(PKGSYSCONFDIR "/networkd.conf",
                                     CONF_PATHS_NULSTR("systemd/networkd.conf.d"),
                                     "Network\0DHCP\0",
                                     config_item_perf_lookup, networkd_gperf_lookup,
                                     CONFIG_PARSE_WARN, m);
        if (r < 0)
                return r;

        if (m->use_speed_meter && m->speed_meter_interval_usec < SPEED_METER_MINIMUM_TIME_INTERVAL) {
                char buf[FORMAT_TIMESPAN_MAX];

                log_warning("SpeedMeterIntervalSec= is too small, using %s.",
                            format_timespan(buf, sizeof buf, SPEED_METER_MINIMUM_TIME_INTERVAL, USEC_PER_SEC));
                m->speed_meter_interval_usec = SPEED_METER_MINIMUM_TIME_INTERVAL;
        }

        return 0;
}

static const char* const duid_type_table[_DUID_TYPE_MAX] = {
        [DUID_TYPE_LLT]  = "link-layer-time",
        [DUID_TYPE_EN]   = "vendor",
        [DUID_TYPE_LL]   = "link-layer",
        [DUID_TYPE_UUID] = "uuid",
};
DEFINE_PRIVATE_STRING_TABLE_LOOKUP_FROM_STRING(duid_type, DUIDType);

int config_parse_duid_type(
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

        _cleanup_free_ char *type_string = NULL;
        const char *p = rvalue;
        DUID *duid = data;
        DUIDType type;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(duid);

        r = extract_first_word(&p, &type_string, ":", 0);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Invalid syntax, ignoring: %s", rvalue);
                return 0;
        }
        if (r == 0) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Failed to extract DUID type from '%s', ignoring.", rvalue);
                return 0;
        }

        type = duid_type_from_string(type_string);
        if (type < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Failed to parse DUID type '%s', ignoring.", type_string);
                return 0;
        }

        if (!isempty(p)) {
                usec_t u;

                if (type != DUID_TYPE_LLT) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Invalid syntax, ignoring: %s", rvalue);
                        return 0;
                }

                r = parse_timestamp(p, &u);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to parse timestamp, ignoring: %s", p);
                        return 0;
                }

                duid->llt_time = u;
        }

        duid->type = type;

        return 0;
}

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
                if (!IN_SET(len, 1, 2)) {
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
