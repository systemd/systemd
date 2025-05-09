/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "conf-parser.h"
#include "log.h"
#include "oomd-conf.h"
#include "oomd-manager.h"
#include "parse-util.h"
#include "string-util.h"
#include "time-util.h"

static int config_parse_duration(
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

        usec_t usec, *duration = ASSERT_PTR(data);
        int r;

        if (isempty(rvalue)) {
                *duration = DEFAULT_MEM_PRESSURE_DURATION_USEC;
                return 0;
        }

        r = parse_sec(rvalue, &usec);
        if (r < 0)
                return log_syntax_parse_error(unit, filename, line, r, lvalue, rvalue);

        if (usec == 0) {
                /* Map zero -> default for backwards compatibility. */
                *duration = DEFAULT_MEM_PRESSURE_DURATION_USEC;
                return 0;
        }

        if (usec < 1 * USEC_PER_SEC || usec == USEC_INFINITY)
                return log_syntax(
                                unit,
                                LOG_WARNING,
                                filename,
                                line,
                                0,
                                "%s= must be at least 1s and less than infinity, ignoring: %s",
                                lvalue,
                                rvalue);

        *duration = usec;
        return 0;
}

void manager_set_defaults(Manager *m) {
        int r;

        assert(m);

        m->default_mem_pressure_duration_usec = DEFAULT_MEM_PRESSURE_DURATION_USEC;

        m->swap_used_limit_permyriad = DEFAULT_SWAP_USED_LIMIT_PERCENT * 100;
        r = store_loadavg_fixed_point(DEFAULT_MEM_PRESSURE_LIMIT_PERCENT, 0, &m->default_mem_pressure_limit);
        if (r < 0)
                log_warning_errno(r, "Failed to set default for default_mem_pressure_limit, ignoring: %m");
}

void manager_parse_config_file(Manager *m) {
        int r;

        assert(m);

        const ConfigTableItem items[] = {
                { "OOM", "SwapUsedLimit",                    config_parse_permyriad, 0, &m->swap_used_limit_permyriad          },
                { "OOM", "DefaultMemoryPressureLimit",       config_parse_loadavg,   0, &m->default_mem_pressure_limit         },
                { "OOM", "DefaultMemoryPressureDurationSec", config_parse_duration,  0, &m->default_mem_pressure_duration_usec },
                {}
        };

        r = config_parse_standard_file_with_dropins(
                        "systemd/oomd.conf",
                        "OOM\0",
                        config_item_table_lookup,
                        items,
                        CONFIG_PARSE_WARN,
                        /* userdata= */ m);
        if (r >= 0)
                log_debug("Config file successfully parsed.");
}
