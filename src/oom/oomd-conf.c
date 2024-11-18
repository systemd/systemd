/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "conf-parser.h"
#include "log.h"
#include "oomd-conf.h"
#include "oomd-manager.h"

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

int manager_set_defaults(Manager *m) {
        int r;

        assert(m);

        m->swap_used_limit_permyriad = DEFAULT_SWAP_USED_LIMIT_PERCENT * 100;
        r = store_loadavg_fixed_point(DEFAULT_MEM_PRESSURE_LIMIT_PERCENT, 0, &m->default_mem_pressure_limit);
        if (r < 0)
                return r;
        m->default_mem_pressure_duration_usec = DEFAULT_MEM_PRESSURE_DURATION_USEC;

        return 0;
}

int manager_parse_config_file(Manager *m) {
        unsigned long l, f;
        int r;
        int swap_used_limit_permyriad = -1;
        int mem_pressure_limit_permyriad = -1;
        usec_t mem_pressure_usec = DEFAULT_MEM_PRESSURE_DURATION_USEC;

        const ConfigTableItem items[] = {
                { "OOM", "SwapUsedLimit",                    config_parse_permyriad, 0, &swap_used_limit_permyriad },
                { "OOM", "DefaultMemoryPressureLimit",       config_parse_permyriad, 0, &mem_pressure_limit_permyriad },
                { "OOM", "DefaultMemoryPressureDurationSec", config_parse_duration,  0, &mem_pressure_usec },
                {}
        };

        assert(m);

        r = config_parse_standard_file_with_dropins(
                        "systemd/oomd.conf",
                        "OOM\0",
                        config_item_table_lookup,
                        items,
                        CONFIG_PARSE_WARN,
                        /* userdata= */ NULL);
        if (r < 0)
                return r;

        m->swap_used_limit_permyriad = swap_used_limit_permyriad >= 0 ?
                        swap_used_limit_permyriad :
                        DEFAULT_SWAP_USED_LIMIT_PERCENT * 100;
        assert(m->swap_used_limit_permyriad <= 10000);

        if (mem_pressure_limit_permyriad >= 0) {
                assert(mem_pressure_limit_permyriad <= 10000);

                l = mem_pressure_limit_permyriad / 100;
                f = mem_pressure_limit_permyriad % 100;
        } else {
                l = DEFAULT_MEM_PRESSURE_LIMIT_PERCENT;
                f = 0;
        }
        r = store_loadavg_fixed_point(l, f, &m->default_mem_pressure_limit);
        if (r < 0)
                return r;

        m->default_mem_pressure_duration_usec = mem_pressure_usec;

        return 0;
}
