/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "oomd-conf.h"
#include "conf-parser.h"
#include "log.h"
#include "oomd-manager.h"

static int arg_swap_used_limit_permyriad = -1;
static int arg_mem_pressure_limit_permyriad = -1;
static usec_t arg_mem_pressure_usec = DEFAULT_MEM_PRESSURE_DURATION_USEC;

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
        assert(m);

        int r;

        m->swap_used_limit_permyriad = DEFAULT_SWAP_USED_LIMIT_PERCENT * 100;
        r = store_loadavg_fixed_point(DEFAULT_MEM_PRESSURE_LIMIT_PERCENT, 0, &m->default_mem_pressure_limit);
        if (r < 0)
                return r;
        m->default_mem_pressure_duration_usec = DEFAULT_MEM_PRESSURE_DURATION_USEC;

        return 0;
}

int manager_parse_config_file(Manager *m) {
        assert(m);

        unsigned long l, f;
        int r;

        static const ConfigTableItem items[] = {
                { "OOM", "SwapUsedLimit", config_parse_permyriad, 0, &arg_swap_used_limit_permyriad },
                { "OOM", "DefaultMemoryPressureLimit", config_parse_permyriad, 0, &arg_mem_pressure_limit_permyriad },
                { "OOM", "DefaultMemoryPressureDurationSec", config_parse_duration, 0, &arg_mem_pressure_usec },
                {}
        };

        r = config_parse_standard_file_with_dropins(
                        "systemd/oomd.conf",
                        "OOM\0",
                        config_item_table_lookup,
                        items,
                        CONFIG_PARSE_WARN,
                        /* userdata= */ NULL);
        if (r < 0)
                return r;

        m->swap_used_limit_permyriad = arg_swap_used_limit_permyriad >= 0 ?
                        arg_swap_used_limit_permyriad :
                        DEFAULT_SWAP_USED_LIMIT_PERCENT * 100;
        assert(m->swap_used_limit_permyriad <= 10000);

        if (arg_mem_pressure_limit_permyriad >= 0) {
                assert(arg_mem_pressure_limit_permyriad <= 10000);

                l = arg_mem_pressure_limit_permyriad / 100;
                f = arg_mem_pressure_limit_permyriad % 100;
        } else {
                l = DEFAULT_MEM_PRESSURE_LIMIT_PERCENT;
                f = 0;
        }
        r = store_loadavg_fixed_point(l, f, &m->default_mem_pressure_limit);
        if (r < 0)
                return r;

        m->default_mem_pressure_duration_usec = arg_mem_pressure_usec;

        return 0;
}
