/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "conf-files.h"
#include "conf-parser.h"
#include "constants.h"
#include "log.h"
#include "oomd-conf.h"
#include "oomd-manager.h"
#include "parse-util.h"
#include "stat-util.h"
#include "string-util.h"
#include "strv.h"
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

static int ruleset_load_one(Manager *m, const char *filename) {
        _cleanup_free_ char *name = NULL;
        struct oom_ruleset *ruleset = NULL;
        int r;

        assert(m);
        assert(filename);

        r = null_or_empty_path(filename);
        if (r < 0)
                return log_warning_errno(r, "Failed to check if \"%s\" is empty: %m", filename);
        if (r > 0) {
                log_debug("Skipping empty file: %s", filename);
                return 0;
        }

        name = strdup(filename);
        if (!name)
                return log_oom();

        ruleset = new(struct oom_ruleset, 1);
        if (!ruleset)
                return log_oom();

        *ruleset = (struct oom_ruleset) {
                .name = TAKE_PTR(name),
        };

        return 0;
}

void manager_parse_config_file(Manager *m) {
        _cleanup_strv_free_ char **files = NULL;
        int r;

        assert(m);

        const ConfigTableItem items[] = {
                { "OOM", "SwapUsedLimit",                    config_parse_permyriad, 0, &m->swap_used_limit_permyriad          },
                { "OOM", "DefaultMemoryPressureLimit",       config_parse_loadavg,   0, &m->default_mem_pressure_limit         },
                { "OOM", "DefaultMemoryPressureDurationSec", config_parse_duration,  0, &m->default_mem_pressure_duration_usec },
                { "OOM", "EnablePrekillHook",                config_parse_bool,      0, &m->prekill_enabled                    },
                { "OOM", "PrekillHookTimeoutSec",            config_parse_sec,       0, &m->prekill_timeout                    },
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

        r = conf_files_list_strv(&files, ".oomrule", NULL, 0, RULESET_DIRS);
        if (r < 0) {
                log_error_errno(r, "failed to enumerate ruleset files: %m");
                return;
        }

        STRV_FOREACH_BACKWARDS(f, files)
                (void) ruleset_load_one(m, *f);
}
