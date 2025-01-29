/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "conf-parser.h"
#include "constants.h"
#include "home-util.h"
#include "homed-conf.h"

int manager_parse_config_file(Manager *m) {

        assert(m);

        return config_parse_standard_file_with_dropins(
                        "systemd/homed.conf",
                        "Home\0",
                        config_item_perf_lookup, homed_gperf_lookup,
                        CONFIG_PARSE_WARN,
                        m);
}

DEFINE_CONFIG_PARSE_ENUM(config_parse_default_storage, user_storage, UserStorage);

int config_parse_default_file_system_type(
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

        char **s = ASSERT_PTR(data);

        assert(rvalue);

        if (!isempty(rvalue) && !supported_fstype(rvalue)) {
                log_syntax(unit, LOG_WARNING, filename, line, 0, "Unsupported file system, ignoring: %s", rvalue);
                return 0;
        }

        return free_and_strdup_warn(s, empty_to_null(rvalue));
}
