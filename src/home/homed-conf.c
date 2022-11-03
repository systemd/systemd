/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "conf-parser.h"
#include "def.h"
#include "home-util.h"
#include "homed-conf.h"

int manager_parse_config_file(Manager *m) {
        int r;

        assert(m);

        r = config_parse_many_nulstr(
                        PKGSYSCONFDIR "/homed.conf",
                        CONF_PATHS_NULSTR("systemd/homed.conf.d"),
                        "Home\0",
                        config_item_perf_lookup, homed_gperf_lookup,
                        CONFIG_PARSE_WARN,
                        m,
                        NULL);
        if (r < 0)
                return r;

        return 0;

}

DEFINE_CONFIG_PARSE_ENUM(config_parse_default_storage, user_storage, UserStorage, "Failed to parse default storage setting");

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
