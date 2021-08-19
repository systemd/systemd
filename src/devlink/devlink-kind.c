/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "string-table.h"

#include "devlink-kind.h"

static const char* const devlink_kind_table[_DEVLINK_KIND_MAX] = {
};

DEFINE_STRING_TABLE_LOOKUP(devlink_kind, DevlinkKind);

int config_parse_devlink_kind(
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
        DevlinkKind k, *kind = data;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        k = devlink_kind_from_string(rvalue);
        if (k < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, k, "Failed to parse devlink kind, ignoring assignment: %s", rvalue);
                return 0;
        }

        if (*kind != _DEVLINK_KIND_INVALID && *kind != k) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Specified devlink kind is different from the previous value '%s', ignoring assignment: %s",
                           devlink_kind_to_string(*kind), rvalue);
                return 0;
        }

        *kind = k;

        return 0;
}
