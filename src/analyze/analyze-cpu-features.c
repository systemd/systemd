/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "analyze.h"
#include "analyze-cpu-features.h"
#include "ansi-color.h"
#include "architecture.h"
#include "format-table.h"
#include "log.h"
#include "string-util.h"
#include "strv.h"
#include "virt.h"

static int add_feature(Table *table, const char *feature, bool known) {
        int r;

        assert(table);
        assert(feature);

        if (known) {
                bool has = has_cpu_with_flag(feature);

                r = table_add_many(table,
                                   TABLE_STRING, feature,
                                   TABLE_BOOLEAN_CHECKMARK, has,
                                   TABLE_SET_COLOR, ansi_highlight_green_red(has));
        } else
                r = table_add_many(table,
                                   TABLE_STRING, feature,
                                   TABLE_TRISTATE, -1,
                                   TABLE_SET_COLOR, ansi_grey());
        if (r < 0)
                return table_log_add_error(r);

        return 0;
}

int verb_cpu_features(int argc, char *argv[], uintptr_t _data, void *userdata) {
        int r;

        _cleanup_strv_free_ char **features = NULL;
        r = cpu_known_features(&features);
        if (r < 0)
                return log_oom();

        if (strv_isempty(features))
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "No known CPU features for the %s architecture.",
                                       architecture_to_string(native_architecture()));

        _cleanup_(table_unrefp) Table *table = table_new("name", "support");
        if (!table)
                return log_oom();

        (void) table_set_sort(table, (size_t) 0);
        table_set_ersatz_string(table, TABLE_ERSATZ_DASH);

        char **args = strv_skip(argv, 1);
        if (args)
                STRV_FOREACH(feat, args) {
                        _cleanup_free_ char *lower = strdup(*feat);
                        if (!lower)
                                return log_oom();

                        ascii_strlower(lower);
                        r = add_feature(table, lower, strv_contains(features, lower));
                        if (r < 0)
                                return r;
                }
        else
                STRV_FOREACH(feat, features) {
                        r = add_feature(table, *feat, /* known= */ true);
                        if (r < 0)
                                return r;
                }

        return table_print_with_pager(table, arg_json_format_flags, arg_pager_flags, arg_legend);
}
