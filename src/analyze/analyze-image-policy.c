/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "analyze.h"
#include "analyze-image-policy.h"
#include "ansi-color.h"
#include "format-table.h"
#include "image-policy.h"
#include "string-util.h"

static int table_add_designator_line(Table *table, PartitionDesignator d, PartitionPolicyFlags f) {
        _cleanup_free_ char *q = NULL;
        const char *color;
        int r;

        assert(table);
        assert(f >= 0);

        if (partition_policy_flags_to_string(f & _PARTITION_POLICY_USE_MASK, /* simplify= */ true, &q) < 0)
                return log_oom();

        color = (f & _PARTITION_POLICY_USE_MASK) == PARTITION_POLICY_IGNORE ? ansi_grey() :
                ((f & (PARTITION_POLICY_UNPROTECTED|PARTITION_POLICY_ENCRYPTED|PARTITION_POLICY_VERITY|PARTITION_POLICY_SIGNED|PARTITION_POLICY_ABSENT)) ==
                   (PARTITION_POLICY_UNPROTECTED|PARTITION_POLICY_ENCRYPTED|PARTITION_POLICY_VERITY|PARTITION_POLICY_SIGNED|PARTITION_POLICY_ABSENT)) ? ansi_highlight_yellow() :
                (f & _PARTITION_POLICY_USE_MASK) == PARTITION_POLICY_ABSENT ? ansi_highlight_red() :
                !(f & PARTITION_POLICY_UNPROTECTED) ? ansi_highlight_green() : NULL;

        if (d < 0)
                r = table_add_many(table,
                                   TABLE_STRING, "default",
                                   TABLE_SET_COLOR, ansi_highlight_green(),
                                   TABLE_STRING, q,
                                   TABLE_SET_COLOR, color);
        else
                r = table_add_many(table,
                                   TABLE_STRING, partition_designator_to_string(d),
                                   TABLE_SET_COLOR, ansi_normal(),
                                   TABLE_STRING, q,
                                   TABLE_SET_COLOR, color);
        if (r < 0)
                return table_log_add_error(r);

        switch (f & _PARTITION_POLICY_READ_ONLY_MASK) {

        case PARTITION_POLICY_READ_ONLY_ON:
                r = table_add_many(table, TABLE_BOOLEAN, true);
                break;

        case PARTITION_POLICY_READ_ONLY_OFF:
                r = table_add_many(table, TABLE_BOOLEAN, false);
                break;

        default:
                r = table_add_many(table, TABLE_EMPTY);
        }
        if (r < 0)
                return table_log_add_error(r);

        switch (f & _PARTITION_POLICY_GROWFS_MASK) {

        case PARTITION_POLICY_GROWFS_ON:
                r = table_add_many(table, TABLE_BOOLEAN, true);
                break;

        case PARTITION_POLICY_GROWFS_OFF:
                r = table_add_many(table, TABLE_BOOLEAN, false);
                break;

        default:
                r = table_add_many(table, TABLE_EMPTY);
        }
        if (r < 0)
                return table_log_add_error(r);

        return 0;
}

int verb_image_policy(int argc, char *argv[], void *userdata) {
        int r;

        for (int i = 1; i < argc; i++) {
                _cleanup_(table_unrefp) Table *table = NULL;
                _cleanup_(image_policy_freep) ImagePolicy *pbuf = NULL;
                _cleanup_free_ char *as_string = NULL, *as_string_simplified = NULL;
                const ImagePolicy *p;

                /* NB: The magic '@' strings are not officially documented for now, since we might change
                 * around defaults (and in particular where precisely to reuse policy). We should document
                 * them once the dust has settled a bit. For now it's just useful for debugging and
                 * introspect our own defaults without guaranteeing API safety. */
                if (streq(argv[i], "@sysext"))
                        p = &image_policy_sysext;
                else if (streq(argv[i], "@sysext-strict"))
                        p = &image_policy_sysext_strict;
                else if (streq(argv[i], "@confext"))
                        p = &image_policy_confext;
                else if (streq(argv[i], "@confext-strict"))
                        p = &image_policy_confext_strict;
                else if (streq(argv[i], "@container"))
                        p = &image_policy_container;
                else if (streq(argv[i], "@service"))
                        p = &image_policy_service;
                else if (streq(argv[i], "@host"))
                        p = &image_policy_host;
                else {
                        r = image_policy_from_string(argv[i], /* graceful= */ false, &pbuf);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse image policy '%s': %m", argv[i]);

                        p = pbuf;
                }

                r = image_policy_to_string(p, /* simplify= */ false, &as_string);
                if (r < 0)
                        return log_error_errno(r, "Failed to format policy '%s' as string: %m", argv[i]);

                r = image_policy_to_string(p, /* simplify= */ true, &as_string_simplified);
                if (r < 0)
                        return log_error_errno(r, "Failed to format policy '%s' as string: %m", argv[i]);

                pager_open(arg_pager_flags);

                if (streq(as_string, as_string_simplified))
                        printf("Analyzing policy: %s%s%s\n", ansi_highlight_magenta_underline(), as_string, ansi_normal());
                else
                        printf("Analyzing policy: %s%s%s\n"
                               "       Long form: %s%s%s\n",
                               ansi_highlight(), as_string_simplified, ansi_normal(),
                               ansi_grey(), as_string, ansi_normal());

                table = table_new("partition", "mode", "read-only", "growfs");
                if (!table)
                        return log_oom();

                (void) table_set_ersatz_string(table, TABLE_ERSATZ_DASH);

                for (PartitionDesignator d = 0; d < _PARTITION_DESIGNATOR_MAX; d++) {
                        PartitionPolicyFlags f = image_policy_get_exhaustively(p, d);
                        assert(f >= 0);

                        r = table_add_designator_line(table, d, f);
                        if (r < 0)
                                return r;
                }

                r = table_add_designator_line(table, _PARTITION_DESIGNATOR_INVALID, image_policy_default(p));
                if (r < 0)
                        return r;

                putc('\n', stdout);

                r = table_print(table, NULL);
                if (r < 0)
                        return r;
        }

        return EXIT_SUCCESS;
}
