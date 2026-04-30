/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>

#include "format-table.h"
#include "help-util.h"
#include "hwdb-util.h"
#include "log.h"
#include "options.h"
#include "udevadm.h"

static const char *arg_test = NULL;
static const char *arg_root = NULL;
static const char *arg_hwdb_bin_dir = NULL;
static bool arg_update = false;
static bool arg_strict = false;

static int help(void) {
        _cleanup_(table_unrefp) Table *options = NULL;
        int r;

        r = option_parser_get_help_table_ns("udevadm-hwdb", &options);
        if (r < 0)
                return r;

        help_cmdline("hwdb [OPTIONS]");
        help_abstract("Update or query the hardware database.");
        help_section("Options:");
        r = table_print_or_warn(options);
        if (r < 0)
                return r;

        printf("\nNOTE:\n"
               "The sub-command 'hwdb' is deprecated, and is left for backwards compatibility.\n"
               "Please use systemd-hwdb instead.\n");
        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        assert(argc >= 0);
        assert(argv);

        OptionParser opts = { argc, argv, .namespace = "udevadm-hwdb" };

        FOREACH_OPTION_OR_RETURN(c, &opts)
                switch (c) {

                OPTION_NAMESPACE("udevadm-hwdb"): {}

                OPTION_COMMON_HELP:
                        return help();

                OPTION('V', "version", NULL, "Show package version"):
                        return print_version();

                OPTION('u', "update", NULL, "Update the hardware database"):
                        arg_update = true;
                        break;

                OPTION('s', "strict", NULL,
                       "When updating, return non-zero exit value on any parsing error"):
                        arg_strict = true;
                        break;

                OPTION_LONG("usr", NULL,
                            "Generate in " UDEVLIBEXECDIR " instead of /etc/udev"):
                        arg_hwdb_bin_dir = UDEVLIBEXECDIR;
                        break;

                OPTION('t', "test", "MODALIAS", "Query database and print result"):
                        arg_test = opts.arg;
                        break;

                OPTION('r', "root", "PATH", "Alternative root path in the filesystem"):
                        arg_root = opts.arg;
                        break;
                }

        return 1;
}

int verb_hwdb_main(int argc, char *argv[], uintptr_t _data, void *userdata) {
        int r;

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        if (!arg_update && !arg_test)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Either --update or --test must be used.");

        log_notice("udevadm hwdb is deprecated. Use systemd-hwdb instead.");

        if (arg_update && !hwdb_bypass()) {
                r = hwdb_update(arg_root, arg_hwdb_bin_dir, arg_strict, true);
                if (r < 0)
                        return r;
        }

        if (arg_test)
                return hwdb_query(arg_test, NULL);

        return 0;
}
