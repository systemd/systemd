/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "build.h"
#include "format-table.h"
#include "hwdb-util.h"
#include "label-util.h"
#include "log.h"
#include "main-func.h"
#include "options.h"
#include "pretty-print.h"
#include "verbs.h"

static const char *arg_hwdb_bin_dir = NULL;
static const char *arg_root = NULL;
static bool arg_strict = false;

VERB(verb_query, "query", "MODALIAS", 2, 2, 0,
     "Query database and print result");
static int verb_query(int argc, char *argv[], uintptr_t _data, void *userdata) {
        return hwdb_query(argv[1], arg_root);
}

VERB_NOARG(verb_update, "update",
           "Update the hwdb database");
static int verb_update(int argc, char *argv[], uintptr_t _data, void *userdata) {
        if (hwdb_bypass())
                return 0;

        return hwdb_update(arg_root, arg_hwdb_bin_dir, arg_strict, false);
}

static int help(void) {
        _cleanup_free_ char *link = NULL;
        _cleanup_(table_unrefp) Table *options = NULL, *verbs = NULL;
        int r;

        r = terminal_urlify_man("systemd-hwdb", "8", &link);
        if (r < 0)
                return log_oom();

        r = verbs_get_help_table(&verbs);
        if (r < 0)
                return r;

        r = option_parser_get_help_table(&options);
        if (r < 0)
                return r;

        (void) table_sync_column_widths(0, verbs, options);

        printf("%s [OPTIONS...] COMMAND ...\n\n"
               "%sUpdate or query the hardware database.%s\n"
               "\n%sCommands:%s\n",
               program_invocation_short_name,
               ansi_highlight(),
               ansi_normal(),
               ansi_underline(),
               ansi_normal());

        r = table_print_or_warn(verbs);
        if (r < 0)
                return r;

        printf("\n%sOptions:%s\n",
               ansi_underline(),
               ansi_normal());

        r = table_print_or_warn(options);
        if (r < 0)
                return r;

        printf("\nSee the %s for details.\n", link);
        return 0;
}

VERB_COMMON_HELP_HIDDEN(help);

static int parse_argv(int argc, char *argv[], char ***ret_args) {
        assert(argc >= 0);
        assert(argv);
        assert(ret_args);

        OptionParser opts = { argc, argv };

        FOREACH_OPTION_OR_RETURN(c, &opts)
                switch (c) {

                OPTION_COMMON_HELP:
                        return help();

                OPTION_COMMON_VERSION:
                        return version();

                OPTION('s', "strict", NULL,
                       "When updating, return non-zero exit value on any parsing error"):
                        arg_strict = true;
                        break;

                OPTION('r', "root", "PATH", "Alternative root path in the filesystem"):
                        arg_root = opts.arg;
                        break;

                OPTION_LONG("usr", NULL,
                            "Generate in " UDEVLIBEXECDIR " instead of /etc/udev"):
                        arg_hwdb_bin_dir = UDEVLIBEXECDIR;
                        break;
                }

        *ret_args = option_parser_get_args(&opts);
        return 1;
}

static int run(int argc, char *argv[]) {
        int r;

        log_setup();

        char **args = NULL;
        r = parse_argv(argc, argv, &args);
        if (r <= 0)
                return r;

        r = mac_init();
        if (r < 0)
                return r;

        return dispatch_verb(args, NULL);
}

DEFINE_MAIN_FUNCTION(run);
