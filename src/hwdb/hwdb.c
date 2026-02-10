/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>

#include "alloc-util.h"
#include "build.h"
#include "hwdb-util.h"
#include "label-util.h"
#include "log.h"
#include "main-func.h"
#include "pretty-print.h"
#include "verbs.h"

static const char *arg_hwdb_bin_dir = NULL;
static const char *arg_root = NULL;
static bool arg_strict = false;

#include "hwdb.args.inc"

static int verb_query(int argc, char *argv[], void *userdata) {
        return hwdb_query(argv[1], arg_root);
}

static int verb_update(int argc, char *argv[], void *userdata) {
        if (hwdb_bypass())
                return 0;

        return hwdb_update(arg_root, arg_hwdb_bin_dir, arg_strict, false);
}

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-hwdb", "8", &link);
        if (r < 0)
                return log_oom();

        printf("%s [OPTIONS...] COMMAND ...\n\n"
               "%sUpdate or query the hardware database.%s\n"
               "\nCommands:\n"
               "  update          Update the hwdb database\n"
               "  query MODALIAS  Query database and print result\n"
               "\nOptions:\n"
               OPTION_HELP_GENERATED
               "\nSee the %s for details.\n",
               program_invocation_short_name,
               ansi_highlight(),
               ansi_normal(),
               link);

        return 0;
}

static int hwdb_main(int argc, char *argv[]) {
        static const Verb verbs[] = {
                { "update", 1, 1, 0, verb_update },
                { "query",  2, 2, 0, verb_query  },
                {},
        };

        return dispatch_verb(argc, argv, verbs, NULL);
}

static int run(int argc, char *argv[]) {
        int r;

        log_setup();

        r = parse_argv_generated(argc, argv);
        if (r <= 0)
                return r;

        r = mac_init();
        if (r < 0)
                return r;

        return hwdb_main(argc, argv);
}

DEFINE_MAIN_FUNCTION(run);
