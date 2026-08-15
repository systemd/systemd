/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"

#include "build.h"
#include "dlopen-note.h"
#include "hwdb-util.h"
#include "label-util.h"
#include "log.h"
#include "main-func.h"
#include "verbs.h"

static const char *arg_hwdb_bin_dir = NULL;
static const char *arg_root = NULL;
static bool arg_strict = false;

COMMAND(
        "systemd-hwdb\0",
        "Update or query the hardware database.",
        .man_pages = "systemd-hwdb.8\0",
);

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

VERB_COMMON_HELP_AUTO_HIDDEN("systemd-hwdb");

static int parse_argv(int argc, char *argv[], char ***ret_args) {
        assert(argc >= 0);
        assert(argv);
        assert(ret_args);

        OptionParser opts = { argc, argv };

        FOREACH_OPTION_OR_RETURN(c, &opts)
                switch (c) {

                OPTION_COMMON_HELP:
                        return command_print_help("systemd-hwdb");

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

                OPTION_COMMON_INTROSPECT_CLI:
                        return introspect_cli(SD_JSON_FORMAT_OFF);
                }

        *ret_args = option_parser_get_args(&opts);
        return 1;
}

static int run(int argc, char *argv[]) {
        int r;

        LIBSELINUX_NOTE(recommended);

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
