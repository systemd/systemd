/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* The C half of the command line parity test: test-cli-rust.rs declares the same command, options and verbs
 * with the Rust macros, and test/test-cli-parity.sh runs both with the same arguments and expects the same
 * output and exit status, byte for byte. */

#include "sd-json.h"

#include "build.h"
#include "parse-argument.h"
#include "log.h"
#include "main-func.h"
#include "pager.h"
#include "string-util.h"
#include "verbs.h"

static bool arg_verbose = false;
static const char *arg_frob = NULL;
static const char *arg_plumb = NULL;
static PagerFlags arg_pager_flags = 0;
static bool arg_legend = true;
static sd_json_format_flags_t arg_json_format_flags = SD_JSON_FORMAT_OFF;

COMMAND(
        "test-cli\0",
        "Exercise the command line framework, to compare a C program with its Rust twin.",
        .man_pages = "systemd.1\0",
        .pager_flags = &arg_pager_flags,
);

static int print_state(const char *verb, int argc, char *argv[]) {
        printf("verb=%s verbose=%s frob=%s plumb=%s legend=%s json=%s args=",
               verb,
               yes_no(arg_verbose),
               strna(arg_frob),
               strna(arg_plumb),
               yes_no(arg_legend),
               yes_no(sd_json_format_enabled(arg_json_format_flags)));
        for (int i = 1; i < argc; i++)
                printf("%s%s", i > 1 ? "," : "", argv[i]);
        printf("\n");
        return 0;
}

VERB_DEFAULT_NOARG(verb_status, "status", "Print the parsed options");
static int verb_status(int argc, char *argv[], uintptr_t data, void *userdata) {
        return print_state("status", argc, argv);
}

VERB(verb_show, "show", "NAME [NAME]", 2, 3, 0, "Print one or two names");
static int verb_show(int argc, char *argv[], uintptr_t data, void *userdata) {
        return print_state("show", argc, argv);
}

VERB_GROUP("Other commands");

VERB(verb_fail, "fail", NULL, VERB_ANY, 1, 0, "Fail with EIO");
static int verb_fail(int argc, char *argv[], uintptr_t data, void *userdata) {
        return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failing on request.");
}

VERB_COMMON_HELP_AUTO();

static int parse_argv(int argc, char *argv[], char ***ret_args) {
        int r;

        assert(argc >= 0);
        assert(argv);

        OptionParser opts = { argc, argv };

        FOREACH_OPTION_OR_RETURN(c, &opts)
                switch (c) {
                OPTION_COMMON_HELP:
                        return command_print_help();

                OPTION_COMMON_VERSION:
                        return version();

                OPTION_COMMON_NO_PAGER:
                        arg_pager_flags |= PAGER_DISABLE;
                        break;

                OPTION_COMMON_NO_LEGEND:
                        arg_legend = false;
                        break;

                OPTION_COMMON_JSON:
                        r = parse_json_argument(opts.arg, &arg_json_format_flags);
                        if (r <= 0)
                                return r;
                        break;

                OPTION_COMMON_LOWERCASE_J:
                        arg_json_format_flags = SD_JSON_FORMAT_PRETTY_AUTO|SD_JSON_FORMAT_COLOR_AUTO;
                        break;

                OPTION('v', "verbose", NULL, "Print more"):
                        arg_verbose = true;
                        break;

                OPTION('f', "frob", "VALUE", "Set the frob value"):
                        arg_frob = opts.arg;
                        break;

                OPTION_GROUP("Rarely used options"):
                OPTION_LONG_FLAGS(OPTION_OPTIONAL_ARG, "plumb", "LEVEL", "Set the plumbing level"):
                        arg_plumb = opts.arg ?: "default";
                        break;

                OPTION_COMMON_INTROSPECT_CLI:
                        return introspect_cli(arg_json_format_flags);
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

        return dispatch_verb(args, NULL);
}

DEFINE_MAIN_FUNCTION(run);
