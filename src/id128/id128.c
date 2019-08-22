/* SPDX-License-Identifier: LGPL-2.1+ */

#include <getopt.h>
#include <stdio.h>

#include "alloc-util.h"
#include "id128-print.h"
#include "main-func.h"
#include "pretty-print.h"
#include "util.h"
#include "verbs.h"

static bool arg_pretty = false;
static sd_id128_t arg_app = {};

static int verb_new(int argc, char **argv, void *userdata) {
        return id128_print_new(arg_pretty);
}

static int verb_machine_id(int argc, char **argv, void *userdata) {
        sd_id128_t id;
        int r;

        if (sd_id128_is_null(arg_app))
                r = sd_id128_get_machine(&id);
        else
                r = sd_id128_get_machine_app_specific(arg_app, &id);
        if (r < 0)
                return log_error_errno(r, "Failed to get %smachine-ID: %m",
                                       sd_id128_is_null(arg_app) ? "" : "app-specific ");

        return id128_pretty_print(id, arg_pretty);
}

static int verb_boot_id(int argc, char **argv, void *userdata) {
        sd_id128_t id;
        int r;

        if (sd_id128_is_null(arg_app))
                r = sd_id128_get_boot(&id);
        else
                r = sd_id128_get_boot_app_specific(arg_app, &id);
        if (r < 0)
                return log_error_errno(r, "Failed to get %sboot-ID: %m",
                                       sd_id128_is_null(arg_app) ? "" : "app-specific ");

        return id128_pretty_print(id, arg_pretty);
}

static int verb_invocation_id(int argc, char **argv, void *userdata) {
        sd_id128_t id;
        int r;

        if (!sd_id128_is_null(arg_app))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Verb \"invocation-id\" cannot be combined with --app-specific=.");

        r = sd_id128_get_invocation(&id);
        if (r < 0)
                return log_error_errno(r, "Failed to get invocation-ID: %m");

        return id128_pretty_print(id, arg_pretty);
}

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-id128", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%s [OPTIONS...] {COMMAND}\n\n"
               "Generate and print id128 strings.\n\n"
               "  -h --help               Show this help\n"
               "  -p --pretty             Generate samples of program code\n"
               "  -a --app-specific=ID    Generate app-specific IDs\n"
               "\nCommands:\n"
               "  new                     Generate a new id128 string\n"
               "  machine-id              Print the ID of current machine\n"
               "  boot-id                 Print the ID of current boot\n"
               "  invocation-id           Print the ID of current invocation\n"
               "  help                    Show this help\n"
               "\nSee the %s for details.\n"
               , program_invocation_short_name
               , link
        );

        return 0;
}

static int verb_help(int argc, char **argv, void *userdata) {
        return help();
}

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_VERSION = 0x100,
        };

        static const struct option options[] = {
                { "help",         no_argument,       NULL, 'h'              },
                { "version",      no_argument,       NULL, ARG_VERSION      },
                { "pretty",       no_argument,       NULL, 'p'              },
                { "app-specific", required_argument, NULL, 'a'              },
                {},
        };

        int c, r;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "hpa:", options, NULL)) >= 0)
                switch (c) {

                case 'h':
                        return help();

                case ARG_VERSION:
                        return version();

                case 'p':
                        arg_pretty = true;
                        break;

                case 'a':
                        r = sd_id128_from_string(optarg, &arg_app);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse \"%s\" as application-ID: %m", optarg);
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unhandled option");
                }

        return 1;
}

static int id128_main(int argc, char *argv[]) {
        static const Verb verbs[] = {
                { "new",            VERB_ANY, 1,        0,  verb_new           },
                { "machine-id",     VERB_ANY, 1,        0,  verb_machine_id    },
                { "boot-id",        VERB_ANY, 1,        0,  verb_boot_id       },
                { "invocation-id",  VERB_ANY, 1,        0,  verb_invocation_id },
                { "help",           VERB_ANY, VERB_ANY, 0,  verb_help          },
                {}
        };

        return dispatch_verb(argc, argv, verbs, NULL);
}

static int run(int argc, char *argv[]) {
        int r;

        log_show_color(true);
        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        return id128_main(argc, argv);
}

DEFINE_MAIN_FUNCTION(run);
