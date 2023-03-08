/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <errno.h>
#include <getopt.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "log.h"
#include "pretty-print.h"
#include "strv.h"
#include "udev-rules.h"
#include "udevadm.h"

static ResolveNameTiming arg_resolve_name_timing = RESOLVE_NAME_EARLY;

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("udevadm", "8", &link);
        if (r < 0)
                return log_oom();

        printf("%s verify [OPTIONS] FILE...\n"
               "\n%sVerify udev rules files.%s\n\n"
               "  -h --help                            Show this help\n"
               "  -V --version                         Show package version\n"
               "  -N --resolve-names=early|never       When to resolve names\n"
               "\nSee the %s for details.\n",
               program_invocation_short_name,
               ansi_highlight(),
               ansi_normal(),
               link);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        static const struct option options[] = {
                { "help",          no_argument,       NULL, 'h' },
                { "version",       no_argument,       NULL, 'V' },
                { "resolve-names", required_argument, NULL, 'N' },
                {}
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "hVN:", options, NULL)) >= 0)
                switch (c) {
                case 'h':
                        return help();
                case 'V':
                        return print_version();
                case 'N':
                        arg_resolve_name_timing = resolve_name_timing_from_string(optarg);
                        if (arg_resolve_name_timing < 0)
                                return log_error_errno(arg_resolve_name_timing,
                                                       "--resolve-names= takes \"early\" or \"never\"");
                        /*
                         * In the verifier "late" has the effect of "never",
                         * and "never" would generate irrelevant diagnostics,
                         * so map "never" to "late".
                         */
                        if (arg_resolve_name_timing == RESOLVE_NAME_NEVER)
                                arg_resolve_name_timing = RESOLVE_NAME_LATE;
                        break;
                case '?':
                        return -EINVAL;
                default:
                        assert_not_reached();
                }

        if (optind == argc)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "No rules file specified.");

        return 1;
}

static int verify_rules_file(UdevRules *rules, const char *fname) {
        int r;

        r = udev_rules_parse_file(rules, fname);
        if (r < 0)
                return log_error_errno(r, "Failed to parse rules file %s: %m", fname);

        unsigned issues = udev_check_current_rule_file(rules);
        unsigned mask = (1U << LOG_ERR) | (1U << LOG_WARNING);
        if (issues & mask)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "%s: udev rules check failed", fname);

        return 0;
}

static int verify_rules(UdevRules *rules, char **files) {
        int r, rv = 0;

        STRV_FOREACH(fp, files) {
                r = verify_rules_file(rules, *fp);
                if (r < 0 && rv >= 0)
                        rv = r;
        }

        return rv;
}

int verify_main(int argc, char *argv[], void *userdata) {
        _cleanup_(udev_rules_freep) UdevRules *rules = NULL;
        int r;

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        rules = udev_rules_new(arg_resolve_name_timing);
        if (!rules)
                return -ENOMEM;

        return verify_rules(rules, strv_skip(argv, optind));
}
