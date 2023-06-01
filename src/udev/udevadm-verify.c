/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <errno.h>
#include <getopt.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "conf-files.h"
#include "constants.h"
#include "log.h"
#include "parse-argument.h"
#include "pretty-print.h"
#include "stat-util.h"
#include "static-destruct.h"
#include "strv.h"
#include "udev-rules.h"
#include "udevadm.h"

static ResolveNameTiming arg_resolve_name_timing = RESOLVE_NAME_EARLY;
static char *arg_root = NULL;
static bool arg_summary = true;
static bool arg_style = true;

STATIC_DESTRUCTOR_REGISTER(arg_root, freep);

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("udevadm", "8", &link);
        if (r < 0)
                return log_oom();

        printf("%s verify [OPTIONS] [FILE...]\n"
               "\n%sVerify udev rules files.%s\n\n"
               "  -h --help                            Show this help\n"
               "  -V --version                         Show package version\n"
               "  -N --resolve-names=early|never       When to resolve names\n"
               "     --root=PATH                       Operate on an alternate filesystem root\n"
               "     --no-summary                      Do not show summary\n"
               "     --no-style                        Ignore style issues\n"
               "\nSee the %s for details.\n",
               program_invocation_short_name,
               ansi_highlight(),
               ansi_normal(),
               link);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_ROOT = 0x100,
                ARG_NO_SUMMARY,
                ARG_NO_STYLE,
        };
        static const struct option options[] = {
                { "help",          no_argument,       NULL, 'h'             },
                { "version",       no_argument,       NULL, 'V'             },
                { "resolve-names", required_argument, NULL, 'N'             },
                { "root",          required_argument, NULL, ARG_ROOT        },
                { "no-summary",    no_argument,       NULL, ARG_NO_SUMMARY  },
                { "no-style",      no_argument,       NULL, ARG_NO_STYLE    },
                {}
        };

        int r, c;

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
                case ARG_ROOT:
                        r = parse_path_argument(optarg, /* suppress_root= */ true, &arg_root);
                        if (r < 0)
                                return r;
                        break;
                case ARG_NO_SUMMARY:
                        arg_summary = false;
                        break;

                case ARG_NO_STYLE:
                        arg_style = false;
                        break;

                case '?':
                        return -EINVAL;
                default:
                        assert_not_reached();
                }

        if (arg_root && optind < argc)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Combination of --root= and FILEs is not supported.");

        return 1;
}

static int verify_rules_file(UdevRules *rules, const char *fname) {
        UdevRuleFile *file;
        int r;

        r = udev_rules_parse_file(rules, fname, /* extra_checks = */ true, &file);
        if (r < 0)
                return log_error_errno(r, "Failed to parse rules file %s: %m", fname);
        if (r == 0) /* empty file. */
                return 0;

        unsigned issues = udev_rule_file_get_issues(file);
        unsigned mask = (1U << LOG_ERR) | (1U << LOG_WARNING);
        if (issues & mask)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "%s: udev rules check failed.", fname);

        if (arg_style && (issues & (1U << LOG_NOTICE)))
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                         "%s: udev rules have style issues.", fname);

        return 0;
}

static int verify_rules_filelist(UdevRules *rules, char **files, size_t *fail_count, size_t *success_count, bool walk_dirs);

static int verify_rules_dir(UdevRules *rules, const char *dir, size_t *fail_count, size_t *success_count) {
        int r;
        _cleanup_strv_free_ char **files = NULL;

        assert(rules);
        assert(dir);
        assert(fail_count);
        assert(success_count);

        r = conf_files_list(&files, ".rules", NULL, 0, dir);
        if (r < 0)
                return log_error_errno(r, "Failed to enumerate rules files: %m");

        return verify_rules_filelist(rules, files, fail_count, success_count, /* walk_dirs */ false);
}

static int verify_rules_filelist(UdevRules *rules, char **files, size_t *fail_count, size_t *success_count, bool walk_dirs) {
        int r, rv = 0;

        assert(rules);
        assert(files);
        assert(fail_count);
        assert(success_count);

        STRV_FOREACH(fp, files) {
                if (walk_dirs && is_dir(*fp, /* follow = */ true) > 0)
                        r = verify_rules_dir(rules, *fp, fail_count, success_count);
                else {
                        r = verify_rules_file(rules, *fp);
                        if (r < 0)
                                ++(*fail_count);
                        else
                                ++(*success_count);
                }
                if (r < 0 && rv >= 0)
                        rv = r;
        }

        return rv;
}

static int verify_rules(UdevRules *rules, char **files) {
        size_t fail_count = 0, success_count = 0;
        int r;

        assert(rules);
        assert(files);

        r = verify_rules_filelist(rules, files, &fail_count, &success_count, /* walk_dirs */ true);

        if (arg_summary)
                printf("\n%s%zu udev rules files have been checked.%s\n"
                       "  Success: %zu\n"
                       "%s  Fail:    %zu%s\n",
                       ansi_highlight(),
                       fail_count + success_count,
                       ansi_normal(),
                       success_count,
                       fail_count > 0 ? ansi_highlight_red() : "",
                       fail_count,
                       fail_count > 0 ? ansi_normal() : "");

        return r;
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

        if (optind == argc) {
                const char* const* rules_dirs = STRV_MAKE_CONST(CONF_PATHS("udev/rules.d"));
                _cleanup_strv_free_ char **files = NULL;

                r = conf_files_list_strv(&files, ".rules", arg_root, 0, rules_dirs);
                if (r < 0)
                        return log_error_errno(r, "Failed to enumerate rules files: %m");
                if (arg_root && strv_isempty(files))
                        return log_error_errno(SYNTHETIC_ERRNO(ENOENT),
                                               "No rules files found in %s.", arg_root);

                return verify_rules(rules, files);
        }

        return verify_rules(rules, strv_skip(argv, optind));
}
