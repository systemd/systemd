/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <getopt.h>
#include <stdio.h>

#include "alloc-util.h"
#include "conf-files.h"
#include "errno-util.h"
#include "log.h"
#include "parse-argument.h"
#include "pretty-print.h"
#include "static-destruct.h"
#include "strv.h"
#include "udev-rules.h"
#include "udevadm.h"
#include "udevadm-util.h"

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
               "  -N --resolve-names=early|late|never  When to resolve names\n"
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
                        r = parse_resolve_name_timing(optarg, &arg_resolve_name_timing);
                        if (r <= 0)
                                return r;
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

        return 1;
}

static int verify_rules_file(UdevRules *rules, const ConfFile *c) {
        UdevRuleFile *file;
        int r;

        assert(rules);
        assert(c);

        r = udev_rules_parse_file(rules, c, /* extra_checks = */ true, &file);
        if (r < 0)
                return log_error_errno(r, "Failed to parse rules file %s: %m", c->original_path);

        unsigned issues = udev_rule_file_get_issues(file);
        unsigned mask = (1U << LOG_ERR) | (1U << LOG_WARNING);
        if (issues & mask)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "%s: udev rules check failed.", c->original_path);

        if (arg_style && (issues & (1U << LOG_NOTICE)))
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                         "%s: udev rules have style issues.", c->original_path);

        return 0;
}

static int verify_rules(UdevRules *rules, ConfFile * const *files, size_t n_files) {
        size_t fail_count = 0, success_count = 0;
        int r, ret = 0;

        assert(rules);
        assert(files || n_files == 0);

        FOREACH_ARRAY(i, files, n_files) {
                r = verify_rules_file(rules, *i);
                if (r < 0)
                        ++fail_count;
                else
                        ++success_count;
                RET_GATHER(ret, r);
        }

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

        return ret;
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

        ConfFile **files = NULL;
        size_t n_files = 0;

        CLEANUP_ARRAY(files, n_files, conf_file_free_many);

        r = search_rules_files(strv_skip(argv, optind), arg_root, &files, &n_files);
        if (r < 0)
                return r;

        return verify_rules(rules, files, n_files);
}
