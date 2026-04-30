/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <stdio.h>

#include "alloc-util.h"
#include "ansi-color.h"
#include "conf-files.h"
#include "errno-util.h"
#include "format-table.h"
#include "help-util.h"
#include "log.h"
#include "options.h"
#include "parse-argument.h"
#include "static-destruct.h"
#include "udev-rules.h"
#include "udevadm.h"
#include "udevadm-util.h"

static ResolveNameTiming arg_resolve_name_timing = RESOLVE_NAME_EARLY;
static char *arg_root = NULL;
static bool arg_summary = true;
static bool arg_style = true;

STATIC_DESTRUCTOR_REGISTER(arg_root, freep);

static int help(void) {
        _cleanup_(table_unrefp) Table *options = NULL;
        int r;

        r = option_parser_get_help_table_ns("udevadm-verify", &options);
        if (r < 0)
                return r;

        help_cmdline("verify [OPTIONS] [FILE...]");
        help_abstract("Verify udev rules files.");
        help_section("Options:");
        r = table_print_or_warn(options);
        if (r < 0)
                return r;

        help_man_page_reference("udevadm", "8");
        return 0;
}

static int parse_argv(int argc, char *argv[], char ***remaining_args) {
        int r;

        assert(argc >= 0);
        assert(argv);
        assert(remaining_args);

        OptionParser opts = { argc, argv, .namespace = "udevadm-verify" };

        FOREACH_OPTION_OR_RETURN(c, &opts)
                switch (c) {

                OPTION_NAMESPACE("udevadm-verify"): {}

                OPTION_COMMON_HELP:
                        return help();

                OPTION('V', "version", NULL, "Show package version"):
                        return print_version();

                OPTION_COMMON_RESOLVE_NAMES:
                        r = parse_resolve_name_timing(opts.arg, &arg_resolve_name_timing);
                        if (r <= 0)
                                return r;
                        break;

                OPTION_LONG("root", "PATH", "Operate on an alternate filesystem root"):
                        r = parse_path_argument(opts.arg, /* suppress_root= */ true, &arg_root);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("no-summary", NULL, "Do not show summary"):
                        arg_summary = false;
                        break;

                OPTION_LONG("no-style", NULL, "Ignore style issues"):
                        arg_style = false;
                        break;
                }

        *remaining_args = option_parser_get_args(&opts);
        return 1;
}

static int verify_rules_file(UdevRules *rules, const ConfFile *c) {
        UdevRuleFile *file;
        int r;

        assert(rules);
        assert(c);

        r = udev_rules_parse_file(rules, c, /* extra_checks= */ true, &file);
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

int verb_verify_main(int argc, char *argv[], uintptr_t _data, void *userdata) {
        _cleanup_(udev_rules_freep) UdevRules *rules = NULL;
        char **args = NULL;
        int r;

        r = parse_argv(argc, argv, &args);
        if (r <= 0)
                return r;

        rules = udev_rules_new(arg_resolve_name_timing);
        if (!rules)
                return -ENOMEM;

        ConfFile **files = NULL;
        size_t n_files = 0;

        CLEANUP_ARRAY(files, n_files, conf_file_free_array);

        r = search_rules_files(args, arg_root, &files, &n_files);
        if (r < 0)
                return r;

        return verify_rules(rules, files, n_files);
}
