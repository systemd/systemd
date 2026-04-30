/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright © 2003-2004 Greg Kroah-Hartman <greg@kroah.com>
 */

#include <signal.h>
#include <stdio.h>

#include "sd-device.h"
#include "sd-json.h"

#include "alloc-util.h"
#include "device-private.h"
#include "format-table.h"
#include "help-util.h"
#include "log.h"
#include "options.h"
#include "parse-argument.h"
#include "static-destruct.h"
#include "strv.h"
#include "udev-builtin.h"
#include "udev-dump.h"
#include "udev-event.h"
#include "udev-rules.h"
#include "udevadm.h"
#include "udevadm-util.h"

static sd_device_action_t arg_action = SD_DEVICE_ADD;
static ResolveNameTiming arg_resolve_name_timing = RESOLVE_NAME_EARLY;
static const char *arg_syspath = NULL;
static char **arg_extra_rules_dir = NULL;
static bool arg_verbose = false;
static sd_json_format_flags_t arg_json_format_flags = SD_JSON_FORMAT_OFF;

STATIC_DESTRUCTOR_REGISTER(arg_extra_rules_dir, strv_freep);

static int help(void) {
        _cleanup_(table_unrefp) Table *options = NULL;
        int r;

        r = option_parser_get_help_table_ns("udevadm-test", &options);
        if (r < 0)
                return r;

        help_cmdline("test [OPTIONS] DEVPATH");
        help_abstract("Test an event run.");
        help_section("Options:");
        r = table_print_or_warn(options);
        if (r < 0)
                return r;

        help_man_page_reference("udevadm", "8");
        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        int r;

        assert(argc >= 0);
        assert(argv);

        OptionParser opts = { argc, argv, .namespace = "udevadm-test" };

        FOREACH_OPTION_OR_RETURN(c, &opts)
                switch (c) {

                OPTION_NAMESPACE("udevadm-test"): {}

                OPTION_COMMON_HELP:
                        return help();

                OPTION('V', "version", NULL, "Show package version"):
                        return print_version();

                OPTION('a', "action", "ACTION|help", "Set action string"):
                        r = parse_device_action(opts.arg, &arg_action);
                        if (r <= 0)
                                return r;
                        break;

                OPTION_COMMON_RESOLVE_NAMES:
                        r = parse_resolve_name_timing(opts.arg, &arg_resolve_name_timing);
                        if (r <= 0)
                                return r;
                        break;

                OPTION('D', "extra-rules-dir", "DIR", "Also load rules from the directory"): {
                        _cleanup_free_ char *p = NULL;

                        r = parse_path_argument(opts.arg, /* suppress_root= */ false, &p);
                        if (r < 0)
                                return r;

                        r = strv_consume(&arg_extra_rules_dir, TAKE_PTR(p));
                        if (r < 0)
                                return log_oom();
                        break;
                }

                OPTION('v', "verbose", NULL, "Show verbose logs"):
                        arg_verbose = true;
                        break;

                OPTION_COMMON_JSON:
                        r = parse_json_argument(opts.arg, &arg_json_format_flags);
                        if (r <= 0)
                                return r;
                        break;
                }

        char **args = option_parser_get_args(&opts);
        arg_syspath = args[0];
        if (!arg_syspath)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "syspath parameter missing.");

        return 1;
}

static void maybe_insert_empty_line(void) {
        if (log_get_max_level() < LOG_INFO)
                return;

        LogTarget target = log_get_target();
        if (!IN_SET(log_get_target(), LOG_TARGET_CONSOLE, LOG_TARGET_CONSOLE_PREFIXED, LOG_TARGET_AUTO))
                return;

        if (target == LOG_TARGET_AUTO && stderr_is_journal())
                return;

        fputs("\n", stderr);
}

int verb_test_main(int argc, char *argv[], uintptr_t _data, void *userdata) {
        _cleanup_(udev_rules_freep) UdevRules *rules = NULL;
        _cleanup_(udev_event_unrefp) UdevEvent *event = NULL;
        _cleanup_(sd_device_unrefp) sd_device *dev = NULL;
        sigset_t mask, sigmask_orig;
        int r;

        log_set_max_level(LOG_DEBUG);
        log_setup();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        log_info("This program is for debugging only, it does not run any program\n"
                 "specified by a RUN key. It may show incorrect results, because\n"
                 "some values may be different, or not available at a simulation run.");

        assert_se(sigprocmask(SIG_SETMASK, NULL, &sigmask_orig) >= 0);

        maybe_insert_empty_line();
        log_info("Loading builtins...");
        udev_builtin_init();
        UDEV_BUILTIN_DESTRUCTOR;
        log_info("Loading builtins done.");

        maybe_insert_empty_line();
        log_info("Loading udev rules files...");
        r = udev_rules_load(&rules, arg_resolve_name_timing, arg_extra_rules_dir);
        if (r < 0)
                return log_error_errno(r, "Failed to read udev rules: %m");
        log_info("Loading udev rules files done.");

        r = find_device_with_action(arg_syspath, arg_action, &dev);
        if (r < 0)
                return log_error_errno(r, "Failed to open device '%s': %m", arg_syspath);

        /* don't read info from the db */
        device_seal(dev);

        event = udev_event_new(dev, NULL, EVENT_UDEVADM_TEST);
        if (!event)
                return log_oom();
        event->trace = arg_verbose;

        assert_se(sigfillset(&mask) >= 0);
        assert_se(sigprocmask(SIG_SETMASK, &mask, &sigmask_orig) >= 0);

        maybe_insert_empty_line();
        log_info("Processing udev rules%s...", arg_verbose ? "" : " (verbose logs can be shown by -v/--verbose)");
        udev_event_execute_rules(event, rules);
        log_info("Processing udev rules done.");

        maybe_insert_empty_line();
        r = dump_event(event, arg_json_format_flags, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to dump result: %m");
        maybe_insert_empty_line();

        return 0;
}
