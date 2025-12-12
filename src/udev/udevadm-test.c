/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright © 2003-2004 Greg Kroah-Hartman <greg@kroah.com>
 */

#include <getopt.h>
#include <signal.h>
#include <stdio.h>

#include "sd-device.h"
#include "sd-json.h"

#include "alloc-util.h"
#include "device-private.h"
#include "log.h"
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

        printf("%s test [OPTIONS] DEVPATH\n\n"
               "Test an event run.\n\n"
               "  -h --help                            Show this help\n"
               "  -V --version                         Show package version\n"
               "  -a --action=ACTION|help              Set action string\n"
               "  -N --resolve-names=early|late|never  When to resolve names\n"
               "  -D --extra-rules-dir=DIR             Also load rules from the directory\n"
               "  -v --verbose                         Show verbose logs\n"
               "     --json=pretty|short|off           Generate JSON output\n",
               program_invocation_short_name);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_JSON = 0x100,
        };

        static const struct option options[] = {
                { "action",          required_argument, NULL, 'a'      },
                { "resolve-names",   required_argument, NULL, 'N'      },
                { "extra-rules-dir", required_argument, NULL, 'D'      },
                { "verbose",         no_argument,       NULL, 'v'      },
                { "json",            required_argument, NULL, ARG_JSON },
                { "version",         no_argument,       NULL, 'V'      },
                { "help",            no_argument,       NULL, 'h'      },
                {}
        };

        int r, c;

        while ((c = getopt_long(argc, argv, "a:N:D:vVh", options, NULL)) >= 0)
                switch (c) {
                case 'a':
                        r = parse_device_action(optarg, &arg_action);
                        if (r <= 0)
                                return r;
                        break;
                case 'N':
                        r = parse_resolve_name_timing(optarg, &arg_resolve_name_timing);
                        if (r <= 0)
                                return r;
                        break;
                case 'D': {
                        _cleanup_free_ char *p = NULL;

                        r = parse_path_argument(optarg, /* suppress_root = */ false, &p);
                        if (r < 0)
                                return r;

                        r = strv_consume(&arg_extra_rules_dir, TAKE_PTR(p));
                        if (r < 0)
                                return log_oom();
                        break;
                }
                case 'v':
                        arg_verbose = true;
                        break;
                case ARG_JSON:
                        r = parse_json_argument(optarg, &arg_json_format_flags);
                        if (r <= 0)
                                return r;
                        break;
                case 'V':
                        return print_version();
                case 'h':
                        return help();
                case '?':
                        return -EINVAL;
                default:
                        assert_not_reached();
                }

        arg_syspath = argv[optind];
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

int test_main(int argc, char *argv[], void *userdata) {
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
