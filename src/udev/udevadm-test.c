/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright © 2003-2004 Greg Kroah-Hartman <greg@kroah.com>
 */

#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/signalfd.h>
#include <unistd.h>

#include "sd-device.h"

#include "device-private.h"
#include "device-util.h"
#include "string-util.h"
#include "udev-builtin.h"
#include "udev.h"
#include "udevadm.h"

static const char *arg_action = "add";
static ResolveNameTiming arg_resolve_name_timing = RESOLVE_NAME_EARLY;
static char arg_syspath[UTIL_PATH_SIZE] = {};

static int help(void) {

        printf("%s test [OPTIONS] DEVPATH\n\n"
               "Test an event run.\n\n"
               "  -h --help                            Show this help\n"
               "  -V --version                         Show package version\n"
               "  -a --action=ACTION                   Set action string\n"
               "  -N --resolve-names=early|late|never  When to resolve names\n"
               , program_invocation_short_name);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        static const struct option options[] = {
                { "action",        required_argument, NULL, 'a' },
                { "resolve-names", required_argument, NULL, 'N' },
                { "version",       no_argument,       NULL, 'V' },
                { "help",          no_argument,       NULL, 'h' },
                {}
        };

        int c;

        while ((c = getopt_long(argc, argv, "a:N:Vh", options, NULL)) >= 0)
                switch (c) {
                case 'a':
                        arg_action = optarg;
                        break;
                case 'N':
                        arg_resolve_name_timing = resolve_name_timing_from_string(optarg);
                        if (arg_resolve_name_timing < 0) {
                                log_error("--resolve-names= must be early, late or never");
                                return -EINVAL;
                        }
                        break;
                case 'V':
                        return print_version();
                case 'h':
                        return help();
                case '?':
                        return -EINVAL;
                default:
                        assert_not_reached("Unknown option");
                }

        if (!argv[optind]) {
                log_error("syspath parameter missing.");
                return -EINVAL;
        }

        /* add /sys if needed */
        if (!startswith(argv[optind], "/sys"))
                strscpyl(arg_syspath, sizeof(arg_syspath), "/sys", argv[optind], NULL);
        else
                strscpy(arg_syspath, sizeof(arg_syspath), argv[optind]);

        return 1;
}

int test_main(int argc, char *argv[], void *userdata) {
        _cleanup_(udev_rules_unrefp) struct udev_rules *rules = NULL;
        _cleanup_(udev_event_freep) struct udev_event *event = NULL;
        _cleanup_(sd_device_unrefp) sd_device *dev = NULL;
        const char *cmd, *key, *value;
        sigset_t mask, sigmask_orig;
        Iterator i;
        void *val;
        int r;

        log_set_max_level(LOG_DEBUG);

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        printf("This program is for debugging only, it does not run any program\n"
               "specified by a RUN key. It may show incorrect results, because\n"
               "some values may be different, or not available at a simulation run.\n"
               "\n");

        assert_se(sigprocmask(SIG_SETMASK, NULL, &sigmask_orig) >= 0);

        udev_builtin_init();

        rules = udev_rules_new(arg_resolve_name_timing);
        if (!rules) {
                log_error("Failed to read udev rules.");
                r = -ENOMEM;
                goto out;
        }

        r = device_new_from_synthetic_event(&dev, arg_syspath, arg_action);
        if (r < 0) {
                log_error_errno(r, "Failed to open device '%s': %m", arg_syspath);
                goto out;
        }

        /* don't read info from the db */
        device_seal(dev);

        event = udev_event_new(dev, 0, NULL);

        sigfillset(&mask);
        sigprocmask(SIG_SETMASK, &mask, &sigmask_orig);

        udev_event_execute_rules(event, 60 * USEC_PER_SEC, NULL, rules);

        FOREACH_DEVICE_PROPERTY(dev, key, value)
                printf("%s=%s\n", key, value);

        HASHMAP_FOREACH_KEY(val, cmd, event->run_list, i) {
                char program[UTIL_PATH_SIZE];

                udev_event_apply_format(event, cmd, program, sizeof(program), false);
                printf("run: '%s'\n", program);
        }

        r = 0;
out:
        udev_builtin_exit();
        return r;
}
