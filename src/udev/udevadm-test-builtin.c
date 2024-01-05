/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <errno.h>
#include <getopt.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#include "device-private.h"
#include "device-util.h"
#include "log.h"
#include "udev-builtin.h"
#include "udevadm.h"
#include "udevadm-util.h"

static sd_device_action_t arg_action = SD_DEVICE_ADD;
static const char *arg_command = NULL;
static const char *arg_syspath = NULL;

static int help(void) {
        printf("%s test-builtin [OPTIONS] COMMAND DEVPATH\n\n"
               "Test a built-in command.\n\n"
               "  -h --help               Print this message\n"
               "  -V --version            Print version of the program\n\n"
               "  -a --action=ACTION|help Set action string\n"
               "Commands:\n",
               program_invocation_short_name);

        udev_builtin_list();

        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        static const struct option options[] = {
                { "action",  required_argument, NULL, 'a' },
                { "version", no_argument,       NULL, 'V' },
                { "help",    no_argument,       NULL, 'h' },
                {}
        };

        int r, c;

        while ((c = getopt_long(argc, argv, "a:Vh", options, NULL)) >= 0)
                switch (c) {
                case 'a':
                        r = parse_device_action(optarg, &arg_action);
                        if (r < 0)
                                return log_error_errno(r, "Invalid action '%s'", optarg);
                        if (r == 0)
                                return 0;
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

        arg_command = argv[optind++];
        if (!arg_command)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Command missing.");

        arg_syspath = argv[optind++];
        if (!arg_syspath)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "device is missing.");

        return 1;
}

int builtin_main(int argc, char *argv[], void *userdata) {
        _cleanup_(udev_event_freep) UdevEvent *event = NULL;
        _cleanup_(sd_device_unrefp) sd_device *dev = NULL;
        UdevBuiltinCommand cmd;
        int r;

        log_set_max_level(LOG_DEBUG);
        log_parse_environment();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        udev_builtin_init();

        cmd = udev_builtin_lookup(arg_command);
        if (cmd < 0) {
                r = log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Unknown command '%s'", arg_command);
                goto finish;
        }

        r = find_device_with_action(arg_syspath, arg_action, &dev);
        if (r < 0) {
                log_error_errno(r, "Failed to open device '%s': %m", arg_syspath);
                goto finish;
        }

        event = udev_event_new(dev, NULL);
        if (!event) {
                r = log_oom();
                goto finish;
        }

        if (arg_action != SD_DEVICE_REMOVE) {
                /* For net_setup_link */
                r = device_clone_with_db(dev, &event->dev_db_clone);
                if (r < 0) {
                        log_device_error_errno(dev, r, "Failed to clone device: %m");
                        goto finish;
                }
        }

        r = udev_builtin_run(event, cmd, arg_command, true);
        if (r < 0) {
                log_debug_errno(r, "Builtin command '%s' fails: %m", arg_command);
                goto finish;
        }

        r = 0;
finish:
        udev_builtin_exit();
        return r;
}
