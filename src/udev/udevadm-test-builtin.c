/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <getopt.h>
#include <stdio.h>

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

        if (argc != optind + 2)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Expected two arguments: command string and device path.");

        arg_command = ASSERT_PTR(argv[optind]);
        arg_syspath = ASSERT_PTR(argv[optind+1]);
        return 1;
}

int builtin_main(int argc, char *argv[], void *userdata) {
        _cleanup_(udev_event_unrefp) UdevEvent *event = NULL;
        _cleanup_(sd_device_unrefp) sd_device *dev = NULL;
        UdevBuiltinCommand cmd;
        int r;

        log_set_max_level(LOG_DEBUG);
        log_setup();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        udev_builtin_init();
        UDEV_BUILTIN_DESTRUCTOR;

        cmd = udev_builtin_lookup(arg_command);
        if (cmd < 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Unknown command '%s'", arg_command);

        r = find_device_with_action(arg_syspath, arg_action, &dev);
        if (r < 0)
                return log_error_errno(r, "Failed to open device '%s': %m", arg_syspath);

        event = udev_event_new(dev, NULL, EVENT_UDEVADM_TEST_BUILTIN);
        if (!event)
                return log_oom();

        if (arg_action != SD_DEVICE_REMOVE) {
                /* For net_setup_link */
                r = device_clone_with_db(dev, &event->dev_db_clone);
                if (r < 0)
                        return log_device_error_errno(dev, r, "Failed to clone device: %m");
        }

        r = udev_builtin_run(event, cmd, arg_command);
        if (r < 0)
                return log_debug_errno(r, "Builtin command '%s' fails: %m", arg_command);

        return 0;
}
