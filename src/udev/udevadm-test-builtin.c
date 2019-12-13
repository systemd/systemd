/* SPDX-License-Identifier: GPL-2.0+ */

#include <errno.h>
#include <getopt.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#include "log.h"
#include "udev-builtin.h"
#include "udevadm.h"
#include "udevadm-util.h"

static const char *arg_command = NULL;
static const char *arg_syspath = NULL;

static int help(void) {
        printf("%s test-builtin [OPTIONS] COMMAND DEVPATH\n\n"
               "Test a built-in command.\n\n"
               "  -h --help     Print this message\n"
               "  -V --version  Print version of the program\n\n"
               "Commands:\n"
               , program_invocation_short_name);

        udev_builtin_list();

        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        static const struct option options[] = {
                { "version", no_argument, NULL, 'V' },
                { "help",    no_argument, NULL, 'h' },
                {}
        };

        int c;

        while ((c = getopt_long(argc, argv, "Vh", options, NULL)) >= 0)
                switch (c) {
                case 'V':
                        return print_version();
                case 'h':
                        return help();
                case '?':
                        return -EINVAL;
                default:
                        assert_not_reached("Unknown option");
                }

        arg_command = argv[optind++];
        if (!arg_command)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Command missing.");

        arg_syspath = argv[optind++];
        if (!arg_syspath)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "syspath missing.");

        return 1;
}

int builtin_main(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_device_unrefp) sd_device *dev = NULL;
        UdevBuiltinCommand cmd;
        int r;

        log_set_max_level(LOG_DEBUG);

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        udev_builtin_init();

        cmd = udev_builtin_lookup(arg_command);
        if (cmd < 0) {
                log_error("Unknown command '%s'", arg_command);
                r = -EINVAL;
                goto finish;
        }

        r = find_device(arg_syspath, "/sys", &dev);
        if (r < 0) {
                log_error_errno(r, "Failed to open device '%s': %m", arg_syspath);
                goto finish;
        }

        r = udev_builtin_run(dev, cmd, arg_command, true);
        if (r < 0)
                log_debug_errno(r, "Builtin command '%s' fails: %m", arg_command);

finish:
        udev_builtin_exit();
        return r;
}
