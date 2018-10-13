/* SPDX-License-Identifier: GPL-2.0+ */

#include <errno.h>
#include <getopt.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#include "libudev-private.h"
#include "path-util.h"
#include "string-util.h"
#include "strxcpyx.h"
#include "udev-builtin.h"
#include "udevadm.h"

static const char *arg_command = NULL;
static char arg_syspath[UTIL_PATH_SIZE] = {};

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

        const char *s;
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
        if (!arg_command) {
                log_error("Command missing.");
                return -EINVAL;
        }

        s = argv[optind++];
        if (!s) {
                log_error("syspath missing.");
                return -EINVAL;
        }

        /* add /sys if needed */
        if (!path_startswith(s, "/sys"))
                strscpyl(arg_syspath, sizeof(arg_syspath), "/sys", s, NULL);
        else
                strscpy(arg_syspath, sizeof(arg_syspath), s);

        return 1;
}

int builtin_main(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_device_unrefp) sd_device *dev = NULL;
        enum udev_builtin_cmd cmd;
        int r;

        log_set_max_level(LOG_DEBUG);

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        udev_builtin_init();

        cmd = udev_builtin_lookup(arg_command);
        if (cmd >= UDEV_BUILTIN_MAX) {
                log_error("Unknown command '%s'", arg_command);
                r = -EINVAL;
                goto finish;
        }

        r = sd_device_new_from_syspath(&dev, arg_syspath);
        if (r < 0) {
                log_error_errno(r, "Failed to open device '%s': %m", arg_syspath);
                goto finish;
        }

        r = udev_builtin_run(dev, cmd, arg_command, true);
        if (r < 0)
                log_debug("error executing '%s', exit code %i", arg_command, r);

finish:
        udev_builtin_exit();
        return r;
}
