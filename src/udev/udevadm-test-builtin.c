/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "device-private.h"
#include "device-util.h"
#include "format-table.h"
#include "help-util.h"
#include "log.h"
#include "options.h"
#include "udev-builtin.h"
#include "udevadm.h"
#include "udevadm-util.h"

static sd_device_action_t arg_action = SD_DEVICE_ADD;
static const char *arg_command = NULL;
static const char *arg_syspath = NULL;

static int help(void) {
        _cleanup_(table_unrefp) Table *options = NULL;
        int r;

        r = option_parser_get_help_table_ns("udevadm-test-builtin", &options);
        if (r < 0)
                return r;

        help_cmdline("test-builtin [OPTIONS] COMMAND DEVPATH");
        help_abstract("Test a built-in command.");
        help_section("Options:");
        r = table_print_or_warn(options);
        if (r < 0)
                return r;

        help_section("Commands:");
        udev_builtin_list();
        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        int r;

        assert(argc >= 0);
        assert(argv);

        OptionParser opts = { argc, argv, .namespace = "udevadm-test-builtin" };

        FOREACH_OPTION(c, &opts, /* on_error= */ return c)
                switch (c) {

                OPTION_NAMESPACE("udevadm-test-builtin"): {}

                OPTION_COMMON_HELP:
                        return help();

                OPTION('V', "version", NULL, "Show package version"):
                        return print_version();

                OPTION('a', "action", "ACTION|help", "Set action string"):
                        r = parse_device_action(opts.arg, &arg_action);
                        if (r <= 0)
                                return r;
                        break;
                }

        if (option_parser_get_n_args(&opts) != 2)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Expected two arguments: command string and device path.");

        char **args = option_parser_get_args(&opts);
        arg_command = ASSERT_PTR(args[0]);
        arg_syspath = ASSERT_PTR(args[1]);
        return 1;
}

int verb_builtin_main(int argc, char *argv[], uintptr_t _data, void *userdata) {
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
