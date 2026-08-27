/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <stdio.h>

#include "sd-json.h"

#include "argv-util.h"
#include "dlopen-note.h"
#include "label-util.h"
#include "main-func.h"
#include "options.h"
#include "pager.h"
#include "udev-util.h"
#include "udevadm.h"
#include "udevd.h"
#include "verbs.h"

PagerFlags arg_pager_flags = 0;

COMMAND(
        "udevadm\0",
        "Send control commands or test the device manager.",
        .argspec = "COMMAND [COMMAND OPTION…]\0",
        .man_pages = "udevadm(8)\0",
        .option_namespace = "udevadm",
        .pager_flags = &arg_pager_flags,
);

/* All verbs are defined here, right after the COMMAND, so that they are attributed to it. Each
 * subcommand parses its own options from the "udevadm-<verb>" namespace, see udevadm-*.c. */
VERB_COMMON_HELP_AUTO_PROGRAM("udevadm");

#define UDEVADM_VERB(fn, name, args, flags, help, footer)               \
        VERB_SCOPE_NS_FULL(, fn, name, "udevadm-" name, args, VERB_ANY, VERB_ANY, flags, /* dat= */ 0, help, footer)

UDEVADM_VERB(verb_info_main,    "info",         "[DEVPATH|FILE]\0",   0,                    "Query sysfs or the udev database",      NULL);
UDEVADM_VERB(verb_trigger_main, "trigger",      "DEVPATH\0",          0,                    "Request events from the kernel",        NULL);
UDEVADM_VERB(verb_settle_main,  "settle",       NULL,                 0,                    "Wait for pending udev events",          NULL);
UDEVADM_VERB(verb_control_main, "control",      NULL,                 VERB_OPTION_REQUIRED, "Control the udev daemon",               NULL);
UDEVADM_VERB(verb_monitor_main, "monitor",      NULL,                 0,                    "Listen to kernel and udev events",      NULL);
UDEVADM_VERB(verb_test_main,    "test",         "DEVPATH\0",          0,                    "Test an event run",                     NULL);
UDEVADM_VERB(verb_builtin_main, "test-builtin", "COMMAND DEVPATH\0",  0,                    "Test a built-in command",               NULL);
UDEVADM_VERB(verb_verify_main,  "verify",       "[FILE…]\0",          0,                    "Verify udev rules files",               NULL);
UDEVADM_VERB(verb_cat_main,     "cat",          "[FILE…]\0",          0,                    "Show udev rules files",                 NULL);
UDEVADM_VERB(verb_wait_main,    "wait",         "DEVICE [DEVICE…]\0", 0,                    "Wait for device or device symlink",     NULL);
UDEVADM_VERB(verb_lock_main,    "lock",         "COMMAND\0--print\0", 0,                    "Lock a block device and run a command", NULL);
UDEVADM_VERB(verb_hwdb_main,    "hwdb",         NULL,                 VERB_DEPRECATED,      "Update or query the hardware database",
                                                                                            "Verb 'hwdb' is deprecated. Use systemd-hwdb instead.");

VERB_NOARG(verb_version_main, "version", /* help= */ NULL);
static int verb_version_main(int argc, char *argv[], uintptr_t _data, void *userdata) {
        return print_version();
}

static int parse_argv(int argc, char *argv[], char ***remaining_args) {
        assert(argc >= 0);
        assert(argv);
        assert(remaining_args);

        OptionParser opts = { argc, argv, OPTION_PARSER_STOP_AT_FIRST_NONOPTION, "udevadm" };

        FOREACH_OPTION_OR_RETURN(c, &opts)
                switch (c) {

                OPTION_NAMESPACE("udevadm"): {}

                OPTION_COMMON_HELP:
                        return command_print_help_name("udevadm");

                OPTION_COMMON_VERSION_WITH_HIDDEN_V:
                        return print_version();

                OPTION('d', "debug", NULL, "Enable debug logging"):
                        log_set_max_level(LOG_DEBUG);
                        break;

                OPTION_COMMON_INTROSPECT_CLI:
                        return introspect_cli(SD_JSON_FORMAT_OFF);
                }

        *remaining_args = option_parser_get_args(&opts);
        return 1; /* work to do */
}

int print_version(void) {
        /* Dracut relies on the version being a single integer */
        puts(PROJECT_VERSION_STR);
        return 0;
}

static int run(int argc, char *argv[]) {
        char **args = NULL;
        int r;

        LIBACL_NOTE(recommended);
        LIBBLKID_NOTE(recommended);
        LIBKMOD_NOTE(recommended);
        LIBMOUNT_NOTE(recommended);
        LIBSELINUX_NOTE(recommended);
        TPM2_NOTE(recommended);

        if (invoked_as(argv, "udevd"))
                return run_udevd(argc, argv);

        (void) udev_parse_config();
        log_setup();

        r = parse_argv(argc, argv, &args);
        if (r <= 0)
                return r;

        r = mac_init();
        if (r < 0)
                return r;

        return dispatch_verb(args, NULL);
}

DEFINE_MAIN_FUNCTION_WITH_POSITIVE_FAILURE(run);
