/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <stdio.h>

#include "argv-util.h"
#include "format-table.h"
#include "help-util.h"
#include "label-util.h"
#include "main-func.h"
#include "options.h"
#include "udev-util.h"
#include "udevadm.h"
#include "udevd.h"
#include "verbs.h"

static int help(void) {
        _cleanup_(table_unrefp) Table *verbs = NULL, *options = NULL;
        int r;

        r = verbs_get_help_table(&verbs);
        if (r < 0)
                return r;

        r = option_parser_get_help_table_ns("udevadm", &options);
        if (r < 0)
                return r;

        (void) table_sync_column_widths(0, verbs, options);

        help_cmdline("[OPTIONS…] COMMAND [COMMAND OPTIONS…]");
        help_abstract("Send control commands or test the device manager.");

        help_section("Commands");
        r = table_print_or_warn(verbs);
        if (r < 0)
                return r;

        help_section("Options");
        r = table_print_or_warn(options);
        if (r < 0)
                return r;

        help_man_page_reference("udevadm", "8");
        return 0;
}

VERB_COMMON_HELP(help);

VERB_SCOPE(, verb_info_main,    "info",         "[DEVPATH|FILE]",       VERB_ANY, VERB_ANY, 0, "Query sysfs or the udev database");
VERB_SCOPE(, verb_trigger_main, "trigger",      "DEVPATH",              VERB_ANY, VERB_ANY, 0, "Request events from the kernel");
VERB_SCOPE(, verb_settle_main,  "settle",       NULL,                   VERB_ANY, VERB_ANY, 0, "Wait for pending udev events");
VERB_SCOPE(, verb_control_main, "control",      "OPTION",               VERB_ANY, VERB_ANY, 0, "Control the udev daemon");
VERB_SCOPE(, verb_monitor_main, "monitor",      NULL,                   VERB_ANY, VERB_ANY, 0, "Listen to kernel and udev events");
VERB_SCOPE(, verb_test_main,    "test",         "DEVPATH",              VERB_ANY, VERB_ANY, 0, "Test an event run");
VERB_SCOPE(, verb_builtin_main, "test-builtin", "COMMAND DEVPATH",      VERB_ANY, VERB_ANY, 0, "Test a built-in command");
VERB_SCOPE(, verb_verify_main,  "verify",       "[FILE…]",              VERB_ANY, VERB_ANY, 0, "Verify udev rules files");
VERB_SCOPE(, verb_cat_main,     "cat",          "[FILE…]",              VERB_ANY, VERB_ANY, 0, "Show udev rules files");
VERB_SCOPE(, verb_wait_main,    "wait",         "DEVICE [DEVICE…]",     VERB_ANY, VERB_ANY, 0, "Wait for device or device symlink");
VERB_SCOPE(, verb_lock_main,    "lock",         "[OPTIONS…] COMMAND",   VERB_ANY, VERB_ANY, 0, "Lock a block device");
VERB_SCOPE(, verb_hwdb_main,    "hwdb",         NULL,                   VERB_ANY, VERB_ANY, 0, /* help= */ NULL); /* deprecated */

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
                        return help();

                OPTION_COMMON_VERSION_WITH_HIDDEN_V:
                        return print_version();

                OPTION('d', "debug", NULL, "Enable debug logging"):
                        log_set_max_level(LOG_DEBUG);
                        break;
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
