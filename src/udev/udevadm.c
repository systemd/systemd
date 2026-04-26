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
        static const char *const short_descriptions[][2] = {
                { "info",         "Query sysfs or the udev database"  },
                { "trigger",      "Request events from the kernel"    },
                { "settle",       "Wait for pending udev events"      },
                { "control",      "Control the udev daemon"           },
                { "monitor",      "Listen to kernel and udev events"  },
                { "test",         "Test an event run"                 },
                { "test-builtin", "Test a built-in command"           },
                { "verify",       "Verify udev rules files"           },
                { "cat",          "Show udev rules files"             },
                { "wait",         "Wait for device or device symlink" },
                { "lock",         "Lock a block device"               },
        };

        _cleanup_(table_unrefp) Table *options = NULL;
        int r;

        r = option_parser_get_help_table_ns("udevadm", &options);
        if (r < 0)
                return r;

        help_cmdline("[OPTIONS…] COMMAND [COMMAND OPTIONS…]");
        help_abstract("Send control commands or test the device manager.");

        help_section("Commands:");
        FOREACH_ELEMENT(desc, short_descriptions)
                printf("  %-12s  %s\n", (*desc)[0], (*desc)[1]);

        help_section("Options:");
        r = table_print_or_warn(options);
        if (r < 0)
                return r;

        help_man_page_reference("udevadm", "8");
        return 0;
}

static int parse_argv(int argc, char *argv[], char ***remaining_args) {
        assert(argc >= 0);
        assert(argv);
        assert(remaining_args);

        OptionParser opts = { argc, argv, OPTION_PARSER_STOP_AT_FIRST_NONOPTION, "udevadm" };

        FOREACH_OPTION(c, &opts, /* on_error= */ return c)
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

static int verb_version_main(int argc, char *argv[], uintptr_t _data, void *userdata) {
        return print_version();
}

static int verb_help_main(int argc, char *argv[], uintptr_t _data, void *userdata) {
        return help();
}

static int udevadm_main(char **args) {
        static const Verb verbs[] = {
                { "cat",          VERB_ANY, VERB_ANY, 0, verb_cat_main     },
                { "info",         VERB_ANY, VERB_ANY, 0, verb_info_main    },
                { "trigger",      VERB_ANY, VERB_ANY, 0, verb_trigger_main },
                { "settle",       VERB_ANY, VERB_ANY, 0, verb_settle_main  },
                { "control",      VERB_ANY, VERB_ANY, 0, verb_control_main },
                { "monitor",      VERB_ANY, VERB_ANY, 0, verb_monitor_main },
                { "hwdb",         VERB_ANY, VERB_ANY, 0, verb_hwdb_main    },
                { "test",         VERB_ANY, VERB_ANY, 0, verb_test_main    },
                { "test-builtin", VERB_ANY, VERB_ANY, 0, verb_builtin_main },
                { "wait",         VERB_ANY, VERB_ANY, 0, verb_wait_main    },
                { "lock",         VERB_ANY, VERB_ANY, 0, verb_lock_main    },
                { "verify",       VERB_ANY, VERB_ANY, 0, verb_verify_main  },
                { "version",      VERB_ANY, VERB_ANY, 0, verb_version_main },
                { "help",         VERB_ANY, VERB_ANY, 0, verb_help_main    },
                {}
        };

        return _dispatch_verb_with_args(args, verbs, verbs + ELEMENTSOF(verbs) - 1, NULL);
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

        return udevadm_main(args);
}

DEFINE_MAIN_FUNCTION_WITH_POSITIVE_FAILURE(run);
