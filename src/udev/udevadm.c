/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <getopt.h>
#include <stdio.h>

#include "alloc-util.h"
#include "argv-util.h"
#include "label-util.h"
#include "main-func.h"
#include "pretty-print.h"
#include "udev-util.h"
#include "udevadm.h"
#include "udevd.h"
#include "verbs.h"

#include "udevadm.args.inc"

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("udevadm", "8", &link);
        if (r < 0)
                return log_oom();

        printf("%s [--help] [--version] [--debug] COMMAND [COMMAND OPTIONS]\n\n"
               "Send control commands or test the device manager.\n\n"
               "Commands:\n"
               "  info          Query sysfs or the udev database\n"
               "  trigger       Request events from the kernel\n"
               "  settle        Wait for pending udev events\n"
               "  control       Control the udev daemon\n"
               "  monitor       Listen to kernel and udev events\n"
               "  test          Test an event run\n"
               "  test-builtin  Test a built-in command\n"
               "  verify        Verify udev rules files\n"
               "  cat           Show udev rules files\n"
               "  wait          Wait for device or device symlink\n"
               "  lock          Lock a block device\n"
               "\nOptions:\n"
               OPTION_HELP_GENERATED
               "\nSee the %s for details.\n",
               program_invocation_short_name,
               link);

        return 0;
}

int print_version(void) {
        /* Dracut relies on the version being a single integer */
        puts(PROJECT_VERSION_STR);
        return 0;
}

static int version_main(int argc, char *argv[], void *userdata) {
        return print_version();
}

static int help_main(int argc, char *argv[], void *userdata) {
        return help();
}

static int udevadm_main(int argc, char *argv[]) {
        static const Verb verbs[] = {
                { "cat",          VERB_ANY, VERB_ANY, 0, cat_main     },
                { "info",         VERB_ANY, VERB_ANY, 0, info_main    },
                { "trigger",      VERB_ANY, VERB_ANY, 0, trigger_main },
                { "settle",       VERB_ANY, VERB_ANY, 0, settle_main  },
                { "control",      VERB_ANY, VERB_ANY, 0, control_main },
                { "monitor",      VERB_ANY, VERB_ANY, 0, monitor_main },
                { "hwdb",         VERB_ANY, VERB_ANY, 0, hwdb_main    },
                { "test",         VERB_ANY, VERB_ANY, 0, test_main    },
                { "test-builtin", VERB_ANY, VERB_ANY, 0, builtin_main },
                { "wait",         VERB_ANY, VERB_ANY, 0, wait_main    },
                { "lock",         VERB_ANY, VERB_ANY, 0, lock_main    },
                { "verify",       VERB_ANY, VERB_ANY, 0, verify_main  },
                { "version",      VERB_ANY, VERB_ANY, 0, version_main },
                { "help",         VERB_ANY, VERB_ANY, 0, help_main    },
                {}
        };

        return dispatch_verb(argc, argv, verbs, NULL);
}

static int run(int argc, char *argv[]) {
        int r;

        if (invoked_as(argv, "udevd"))
                return run_udevd(argc, argv);

        (void) udev_parse_config();
        log_setup();

        r = parse_argv_generated(argc, argv);
        if (r <= 0)
                return r;

        r = mac_init();
        if (r < 0)
                return r;

        return udevadm_main(argc, argv);
}

DEFINE_MAIN_FUNCTION_WITH_POSITIVE_FAILURE(run);
