/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <errno.h>
#include <getopt.h>
#include <stddef.h>
#include <stdio.h>

#include "alloc-util.h"
#include "main-func.h"
#include "pretty-print.h"
#include "process-util.h"
#include "selinux-util.h"
#include "string-util.h"
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

        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("udevadm", "8", &link);
        if (r < 0)
                return log_oom();

        printf("%s [--help] [--version] [--debug] COMMAND [COMMAND OPTIONS]\n\n"
               "Send control commands or test the device manager.\n\n"
               "Commands:\n",
               program_invocation_short_name);

        FOREACH_ELEMENT(desc, short_descriptions)
                printf("  %-12s  %s\n", (*desc)[0], (*desc)[1]);

        printf("\nSee the %s for details.\n", link);
        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        static const struct option options[] = {
                { "debug",   no_argument, NULL, 'd' },
                { "help",    no_argument, NULL, 'h' },
                { "version", no_argument, NULL, 'V' },
                {}
        };
        int c;

        assert(argc >= 0);
        assert(argv);

        /* Resetting to 0 forces the invocation of an internal initialization routine of getopt_long()
         * that checks for GNU extensions in optstring ('-' or '+' at the beginning). */
        optind = 0;
        while ((c = getopt_long(argc, argv, "+dhV", options, NULL)) >= 0)
                switch (c) {

                case 'd':
                        log_set_max_level(LOG_DEBUG);
                        break;

                case 'h':
                        return help();

                case 'V':
                        return print_version();

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        return 1; /* work to do */
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

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        r = mac_init();
        if (r < 0)
                return r;

        return udevadm_main(argc, argv);
}

DEFINE_MAIN_FUNCTION_WITH_POSITIVE_FAILURE(run);
