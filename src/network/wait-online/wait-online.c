/* SPDX-License-Identifier: LGPL-2.1+ */

#include <getopt.h>

#include "sd-daemon.h"

#include "manager.h"
#include "pretty-print.h"
#include "signal-util.h"
#include "strv.h"

static bool arg_quiet = false;
static usec_t arg_timeout = 120 * USEC_PER_SEC;
static char **arg_interfaces = NULL;
static char **arg_ignore = NULL;

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-networkd-wait-online.service", "8", &link);
        if (r < 0)
                return log_oom();

        printf("%s [OPTIONS...]\n\n"
               "Block until network is configured.\n\n"
               "  -h --help                 Show this help\n"
               "     --version              Print version string\n"
               "  -q --quiet                Do not show status information\n"
               "  -i --interface=INTERFACE  Block until at least these interfaces have appeared\n"
               "     --ignore=INTERFACE     Don't take these interfaces into account\n"
               "     --timeout=SECS         Maximum time to wait for network connectivity\n"
               "\nSee the %s for details.\n"
               , program_invocation_short_name
               , link
        );

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_IGNORE,
                ARG_TIMEOUT,
        };

        static const struct option options[] = {
                { "help",            no_argument,       NULL, 'h'         },
                { "version",         no_argument,       NULL, ARG_VERSION },
                { "quiet",           no_argument,       NULL, 'q'         },
                { "interface",       required_argument, NULL, 'i'         },
                { "ignore",          required_argument, NULL, ARG_IGNORE  },
                { "timeout",         required_argument, NULL, ARG_TIMEOUT  },
                {}
        };

        int c, r;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "+hi:q", options, NULL)) >= 0)

                switch (c) {

                case 'h':
                        help();
                        return 0;

                case 'q':
                        arg_quiet = true;
                        break;

                case ARG_VERSION:
                        return version();

                case 'i':
                        if (strv_extend(&arg_interfaces, optarg) < 0)
                                return log_oom();

                        break;

                case ARG_IGNORE:
                        if (strv_extend(&arg_ignore, optarg) < 0)
                                return log_oom();

                        break;

                case ARG_TIMEOUT:
                        r = parse_sec(optarg, &arg_timeout);
                        if (r < 0)
                                return r;

                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unhandled option");
                }

        return 1;
}

int main(int argc, char *argv[]) {
        _cleanup_(manager_freep) Manager *m = NULL;
        int r;

        log_setup_service();

        umask(0022);

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        if (arg_quiet)
                log_set_max_level(LOG_WARNING);

        assert_se(sigprocmask_many(SIG_BLOCK, NULL, SIGTERM, SIGINT, -1) >= 0);

        r = manager_new(&m, arg_interfaces, arg_ignore, arg_timeout);
        if (r < 0) {
                log_error_errno(r, "Could not create manager: %m");
                goto finish;
        }

        if (manager_all_configured(m)) {
                r = 0;
                goto finish;
        }

        sd_notify(false,
                  "READY=1\n"
                  "STATUS=Waiting for network connections...");

        r = sd_event_loop(m->event);
        if (r < 0) {
                log_error_errno(r, "Event loop failed: %m");
                goto finish;
        }

finish:
        strv_free(arg_interfaces);
        strv_free(arg_ignore);

        if (r >= 0) {
                sd_notify(false, "STATUS=All interfaces configured...");

                return EXIT_SUCCESS;
        } else {
                sd_notify(false, "STATUS=Failed waiting for network connectivity...");

                return EXIT_FAILURE;
        }
}
