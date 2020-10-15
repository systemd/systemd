/* SPDX-License-Identifier: LGPL-2.1+ */

#include <getopt.h>

#include "cgroup-util.h"
#include "conf-parser.h"
#include "daemon-util.h"
#include "log.h"
#include "main-func.h"
#include "oomd-manager.h"
#include "parse-util.h"
#include "pretty-print.c"
#include "psi-util.h"
#include "signal-util.h"

static bool arg_dry_run = false;
static int arg_swap_used_limit = -1;
static int arg_mem_pressure_limit = -1;

static int parse_config(void) {
        static const ConfigTableItem items[] = {
                { "OOM", "SwapUsedLimitPercent",              config_parse_percent, 0, &arg_swap_used_limit    },
                { "OOM", "DefaultMemoryPressureLimitPercent", config_parse_percent, 0, &arg_mem_pressure_limit },
                {}
        };

        return config_parse_many_nulstr(PKGSYSCONFDIR "/oomd.conf",
                                        CONF_PATHS_NULSTR("systemd/oomd.conf.d"),
                                        "OOM\0",
                                        config_item_table_lookup,
                                        items,
                                        CONFIG_PARSE_WARN,
                                        NULL,
                                        NULL);
}

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-oomd", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%s [OPTIONS...]\n\n"
                        "Run the userspace out-of-memory (OOM) killer.\n\n"
                        "  -h --help     Show this help\n"
                        "     --dry-run  Log write/destructive actions instead of doing them\n"
                        "\nSee the %s for details.\n"
                        , program_invocation_short_name
                        , link
              );

        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_DRY_RUN,
        };

        static const struct option options[] = {
                { "help",    no_argument, NULL, 'h'         },
                { "dry-run", no_argument, NULL, ARG_DRY_RUN },
                {}
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0)

                switch (c) {

                        case 'h':
                                return help();

                        case ARG_DRY_RUN:
                                arg_dry_run = true;
                                break;

                        case '?':
                                return -EINVAL;

                        default:
                                assert_not_reached("Invalid option passed.");
                }

        return 1;
}

static int run(int argc, char *argv[]) {
        _cleanup_(notify_on_cleanup) const char *notify_msg = NULL;
        _cleanup_(manager_freep) Manager *m = NULL;
        int r;

        log_setup_service();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        r = parse_config();
        if (r < 0)
                return r;

        /* Do some basic requirement checks for running systemd-oomd. It's not exhaustive as some of the other
         * requirements do not have a reliable means to check for in code. */
        if (access("/proc/swaps", F_OK) < 0)
                return log_error_errno(errno, "Swap not enabled: %m");

        if (!is_pressure_supported())
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Pressure Stall Information (PSI) is not supported");

        r = cg_all_unified();
        if (r < 0)
                return log_error_errno(r, "Failed to determine whether the unified cgroups hierarchy is used: %m");
        if (r == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Requires the unified cgroups hierarchy");

        assert_se(sigprocmask_many(SIG_BLOCK, NULL, SIGTERM, SIGINT, -1) >= 0);

        r = manager_new(&m);
        if (r < 0)
                return log_error_errno(r, "Failed to create manager: %m");

        r = manager_start(m, arg_dry_run, arg_swap_used_limit, arg_mem_pressure_limit);
        if (r < 0)
                return log_error_errno(r, "Failed to start up daemon: %m");

        notify_msg = notify_start(NOTIFY_READY, NOTIFY_STOPPING);

        log_info("systemd-oomd starting%s!", arg_dry_run ? " in dry run mode" : "");

        r = sd_event_loop(m->event);
        if (r < 0)
                return log_error_errno(r, "Event loop failed: %m");

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
