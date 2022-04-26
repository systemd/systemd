/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>

#include "bus-log-control-api.h"
#include "bus-object.h"
#include "cgroup-util.h"
#include "conf-parser.h"
#include "daemon-util.h"
#include "log.h"
#include "main-func.h"
#include "oomd-manager.h"
#include "oomd-manager-bus.h"
#include "parse-util.h"
#include "pretty-print.c"
#include "psi-util.h"
#include "signal-util.h"

static bool arg_dry_run = false;
static int arg_swap_used_limit_permyriad = -1;
static int arg_mem_pressure_limit_permyriad = -1;
static usec_t arg_mem_pressure_usec = 0;

static int parse_config(void) {
        static const ConfigTableItem items[] = {
                { "OOM", "SwapUsedLimit",                    config_parse_permyriad, 0, &arg_swap_used_limit_permyriad    },
                { "OOM", "DefaultMemoryPressureLimit",       config_parse_permyriad, 0, &arg_mem_pressure_limit_permyriad },
                { "OOM", "DefaultMemoryPressureDurationSec", config_parse_sec,       0, &arg_mem_pressure_usec            },
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
               "  -h --help                 Show this help\n"
               "     --version              Show package version\n"
               "     --dry-run              Only print destructive actions instead of doing them\n"
               "     --bus-introspect=PATH  Write D-Bus XML introspection data\n"
               "\nSee the %s for details.\n",
               program_invocation_short_name,
               link);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_VERSION = 0x100,
                ARG_DRY_RUN,
                ARG_BUS_INTROSPECT,
        };

        static const struct option options[] = {
                { "help",           no_argument,       NULL, 'h'                },
                { "version",        no_argument,       NULL, ARG_VERSION        },
                { "dry-run",        no_argument,       NULL, ARG_DRY_RUN        },
                { "bus-introspect", required_argument, NULL, ARG_BUS_INTROSPECT },
                {}
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0)

                switch (c) {

                case 'h':
                        return help();

                case ARG_VERSION:
                        return version();

                case ARG_DRY_RUN:
                        arg_dry_run = true;
                        break;

                case ARG_BUS_INTROSPECT:
                        return bus_introspect_implementations(
                                        stdout,
                                        optarg,
                                        BUS_IMPLEMENTATIONS(&manager_object,
                                                            &log_control_object));

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        if (optind < argc)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "This program takes no arguments.");

        return 1;
}

static int run(int argc, char *argv[]) {
        _unused_ _cleanup_(notify_on_cleanup) const char *notify_msg = NULL;
        _cleanup_(manager_freep) Manager *m = NULL;
        _cleanup_free_ char *swap = NULL;
        unsigned long long s = 0;
        CGroupMask mask;
        int r;

        log_setup();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        r = parse_config();
        if (r < 0)
                return r;

        /* Do some basic requirement checks for running systemd-oomd. It's not exhaustive as some of the other
         * requirements do not have a reliable means to check for in code. */

        int n = sd_listen_fds(0);
        if (n > 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Received too many file descriptors");

        int fd = n == 1 ? SD_LISTEN_FDS_START : -1;

        /* SwapTotal is always available in /proc/meminfo and defaults to 0, even on swap-disabled kernels. */
        r = get_proc_field("/proc/meminfo", "SwapTotal", WHITESPACE, &swap);
        if (r < 0)
                return log_error_errno(r, "Failed to get SwapTotal from /proc/meminfo: %m");

        r = safe_atollu(swap, &s);
        if (r < 0 || s == 0)
                log_warning("Swap is currently not detected; memory pressure usage will be degraded");

        if (!is_pressure_supported())
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Pressure Stall Information (PSI) is not supported");

        r = cg_all_unified();
        if (r < 0)
                return log_error_errno(r, "Failed to determine whether the unified cgroups hierarchy is used: %m");
        if (r == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Requires the unified cgroups hierarchy");

        r = cg_mask_supported(&mask);
        if (r < 0)
                return log_error_errno(r, "Failed to get supported cgroup controllers: %m");

        if (!FLAGS_SET(mask, CGROUP_MASK_MEMORY))
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Requires the cgroup memory controller.");

        assert_se(sigprocmask_many(SIG_BLOCK, NULL, SIGTERM, SIGINT, -1) >= 0);

        if (arg_mem_pressure_usec > 0 && arg_mem_pressure_usec < 1 * USEC_PER_SEC)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "DefaultMemoryPressureDurationSec= must be 0 or at least 1s");

        r = manager_new(&m);
        if (r < 0)
                return log_error_errno(r, "Failed to create manager: %m");

        r = manager_start(
                        m,
                        arg_dry_run,
                        arg_swap_used_limit_permyriad,
                        arg_mem_pressure_limit_permyriad,
                        arg_mem_pressure_usec,
                        fd);
        if (r < 0)
                return log_error_errno(r, "Failed to start up daemon: %m");

        notify_msg = notify_start(NOTIFY_READY, NOTIFY_STOPPING);

        log_debug("systemd-oomd started%s.", arg_dry_run ? " in dry run mode" : "");

        r = sd_event_loop(m->event);
        if (r < 0)
                return log_error_errno(r, "Event loop failed: %m");

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
