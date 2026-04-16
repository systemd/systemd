/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-event.h"

#include "alloc-util.h"
#include "build.h"
#include "bus-log-control-api.h"
#include "bus-object.h"
#include "cgroup-util.h"
#include "daemon-util.h"
#include "fileio.h"
#include "format-table.h"
#include "log.h"
#include "main-func.h"
#include "oomd-conf.h"
#include "oomd-manager.h"
#include "oomd-manager-bus.h"
#include "options.h"
#include "parse-util.h"
#include "pretty-print.h"
#include "psi-util.h"

static bool arg_dry_run = false;

static int help(void) {
        _cleanup_free_ char *link = NULL;
        _cleanup_(table_unrefp) Table *options = NULL;
        int r;

        r = terminal_urlify_man("systemd-oomd", "8", &link);
        if (r < 0)
                return log_oom();

        r = option_parser_get_help_table(&options);
        if (r < 0)
                return r;

        printf("%s [OPTIONS...]\n\n"
               "Run the userspace out-of-memory (OOM) killer.\n\n",
               program_invocation_short_name);

        r = table_print_or_warn(options);
        if (r < 0)
                return r;

        printf("\nSee the %s for details.\n", link);
        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        assert(argc >= 0);
        assert(argv);

        OptionParser state = { argc, argv };
        const char *arg;

        FOREACH_OPTION(&state, c, &arg, /* on_error= */ return c)
                switch (c) {

                OPTION_COMMON_HELP:
                        return help();

                OPTION_COMMON_VERSION:
                        return version();

                OPTION_LONG("dry-run", NULL,
                            "Only print destructive actions instead of doing them"):
                        arg_dry_run = true;
                        break;

                OPTION_LONG("bus-introspect", "PATH",
                            "Write D-Bus XML introspection data"):
                        return bus_introspect_implementations(
                                        stdout,
                                        arg,
                                        BUS_IMPLEMENTATIONS(&manager_object,
                                                            &log_control_object));
                }

        if (option_parser_get_n_args(&state) > 0)
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

        /* Do some basic requirement checks for running systemd-oomd. It's not exhaustive as some of the other
         * requirements do not have a reliable means to check for in code. */

        int n = sd_listen_fds(0);
        if (n < 0)
                return log_error_errno(n, "Failed to determine number of listening fds: %m");
        if (n > 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Received too many file descriptors");

        int fd = n == 1 ? SD_LISTEN_FDS_START : -EBADF;

        /* SwapTotal is always available in /proc/meminfo and defaults to 0, even on swap-disabled kernels. */
        r = get_proc_field("/proc/meminfo", "SwapTotal", &swap);
        if (r < 0)
                return log_error_errno(r, "Failed to get SwapTotal from /proc/meminfo: %m");

        r = safe_atollu(swap, &s);
        if (r < 0 || s == 0)
                log_warning("No swap; memory pressure usage will be degraded");

        if (!is_pressure_supported())
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Pressure Stall Information (PSI) is not supported");

        r = cg_mask_supported(&mask);
        if (r < 0)
                return log_error_errno(r, "Failed to get supported cgroup controllers: %m");

        if (!FLAGS_SET(mask, CGROUP_MASK_MEMORY))
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Requires the cgroup memory controller.");

        r = manager_new(&m);
        if (r < 0)
                return log_error_errno(r, "Failed to create manager: %m");

        r = manager_start(
                        m,
                        arg_dry_run,
                        fd);
        if (r < 0)
                return log_error_errno(r, "Failed to start up daemon: %m");

        notify_msg = notify_start(NOTIFY_READY_MESSAGE, NOTIFY_STOPPING_MESSAGE);

        log_debug("systemd-oomd started%s.", arg_dry_run ? " in dry run mode" : "");

        r = sd_event_loop(m->event);
        if (r < 0)
                return log_error_errno(r, "Event loop failed: %m");

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
