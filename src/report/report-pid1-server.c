/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-varlink.h"

#include "alloc-util.h"
#include "ansi-color.h"
#include "build.h"
#include "capability-util.h"
#include "fd-util.h"
#include "format-table.h"
#include "log.h"
#include "main-func.h"
#include "options.h"
#include "report-pid1.h"
#include "user-util.h"
#include "varlink-io.systemd.Metrics.h"
#include "varlink-util.h"

static int vl_server(void) {
        _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *vs = NULL;
        _cleanup_free_ Pid1Context *ctx = NULL;
        _cleanup_close_ int stat_fd = -EBADF, status_fd = -EBADF;
        int r;

        ctx = new0(Pid1Context, 1);
        if (!ctx)
                return log_oom();

        /* Do the privileged collection now: count /proc/1/fd (root-only) and open /proc/1/stat and
         * /proc/1/status so the subsequent reads survive the privilege drop. The snapshot is served for
         * the lifetime of this (short-lived, Accept=yes) process; per-source errors are recorded in ctx
         * and callbacks skip emission for any source that failed. */
        pid1_context_collect_privileged(ctx, &stat_fd, &status_fd);

        /* Drop to nobody before touching anything remote-reachable. Everything below this line — parsing
         * the /proc fds, JSON building, Varlink dispatch — runs unprivileged. */
        r = drop_privileges(UID_NOBODY, GID_NOBODY, /* keep_capabilities= */ 0);
        if (r < 0)
                return log_error_errno(r, "Failed to drop privileges to nobody: %m");

        pid1_context_collect_unprivileged(ctx, TAKE_FD(stat_fd), TAKE_FD(status_fd));

        r = varlink_server_new(&vs, SD_VARLINK_SERVER_INHERIT_USERDATA, ctx);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate Varlink server: %m");

        r = sd_varlink_server_add_interface(vs, &vl_interface_io_systemd_Metrics);
        if (r < 0)
                return log_error_errno(r, "Failed to add Varlink interface: %m");

        r = sd_varlink_server_bind_method_many(
                        vs,
                        "io.systemd.Metrics.List",     vl_method_list_metrics,
                        "io.systemd.Metrics.Describe", vl_method_describe_metrics);
        if (r < 0)
                return log_error_errno(r, "Failed to bind Varlink methods: %m");

        r = sd_varlink_server_loop_auto(vs);
        if (r < 0)
                return log_error_errno(r, "Failed to run Varlink event loop: %m");

        return 0;
}

static int help(void) {
        _cleanup_(table_unrefp) Table *options = NULL;
        int r;

        r = option_parser_get_help_table(&options);
        if (r < 0)
                return r;

        printf("%s [OPTIONS...]\n"
               "\n%sReport PID1 resource metrics.%s\n"
               "\n%sOptions:%s\n",
               program_invocation_short_name,
               ansi_highlight(),
               ansi_normal(),
               ansi_underline(),
               ansi_normal());

        return table_print_or_warn(options);
}

static int parse_argv(int argc, char *argv[]) {
        int r;

        assert(argc >= 0);
        assert(argv);

        OptionParser state = { argc, argv };

        FOREACH_OPTION(&state, c, /* ret_a= */ NULL, /* on_error= */ return c)
                switch (c) {
                OPTION_COMMON_HELP:
                        return help();

                OPTION_COMMON_VERSION:
                        return version();
                }

        if (state.optind < argc)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "This program takes no arguments.");

        r = sd_varlink_invocation(SD_VARLINK_ALLOW_ACCEPT);
        if (r < 0)
                return log_error_errno(r, "Failed to check if invoked in Varlink mode: %m");
        if (r == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "This program can only run as a Varlink service.");

        return 1;
}

static int run(int argc, char *argv[]) {
        int r;

        log_setup();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        return vl_server();
}

DEFINE_MAIN_FUNCTION(run);
