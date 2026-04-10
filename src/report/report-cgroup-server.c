/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>

#include "sd-varlink.h"

#include "alloc-util.h"
#include "ansi-color.h"
#include "build.h"
#include "log.h"
#include "main-func.h"
#include "pretty-print.h"
#include "report-cgroup.h"
#include "varlink-io.systemd.Metrics.h"
#include "varlink-util.h"

static int vl_server(void) {
        _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *vs = NULL;
        _cleanup_(cgroup_context_freep) CGroupContext *ctx = NULL;
        int r;

        ctx = new0(CGroupContext, 1);
        if (!ctx)
                return log_oom();

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
        _cleanup_free_ char *url = NULL;
        int r;

        r = terminal_urlify_man("systemd-report-cgroup", "8", &url);
        if (r < 0)
                return log_oom();

        printf("%s [OPTIONS...]\n"
               "\n%sReport cgroup metrics.%s\n"
               "\n%sOptions:%s\n"
               "  -h --help     Show this help\n"
               "     --version  Show package version\n"
               "\nSee the %s for details.\n",
               program_invocation_short_name,
               ansi_highlight(),
               ansi_normal(),
               ansi_underline(),
               ansi_normal(),
               url);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_VERSION = 0x100,
        };

        static const struct option options[] = {
                { "help",    no_argument, NULL, 'h'         },
                { "version", no_argument, NULL, ARG_VERSION },
                {}
        };

        int c, r;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0)

                switch (c) {

                case 'h':
                        return help();

                case ARG_VERSION:
                        return version();

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        if (optind < argc)
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
