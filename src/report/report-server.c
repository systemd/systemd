/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"
#include "sd-varlink.h"

#include "build.h"
#include "log.h"
#include "main-func.h"
#include "report-server.h"
#include "varlink-io.systemd.Metrics.h"
#include "varlink-io.systemd.Report.Signer.h"
#include "varlink-util.h"
#include "verbs.h"

int report_server_add_metrics_interface(
                sd_varlink_server *server,
                sd_varlink_method_t list,
                sd_varlink_method_t describe) {

        int r;

        assert(server);
        assert(list);
        assert(describe);

        r = sd_varlink_server_add_interface(server, &vl_interface_io_systemd_Metrics);
        if (r < 0)
                return log_error_errno(r, "Failed to add io.systemd.Metrics Varlink interface: %m");

        r = sd_varlink_server_bind_method_many(
                        server,
                        "io.systemd.Metrics.List",     list,
                        "io.systemd.Metrics.Describe", describe);
        if (r < 0)
                return log_error_errno(r, "Failed to bind io.systemd.Metrics Varlink methods: %m");

        return 0;
}

int report_server_add_signer_interface(sd_varlink_server *server, sd_varlink_method_t sign) {
        int r;

        assert(server);
        assert(sign);

        r = sd_varlink_server_add_interface(server, &vl_interface_io_systemd_Report_Signer);
        if (r < 0)
                return log_error_errno(r, "Failed to add io.systemd.Report.Signer Varlink interface: %m");

        r = sd_varlink_server_bind_method(server, "io.systemd.Report.Signer.Sign", sign);
        if (r < 0)
                return log_error_errno(r, "Failed to bind io.systemd.Report.Signer.Sign Varlink method: %m");

        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        int r;

        assert(argc >= 0);
        assert(argv);

        OptionParser opts = { argc, argv };

        FOREACH_OPTION_OR_RETURN(c, &opts)
                switch (c) {
                OPTION_COMMON_HELP:
                        return command_print_help();

                OPTION_COMMON_VERSION:
                        return version();

                OPTION_COMMON_INTROSPECT_CLI:
                        return introspect_cli(SD_JSON_FORMAT_OFF);
                }

        if (option_parser_get_n_args(&opts) > 0)
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
        _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *server = NULL;
        int r;

        log_setup();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        r = varlink_server_new(&server, report_server_flags, /* userdata= */ NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate Varlink server: %m");

        r = report_server_setup(server);
        if (r < 0)
                return r;

        r = sd_varlink_server_loop_auto(server);
        if (r < 0)
                return log_error_errno(r, "Failed to run Varlink event loop: %m");

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
