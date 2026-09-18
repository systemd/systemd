/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"
#include "sd-varlink.h"

#include "alloc-util.h"
#include "build.h"
#include "conf-parser.h"
#include "log.h"
#include "main-func.h"
#include "report-geoip.h"
#include "string-util.h"
#include "time-util.h"
#include "varlink-io.systemd.Metrics.h"
#include "varlink-util.h"
#include "verbs.h"
#include "web-util.h"

#define REPORT_GEOIP_DEFAULT_REFRESH_USEC (30 * USEC_PER_MINUTE)

COMMAND(
        "systemd-report-geoip\0",
        "Report the approximate geographic location of the system as system report metrics.",
        .man_pages = "systemd-report-geoip@.service(8)\0",
);

char *arg_endpoint = NULL;
usec_t arg_refresh_usec = REPORT_GEOIP_DEFAULT_REFRESH_USEC;

STATIC_DESTRUCTOR_REGISTER(arg_endpoint, freep);

static int config_parse_endpoint(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        char **s = ASSERT_PTR(data);

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                *s = mfree(*s);
                return 0;
        }

        if (!http_url_is_valid(rvalue)) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "%s= URL is not valid, ignoring: %s", lvalue, rvalue);
                return 0;
        }

        return free_and_strdup_warn(s, rvalue);
}

static int parse_config(void) {
        static const ConfigTableItem items[] = {
                { "GeoIP", "Endpoint",   config_parse_endpoint, 0, &arg_endpoint     },
                { "GeoIP", "RefreshSec", config_parse_sec,      0, &arg_refresh_usec },
                {}
        };

        return config_parse_standard_file_with_dropins(
                        "systemd/report-geoip.conf",
                        "GeoIP\0",
                        config_item_table_lookup, items,
                        CONFIG_PARSE_WARN,
                        /* userdata= */ NULL);
}

static int vl_server(void) {
        _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *vs = NULL;
        int r;

        r = varlink_server_new(&vs, /* flags= */ 0, /* userdata= */ NULL);
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
        int r;

        log_setup();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        (void) parse_config();

        return vl_server();
}

DEFINE_MAIN_FUNCTION(run);
