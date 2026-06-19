/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"
#include "sd-varlink.h"

#include "build.h"
#include "format-table.h"
#include "help-util.h"
#include "iovec-util.h"
#include "json-util.h"
#include "log.h"
#include "main-func.h"
#include "options.h"
#include "sha256.h"
#include "string-util.h"
#include "tsm-report.h"
#include "varlink-io.systemd.Report.Signer.h"
#include "varlink-util.h"

typedef struct SignParameters {
        struct iovec digest;
        const char *algorithm;
} SignParameters;

static void sign_parameters_done(SignParameters *p) {
        iovec_done(&p->digest);
}

static int vl_method_sign(
                sd_varlink *link,
                sd_json_variant *parameters,
                sd_varlink_method_flags_t flags,
                void *userdata) {

        static const sd_json_dispatch_field dispatch_table[] = {
                { "digest",    SD_JSON_VARIANT_STRING, json_dispatch_unhex_iovec,     offsetof(SignParameters, digest),    SD_JSON_MANDATORY },
                { "algorithm", SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, offsetof(SignParameters, algorithm), SD_JSON_MANDATORY },
                {}
        };

        _cleanup_(sign_parameters_done) SignParameters sp = {};
        _cleanup_(tsm_report_freep) TsmReport *report = NULL;
        int r;

        assert(link);
        assert(parameters);

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &sp);
        if (r != 0)
                return r;

        if (!streq(sp.algorithm, "SHA256"))
                return sd_varlink_error_invalid_parameter_name(link, "algorithm");
        if (sp.digest.iov_len != SHA256_DIGEST_SIZE)
                return sd_varlink_error_invalid_parameter_name(link, "digest");

        uint8_t report_data[TSM_REPORT_DATA_SIZE] = {};
        memcpy(report_data, sp.digest.iov_base, sp.digest.iov_len);

        r = tsm_report_acquire(&IOVEC_MAKE(report_data, sizeof report_data), /* options= */ NULL, &report);
        if (IN_SET(r, -EOPNOTSUPP, -ENXIO))
                /* Returning an error will fail the whole report signing, so we return
                 * no signature instead which will be ignored by the aggregator. */
                return sd_varlink_replybo(link, SD_JSON_BUILD_PAIR_EMPTY_ARRAY("data"));
        if (r < 0)
                return log_error_errno(r, "Failed to acquire TSM report: %m");

        return sd_varlink_replybo(
                        link,
                        SD_JSON_BUILD_PAIR("data",
                                        SD_JSON_BUILD_ARRAY(
                                                        SD_JSON_BUILD_OBJECT(
                                                                        SD_JSON_BUILD_PAIR_STRING("provider", report->provider),
                                                                        JSON_BUILD_PAIR_IOVEC_BASE64("outblob", &report->outblob),
                                                                        SD_JSON_BUILD_PAIR_CONDITION(iovec_is_set(&report->auxblob),
                                                                                        "auxblob", JSON_BUILD_IOVEC_BASE64(&report->auxblob)),
                                                                        SD_JSON_BUILD_PAIR_CONDITION(iovec_is_set(&report->manifestblob),
                                                                                        "manifestblob", JSON_BUILD_IOVEC_BASE64(&report->manifestblob))))));
}

static int vl_server(void) {
        _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *vs = NULL;
        int r;

        r = varlink_server_new(&vs, SD_VARLINK_SERVER_ROOT_ONLY|SD_VARLINK_SERVER_MYSELF_ONLY, /* userdata = */ NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate Varlink server: %m");

        r = sd_varlink_server_add_interface(vs, &vl_interface_io_systemd_Report_Signer);
        if (r < 0)
                return log_error_errno(r, "Failed to add Varlink interface: %m");

        r = sd_varlink_server_bind_method(vs, "io.systemd.Report.Signer.Sign", vl_method_sign);
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

        help_cmdline("[OPTIONS...]");
        help_abstract("Get an attestation report via configfs Trusted Security Module (TSM) "
                      "that includes the hash of the system report.");
        help_section("Options");

        r = table_print_or_warn(options);
        if (r < 0)
                return r;

        help_man_page_reference("systemd-report-sign-tsm@.service", "8");
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
                        return help();
                OPTION_COMMON_VERSION:
                        return version();
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

        return vl_server();
}

DEFINE_MAIN_FUNCTION(run);
