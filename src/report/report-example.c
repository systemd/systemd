/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* Example provider, built with report-server.c but not installed. */

#include "sd-varlink.h"

#include "metrics.h"
#include "report-server.h"
#include "verbs.h"

COMMAND(
        "systemd-report-example\0",
        "Report example metrics.",
        .option_namespace = "common",
);

/* Default for unprivileged metrics.
 * For a privileged-only service, use SD_VARLINK_SERVER_ROOT_ONLY|SD_VARLINK_SERVER_MYSELF_ONLY.
 * To pass server userdata to method handlers, also set SD_VARLINK_SERVER_INHERIT_USERDATA. */
const sd_varlink_server_flags_t report_server_flags = 0;

static int example_generate(const MetricFamily *mf, sd_varlink *link, void *userdata) {
        return metric_build_send_unsigned(mf, link, /* object= */ NULL, 1, /* fields= */ NULL);
}

static const MetricFamily example_metrics[] = {
        {
                .name = "io.systemd.Example.Value",
                .description = "An example value.",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = example_generate,
        },
        {}
};

static int vl_method_list_metrics(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return metrics_method_list(example_metrics, link, parameters, flags, userdata);
}

static int vl_method_describe_metrics(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return metrics_method_describe(example_metrics, link, parameters, flags, userdata);
}

int report_server_setup(sd_varlink_server *server) {
        /* Optional signer: define vl_method_sign() with the same callback signature.
         * With flags = 0, the signing handler must enforce privileged access itself.
         *
         * int r;
         * r = report_server_add_signer_interface(server, vl_method_sign);
         * if (r < 0)
         *         return r;
         */

        return report_server_add_metrics_interface(server, vl_method_list_metrics, vl_method_describe_metrics);
}
