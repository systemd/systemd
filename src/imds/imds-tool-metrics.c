/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"
#include "sd-varlink.h"

#include "imds-tool.h"
#include "imds-tool-metrics.h"
#include "imds-util.h"
#include "log.h"
#include "metrics.h"
#include "string-util.h"
#include "varlink-io.systemd.Metrics.h"
#include "varlink-util.h"

#define METRIC_IO_SYSTEMD_INSTANCE_METADATA_PREFIX "io.systemd.InstanceMetadata."

static int metric_vendor_build_json(const MetricFamily *mf, sd_varlink *vl, void *userdata) {
        sd_varlink *imds = userdata; /* The live systemd-imdsd connection, or NULL if unavailable */
        _cleanup_free_ char *vendor = NULL;
        int r;

        assert(mf && mf->name);
        assert(vl);

        if (!imds)
                return 0;

        r = acquire_imds_vendor(imds, &vendor);
        if (r <= 0)
                return 0; /* On error or absence simply omit the metric */

        return metric_build_send_string(mf, vl, /* object= */ NULL, vendor, /* fields= */ NULL);
}

static int metric_well_known_build_json(
                const MetricFamily *mf,
                sd_varlink *vl,
                void *userdata,
                ImdsWellKnown wk) {

        sd_varlink *imds = userdata;
        _cleanup_free_ char *value = NULL;
        int r;

        assert(mf && mf->name);
        assert(vl);

        if (!imds)
                return 0;

        r = acquire_imds_key_as_string(imds, wk, /* key= */ NULL, &value);
        if (r <= 0 || isempty(value))
                return 0; /* Field not supported/set, or error: omit the metric */

        return metric_build_send_string(mf, vl, /* object= */ NULL, value, /* fields= */ NULL);
}

static int metric_hostname_build_json(const MetricFamily *mf, sd_varlink *vl, void *userdata) {
        return metric_well_known_build_json(mf, vl, userdata, IMDS_HOSTNAME);
}

static int metric_ipv4_public_build_json(const MetricFamily *mf, sd_varlink *vl, void *userdata) {
        return metric_well_known_build_json(mf, vl, userdata, IMDS_IPV4_PUBLIC);
}

static int metric_ipv6_public_build_json(const MetricFamily *mf, sd_varlink *vl, void *userdata) {
        return metric_well_known_build_json(mf, vl, userdata, IMDS_IPV6_PUBLIC);
}

static int metric_region_build_json(const MetricFamily *mf, sd_varlink *vl, void *userdata) {
        return metric_well_known_build_json(mf, vl, userdata, IMDS_REGION);
}

static int metric_zone_build_json(const MetricFamily *mf, sd_varlink *vl, void *userdata) {
        return metric_well_known_build_json(mf, vl, userdata, IMDS_ZONE);
}

/* Keep metrics ordered alphabetically */
static const MetricFamily imds_metric_family_table[] = {
        {
                .name = METRIC_IO_SYSTEMD_INSTANCE_METADATA_PREFIX "Hostname",
                .description = "Instance hostname reported by IMDS",
                .type = METRIC_FAMILY_TYPE_STRING,
                .generate = metric_hostname_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_INSTANCE_METADATA_PREFIX "IPv4Public",
                .description = "Public IPv4 address reported by IMDS",
                .type = METRIC_FAMILY_TYPE_STRING,
                .generate = metric_ipv4_public_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_INSTANCE_METADATA_PREFIX "IPv6Public",
                .description = "Public IPv6 address reported by IMDS",
                .type = METRIC_FAMILY_TYPE_STRING,
                .generate = metric_ipv6_public_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_INSTANCE_METADATA_PREFIX "Region",
                .description = "Cloud region reported by IMDS",
                .type = METRIC_FAMILY_TYPE_STRING,
                .generate = metric_region_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_INSTANCE_METADATA_PREFIX "Vendor",
                .description = "Detected cloud vendor",
                .type = METRIC_FAMILY_TYPE_STRING,
                .generate = metric_vendor_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_INSTANCE_METADATA_PREFIX "Zone",
                .description = "Cloud availability zone reported by IMDS",
                .type = METRIC_FAMILY_TYPE_STRING,
                .generate = metric_zone_build_json,
        },
        {}
};

static int vl_method_metrics_describe(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return metrics_method_describe(imds_metric_family_table, link, parameters, flags, userdata);
}

static int vl_method_metrics_list(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        int r;

        /* Acquire a single connection to systemd-imdsd, shared by all metric generators (so they benefit
         * from the daemon's token/data cache). If the daemon is unreachable we still serve an empty list
         * rather than failing the whole request. */
        _cleanup_(sd_varlink_unrefp) sd_varlink *imds = NULL;
        r = connect_imdsd(&imds);
        if (r < 0)
                log_debug_errno(r, "Failed to connect to systemd-imdsd, serving empty metrics list: %m");

        return metrics_method_list(imds_metric_family_table, link, parameters, flags, imds);
}

int imds_metrics_run(void) {
        int r;

        /* Invocation as a Varlink metrics provider (io.systemd.Metrics), typically socket-activated via
         * /run/systemd/report/io.systemd.InstanceMetadata. */

        _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *server = NULL;
        r = varlink_server_new(&server, /* flags= */ 0, /* userdata= */ NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate Varlink server: %m");

        r = sd_varlink_server_add_interface(server, &vl_interface_io_systemd_Metrics);
        if (r < 0)
                return log_error_errno(r, "Failed to add Varlink interface: %m");

        r = sd_varlink_server_bind_method_many(
                        server,
                        "io.systemd.Metrics.List",     vl_method_metrics_list,
                        "io.systemd.Metrics.Describe", vl_method_metrics_describe);
        if (r < 0)
                return log_error_errno(r, "Failed to bind Varlink methods: %m");

        r = sd_varlink_server_loop_auto(server);
        if (r < 0)
                return log_error_errno(r, "Failed to run Varlink event loop: %m");

        return 0;
}
