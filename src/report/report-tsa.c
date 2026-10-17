/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"
#include "sd-varlink.h"

#include "alloc-util.h"
#include "hexdecoct.h"
#include "log.h"
#include "metrics.h"
#include "random-util.h"
#include "report-tsa.h"
#include "time-util.h"

static int timestamp_query(const char *digest, const char *algorithm, char **ret_token) {
        _cleanup_(sd_varlink_unrefp) sd_varlink *vl = NULL;
        _cleanup_free_ char *token = NULL;
        sd_json_variant *reply = NULL;
        const char *error_id = NULL;
        int r;

        assert(digest);
        assert(algorithm);
        assert(ret_token);

        r = sd_varlink_connect_address(&vl, "/run/systemd/io.systemd.Timestamp");
        if (r < 0)
                return log_error_errno(r, "Failed to connect to timestampd: %m");

        /* timestampd waits up to 90s, so ensure to not give up before it does.*/
        r = sd_varlink_set_relative_timeout(vl, 2 * USEC_PER_MINUTE);
        if (r < 0)
                return log_error_errno(r, "Failed to set Varlink timeout: %m");

        r = sd_varlink_callbo(
                        vl,
                        "io.systemd.Timestamp.Request",
                        &reply,
                        &error_id,
                        SD_JSON_BUILD_PAIR_STRING("digest", digest),
                        SD_JSON_BUILD_PAIR_STRING("hashAlgorithm", algorithm));
        if (r < 0)
                return log_error_errno(r, "Failed to call timestampd: %m");
        if (error_id)
                return log_error_errno(
                                sd_varlink_error_to_errno(error_id, reply),
                                "timestampd returned an error: %s",
                                error_id);

        static const sd_json_dispatch_field table[] = {
                { "token", SD_JSON_VARIANT_STRING, sd_json_dispatch_string, 0, SD_JSON_MANDATORY },
                {}
        };

        r = sd_json_dispatch(reply, table, SD_JSON_ALLOW_EXTENSIONS, &token);
        if (r < 0)
                return log_error_errno(r, "Failed to parse timestampd reply: %m");

        *ret_token = TAKE_PTR(token);
        return 0;
}

static int tsa_generate(const MetricFamily *mf, sd_varlink *link, void *userdata) {
        _cleanup_free_ char *hex = NULL, *token = NULL;
        uint8_t buf[32];
        int r;

        assert(mf);
        assert(link);

        random_bytes(buf, sizeof(buf));

        hex = hexmem(buf, sizeof(buf));
        if (!hex)
                return log_oom();

        r = timestamp_query(hex, "SHA256", &token);
        if (r < 0)
                return r;

        return metric_build_send_string(mf, link, /* object= */ NULL, token, /* fields= */ NULL);
}

static const MetricFamily metric_family_table[] = {
        {
                METRIC_IO_SYSTEMD_TSA_PREFIX "Timestamp",
                "Timestamp token from Timestamp Authority", METRIC_FAMILY_TYPE_STRING,
                .generate = tsa_generate,
        },
        {}
};

int vl_method_describe_metrics(
                sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return metrics_method_describe(metric_family_table, link, parameters, flags, userdata);
}

int vl_method_list_metrics(
                sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return metrics_method_list(metric_family_table, link, parameters, flags, userdata);
}
