/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"

#include "log.h"
#include "report.h"
#include "report-generate.h"
#include "time-util.h"

int context_build_report(Context *context, sd_json_variant **ret) {
        int r;

        /* Convert the variant array to a JSON report. */

        assert(context);
        assert(ret);

        usec_t ts = now(CLOCK_REALTIME);

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *report = NULL;
        r = sd_json_buildo(&report,
                           SD_JSON_BUILD_PAIR_STRING("mediaType", "application/vnd.io.systemd.report"),
                           SD_JSON_BUILD_PAIR("timestamp",
                                              SD_JSON_BUILD_STRING(FORMAT_TIMESTAMP_STYLE(ts, TIMESTAMP_UTC))),
                           SD_JSON_BUILD_PAIR("metrics",
                                              SD_JSON_BUILD_VARIANT_ARRAY(context->metrics, context->n_metrics)));
        if (r < 0)
                return log_error_errno(r, "Failed to build JSON data: %m");

        *ret = TAKE_PTR(report);
        return 0;
}

int context_generate_report(Context *context) {
        int r;

        assert(context);

        /* Make a structured report and either print it or upload it. */

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *report = NULL;
        r = context_build_report(context, &report);
        if (r < 0)
                return r;

        r = sd_json_variant_dump(report, arg_json_format_flags, /* f= */ NULL, /* prefix= */ NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to dump json object: %m");

        return 0;
}
