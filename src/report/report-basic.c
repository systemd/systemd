/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/utsname.h>

#include "sd-id128.h"
#include "sd-json.h"
#include "sd-varlink.h"

#include "alloc-util.h"
#include "architecture.h"
#include "escape.h"
#include "hostname-setup.h"
#include "log.h"
#include "metrics.h"
#include "os-util.h"
#include "report-basic.h"
#include "string-util.h"
#include "strv.h"
#include "virt.h"

static int architecture_generate(MetricFamilyContext *context, void *userdata) {
        assert(context);

        return metric_build_send_string(
                        context,
                        /* object= */ NULL,
                        architecture_to_string(uname_architecture()),
                        /* fields= */ NULL);
}

static int boot_id_generate(MetricFamilyContext *context, void *userdata) {
        sd_id128_t id;
        int r;

        assert(context);

        r = sd_id128_get_boot(&id);
        if (r < 0)
                return r;

        return metric_build_send_string(
                        context,
                        /* object= */ NULL,
                        SD_ID128_TO_STRING(id),
                        /* fields= */ NULL);
}

static int hostname_generate(MetricFamilyContext *context, void *userdata) {
        _cleanup_free_ char *hostname = NULL;
        int r;

        assert(context);

        r = gethostname_full(GET_HOSTNAME_ALLOW_LOCALHOST | GET_HOSTNAME_FALLBACK_DEFAULT, &hostname);
        if (r < 0)
                return r;

        return metric_build_send_string(
                        context,
                        /* object= */ NULL,
                        hostname,
                        /* fields= */ NULL);
}

static int kernel_version_generate(MetricFamilyContext *context, void *userdata) {
        struct utsname u;

        assert(context);

        assert_se(uname(&u) >= 0);

        return metric_build_send_string(
                        context,
                        /* object= */ NULL,
                        u.release,
                        /* fields= */ NULL);
}

static int machine_id_generate(MetricFamilyContext *context, void *userdata) {
        sd_id128_t id;
        int r;

        assert(context);

        r = sd_id128_get_machine(&id);
        if (r < 0)
                return r;

        return metric_build_send_string(
                        context,
                        /* object= */ NULL,
                        SD_ID128_TO_STRING(id),
                        /* fields= */ NULL);
}

static int os_release_generate(MetricFamilyContext *context, void *userdata) {
        _cleanup_strv_free_ char **pairs = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *fields = NULL;
        int r;

        assert(context);
        assert(context->link);

        r = load_os_release_pairs(/* root= */ NULL, &pairs);
        if (r < 0) {
                log_warning_errno(r, "Failed to load os-release, ignoring: %m");
                return 0;
        }

        STRV_FOREACH_PAIR(k, v, pairs) {
                if (!string_is_safe(*k, STRING_ASCII | STRING_FILENAME)) {
                        if (DEBUG_LOGGING) {
                                _cleanup_free_ char *t = cescape(*k);
                                log_debug("Invalid field in os-release, ignoring: %s", strnull(t));
                        }
                        continue;
                }

                r = sd_json_variant_set_field_string(&fields, *k, *v);
                if (r < 0)
                        return r;
        }

        return metric_build_send_unsigned(
                        context,
                        /* object= */ NULL,
                        /* value= */ 0,       /* placeholder value */
                        fields);              /* the actual data */
}

static int virtualization_generate(MetricFamilyContext *context, void *userdata) {
        Virtualization v;

        assert(context);

        v = detect_virtualization();
        if (v < 0)
                return v;

        return metric_build_send_string(
                        context,
                        /* object= */ NULL,
                        virtualization_to_string(v),
                        /* fields= */ NULL);
}

static const MetricFamily metric_family_table[] = {
        /* Keep entries ordered alphabetically */
        {
                .name = METRIC_IO_SYSTEMD_BASIC_PREFIX "Architecture",
                .description = "CPU architecture",
                .type = METRIC_FAMILY_TYPE_STRING,
                .generate = architecture_generate,
        },
        {
                .name = METRIC_IO_SYSTEMD_BASIC_PREFIX "BootID",
                .description = "Current boot ID",
                .type = METRIC_FAMILY_TYPE_STRING,
                .generate = boot_id_generate,
        },
        {
                .name = METRIC_IO_SYSTEMD_BASIC_PREFIX "Hostname",
                .description = "System hostname",
                .type = METRIC_FAMILY_TYPE_STRING,
                .generate = hostname_generate,
        },
        {
                .name = METRIC_IO_SYSTEMD_BASIC_PREFIX "KernelVersion",
                .description = "Kernel version",
                .type = METRIC_FAMILY_TYPE_STRING,
                .generate = kernel_version_generate,
        },
        {
                .name = METRIC_IO_SYSTEMD_BASIC_PREFIX "MachineID",
                .description = "Machine ID",
                .type = METRIC_FAMILY_TYPE_STRING,
                .generate = machine_id_generate,
        },
        {
                .name = METRIC_IO_SYSTEMD_BASIC_PREFIX "OSRelease",
                .description = "Operating system identification (from os-release)",
                .type = METRIC_FAMILY_TYPE_STRING,
                .generate = os_release_generate,
        },
        {
                .name = METRIC_IO_SYSTEMD_BASIC_PREFIX "Virtualization",
                .description = "Virtualization type",
                .type = METRIC_FAMILY_TYPE_STRING,
                .generate = virtualization_generate,
        },
        {}
};

int vl_method_describe_metrics(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return metrics_method_describe(metric_family_table, link, parameters, flags, userdata);
}

int vl_method_list_metrics(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return metrics_method_list(metric_family_table, link, parameters, flags, userdata);
}
