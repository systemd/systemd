/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/utsname.h>

#include "sd-id128.h"
#include "sd-json.h"
#include "sd-varlink.h"

#include "alloc-util.h"
#include "architecture.h"
#include "hostname-setup.h"
#include "metrics.h"
#include "report-basic.h"
#include "virt.h"

static int architecture_generate(const MetricFamily *mf, sd_varlink *link, void *userdata) {
        assert(mf && mf->name);
        assert(link);

        return metric_build_send_string(
                        mf,
                        link,
                        /* object= */ NULL,
                        architecture_to_string(uname_architecture()),
                        /* fields= */ NULL);
}

static int boot_id_generate(const MetricFamily *mf, sd_varlink *link, void *userdata) {
        sd_id128_t id;
        int r;

        assert(mf && mf->name);
        assert(link);

        r = sd_id128_get_boot(&id);
        if (r < 0)
                return r;

        return metric_build_send_string(
                        mf,
                        link,
                        /* object= */ NULL,
                        SD_ID128_TO_STRING(id),
                        /* fields= */ NULL);
}

static int hostname_generate(const MetricFamily *mf, sd_varlink *link, void *userdata) {
        _cleanup_free_ char *hostname = NULL;
        int r;

        assert(mf && mf->name);
        assert(link);

        r = gethostname_full(GET_HOSTNAME_ALLOW_LOCALHOST | GET_HOSTNAME_FALLBACK_DEFAULT, &hostname);
        if (r < 0)
                return r;

        return metric_build_send_string(
                        mf,
                        link,
                        /* object= */ NULL,
                        hostname,
                        /* fields= */ NULL);
}

static int kernel_version_generate(const MetricFamily *mf, sd_varlink *link, void *userdata) {
        struct utsname u;

        assert(mf && mf->name);
        assert(link);

        assert_se(uname(&u) >= 0);

        return metric_build_send_string(
                        mf,
                        link,
                        /* object= */ NULL,
                        u.release,
                        /* fields= */ NULL);
}

static int machine_id_generate(const MetricFamily *mf, sd_varlink *link, void *userdata) {
        sd_id128_t id;
        int r;

        assert(mf && mf->name);
        assert(link);

        r = sd_id128_get_machine(&id);
        if (r < 0)
                return r;

        return metric_build_send_string(
                        mf,
                        link,
                        /* object= */ NULL,
                        SD_ID128_TO_STRING(id),
                        /* fields= */ NULL);
}

static int virtualization_generate(const MetricFamily *mf, sd_varlink *link, void *userdata) {
        assert(mf && mf->name);
        assert(link);

        Virtualization v = detect_virtualization();
        if (v < 0)
                return v;

        return metric_build_send_string(
                        mf,
                        link,
                        /* object= */ NULL,
                        virtualization_to_string(v),
                        /* fields= */ NULL);
}

static const MetricFamily metric_family_table[] = {
        /* Keep entries ordered alphabetically */
        {
                METRIC_IO_SYSTEMD_BASIC_PREFIX "Architecture",
                "CPU architecture",
                METRIC_FAMILY_TYPE_STRING,
                .generate = architecture_generate,
        },
        {
                METRIC_IO_SYSTEMD_BASIC_PREFIX "BootID",
                "Current boot ID",
                METRIC_FAMILY_TYPE_STRING,
                .generate = boot_id_generate,
        },
        {
                METRIC_IO_SYSTEMD_BASIC_PREFIX "Hostname",
                "System hostname",
                METRIC_FAMILY_TYPE_STRING,
                .generate = hostname_generate,
        },
        {
                METRIC_IO_SYSTEMD_BASIC_PREFIX "KernelVersion",
                "Kernel version",
                METRIC_FAMILY_TYPE_STRING,
                .generate = kernel_version_generate,
        },
        {
                METRIC_IO_SYSTEMD_BASIC_PREFIX "MachineID",
                "Machine ID",
                METRIC_FAMILY_TYPE_STRING,
                .generate = machine_id_generate,
        },
        {
                METRIC_IO_SYSTEMD_BASIC_PREFIX "Virtualization",
                "Virtualization type",
                METRIC_FAMILY_TYPE_STRING,
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
