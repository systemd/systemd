/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/utsname.h>

#include "sd-id128.h"
#include "sd-json.h"
#include "sd-varlink.h"

#include "alloc-util.h"
#include "architecture.h"
#include "hostname-setup.h"
#include "log.h"
#include "metrics.h"
#include "os-util.h"
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

static int os_release_generate(const MetricFamily mf[static 12], sd_varlink *link, void *userdata) {
        char* values[13] = {};
        CLEANUP_ELEMENTS(values, free_many_charp);
        int r;

        assert(mf && mf->name);
        assert(link);

        r = parse_os_release(NULL,
                             "PRETTY_NAME",   &values[0],
                             "NAME",          &values[1],
                             "ID",            &values[2],
                             "CPE_NAME",      &values[3],
                             "VARIANT_ID",    &values[4],
                             "VERSION_ID",    &values[5],
                             "BUILD_ID",      &values[6],
                             "IMAGE_VERSION", &values[7],
                             "IMAGE_ID",      &values[8],
                             "SUPPORT_END",   &values[9],
                             "EXPERIMENT",    &values[10],
                             "SYSEXT_LEVEL",  &values[12],
                             "CONTEXT_LEVEL", &values[12]);
        if (r < 0)
                return log_full_errno(r == -ENOENT ? LOG_DEBUG : LOG_WARNING, r,
                                      "Failed to read os-release file, ignoring: %m");

        static const char* fields[] = {
                "NAME",
                "ID",
                "CPE_NAME",
                "VARIANT_ID",
                "VERSION_ID",
                "BUILD_ID",
                "IMAGE_VERSION",
                "IMAGE_ID",
                "SUPPORT_END",
                "EXPERIMENT",
                "SYSEXT_LEVEL",
                "CONTEXT_LEVEL",
        };
        assert_cc(1 + ELEMENTSOF(fields)== ELEMENTSOF(values));

        for (size_t i = 0; i < ELEMENTSOF(fields); i++) {
                const char *v = values[i + 1];
                if (i == 0 && values[0])
                        v = values[0];  /* Prefer PRETTY_NAME to NAME */

                if (v) {
                        r = metric_build_send_string(
                                        mf + i,
                                        link,
                                        /* object= */ NULL,
                                        v,
                                        /* fields= */ NULL);
                        if (r < 0)
                                return r;
                }
        }

        return 0;
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

#define OS_RELEASE_STANDARD_FIELD(name)                                 \
        {                                                               \
                METRIC_IO_SYSTEMD_BASIC_PREFIX "OSRelease." name,       \
                "Operating system identification (" name " field from os-release)", \
                METRIC_FAMILY_TYPE_STRING,                              \
                NULL,                                                   \
        }

static const MetricFamily metric_family_table[] = {
        /* Keep entries ordered alphabetically */
        {
                METRIC_IO_SYSTEMD_BASIC_PREFIX "Architecture",
                "CPU architecture",
                METRIC_FAMILY_TYPE_STRING,
                architecture_generate,
        },
        {
                METRIC_IO_SYSTEMD_BASIC_PREFIX "BootID",
                "Current boot ID",
                METRIC_FAMILY_TYPE_STRING,
                boot_id_generate,
        },
        {
                METRIC_IO_SYSTEMD_BASIC_PREFIX "Hostname",
                "System hostname",
                METRIC_FAMILY_TYPE_STRING,
                hostname_generate,
        },
        {
                METRIC_IO_SYSTEMD_BASIC_PREFIX "KernelVersion",
                "Kernel version",
                METRIC_FAMILY_TYPE_STRING,
                kernel_version_generate,
        },
        {
                METRIC_IO_SYSTEMD_BASIC_PREFIX "MachineID",
                "Machine ID",
                METRIC_FAMILY_TYPE_STRING,
                machine_id_generate,
        },
        {
                METRIC_IO_SYSTEMD_BASIC_PREFIX "OSRelease.NAME",
                "Operating system human-readable name (PRETTY_NAME or NAME field from os-release)",
                METRIC_FAMILY_TYPE_STRING,
                os_release_generate,
        },
        OS_RELEASE_STANDARD_FIELD("ID"),
        OS_RELEASE_STANDARD_FIELD("CPE_NAME"),
        OS_RELEASE_STANDARD_FIELD("VARIANT_ID"),
        OS_RELEASE_STANDARD_FIELD("VERSION_ID"),
        OS_RELEASE_STANDARD_FIELD("BUILD_ID"),
        OS_RELEASE_STANDARD_FIELD("IMAGE_VERSION"),
        OS_RELEASE_STANDARD_FIELD("IMAGE_ID"),
        OS_RELEASE_STANDARD_FIELD("SUPPORT_END"),
        OS_RELEASE_STANDARD_FIELD("EXPERIMENT"),
        OS_RELEASE_STANDARD_FIELD("SYSEXT_LEVEL"),
        OS_RELEASE_STANDARD_FIELD("CONTEXT_LEVEL"),
        /* Keep those ^ in sync with os_release_generate. */
        {
                METRIC_IO_SYSTEMD_BASIC_PREFIX "Virtualization",
                "Virtualization type",
                METRIC_FAMILY_TYPE_STRING,
                virtualization_generate,
        },
        {}
};

int vl_method_describe_metrics(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return metrics_method_describe(metric_family_table, link, parameters, flags, userdata);
}

int vl_method_list_metrics(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return metrics_method_list(metric_family_table, link, parameters, flags, userdata);
}
