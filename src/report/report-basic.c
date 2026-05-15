/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/utsname.h>

#include "sd-id128.h"
#include "sd-json.h"
#include "sd-varlink.h"

#include "alloc-util.h"
#include "architecture.h"
#include "cpu-set-util.h"
#include "hostname-setup.h"
#include "limits-util.h"
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

static int physical_memory_generate(const MetricFamily *mf, sd_varlink *link, void *userdata) {
        assert(mf && mf->name);
        assert(link);

        return metric_build_send_unsigned(
                        mf,
                        link,
                        /* object= */ NULL,
                        physical_memory(),
                        /* fields= */ NULL);
}

static int cpus_online_generate(const MetricFamily *mf, sd_varlink *link, void *userdata) {
        int r;

        assert(mf && mf->name);
        assert(link);

        unsigned n_cpus;
        r = cpus_online(&n_cpus);
        if (r < 0)
                return r;

        return metric_build_send_unsigned(
                        mf,
                        link,
                        /* object= */ NULL,
                        n_cpus,
                        /* fields= */ NULL);
}

enum {
        FIELD_PRETTY_NAME,
        FIELD_NAME,
        FIELD_ID,
        FIELD_CPE_NAME,
        FIELD_VARIANT_ID,
        FIELD_VERSION_ID,
        FIELD_BUILD_ID,
        FIELD_IMAGE_VERSION,
        FIELD_IMAGE_ID,
        FIELD_SUPPORT_END,
        FIELD_EXPERIMENT,
        FIELD_SYSEXT_LEVEL,
        FIELD_CONFEXT_LEVEL,
        _FIELD_MAX,
};

static int os_release_generate(const MetricFamily mf[static _FIELD_MAX - 1], sd_varlink *link, void *userdata) {
        char* values[_FIELD_MAX] = {};
        CLEANUP_ELEMENTS(values, free_many_charp);
        int r;

        assert(mf && mf->name);
        assert(link);

        r = parse_os_release(NULL,
                             "PRETTY_NAME",   &values[FIELD_PRETTY_NAME],
                             "NAME",          &values[FIELD_NAME],
                             "ID",            &values[FIELD_ID],
                             "CPE_NAME",      &values[FIELD_CPE_NAME],
                             "VARIANT_ID",    &values[FIELD_VARIANT_ID],
                             "VERSION_ID",    &values[FIELD_VERSION_ID],
                             "BUILD_ID",      &values[FIELD_BUILD_ID],
                             "IMAGE_VERSION", &values[FIELD_IMAGE_VERSION],
                             "IMAGE_ID",      &values[FIELD_IMAGE_ID],
                             "SUPPORT_END",   &values[FIELD_SUPPORT_END],
                             "EXPERIMENT",    &values[FIELD_EXPERIMENT],
                             "SYSEXT_LEVEL",  &values[FIELD_SYSEXT_LEVEL],
                             "CONFEXT_LEVEL", &values[FIELD_CONFEXT_LEVEL]);
        if (r < 0) {
                log_full_errno(r == -ENOENT ? LOG_DEBUG : LOG_WARNING, r,
                               "Failed to read os-release file, ignoring: %m");
                return 0;
        }

        for (size_t i = 1; i < _FIELD_MAX; i++) {
                const char *v = values[i];
                if (i == FIELD_NAME && values[FIELD_PRETTY_NAME])
                        v = values[FIELD_PRETTY_NAME];  /* Prefer PRETTY_NAME to NAME */

                if (v) {
                        r = metric_build_send_string(
                                        mf + i - 1,
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
                "Operating system identification (" name "= field from os-release)", \
                METRIC_FAMILY_TYPE_STRING,                              \
                .generate = NULL,                                       \
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
                METRIC_IO_SYSTEMD_BASIC_PREFIX "CPUsOnline",
                "Number of CPUs currently online",
                METRIC_FAMILY_TYPE_GAUGE,
                .generate = cpus_online_generate,
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
                METRIC_IO_SYSTEMD_BASIC_PREFIX "OSRelease.NAME",
                "Operating system human-readable name (PRETTY_NAME= or NAME= field from os-release)",
                METRIC_FAMILY_TYPE_STRING,
                .generate = os_release_generate,
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
        OS_RELEASE_STANDARD_FIELD("CONFEXT_LEVEL"),
        /* Keep those ↑ in sync with os_release_generate(). */
        {
                METRIC_IO_SYSTEMD_BASIC_PREFIX "PhysicalMemoryBytes",
                "Installed physical memory in bytes",
                METRIC_FAMILY_TYPE_GAUGE,
                .generate = physical_memory_generate,
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
