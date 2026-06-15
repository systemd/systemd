/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <sys/sysinfo.h>
#include <sys/utsname.h>

#include "sd-device.h"
#include "sd-id128.h"
#include "sd-json.h"
#include "sd-varlink.h"

#include "alloc-util.h"
#include "architecture.h"
#include "confidential-virt.h"
#include "cpu-set-util.h"
#include "env-file.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "hostname-setup.h"
#include "hostname-util.h"
#include "limits-util.h"
#include "log.h"
#include "metrics.h"
#include "os-util.h"
#include "report-basic.h"
#include "string-util.h"
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

static int load_average_generate(const MetricFamily *mf, sd_varlink *link, void *userdata) {
        enum {
                LOAD_AVERAGE_FIELD_1MIN,
                LOAD_AVERAGE_FIELD_5MIN,
                LOAD_AVERAGE_FIELD_15MIN,
                _LOAD_AVERAGE_FIELD_MAX,
        };

        assert(mf && mf->name);
        assert(link);

        /* The classic Linux load average, i.e. the exponentially damped moving average of the number of
         * runnable plus uninterruptible tasks over the last 1, 5 and 15 minutes. The kernel exposes these as
         * fixed-point numbers shifted left by SI_LOAD_SHIFT bits. */

        struct sysinfo info;
        if (sysinfo(&info) < 0)
                return log_debug_errno(errno, "Failed to call sysinfo(): %m");

        assert_cc(_LOAD_AVERAGE_FIELD_MAX == ELEMENTSOF(info.loads));

        for (size_t i = 0; i < _LOAD_AVERAGE_FIELD_MAX; i++) {
                int r;

                r = metric_build_send_double(
                                mf + i,
                                link,
                                /* object= */ NULL,
                                (double) info.loads[i] / (UINT64_C(1) << SI_LOAD_SHIFT),
                                /* fields= */ NULL);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int swap_generate(const MetricFamily *mf, sd_varlink *link, void *userdata) {
        assert(mf && mf->name);
        assert(link);

        /* The total amount of configured swap space, in bytes. */

        struct sysinfo info;
        if (sysinfo(&info) < 0)
                return log_debug_errno(errno, "Failed to call sysinfo(): %m");

        return metric_build_send_unsigned(
                        mf,
                        link,
                        /* object= */ NULL,
                        (uint64_t) info.totalswap * info.mem_unit,
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

static int machine_info_generate(const MetricFamily *mf, sd_varlink *link, void *userdata) {
        enum {
                MACHINE_INFO_FIELD_PRETTY_HOSTNAME,
                MACHINE_INFO_FIELD_DEPLOYMENT,
                MACHINE_INFO_FIELD_LOCATION,
                MACHINE_INFO_FIELD_TAGS,
                _MACHINE_INFO_FIELD_MAX,
        };

        char* values[_MACHINE_INFO_FIELD_MAX] = {};
        CLEANUP_ELEMENTS(values, free_many_charp);
        int r;

        assert(mf && mf->name);
        assert(link);

        r = parse_env_file(/* f= */ NULL, etc_machine_info(),
                           "PRETTY_HOSTNAME", &values[MACHINE_INFO_FIELD_PRETTY_HOSTNAME],
                           "DEPLOYMENT",      &values[MACHINE_INFO_FIELD_DEPLOYMENT],
                           "LOCATION",        &values[MACHINE_INFO_FIELD_LOCATION],
                           "TAGS",            &values[MACHINE_INFO_FIELD_TAGS]);
        if (r < 0) {
                log_full_errno(r == -ENOENT ? LOG_DEBUG : LOG_WARNING, r,
                               "Failed to read machine-info file, ignoring: %m");
                return 0;
        }

        for (size_t i = 0; i < _MACHINE_INFO_FIELD_MAX; i++) {
                const char *v = values[i];
                if (!v)
                        continue;

                r = metric_build_send_string(
                                mf + i,
                                link,
                                /* object= */ NULL,
                                v,
                                /* fields= */ NULL);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int smbios_generate(const MetricFamily *mf, sd_varlink *link, void *userdata) {
        enum {
                SMBIOS_FIELD_SYS_VENDOR,
                SMBIOS_FIELD_PRODUCT_NAME,
                SMBIOS_FIELD_PRODUCT_VERSION,
                SMBIOS_FIELD_PRODUCT_SKU,
                SMBIOS_FIELD_PRODUCT_FAMILY,
                SMBIOS_FIELD_PRODUCT_SERIAL,
                SMBIOS_FIELD_PRODUCT_UUID,
                SMBIOS_FIELD_BOARD_VENDOR,
                SMBIOS_FIELD_BOARD_NAME,
                SMBIOS_FIELD_BOARD_VERSION,
                SMBIOS_FIELD_BOARD_SERIAL,
                SMBIOS_FIELD_BOARD_ASSET_TAG,
                SMBIOS_FIELD_BIOS_VENDOR,
                SMBIOS_FIELD_BIOS_VERSION,
                SMBIOS_FIELD_BIOS_DATE,
                SMBIOS_FIELD_CHASSIS_TYPE,
                SMBIOS_FIELD_CHASSIS_VENDOR,
                SMBIOS_FIELD_CHASSIS_SERIAL,
                SMBIOS_FIELD_CHASSIS_ASSET_TAG,
                _SMBIOS_FIELD_MAX,
        };

        /* The sysfs attribute names exposed by the kernel below /sys/class/dmi/id/. The order must match the
         * SMBIOS_STANDARD_FIELD() entries in the metric family table below. */
        static const char* const smbios_files[_SMBIOS_FIELD_MAX] = {
                /* SMBIOS Type 1 */
                [SMBIOS_FIELD_SYS_VENDOR]        = "sys_vendor",
                [SMBIOS_FIELD_PRODUCT_NAME]      = "product_name",
                [SMBIOS_FIELD_PRODUCT_VERSION]   = "product_version",
                [SMBIOS_FIELD_PRODUCT_SKU]       = "product_sku",
                [SMBIOS_FIELD_PRODUCT_FAMILY]    = "product_family",
                [SMBIOS_FIELD_PRODUCT_SERIAL]    = "product_serial",
                [SMBIOS_FIELD_PRODUCT_UUID]      = "product_uuid",
                /* SMBIOS Type 2 */
                [SMBIOS_FIELD_BOARD_VENDOR]      = "board_vendor",
                [SMBIOS_FIELD_BOARD_NAME]        = "board_name",
                [SMBIOS_FIELD_BOARD_VERSION]     = "board_version",
                [SMBIOS_FIELD_BOARD_SERIAL]      = "board_serial",
                [SMBIOS_FIELD_BOARD_ASSET_TAG]   = "board_asset_tag",
                /* SMBIOS Type 0 */
                [SMBIOS_FIELD_BIOS_VENDOR]       = "bios_vendor",
                [SMBIOS_FIELD_BIOS_VERSION]      = "bios_version",
                [SMBIOS_FIELD_BIOS_DATE]         = "bios_date",
                /* SMBIOS Type 3 */
                [SMBIOS_FIELD_CHASSIS_TYPE]      = "chassis_type",
                [SMBIOS_FIELD_CHASSIS_VENDOR]    = "chassis_vendor",
                [SMBIOS_FIELD_CHASSIS_SERIAL]    = "chassis_serial",
                [SMBIOS_FIELD_CHASSIS_ASSET_TAG] = "chassis_asset_tag",
        };

        int r;

        assert(mf && mf->name);
        assert(link);

        /* Reports the fundamental SMBIOS/DMI identification fields. Some of these (serial numbers, asset
         * tags, the system UUID) are privacy sensitive and only readable by root — if we lack the
         * privileges to read them we simply skip them. */

        _cleanup_close_ int dir_fd = open("/sys/class/dmi/id", O_RDONLY|O_DIRECTORY|O_CLOEXEC);
        if (dir_fd < 0) {
                log_full_errno(ERRNO_IS_DEVICE_ABSENT(errno) ? LOG_DEBUG : LOG_WARNING, errno,
                               "Failed to open /sys/class/dmi/id/, ignoring: %m");
                return 0;
        }

        for (size_t i = 0; i < _SMBIOS_FIELD_MAX; i++) {
                _cleanup_free_ char *buf = NULL;

                r = read_virtual_file_at(dir_fd, smbios_files[i], /* max_size= */ SIZE_MAX, &buf, /* ret_size= */ NULL);
                if (r < 0) {
                        log_full_errno(r == -ENOENT || ERRNO_IS_NEG_PRIVILEGE(r) ? LOG_DEBUG : LOG_WARNING, r,
                                       "Failed to read SMBIOS field '%s', ignoring: %m", smbios_files[i]);
                        continue;
                }

                delete_trailing_chars(buf, NEWLINE);

                if (isempty(buf))
                        continue;

                if (!string_is_safe(buf, STRING_ALLOW_BACKSLASHES|STRING_ALLOW_QUOTES|STRING_ALLOW_GLOBS)) {
                        log_debug("SMBIOS field '%s' contains unsafe characters, ignoring.", smbios_files[i]);
                        continue;
                }

                r = metric_build_send_string(
                                mf + i,
                                link,
                                /* object= */ NULL,
                                buf,
                                /* fields= */ NULL);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int tpm2_generate(const MetricFamily *mf, sd_varlink *link, void *userdata) {
        enum {
                TPM2_FIELD_MANUFACTURER,
                TPM2_FIELD_VENDOR_STRING,
                _TPM2_FIELD_MAX,
        };

        /* The udev properties set by the 'tpm2_id' builtin on the tpmrm device. The order must match the
         * metric family table entries below. */
        static const char* const tpm2_properties[_TPM2_FIELD_MAX] = {
                [TPM2_FIELD_MANUFACTURER]  = "ID_TPM2_MANUFACTURER",
                [TPM2_FIELD_VENDOR_STRING] = "ID_TPM2_VENDOR_STRING",
        };

        int r;

        assert(mf && mf->name);
        assert(link);

        _cleanup_(sd_device_unrefp) sd_device *dev = NULL;
        r = sd_device_new_from_subsystem_sysname(&dev, "tpmrm", "tpmrm0");
        if (r < 0) {
                log_full_errno(ERRNO_IS_NEG_DEVICE_ABSENT(r) ? LOG_DEBUG : LOG_WARNING, r,
                               "Failed to open tpmrm0 device, ignoring: %m");
                return 0;
        }

        for (size_t i = 0; i < _TPM2_FIELD_MAX; i++) {
                const char *v;

                r = sd_device_get_property_value(dev, tpm2_properties[i], &v);
                if (r < 0) {
                        log_full_errno(r == -ENOENT ? LOG_DEBUG : LOG_WARNING, r,
                                       "Failed to read TPM2 property '%s', ignoring: %m", tpm2_properties[i]);
                        continue;
                }

                if (isempty(v))
                        continue;

                r = metric_build_send_string(
                                mf + i,
                                link,
                                /* object= */ NULL,
                                v,
                                /* fields= */ NULL);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int confidential_virtualization_generate(const MetricFamily *mf, sd_varlink *link, void *userdata) {
        assert(mf && mf->name);
        assert(link);

        ConfidentialVirtualization cv = detect_confidential_virtualization();
        if (cv < 0)
                return cv;

        return metric_build_send_string(
                        mf,
                        link,
                        /* object= */ NULL,
                        confidential_virtualization_to_string(cv),
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

#define OS_RELEASE_STANDARD_FIELD(name)                                 \
        {                                                               \
                METRIC_IO_SYSTEMD_BASIC_PREFIX "OSRelease." name,       \
                "Operating system identification (" name "= field from os-release)", \
                METRIC_FAMILY_TYPE_STRING,                              \
                .generate = NULL,                                       \
        }

#define MACHINE_INFO_STANDARD_FIELD(name)                               \
        {                                                               \
                METRIC_IO_SYSTEMD_BASIC_PREFIX "MachineInfo." name,     \
                "Machine identification (" name "= field from machine-info)", \
                METRIC_FAMILY_TYPE_STRING,                              \
                .generate = NULL,                                       \
        }

#define SMBIOS_STANDARD_FIELD(name)                                     \
        {                                                               \
                METRIC_IO_SYSTEMD_BASIC_PREFIX "SMBIOS." name,          \
                "Firmware/hardware identification (" name " field from SMBIOS/DMI)", \
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
                METRIC_IO_SYSTEMD_BASIC_PREFIX "ConfidentialVirtualization",
                "Confidential computing technology",
                METRIC_FAMILY_TYPE_STRING,
                .generate = confidential_virtualization_generate,
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
                METRIC_IO_SYSTEMD_BASIC_PREFIX "LoadAverage1Min",
                "System load average over the last 1 minute",
                METRIC_FAMILY_TYPE_GAUGE,
                .generate = load_average_generate,
        },
        {
                METRIC_IO_SYSTEMD_BASIC_PREFIX "LoadAverage5Min",
                "System load average over the last 5 minutes",
                METRIC_FAMILY_TYPE_GAUGE,
                .generate = NULL,
        },
        {
                METRIC_IO_SYSTEMD_BASIC_PREFIX "LoadAverage15Min",
                "System load average over the last 15 minutes",
                METRIC_FAMILY_TYPE_GAUGE,
                .generate = NULL,
        },
        /* Keep those ↑ in sync with load_average_generate(). */
        {
                METRIC_IO_SYSTEMD_BASIC_PREFIX "MachineID",
                "Machine ID",
                METRIC_FAMILY_TYPE_STRING,
                .generate = machine_id_generate,
        },
        {
                METRIC_IO_SYSTEMD_BASIC_PREFIX "MachineInfo.PRETTY_HOSTNAME",
                "Pretty hostname (PRETTY_HOSTNAME= field from machine-info)",
                METRIC_FAMILY_TYPE_STRING,
                .generate = machine_info_generate,
        },
        MACHINE_INFO_STANDARD_FIELD("DEPLOYMENT"),
        MACHINE_INFO_STANDARD_FIELD("LOCATION"),
        MACHINE_INFO_STANDARD_FIELD("TAGS"),
        /* Keep those ↑ in sync with machine_info_generate(). */
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
                /* NB: Here we use the naming of the field as per SMBIOS specification, i.e. undo the weird
                 * renaming that Linux did on the fields. When new fields are added here, please make sure to
                 * check the specification again for naming them. */
                METRIC_IO_SYSTEMD_BASIC_PREFIX "SMBIOS.SystemManufacturer",
                "Firmware/hardware identification (SystemManufacturer field from SMBIOS/DMI)",
                METRIC_FAMILY_TYPE_STRING,
                .generate = smbios_generate,
        },
        SMBIOS_STANDARD_FIELD("SystemProductName"),
        SMBIOS_STANDARD_FIELD("SystemVersion"),
        SMBIOS_STANDARD_FIELD("SystemSKUNumber"),
        SMBIOS_STANDARD_FIELD("SystemFamily"),
        SMBIOS_STANDARD_FIELD("SystemSerialNumber"),
        SMBIOS_STANDARD_FIELD("SystemUUID"),
        SMBIOS_STANDARD_FIELD("BaseBoardManufacturer"),
        SMBIOS_STANDARD_FIELD("BaseBoardProduct"),
        SMBIOS_STANDARD_FIELD("BaseBoardVersion"),
        SMBIOS_STANDARD_FIELD("BaseBoardSerial"),
        SMBIOS_STANDARD_FIELD("BaseBoardAssetTag"),
        SMBIOS_STANDARD_FIELD("FirmwareVendor"),
        SMBIOS_STANDARD_FIELD("FirmwareVersion"),
        SMBIOS_STANDARD_FIELD("FirmwareReleaseDate"),
        SMBIOS_STANDARD_FIELD("ChassisType"),
        SMBIOS_STANDARD_FIELD("ChassisManufacturer"),
        SMBIOS_STANDARD_FIELD("ChassisSerialNumber"),
        SMBIOS_STANDARD_FIELD("ChassisAssetTagNumber"),
        /* Keep those ↑ in sync with smbios_generate(). */
        {
                METRIC_IO_SYSTEMD_BASIC_PREFIX "SwapBytes",
                "Total configured swap space in bytes",
                METRIC_FAMILY_TYPE_GAUGE,
                .generate = swap_generate,
        },
        {
                METRIC_IO_SYSTEMD_BASIC_PREFIX "TPM2.Manufacturer",
                "TPM2 device manufacturer (ID_TPM2_MANUFACTURER property of the tpmrm0 device)",
                METRIC_FAMILY_TYPE_STRING,
                .generate = tpm2_generate,
        },
        {
                METRIC_IO_SYSTEMD_BASIC_PREFIX "TPM2.VendorString",
                "TPM2 device vendor string (ID_TPM2_VENDOR_STRING property of the tpmrm0 device)",
                METRIC_FAMILY_TYPE_STRING,
                .generate = NULL,
        },
        /* Keep those ↑ in sync with tpm2_generate(). */
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
