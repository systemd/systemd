/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "sd-device.h"
#include "sd-json.h"

#include "alloc-util.h"
#include "bitfield.h"
#include "bus-common-errors.h"
#include "bus-get-properties.h"
#include "bus-log-control-api.h"
#include "bus-polkit.h"
#include "constants.h"
#include "daemon-util.h"
#include "device-private.h"
#include "env-file-label.h"
#include "env-file.h"
#include "env-util.h"
#include "fileio.h"
#include "hostname-setup.h"
#include "hostname-util.h"
#include "id128-util.h"
#include "json-util.h"
#include "main-func.h"
#include "missing_capability.h"
#include "nulstr-util.h"
#include "os-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "selinux-util.h"
#include "service-util.h"
#include "signal-util.h"
#include "socket-util.h"
#include "stat-util.h"
#include "string-table.h"
#include "strv.h"
#include "user-util.h"
#include "utf8.h"
#include "varlink-io.systemd.Hostname.h"
#include "varlink-io.systemd.service.h"
#include "varlink-util.h"
#include "virt.h"

#define VALID_DEPLOYMENT_CHARS (DIGITS LETTERS "-.:")

/* Properties we cache are indexed by an enum, to make invalidation easy and systematic (as we can iterate
 * through them all, and they are uniformly strings). */
typedef enum {
        /* Read from /etc/hostname */
        PROP_STATIC_HOSTNAME,

        /* Read from /etc/machine-info */
        PROP_PRETTY_HOSTNAME,
        PROP_ICON_NAME,
        PROP_CHASSIS,
        PROP_DEPLOYMENT,
        PROP_LOCATION,
        PROP_HARDWARE_VENDOR,
        PROP_HARDWARE_MODEL,

        /* Read from /etc/os-release (or /usr/lib/os-release) */
        PROP_OS_PRETTY_NAME,
        PROP_OS_CPE_NAME,
        PROP_OS_HOME_URL,
        PROP_OS_SUPPORT_END,
        _PROP_MAX,
        _PROP_INVALID = -EINVAL,
} HostProperty;

typedef struct Context {
        char *data[_PROP_MAX];

        HostnameSource hostname_source;

        struct stat etc_hostname_stat;
        struct stat etc_os_release_stat;
        struct stat etc_machine_info_stat;

        sd_event *event;
        sd_bus *bus;
        sd_varlink_server *varlink_server;
        Hashmap *polkit_registry;
        sd_device *device_dmi;
        sd_device *device_acpi;
        sd_device *device_tree;
} Context;

static void context_reset(Context *c, uint64_t mask) {
        assert(c);

        for (int p = 0; p < _PROP_MAX; p++) {
                if (!BIT_SET(mask, p))
                        continue;

                c->data[p] = mfree(c->data[p]);
        }
}

static void context_destroy(Context *c) {
        assert(c);

        context_reset(c, UINT64_MAX);
        hashmap_free(c->polkit_registry);
        sd_event_unref(c->event);
        sd_bus_flush_close_unref(c->bus);
        sd_varlink_server_unref(c->varlink_server);
        sd_device_unref(c->device_dmi);
        sd_device_unref(c->device_acpi);
        sd_device_unref(c->device_tree);
}

static void context_read_etc_hostname(Context *c) {
        struct stat current_stat = {};
        int r;

        assert(c);

        if (stat("/etc/hostname", &current_stat) >= 0 &&
            stat_inode_unmodified(&c->etc_hostname_stat, &current_stat))
                return;

        context_reset(c, UINT64_C(1) << PROP_STATIC_HOSTNAME);

        r = read_etc_hostname(NULL, &c->data[PROP_STATIC_HOSTNAME]);
        if (r < 0 && r != -ENOENT)
                log_warning_errno(r, "Failed to read /etc/hostname, ignoring: %m");

        c->etc_hostname_stat = current_stat;
}

static void context_read_machine_info(Context *c) {
        struct stat current_stat = {};
        int r;

        assert(c);

        if (stat("/etc/machine-info", &current_stat) >= 0 &&
            stat_inode_unmodified(&c->etc_machine_info_stat, &current_stat))
                return;

        context_reset(c,
                      (UINT64_C(1) << PROP_PRETTY_HOSTNAME) |
                      (UINT64_C(1) << PROP_ICON_NAME) |
                      (UINT64_C(1) << PROP_CHASSIS) |
                      (UINT64_C(1) << PROP_DEPLOYMENT) |
                      (UINT64_C(1) << PROP_LOCATION) |
                      (UINT64_C(1) << PROP_HARDWARE_VENDOR) |
                      (UINT64_C(1) << PROP_HARDWARE_MODEL));

        r = parse_env_file(NULL, "/etc/machine-info",
                           "PRETTY_HOSTNAME", &c->data[PROP_PRETTY_HOSTNAME],
                           "ICON_NAME", &c->data[PROP_ICON_NAME],
                           "CHASSIS", &c->data[PROP_CHASSIS],
                           "DEPLOYMENT", &c->data[PROP_DEPLOYMENT],
                           "LOCATION", &c->data[PROP_LOCATION],
                           "HARDWARE_VENDOR", &c->data[PROP_HARDWARE_VENDOR],
                           "HARDWARE_MODEL", &c->data[PROP_HARDWARE_MODEL]);
        if (r < 0 && r != -ENOENT)
                log_warning_errno(r, "Failed to read /etc/machine-info, ignoring: %m");

        c->etc_machine_info_stat = current_stat;
}

static void context_read_os_release(Context *c) {
        _cleanup_free_ char *os_name = NULL, *os_pretty_name = NULL;
        struct stat current_stat = {};
        int r;

        assert(c);

        if ((stat("/etc/os-release", &current_stat) >= 0 ||
             stat("/usr/lib/os-release", &current_stat) >= 0) &&
            stat_inode_unmodified(&c->etc_os_release_stat, &current_stat))
                return;

        context_reset(c,
                      (UINT64_C(1) << PROP_OS_PRETTY_NAME) |
                      (UINT64_C(1) << PROP_OS_CPE_NAME) |
                      (UINT64_C(1) << PROP_OS_HOME_URL) |
                      (UINT64_C(1) << PROP_OS_SUPPORT_END));

        r = parse_os_release(NULL,
                             "PRETTY_NAME", &os_pretty_name,
                             "NAME",        &os_name,
                             "CPE_NAME",    &c->data[PROP_OS_CPE_NAME],
                             "HOME_URL",    &c->data[PROP_OS_HOME_URL],
                             "SUPPORT_END", &c->data[PROP_OS_SUPPORT_END]);
        if (r < 0 && r != -ENOENT)
                log_warning_errno(r, "Failed to read os-release file, ignoring: %m");

        if (free_and_strdup(&c->data[PROP_OS_PRETTY_NAME], os_release_pretty_name(os_pretty_name, os_name)) < 0)
                log_oom();

        c->etc_os_release_stat = current_stat;
}

static bool use_dmi_data(void) {
        int r;

        r = getenv_bool("SYSTEMD_HOSTNAME_FORCE_DMI");
        if (r >= 0) {
                log_debug("Honouring $SYSTEMD_HOSTNAME_FORCE_DMI override: %s", yes_no(r));
                return r;
        }
        if (r != -ENXIO)
                log_debug_errno(r, "Failed to parse $SYSTEMD_HOSTNAME_FORCE_DMI, ignoring: %m");

        if (detect_container() > 0) {
                log_debug("Running in a container, not using DMI hardware data.");
                return false;
        }

        return true;
}

static int context_acquire_dmi_device(Context *c) {
        int r;

        assert(c);
        assert(!c->device_dmi);

        if (!use_dmi_data())
                return 0;

        r = sd_device_new_from_syspath(&c->device_dmi, "/sys/class/dmi/id/");
        if (ERRNO_IS_NEG_DEVICE_ABSENT(r)) {
                log_debug_errno(r, "Failed to open /sys/class/dmi/id/ device, ignoring: %m");
                return 0;
        }
        if (r < 0)
                return log_error_errno(r, "Failed to open /sys/class/dmi/id/ device: %m");

        return 1;
}

static int context_acquire_acpi_device(Context *c) {
        int r;

        assert(c);
        assert(!c->device_acpi);

        r = sd_device_new_from_syspath(&c->device_acpi, "/sys/firmware/acpi/");
        if (ERRNO_IS_NEG_DEVICE_ABSENT(r)) {
                log_debug_errno(r, "Failed to open /sys/firmware/acpi/ device, ignoring: %m");
                return 0;
        }
        if (r < 0)
                return log_error_errno(r, "Failed to open /sys/firmware/acpi/ device: %m");

        return 1;
}

static int context_acquire_device_tree(Context *c) {
        int r;

        assert(c);
        assert(!c->device_tree);

        r = sd_device_new_from_path(&c->device_dmi, "/proc/device-tree/");
        if (ERRNO_IS_NEG_DEVICE_ABSENT(r)) {
                log_debug_errno(r, "Failed to open /proc/device-tree/ device, ignoring: %m");
                return 0;
        }
        if (r < 0)
                return log_error_errno(r, "Failed to open /proc/device-tree/ device: %m");

        return 1;
}

static bool string_is_safe_for_dbus(const char *s) {
        assert(s);

        /* Do some superficial validation: do not allow CCs and make sure D-Bus won't kick us off the bus
         * because we send invalid UTF-8 data */

        if (string_has_cc(s, /* ok= */ NULL))
                return false;

        return utf8_is_valid(s);
}

static int get_dmi_property(Context *c, const char *key, char **ret) {
        const char *s;
        int r;

        assert(c);
        assert(key);
        assert(ret);

        if (!c->device_dmi)
                return -ENODEV;

        r = sd_device_get_property_value(c->device_dmi, key, &s);
        if (r < 0)
                return r;

        if (!string_is_safe_for_dbus(s))
                return -ENXIO;

        return strdup_to(ret, s);
}

static int get_dmi_properties(Context *c, const char * const * keys, char **ret) {
        int r = -ENOENT;

        assert(c);
        assert(ret);

        STRV_FOREACH(k, keys) {
                r = get_dmi_property(c, *k, ret);
                if (r >= 0 || !ERRNO_IS_NEG_DEVICE_ABSENT(r))
                        return r;
        }

        return r;
}

static int get_hardware_vendor(Context *c, char **ret) {
        return get_dmi_properties(c, STRV_MAKE_CONST("ID_VENDOR_FROM_DATABASE", "ID_VENDOR"), ret);
}

static int get_hardware_model(Context *c, char **ret) {
        return get_dmi_properties(c, STRV_MAKE_CONST("ID_MODEL_FROM_DATABASE", "ID_MODEL"), ret);
}

static int get_sysattr(sd_device *device, const char *key, char **ret) {
        const char *s;
        int r;

        assert(key);
        assert(ret);

        if (!device)
                return -ENODEV;

        r = sd_device_get_sysattr_value(device, key, &s);
        if (r < 0)
                return r;

        if (!string_is_safe_for_dbus(s))
                return -ENXIO;

        return strdup_to(ret, empty_to_null(s));
}

static int get_dmi_sysattr(Context *c, const char *key, char **ret) {
        return get_sysattr(ASSERT_PTR(c)->device_dmi, key, ret);
}

static int get_device_tree_sysattr(Context *c, const char *key, char **ret) {
        return get_sysattr(ASSERT_PTR(c)->device_tree, key, ret);
}

static int get_hardware_serial(Context *c, char **ret) {
        int r;

        assert(c);
        assert(ret);

        FOREACH_STRING(attr, "product_serial", "board_serial") {
                r = get_dmi_sysattr(c, attr, ret);
                if (r >= 0 || !ERRNO_IS_NEG_DEVICE_ABSENT(r))
                        return r;
        }

        return get_device_tree_sysattr(c, "serial-number", ret);
}

static int get_firmware_version(Context *c, char **ret) {
        return get_dmi_sysattr(c, "bios_version", ret);
}

static int get_firmware_vendor(Context *c, char **ret) {
        return get_dmi_sysattr(c, "bios_vendor", ret);
}

static int get_firmware_date(Context *c, usec_t *ret) {
        _cleanup_free_ char *bios_date = NULL, *month = NULL, *day = NULL, *year = NULL;
        int r;

        assert(c);
        assert(ret);

        r = get_dmi_sysattr(c, "bios_date", &bios_date);
        if (ERRNO_IS_NEG_DEVICE_ABSENT(r)) {
                *ret = USEC_INFINITY;
                return 0;
        }
        if (r < 0)
                return r;

        const char *p = bios_date;
        r = extract_many_words(&p, "/", EXTRACT_DONT_COALESCE_SEPARATORS, &month, &day, &year);
        if (r < 0)
                return r;
        if (r != 3) /* less than three args read? */
                return -EINVAL;
        if (!isempty(p)) /* more left in the string? */
                return -EINVAL;

        unsigned m, d, y;
        r = safe_atou_full(month, 10 | SAFE_ATO_REFUSE_PLUS_MINUS | SAFE_ATO_REFUSE_LEADING_WHITESPACE, &m);
        if (r < 0)
                return r;
        if (m < 1 || m > 12)
                return -EINVAL;
        m -= 1;

        r = safe_atou_full(day, 10 | SAFE_ATO_REFUSE_PLUS_MINUS | SAFE_ATO_REFUSE_LEADING_WHITESPACE, &d);
        if (r < 0)
                return r;
        if (d < 1 || d > 31)
                return -EINVAL;

        r = safe_atou_full(year, 10 | SAFE_ATO_REFUSE_PLUS_MINUS | SAFE_ATO_REFUSE_LEADING_WHITESPACE, &y);
        if (r < 0)
                return r;
        if (y < 1970 || y > (unsigned) INT_MAX)
                return -EINVAL;
        y -= 1900;

        struct tm tm = {
                .tm_mday = d,
                .tm_mon = m,
                .tm_year = y,
        };

        usec_t v;
        r = mktime_or_timegm_usec(&tm, /* utc= */ true, &v);
        if (r < 0)
                return r;
        if (tm.tm_mday != (int) d || tm.tm_mon != (int) m || tm.tm_year != (int) y)
                return -EINVAL; /* date was not normalized? (e.g. "30th of feb") */

        *ret = v;
        return 0;
}

static const char* valid_chassis(const char *chassis) {
        assert(chassis);

        return nulstr_get(
                        "vm\0"
                        "container\0"
                        "desktop\0"
                        "laptop\0"
                        "convertible\0"
                        "server\0"
                        "tablet\0"
                        "handset\0"
                        "watch\0"
                        "embedded\0",
                        chassis);
}

static bool valid_deployment(const char *deployment) {
        assert(deployment);

        return in_charset(deployment, VALID_DEPLOYMENT_CHARS);
}

static const char* fallback_chassis_by_virtualization(void) {
        Virtualization v = detect_virtualization();
        if (v < 0) {
                log_debug_errno(v, "Failed to detect virtualization, ignoring: %m");
                return NULL;
        }

        if (VIRTUALIZATION_IS_VM(v))
                return "vm";
        if (VIRTUALIZATION_IS_CONTAINER(v))
                return "container";

        return NULL;
}

static const char* fallback_chassis_by_dmi(Context *c) {
        unsigned t;
        int r;

        assert(c);

        if (!c->device_dmi)
                return NULL;

        r = device_get_sysattr_unsigned(c->device_dmi, "chassis_type", &t);
        if (r < 0) {
                log_debug_errno(r, "Failed to read/parse DMI chassis type, ignoring: %m");
                return NULL;
        }

        /* We only list the really obvious cases here. The DMI data is unreliable enough, so let's not do any
         * additional guesswork on top of that.
         *
         * See the SMBIOS Specification 3.5.0 section 7.4.1 for details about the values listed here:
         *
         * https://www.dmtf.org/sites/default/files/standards/documents/DSP0134_3.5.0.pdf
         */

        switch (t) {

        case 0x03: /* Desktop */
        case 0x04: /* Low Profile Desktop */
        case 0x06: /* Mini Tower */
        case 0x07: /* Tower */
        case 0x0D: /* All in one (i.e. PC built into monitor) */
        case 0x23: /* Mini PC */
        case 0x24: /* Stick PC */
                return "desktop";

        case 0x8: /* Portable */
        case 0x9: /* Laptop */
        case 0xA: /* Notebook */
        case 0xE: /* Sub Notebook */
                return "laptop";

        case 0xB: /* Hand Held */
                return "handset";

        case 0x11: /* Main Server Chassis */
        case 0x1C: /* Blade */
        case 0x1D: /* Blade Enclosure */
                return "server";

        case 0x1E: /* Tablet */
                return "tablet";

        case 0x1F: /* Convertible */
        case 0x20: /* Detachable */
                return "convertible";

        case 0x21: /* IoT Gateway */
        case 0x22: /* Embedded PC */
                return "embedded";

        default:
                log_debug("Unhandled DMI chassis type 0x%02x, ignoring.", t);
                return NULL;
        }
}

static const char* fallback_chassis_by_acpi(Context *c) {
        unsigned t;
        int r;

        assert(c);

        if (!c->device_acpi)
                return NULL;

        r = device_get_sysattr_unsigned(c->device_acpi, "pm_profile", &t);
        if (r < 0) {
                log_debug_errno(r, "Failed read/parse ACPI PM profile, ignoring: %m");
                return NULL;
        }

        /* We only list the really obvious cases here as the ACPI data is not really super reliable.
         *
         * See the ACPI 5.0 Spec Section 5.2.9.1 for details:
         *
         * http://www.acpi.info/DOWNLOADS/ACPIspec50.pdf
         */

        switch (t) {

        case 1: /* Desktop */
        case 3: /* Workstation */
        case 6: /* Appliance PC */
                return "desktop";

        case 2: /* Mobile */
                return "laptop";

        case 4: /* Enterprise Server */
        case 5: /* SOHO Server */
        case 7: /* Performance Server */
                return "server";

        case 8: /* Tablet */
                return "tablet";

        default:
                log_debug("Unhandled ACPI PM profile 0x%02x, ignoring.", t);
                return NULL;
        }
}

static const char* fallback_chassis_by_device_tree(Context *c) {
        const char *type, *chassis;
        int r;

        assert(c);

        if (!c->device_tree)
                return NULL;

        r = sd_device_get_sysattr_value(c->device_tree, "chassis-type", &type);
        if (r < 0) {
                log_debug_errno(r, "Failed to read device-tree chassis type, ignoring: %m");
                return NULL;
        }

        /* Note that the DeviceTree specification uses the very same vocabulary
         * of chassis types as we do, hence we do not need to translate these types:
         *
         * https://github.com/devicetree-org/devicetree-specification/blob/master/source/chapter3-devicenodes.rst */

        chassis = valid_chassis(type);
        if (!chassis)
                log_debug("Invalid device-tree chassis type \"%s\", ignoring.", type);
        return chassis;
}

static const char* fallback_chassis(Context *c) {
        assert(c);

        return
                fallback_chassis_by_virtualization() ?:
                fallback_chassis_by_dmi(c) ?:
                fallback_chassis_by_acpi(c) ?:
                fallback_chassis_by_device_tree(c);
}

static char* context_get_chassis(Context *c) {
        const char *fallback;
        char *dmi;

        assert(c);

        if (!isempty(c->data[PROP_CHASSIS]))
                return strdup(c->data[PROP_CHASSIS]);

        if (get_dmi_property(c, "ID_CHASSIS", &dmi) >= 0)
                return dmi;

        fallback = fallback_chassis(c);
        if (fallback)
                return strdup(fallback);

        return NULL;
}

static char* context_fallback_icon_name(Context *c) {
        _cleanup_free_ char *chassis = NULL;

        assert(c);

        chassis = context_get_chassis(c);
        if (chassis)
                return strjoin("computer-", chassis);

        return strdup("computer");
}

static int context_update_kernel_hostname(
                Context *c,
                const char *transient_hn) {

        _cleanup_free_ char *_hn_free = NULL;
        const char *hn;
        HostnameSource hns;
        int r;

        assert(c);

        /* /etc/hostname has the highest preference ... */
        if (c->data[PROP_STATIC_HOSTNAME]) {
                hn = c->data[PROP_STATIC_HOSTNAME];
                hns = HOSTNAME_STATIC;

        /* ... the transient hostname, (ie: DHCP) comes next ... */
        } else if (transient_hn) {
                hn = transient_hn;
                hns = HOSTNAME_TRANSIENT;

        /* ... and the ultimate fallback */
        } else {
                hn = _hn_free = get_default_hostname();
                if (!hn)
                        return log_oom();

                hns = HOSTNAME_DEFAULT;
        }

        r = sethostname_idempotent(hn);
        if (r < 0)
                return log_error_errno(r, "Failed to set hostname: %m");

        if (c->hostname_source != hns) {
                c->hostname_source = hns;
                r = 1;
        }

        if (r == 0)
                log_debug("Hostname was already set to <%s>.", hn);
        else {
                log_info("Hostname set to <%s> (%s)", hn, hostname_source_to_string(hns));

                hostname_update_source_hint(hn, hns);
        }

        return r; /* 0 if no change, 1 if something was done  */
}

static void unset_statp(struct stat **p) {
        if (!*p)
                return;

        **p = (struct stat) {};
}

static int context_write_data_static_hostname(Context *c) {
        _cleanup_(unset_statp) struct stat *s = NULL;
        int r;

        assert(c);

        /* Make sure that if we fail here, we invalidate the cached information, since it was updated
         * already, even if we can't make it hit the disk. */
        s = &c->etc_hostname_stat;

        if (isempty(c->data[PROP_STATIC_HOSTNAME])) {
                if (unlink("/etc/hostname") < 0 && errno != ENOENT)
                        return -errno;

                TAKE_PTR(s);
                return 0;
        }

        r = write_string_file("/etc/hostname", c->data[PROP_STATIC_HOSTNAME], WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_ATOMIC|WRITE_STRING_FILE_LABEL);
        if (r < 0)
                return r;

        TAKE_PTR(s);
        return 0;
}

static int context_write_data_machine_info(Context *c) {
        _cleanup_(unset_statp) struct stat *s = NULL;
        static const char * const name[_PROP_MAX] = {
                [PROP_PRETTY_HOSTNAME] = "PRETTY_HOSTNAME",
                [PROP_ICON_NAME] = "ICON_NAME",
                [PROP_CHASSIS] = "CHASSIS",
                [PROP_DEPLOYMENT] = "DEPLOYMENT",
                [PROP_LOCATION] = "LOCATION",
        };
        _cleanup_strv_free_ char **l = NULL;
        int r;

        assert(c);

        /* Make sure that if we fail here, we invalidate the cached information, since it was updated
         * already, even if we can't make it hit the disk. */
        s = &c->etc_machine_info_stat;

        r = load_env_file(NULL, "/etc/machine-info", &l);
        if (r < 0 && r != -ENOENT)
                return r;

        for (int p = PROP_PRETTY_HOSTNAME; p <= PROP_LOCATION; p++) {
                assert(name[p]);

                r = strv_env_assign(&l, name[p], empty_to_null(c->data[p]));
                if (r < 0)
                        return r;
        }

        if (strv_isempty(l)) {
                if (unlink("/etc/machine-info") < 0 && errno != ENOENT)
                        return -errno;

                TAKE_PTR(s);
                return 0;
        }

        r = write_env_file_label(AT_FDCWD, "/etc/machine-info", NULL, l);
        if (r < 0)
                return r;

        TAKE_PTR(s);
        return 0;
}

static int property_get_hardware_property(
                sd_bus_message *reply,
                Context *c,
                HostProperty prop,
                int (*getter)(Context *c, char **ret)) {

        _cleanup_free_ char *from_dmi = NULL;

        assert(reply);
        assert(c);
        assert(IN_SET(prop, PROP_HARDWARE_VENDOR, PROP_HARDWARE_MODEL));
        assert(getter);

        context_read_machine_info(c);

        if (isempty(c->data[prop]))
                (void) getter(c, &from_dmi);

        return sd_bus_message_append(reply, "s", from_dmi ?: c->data[prop]);
}

static int property_get_hardware_vendor(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        return property_get_hardware_property(reply, userdata, PROP_HARDWARE_VENDOR, get_hardware_vendor);
}

static int property_get_hardware_model(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        return property_get_hardware_property(reply, userdata, PROP_HARDWARE_MODEL, get_hardware_model);
}

static int property_get_firmware_version(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        _cleanup_free_ char *firmware_version = NULL;
        Context *c = ASSERT_PTR(userdata);

        (void) get_firmware_version(c, &firmware_version);

        return sd_bus_message_append(reply, "s", firmware_version);
}

static int property_get_firmware_vendor(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        _cleanup_free_ char *firmware_vendor = NULL;
        Context *c = ASSERT_PTR(userdata);

        (void) get_firmware_vendor(c, &firmware_vendor);

        return sd_bus_message_append(reply, "s", firmware_vendor);
}

static int property_get_firmware_date(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        usec_t firmware_date = USEC_INFINITY;
        Context *c = ASSERT_PTR(userdata);

        (void) get_firmware_date(c, &firmware_date);

        return sd_bus_message_append(reply, "t", firmware_date);
}
static int property_get_hostname(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        _cleanup_free_ char *hn = NULL;
        int r;

        r = gethostname_strict(&hn);
        if (r < 0) {
                if (r != -ENXIO)
                        return r;

                hn = get_default_hostname();
                if (!hn)
                        return -ENOMEM;
        }

        return sd_bus_message_append(reply, "s", hn);
}

static int property_get_static_hostname(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Context *c = ASSERT_PTR(userdata);

        context_read_etc_hostname(c);

        return sd_bus_message_append(reply, "s", c->data[PROP_STATIC_HOSTNAME]);
}

static int property_get_default_hostname(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        _cleanup_free_ char *hn = NULL;

        hn = get_default_hostname();
        if (!hn)
                return log_oom();

        return sd_bus_message_append(reply, "s", hn);
}

static void context_determine_hostname_source(Context *c) {
        _cleanup_free_ char *hostname = NULL;
        int r;

        assert(c);

        if (c->hostname_source >= 0)
                return;

        (void) gethostname_full(GET_HOSTNAME_ALLOW_LOCALHOST, &hostname);

        if (streq_ptr(hostname, c->data[PROP_STATIC_HOSTNAME]))
                c->hostname_source = HOSTNAME_STATIC;
        else {
                _cleanup_free_ char *fallback = NULL;

                /* If the hostname was not set by us, try to figure out where it came from. If we set it to
                 * the default hostname, the file will tell us. We compare the string because it is possible
                 * that the hostname was set by an older version that had a different fallback, in the initrd
                 * or before we reexecuted. */

                r = read_one_line_file("/run/systemd/default-hostname", &fallback);
                if (r < 0 && r != -ENOENT)
                        log_warning_errno(r, "Failed to read /run/systemd/default-hostname, ignoring: %m");

                if (streq_ptr(fallback, hostname))
                        c->hostname_source = HOSTNAME_DEFAULT;
                else
                        c->hostname_source = HOSTNAME_TRANSIENT;
        }
}

static int property_get_hostname_source(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Context *c = ASSERT_PTR(userdata);

        context_read_etc_hostname(c);
        context_determine_hostname_source(c);

        return sd_bus_message_append(reply, "s", hostname_source_to_string(c->hostname_source));
}

static int property_get_machine_info_field(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        sd_bus_slot *slot;
        Context *c;

        /* Acquire the context object without this property's userdata offset added. Explanation: we want
         * access to two pointers here: a) the main context object we cache all properties in, and b) the
         * pointer to the property field inside the context object that we are supposed to update and
         * use. The latter (b) we get in the 'userdata' function parameter, and sd-bus calculates that for us
         * from the 'userdata' pointer we supplied when the vtable was registered, with the offset we
         * specified in the vtable added on top. To get the former (a) we need the 'userdata' pointer from
         * the vtable registration directly, without the offset added. Hence we ask sd-bus what the slot
         * object is (which encapsulates the vtable registration), and then query the 'userdata' field
         * directly off it. */
        assert_se(slot = sd_bus_get_current_slot(bus));
        assert_se(c = sd_bus_slot_get_userdata(slot));

        context_read_machine_info(c);

        return sd_bus_message_append(reply, "s", *(char**) userdata);
}

static int property_get_os_release_field(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        sd_bus_slot *slot;
        Context *c;

        /* As above, acquire the current context without this property's userdata offset added. */
        assert_se(slot = sd_bus_get_current_slot(bus));
        assert_se(c = sd_bus_slot_get_userdata(slot));

        context_read_os_release(c);

        return sd_bus_message_append(reply, "s", *(char**) userdata);
}

static int property_get_os_support_end(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Context *c = userdata;
        usec_t eol = USEC_INFINITY;

        context_read_os_release(c);

        if (c->data[PROP_OS_SUPPORT_END])
                (void) os_release_support_ended(c->data[PROP_OS_SUPPORT_END], /* quiet= */ false, &eol);

        return sd_bus_message_append(reply, "t", eol);
}

static int property_get_icon_name(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        _cleanup_free_ char *n = NULL;
        Context *c = userdata;
        const char *name;

        context_read_machine_info(c);

        if (isempty(c->data[PROP_ICON_NAME]))
                name = n = context_fallback_icon_name(c);
        else
                name = c->data[PROP_ICON_NAME];

        if (!name)
                return -ENOMEM;

        return sd_bus_message_append(reply, "s", name);
}

static int property_get_chassis(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        _cleanup_free_ char *chassis = NULL;
        Context *c = userdata;

        context_read_machine_info(c);

        chassis = context_get_chassis(c);

        return sd_bus_message_append(reply, "s", chassis);
}

static int property_get_uname_field(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        struct utsname u;

        assert_se(uname(&u) >= 0);

        return sd_bus_message_append(reply, "s", (char*) &u + PTR_TO_SIZE(userdata));
}

static int property_get_machine_id(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        sd_id128_t id;
        int r;

        r = sd_id128_get_machine(&id);
        if (r < 0)
                return r;

        return bus_property_get_id128(bus, path, interface, property, reply, &id, error);
}

static int property_get_boot_id(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        sd_id128_t id;
        int r;

        r = sd_id128_get_boot(&id);
        if (r < 0)
                return r;

        return bus_property_get_id128(bus, path, interface, property, reply, &id, error);
}

static int property_get_vsock_cid(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        unsigned local_cid = VMADDR_CID_ANY;

        (void) vsock_get_local_cid(&local_cid);

        return sd_bus_message_append(reply, "u", (uint32_t) local_cid);
}

static int method_set_hostname(sd_bus_message *m, void *userdata, sd_bus_error *error) {
        Context *c = ASSERT_PTR(userdata);
        const char *name;
        int interactive, r;

        assert(m);

        r = sd_bus_message_read(m, "sb", &name, &interactive);
        if (r < 0)
                return r;

        name = empty_to_null(name);

        /* We always go through with the procedure below without comparing to the current hostname, because
         * we might want to adjust hostname source information even if the actual hostname is unchanged. */

        if (name && !hostname_is_valid(name, 0))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid hostname '%s'", name);

        context_read_etc_hostname(c);

        r = bus_verify_polkit_async_full(
                        m,
                        "org.freedesktop.hostname1.set-hostname",
                        /* details= */ NULL,
                        /* good_user= */ UID_INVALID,
                        interactive ? POLKIT_ALLOW_INTERACTIVE : 0,
                        &c->polkit_registry,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        r = context_update_kernel_hostname(c, name);
        if (r < 0)
                return sd_bus_error_set_errnof(error, r, "Failed to set hostname: %m");
        else if (r > 0)
                (void) sd_bus_emit_properties_changed(sd_bus_message_get_bus(m),
                                                      "/org/freedesktop/hostname1", "org.freedesktop.hostname1",
                                                      "Hostname", "HostnameSource", NULL);

        return sd_bus_reply_method_return(m, NULL);
}

static int method_set_static_hostname(sd_bus_message *m, void *userdata, sd_bus_error *error) {
        Context *c = ASSERT_PTR(userdata);
        const char *name;
        int interactive;
        int r;

        assert(m);

        r = sd_bus_message_read(m, "sb", &name, &interactive);
        if (r < 0)
                return r;

        name = empty_to_null(name);

        context_read_etc_hostname(c);

        if (streq_ptr(name, c->data[PROP_STATIC_HOSTNAME]))
                return sd_bus_reply_method_return(m, NULL);

        if (name && !hostname_is_valid(name, 0))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid static hostname '%s'", name);

        r = bus_verify_polkit_async_full(
                        m,
                        "org.freedesktop.hostname1.set-static-hostname",
                        /* details= */ NULL,
                        /* good_user= */ UID_INVALID,
                        interactive ? POLKIT_ALLOW_INTERACTIVE : 0,
                        &c->polkit_registry,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        r = free_and_strdup_warn(&c->data[PROP_STATIC_HOSTNAME], name);
        if (r < 0)
                return r;

        r = context_write_data_static_hostname(c);
        if (r < 0) {
                log_error_errno(r, "Failed to write static hostname: %m");
                if (ERRNO_IS_PRIVILEGE(r))
                        return sd_bus_error_set(error, BUS_ERROR_FILE_IS_PROTECTED, "Not allowed to update /etc/hostname.");
                if (r == -EROFS)
                        return sd_bus_error_set(error, BUS_ERROR_READ_ONLY_FILESYSTEM, "/etc/hostname is in a read-only filesystem.");
                return sd_bus_error_set_errnof(error, r, "Failed to set static hostname: %m");
        }

        r = context_update_kernel_hostname(c, NULL);
        if (r < 0) {
                log_error_errno(r, "Failed to set hostname: %m");
                return sd_bus_error_set_errnof(error, r, "Failed to set hostname: %m");
        }

        (void) sd_bus_emit_properties_changed(sd_bus_message_get_bus(m),
                                              "/org/freedesktop/hostname1", "org.freedesktop.hostname1",
                                              "StaticHostname", "Hostname", "HostnameSource", NULL);

        return sd_bus_reply_method_return(m, NULL);
}

static int set_machine_info(Context *c, sd_bus_message *m, int prop, sd_bus_message_handler_t cb, sd_bus_error *error) {
        int interactive;
        const char *name;
        int r;

        assert(c);
        assert(m);

        r = sd_bus_message_read(m, "sb", &name, &interactive);
        if (r < 0)
                return r;

        name = empty_to_null(name);

        context_read_machine_info(c);

        if (streq_ptr(name, c->data[prop]))
                return sd_bus_reply_method_return(m, NULL);

        if (!isempty(name)) {
                /* The icon name might ultimately be used as file
                 * name, so better be safe than sorry */

                if (prop == PROP_ICON_NAME && !filename_is_valid(name))
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid icon name '%s'", name);
                if (prop == PROP_PRETTY_HOSTNAME && string_has_cc(name, NULL))
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid pretty hostname '%s'", name);
                if (prop == PROP_CHASSIS && !valid_chassis(name))
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid chassis '%s'", name);
                if (prop == PROP_DEPLOYMENT && !valid_deployment(name))
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid deployment '%s'", name);
                if (prop == PROP_LOCATION && string_has_cc(name, NULL))
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid location '%s'", name);
        }

        /* Since the pretty hostname should always be changed at the same time as the static one, use the
         * same policy action for both... */

        r = bus_verify_polkit_async_full(
                        m,
                        prop == PROP_PRETTY_HOSTNAME ? "org.freedesktop.hostname1.set-static-hostname" : "org.freedesktop.hostname1.set-machine-info",
                        /* details= */ NULL,
                        /* good_user= */ UID_INVALID,
                        interactive ? POLKIT_ALLOW_INTERACTIVE : 0,
                        &c->polkit_registry,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        r = free_and_strdup_warn(&c->data[prop], name);
        if (r < 0)
                return r;

        r = context_write_data_machine_info(c);
        if (r < 0) {
                log_error_errno(r, "Failed to write machine info: %m");
                if (ERRNO_IS_PRIVILEGE(r))
                        return sd_bus_error_set(error, BUS_ERROR_FILE_IS_PROTECTED, "Not allowed to update /etc/machine-info.");
                if (r == -EROFS)
                        return sd_bus_error_set(error, BUS_ERROR_READ_ONLY_FILESYSTEM, "/etc/machine-info is in a read-only filesystem.");
                return sd_bus_error_set_errnof(error, r, "Failed to write machine info: %m");
        }

        log_info("Changed %s to '%s'",
                 prop == PROP_PRETTY_HOSTNAME ? "pretty hostname" :
                 prop == PROP_DEPLOYMENT ? "deployment" :
                 prop == PROP_LOCATION ? "location" :
                 prop == PROP_CHASSIS ? "chassis" : "icon name", strna(c->data[prop]));

        (void) sd_bus_emit_properties_changed(
                        sd_bus_message_get_bus(m),
                        "/org/freedesktop/hostname1",
                        "org.freedesktop.hostname1",
                        prop == PROP_PRETTY_HOSTNAME ? "PrettyHostname" :
                        prop == PROP_DEPLOYMENT ? "Deployment" :
                        prop == PROP_LOCATION ? "Location" :
                        prop == PROP_CHASSIS ? "Chassis" : "IconName" , NULL);

        return sd_bus_reply_method_return(m, NULL);
}

static int method_set_pretty_hostname(sd_bus_message *m, void *userdata, sd_bus_error *error) {
        return set_machine_info(userdata, m, PROP_PRETTY_HOSTNAME, method_set_pretty_hostname, error);
}

static int method_set_icon_name(sd_bus_message *m, void *userdata, sd_bus_error *error) {
        return set_machine_info(userdata, m, PROP_ICON_NAME, method_set_icon_name, error);
}

static int method_set_chassis(sd_bus_message *m, void *userdata, sd_bus_error *error) {
        return set_machine_info(userdata, m, PROP_CHASSIS, method_set_chassis, error);
}

static int method_set_deployment(sd_bus_message *m, void *userdata, sd_bus_error *error) {
        return set_machine_info(userdata, m, PROP_DEPLOYMENT, method_set_deployment, error);
}

static int method_set_location(sd_bus_message *m, void *userdata, sd_bus_error *error) {
        return set_machine_info(userdata, m, PROP_LOCATION, method_set_location, error);
}

static int method_get_product_uuid(sd_bus_message *m, void *userdata, sd_bus_error *error) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        Context *c = ASSERT_PTR(userdata);
        int interactive, r;
        sd_id128_t uuid;

        assert(m);

        r = sd_bus_message_read(m, "b", &interactive);
        if (r < 0)
                return r;

        r = bus_verify_polkit_async_full(
                        m,
                        "org.freedesktop.hostname1.get-product-uuid",
                        /* details= */ NULL,
                        /* good_user= */ UID_INVALID,
                        interactive ? POLKIT_ALLOW_INTERACTIVE : 0,
                        &c->polkit_registry,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        r = id128_get_product(&uuid);
        if (r < 0) {
                if (r == -EADDRNOTAVAIL)
                        log_debug_errno(r, "DMI product UUID is all 0x00 or all 0xFF, ignoring.");
                else
                        log_full_errno(r == -ENOENT ? LOG_DEBUG : LOG_WARNING, r,
                                       "Failed to read product UUID, ignoring: %m");

                return sd_bus_error_set(error, BUS_ERROR_NO_PRODUCT_UUID,
                                        "Failed to read product UUID from firmware.");
        }

        r = sd_bus_message_new_method_return(m, &reply);
        if (r < 0)
                return r;

        r = sd_bus_message_append_array(reply, 'y', uuid.bytes, sizeof(uuid.bytes));
        if (r < 0)
                return r;

        return sd_bus_send(NULL, reply, NULL);
}

static int method_get_hardware_serial(sd_bus_message *m, void *userdata, sd_bus_error *error) {
        _cleanup_free_ char *serial = NULL;
        Context *c = ASSERT_PTR(userdata);
        int r;

        assert(m);

        r = bus_verify_polkit_async(
                        m,
                        "org.freedesktop.hostname1.get-hardware-serial",
                        /* details= */ NULL,
                        &c->polkit_registry,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        r = get_hardware_serial(c, &serial);
        if (r < 0)
                return sd_bus_error_set(error, BUS_ERROR_NO_HARDWARE_SERIAL,
                                        "Failed to read hardware serial from firmware.");

        return sd_bus_reply_method_return(m, "s", serial);
}

static int build_describe_response(Context *c, bool privileged, sd_json_variant **ret) {
        _cleanup_free_ char *hn = NULL, *dhn = NULL, *in = NULL,
                *chassis = NULL, *vendor = NULL, *model = NULL, *serial = NULL, *firmware_version = NULL,
                *firmware_vendor = NULL;
        _cleanup_strv_free_ char **os_release_pairs = NULL, **machine_info_pairs = NULL;
        usec_t firmware_date = USEC_INFINITY, eol = USEC_INFINITY;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        sd_id128_t machine_id, boot_id, product_uuid = SD_ID128_NULL;
        unsigned local_cid = VMADDR_CID_ANY;
        struct utsname u;
        int r;

        assert(c);
        assert(ret);

        context_read_etc_hostname(c);
        context_read_machine_info(c);
        context_read_os_release(c);
        context_determine_hostname_source(c);

        r = gethostname_strict(&hn);
        if (r < 0) {
                if (r != -ENXIO)
                        return log_error_errno(r, "Failed to read local host name: %m");

                hn = get_default_hostname();
                if (!hn)
                        return log_oom();
        }

        dhn = get_default_hostname();
        if (!dhn)
                return log_oom();

        if (isempty(c->data[PROP_ICON_NAME]))
                in = context_fallback_icon_name(c);

        chassis = context_get_chassis(c);

        assert_se(uname(&u) >= 0);

        if (isempty(c->data[PROP_HARDWARE_VENDOR]))
                (void) get_hardware_vendor(c, &vendor);
        if (isempty(c->data[PROP_HARDWARE_MODEL]))
                (void) get_hardware_model(c, &model);

        if (privileged) {
                /* The product UUID and hardware serial is only available to privileged clients */
                (void) id128_get_product(&product_uuid);
                (void) get_hardware_serial(c, &serial);
        }
        (void) get_firmware_version(c, &firmware_version);
        (void) get_firmware_vendor(c, &firmware_vendor);
        (void) get_firmware_date(c, &firmware_date);

        if (c->data[PROP_OS_SUPPORT_END])
                (void) os_release_support_ended(c->data[PROP_OS_SUPPORT_END], /* quiet= */ false, &eol);

        r = sd_id128_get_machine(&machine_id);
        if (r < 0)
                return log_error_errno(r, "Failed to get machine ID: %m");

        r = sd_id128_get_boot(&boot_id);
        if (r < 0)
                return log_error_errno(r, "Failed to get boot ID: %m");

        (void) vsock_get_local_cid(&local_cid);

        (void) load_os_release_pairs(/* root= */ NULL, &os_release_pairs);
        (void) load_env_file_pairs(/* f=*/ NULL, "/etc/machine-info", &machine_info_pairs);

        r = sd_json_buildo(
                        &v,
                        SD_JSON_BUILD_PAIR("Hostname", SD_JSON_BUILD_STRING(hn)),
                        SD_JSON_BUILD_PAIR("StaticHostname", SD_JSON_BUILD_STRING(c->data[PROP_STATIC_HOSTNAME])),
                        SD_JSON_BUILD_PAIR("PrettyHostname", SD_JSON_BUILD_STRING(c->data[PROP_PRETTY_HOSTNAME])),
                        SD_JSON_BUILD_PAIR("DefaultHostname", SD_JSON_BUILD_STRING(dhn)),
                        SD_JSON_BUILD_PAIR("HostnameSource", SD_JSON_BUILD_STRING(hostname_source_to_string(c->hostname_source))),
                        SD_JSON_BUILD_PAIR("IconName", SD_JSON_BUILD_STRING(in ?: c->data[PROP_ICON_NAME])),
                        SD_JSON_BUILD_PAIR("Chassis", SD_JSON_BUILD_STRING(chassis)),
                        SD_JSON_BUILD_PAIR("Deployment", SD_JSON_BUILD_STRING(c->data[PROP_DEPLOYMENT])),
                        SD_JSON_BUILD_PAIR("Location", SD_JSON_BUILD_STRING(c->data[PROP_LOCATION])),
                        SD_JSON_BUILD_PAIR("KernelName", SD_JSON_BUILD_STRING(u.sysname)),
                        SD_JSON_BUILD_PAIR("KernelRelease", SD_JSON_BUILD_STRING(u.release)),
                        SD_JSON_BUILD_PAIR("KernelVersion", SD_JSON_BUILD_STRING(u.version)),
                        SD_JSON_BUILD_PAIR("OperatingSystemPrettyName", SD_JSON_BUILD_STRING(c->data[PROP_OS_PRETTY_NAME])),
                        SD_JSON_BUILD_PAIR("OperatingSystemCPEName", SD_JSON_BUILD_STRING(c->data[PROP_OS_CPE_NAME])),
                        SD_JSON_BUILD_PAIR("OperatingSystemHomeURL", SD_JSON_BUILD_STRING(c->data[PROP_OS_HOME_URL])),
                        JSON_BUILD_PAIR_FINITE_USEC("OperatingSystemSupportEnd", eol),
                        SD_JSON_BUILD_PAIR("OperatingSystemReleaseData", JSON_BUILD_STRV_ENV_PAIR(os_release_pairs)),
                        SD_JSON_BUILD_PAIR("MachineInformationData", JSON_BUILD_STRV_ENV_PAIR(machine_info_pairs)),
                        SD_JSON_BUILD_PAIR("HardwareVendor", SD_JSON_BUILD_STRING(vendor ?: c->data[PROP_HARDWARE_VENDOR])),
                        SD_JSON_BUILD_PAIR("HardwareModel", SD_JSON_BUILD_STRING(model ?: c->data[PROP_HARDWARE_MODEL])),
                        SD_JSON_BUILD_PAIR("HardwareSerial", SD_JSON_BUILD_STRING(serial)),
                        SD_JSON_BUILD_PAIR("FirmwareVersion", SD_JSON_BUILD_STRING(firmware_version)),
                        SD_JSON_BUILD_PAIR("FirmwareVendor", SD_JSON_BUILD_STRING(firmware_vendor)),
                        JSON_BUILD_PAIR_FINITE_USEC("FirmwareDate", firmware_date),
                        SD_JSON_BUILD_PAIR_ID128("MachineID", machine_id),
                        SD_JSON_BUILD_PAIR_ID128("BootID", boot_id),
                        SD_JSON_BUILD_PAIR_CONDITION(!sd_id128_is_null(product_uuid), "ProductUUID", SD_JSON_BUILD_ID128(product_uuid)),
                        SD_JSON_BUILD_PAIR_CONDITION(sd_id128_is_null(product_uuid), "ProductUUID", SD_JSON_BUILD_NULL),
                        SD_JSON_BUILD_PAIR_CONDITION(local_cid != VMADDR_CID_ANY, "VSockCID", SD_JSON_BUILD_UNSIGNED(local_cid)),
                        SD_JSON_BUILD_PAIR_CONDITION(local_cid == VMADDR_CID_ANY, "VSockCID", SD_JSON_BUILD_NULL));
        if (r < 0)
                return log_error_errno(r, "Failed to build JSON data: %m");

        *ret = TAKE_PTR(v);
        return 0;
}

static int method_describe(sd_bus_message *m, void *userdata, sd_bus_error *error) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        Context *c = ASSERT_PTR(userdata);
        _cleanup_free_ char *text = NULL;
        bool privileged;
        int r;

        assert(m);

        r = bus_verify_polkit_async(
                        m,
                        "org.freedesktop.hostname1.get-description",
                        /* details= */ NULL,
                        &c->polkit_registry,
                        error);
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        /* We ignore all authentication errors here, since most data is unprivileged, the one exception being
         * the product ID which we'll check explicitly. */
        privileged = r > 0;

        r = build_describe_response(c, privileged, &v);
        if (r < 0)
                return r;

        r = sd_json_variant_format(v, 0, &text);
        if (r < 0)
                return log_error_errno(r, "Failed to format JSON data: %m");

        return sd_bus_reply_method_return(m, "s", text);
}

static const sd_bus_vtable hostname_vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_PROPERTY("Hostname", "s", property_get_hostname, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("StaticHostname", "s", property_get_static_hostname, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("PrettyHostname", "s", property_get_machine_info_field, offsetof(Context, data) + sizeof(char*) * PROP_PRETTY_HOSTNAME, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("DefaultHostname", "s", property_get_default_hostname, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("HostnameSource", "s", property_get_hostname_source, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("IconName", "s", property_get_icon_name, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("Chassis", "s", property_get_chassis, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("Deployment", "s", property_get_machine_info_field, offsetof(Context, data) + sizeof(char*) * PROP_DEPLOYMENT, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("Location", "s", property_get_machine_info_field, offsetof(Context, data) + sizeof(char*) * PROP_LOCATION, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("KernelName", "s", property_get_uname_field, offsetof(struct utsname, sysname), SD_BUS_VTABLE_ABSOLUTE_OFFSET|SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("KernelRelease", "s", property_get_uname_field, offsetof(struct utsname, release), SD_BUS_VTABLE_ABSOLUTE_OFFSET|SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("KernelVersion", "s", property_get_uname_field, offsetof(struct utsname, version), SD_BUS_VTABLE_ABSOLUTE_OFFSET|SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("OperatingSystemPrettyName", "s", property_get_os_release_field, offsetof(Context, data) + sizeof(char*) * PROP_OS_PRETTY_NAME, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("OperatingSystemCPEName", "s", property_get_os_release_field, offsetof(Context, data) + sizeof(char*) * PROP_OS_CPE_NAME, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("OperatingSystemSupportEnd", "t", property_get_os_support_end, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("HomeURL", "s", property_get_os_release_field, offsetof(Context, data) + sizeof(char*) * PROP_OS_HOME_URL, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("HardwareVendor", "s", property_get_hardware_vendor, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("HardwareModel", "s", property_get_hardware_model, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("FirmwareVersion", "s", property_get_firmware_version, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("FirmwareVendor", "s", property_get_firmware_vendor, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("FirmwareDate", "t", property_get_firmware_date, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("MachineID", "ay", property_get_machine_id, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("BootID", "ay", property_get_boot_id, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("VSockCID", "u", property_get_vsock_cid, 0, SD_BUS_VTABLE_PROPERTY_CONST),

        SD_BUS_METHOD_WITH_ARGS("SetHostname",
                                SD_BUS_ARGS("s", hostname, "b", interactive),
                                SD_BUS_NO_RESULT,
                                method_set_hostname,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("SetStaticHostname",
                                SD_BUS_ARGS("s", hostname, "b", interactive),
                                SD_BUS_NO_RESULT,
                                method_set_static_hostname,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("SetPrettyHostname",
                                SD_BUS_ARGS("s", hostname, "b", interactive),
                                SD_BUS_NO_RESULT,
                                method_set_pretty_hostname,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("SetIconName",
                                SD_BUS_ARGS("s", icon, "b", interactive),
                                SD_BUS_NO_RESULT,
                                method_set_icon_name,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("SetChassis",
                                SD_BUS_ARGS("s", chassis, "b", interactive),
                                SD_BUS_NO_RESULT,
                                method_set_chassis,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("SetDeployment",
                                SD_BUS_ARGS("s", deployment, "b", interactive),
                                SD_BUS_NO_RESULT,
                                method_set_deployment,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("SetLocation",
                                SD_BUS_ARGS("s", location, "b", interactive),
                                SD_BUS_NO_RESULT,
                                method_set_location,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("GetProductUUID",
                                SD_BUS_ARGS("b", interactive),
                                SD_BUS_RESULT("ay", uuid),
                                method_get_product_uuid,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("GetHardwareSerial",
                                SD_BUS_NO_ARGS,
                                SD_BUS_RESULT("s", serial),
                                method_get_hardware_serial,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("Describe",
                                SD_BUS_NO_ARGS,
                                SD_BUS_RESULT("s", json),
                                method_describe,
                                SD_BUS_VTABLE_UNPRIVILEGED),

        SD_BUS_VTABLE_END,
};

static const BusObjectImplementation manager_object = {
        "/org/freedesktop/hostname1",
        "org.freedesktop.hostname1",
        .vtables = BUS_VTABLES(hostname_vtable),
};

static int connect_bus(Context *c) {
        int r;

        assert(c);
        assert(c->event);
        assert(!c->bus);

        r = sd_bus_default_system(&c->bus);
        if (r < 0)
                return log_error_errno(r, "Failed to get system bus connection: %m");

        r = bus_add_implementation(c->bus, &manager_object, c);
        if (r < 0)
                return r;

        r = bus_log_control_api_register(c->bus);
        if (r < 0)
                return r;

        r = sd_bus_request_name_async(c->bus, NULL, "org.freedesktop.hostname1", 0, NULL, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to request name: %m");

        r = sd_bus_attach_event(c->bus, c->event, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to attach bus to event loop: %m");

        return 0;
}

static int vl_method_describe(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        static const sd_json_dispatch_field dispatch_table[] = {
                VARLINK_DISPATCH_POLKIT_FIELD,
                {}
        };

        Context *c = ASSERT_PTR(userdata);
        bool privileged;
        int r;

        assert(link);
        assert(parameters);

        r = sd_varlink_dispatch(link, parameters, dispatch_table, /* userdata= */ NULL);
        if (r != 0)
                return r;

        r = varlink_verify_polkit_async_full(
                        link,
                        c->bus,
                        "org.freedesktop.hostname1.get-hardware-serial",
                        /* details= */ NULL,
                        UID_INVALID,
                        POLKIT_DONT_REPLY,
                        &c->polkit_registry);
        if (r == 0)
                return 0; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        /* We ignore all authentication errors here, since most data is unprivileged, the one exception being
         * the product ID which we'll check explicitly. */
        privileged = r > 0;

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        r = build_describe_response(c, privileged, &v);
        if (r < 0)
                return r;

        return sd_varlink_reply(link, v);
}

static int connect_varlink(Context *c) {
        int r;

        assert(c);
        assert(c->event);
        assert(!c->varlink_server);

        r = varlink_server_new(
                        &c->varlink_server,
                        SD_VARLINK_SERVER_ACCOUNT_UID|SD_VARLINK_SERVER_INHERIT_USERDATA,
                        c);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate Varlink server: %m");

        r = sd_varlink_server_add_interface_many(
                        c->varlink_server,
                        &vl_interface_io_systemd_Hostname,
                        &vl_interface_io_systemd_service);
        if (r < 0)
                return log_error_errno(r, "Failed to add Hostname interface to Varlink server: %m");

        r = sd_varlink_server_bind_method_many(
                        c->varlink_server,
                        "io.systemd.Hostname.Describe",      vl_method_describe,
                        "io.systemd.service.Ping",           varlink_method_ping,
                        "io.systemd.service.SetLogLevel",    varlink_method_set_log_level,
                        "io.systemd.service.GetEnvironment", varlink_method_get_environment);
        if (r < 0)
                return log_error_errno(r, "Failed to bind Varlink method calls: %m");

        r = sd_varlink_server_attach_event(c->varlink_server, c->event, SD_EVENT_PRIORITY_NORMAL);
        if (r < 0)
                return log_error_errno(r, "Failed to attach Varlink server to event loop: %m");

        r = sd_varlink_server_listen_auto(c->varlink_server);
        if (r < 0)
                return log_error_errno(r, "Failed to bind to passed Varlink sockets: %m");
        if (r == 0) {
                r = sd_varlink_server_listen_address(c->varlink_server, "/run/systemd/io.systemd.Hostname", 0666);
                if (r < 0)
                        return log_error_errno(r, "Failed to bind to Varlink socket: %m");
        }

        return 0;
}

static bool context_check_idle(void *userdata) {
        Context *c = ASSERT_PTR(userdata);

        return sd_varlink_server_current_connections(c->varlink_server) == 0 &&
                hashmap_isempty(c->polkit_registry);
}

static int run(int argc, char *argv[]) {
        _cleanup_(context_destroy) Context context = {
                .hostname_source = _HOSTNAME_INVALID, /* appropriate value will be set later */
        };
        int r;

        log_setup();

        r = service_parse_argv("systemd-hostnamed.service",
                               "Manage the system hostname and related metadata.",
                               BUS_IMPLEMENTATIONS(&manager_object,
                                                   &log_control_object),
                               argc, argv);
        if (r <= 0)
                return r;

        umask(0022);

        r = mac_init();
        if (r < 0)
                return r;

        r = context_acquire_dmi_device(&context);
        if (r < 0)
                return r;

        r = context_acquire_acpi_device(&context);
        if (r < 0)
                return r;

        r = context_acquire_device_tree(&context);
        if (r < 0)
                return r;

        r = sd_event_default(&context.event);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate event loop: %m");

        (void) sd_event_set_watchdog(context.event, true);

        r = sd_event_set_signal_exit(context.event, true);
        if (r < 0)
                return log_error_errno(r, "Failed to install SIGINT/SIGTERM handlers: %m");

        r = connect_bus(&context);
        if (r < 0)
                return r;

        r = connect_varlink(&context);
        if (r < 0)
                return r;

        r = sd_notify(false, NOTIFY_READY);
        if (r < 0)
                log_warning_errno(r, "Failed to send readiness notification, ignoring: %m");

        r = bus_event_loop_with_idle(
                        context.event,
                        context.bus,
                        "org.freedesktop.hostname1",
                        DEFAULT_EXIT_USEC,
                        context_check_idle,
                        &context);
        if (r < 0)
                return log_error_errno(r, "Failed to run event loop: %m");

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
