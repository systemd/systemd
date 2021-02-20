/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "alloc-util.h"
#include "bus-common-errors.h"
#include "bus-get-properties.h"
#include "bus-log-control-api.h"
#include "bus-polkit.h"
#include "def.h"
#include "env-file-label.h"
#include "env-file.h"
#include "env-util.h"
#include "fileio-label.h"
#include "fileio.h"
#include "hostname-setup.h"
#include "hostname-util.h"
#include "id128-util.h"
#include "main-func.h"
#include "missing_capability.h"
#include "nscd-flush.h"
#include "nulstr-util.h"
#include "os-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "sd-device.h"
#include "selinux-util.h"
#include "service-util.h"
#include "signal-util.h"
#include "stat-util.h"
#include "string-table.h"
#include "strv.h"
#include "user-util.h"
#include "util.h"
#include "virt.h"

#define VALID_DEPLOYMENT_CHARS (DIGITS LETTERS "-.:")

enum {
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
        _PROP_MAX,
        _PROP_INVALID = -EINVAL,
};

typedef struct Context {
        char *data[_PROP_MAX];

        HostnameSource hostname_source;

        struct stat etc_hostname_stat;
        struct stat etc_os_release_stat;
        struct stat etc_machine_info_stat;

        Hashmap *polkit_registry;
} Context;

static void context_reset(Context *c, uint64_t mask) {
        assert(c);

        for (int p = 0; p < _PROP_MAX; p++) {
                if (!FLAGS_SET(mask, UINT64_C(1) << p))
                        continue;

                c->data[p] = mfree(c->data[p]);
        }
}

static void context_destroy(Context *c) {
        assert(c);

        context_reset(c, UINT64_MAX);
        bus_verify_polkit_async_registry_free(c->polkit_registry);
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
                      (UINT64_C(1) << PROP_LOCATION));

        r = parse_env_file(NULL, "/etc/machine-info",
                           "PRETTY_HOSTNAME", &c->data[PROP_PRETTY_HOSTNAME],
                           "ICON_NAME", &c->data[PROP_ICON_NAME],
                           "CHASSIS", &c->data[PROP_CHASSIS],
                           "DEPLOYMENT", &c->data[PROP_DEPLOYMENT],
                           "LOCATION", &c->data[PROP_LOCATION]);
        if (r < 0 && r != -ENOENT)
                log_warning_errno(r, "Failed to read /etc/machine-info, ignoring: %m");

        c->etc_machine_info_stat = current_stat;
}

static void context_read_os_release(Context *c) {
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
                      (UINT64_C(1) << PROP_OS_HOME_URL));

        r = parse_os_release(NULL,
                             "PRETTY_NAME", &c->data[PROP_OS_PRETTY_NAME],
                             "CPE_NAME", &c->data[PROP_OS_CPE_NAME],
                             "HOME_URL", &c->data[PROP_OS_HOME_URL]);
        if (r < 0 && r != -ENOENT)
                log_warning_errno(r, "Failed to read os-release file, ignoring: %m");

        c->etc_os_release_stat = current_stat;
}

static bool valid_chassis(const char *chassis) {
        assert(chassis);

        return nulstr_contains(
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

static const char* fallback_chassis(void) {
        char *type;
        unsigned t;
        int v, r;

        v = detect_virtualization();
        if (v < 0)
                log_debug_errno(v, "Failed to detect virtualization, ignoring: %m");
        else if (VIRTUALIZATION_IS_VM(v))
                return "vm";
        else if (VIRTUALIZATION_IS_CONTAINER(v))
                return "container";

        r = read_one_line_file("/sys/class/dmi/id/chassis_type", &type);
        if (r < 0) {
                log_debug_errno(v, "Failed to read DMI chassis type, ignoring: %m");
                goto try_acpi;
        }

        r = safe_atou(type, &t);
        free(type);
        if (r < 0) {
                log_debug_errno(v, "Failed to parse DMI chassis type, ignoring: %m");
                goto try_acpi;
        }

        /* We only list the really obvious cases here. The DMI data is unreliable enough, so let's not do any
           additional guesswork on top of that.

           See the SMBIOS Specification 3.0 section 7.4.1 for details about the values listed here:

           https://www.dmtf.org/sites/default/files/standards/documents/DSP0134_3.0.0.pdf
         */

        switch (t) {

        case 0x3: /* Desktop */
        case 0x4: /* Low Profile Desktop */
        case 0x6: /* Mini Tower */
        case 0x7: /* Tower */
        case 0xD: /* All in one (i.e. PC built into monitor) */
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

        default:
                log_debug("Unhandled DMI chassis type 0x%02x, ignoring.", t);
        }

try_acpi:
        r = read_one_line_file("/sys/firmware/acpi/pm_profile", &type);
        if (r < 0) {
                log_debug_errno(v, "Failed read ACPI PM profile, ignoring: %m");
                return NULL;
        }

        r = safe_atou(type, &t);
        free(type);
        if (r < 0) {
                log_debug_errno(v, "Failed parse ACPI PM profile, ignoring: %m");
                return NULL;
        }

        /* We only list the really obvious cases here as the ACPI data is not really super reliable.
         *
         * See the ACPI 5.0 Spec Section 5.2.9.1 for details:
         *
         * http://www.acpi.info/DOWNLOADS/ACPIspec50.pdf
         */

        switch(t) {

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
        }

        return NULL;
}

static char* context_fallback_icon_name(Context *c) {
        const char *chassis;

        assert(c);

        if (!isempty(c->data[PROP_CHASSIS]))
                return strjoin("computer-", c->data[PROP_CHASSIS]);

        chassis = fallback_chassis();
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

        (void) nscd_flush_cache(STRV_MAKE("hosts"));

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

        r = write_string_file_atomic_label("/etc/hostname", c->data[PROP_STATIC_HOSTNAME]);
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

        r = write_env_file_label("/etc/machine-info", l);
        if (r < 0)
                return r;

        TAKE_PTR(s);
        return 0;
}

static int property_get_hardware_vendor(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {
        _cleanup_(sd_device_unrefp) sd_device *device = NULL;
        const char *hardware_vendor = NULL;
        int r;

        r = sd_device_new_from_syspath(&device, "/sys/class/dmi/id");
        if (r < 0) {
                log_warning_errno(r, "Failed to open /sys/class/dmi/id device, ignoring: %m");
                return sd_bus_message_append(reply, "s", NULL);
        }

        if (sd_device_get_property_value(device, "ID_VENDOR_FROM_DATABASE", &hardware_vendor) < 0)
                (void) sd_device_get_property_value(device, "ID_VENDOR", &hardware_vendor);

        return sd_bus_message_append(reply, "s", hardware_vendor);
}

static int property_get_hardware_model(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {
        _cleanup_(sd_device_unrefp) sd_device *device = NULL;
        const char *hardware_model = NULL;
        int r;

        r = sd_device_new_from_syspath(&device, "/sys/class/dmi/id");
        if (r < 0) {
                log_warning_errno(r, "Failed to open /sys/class/dmi/id device, ignoring: %m");
                return sd_bus_message_append(reply, "s", NULL);
        }

        if (sd_device_get_property_value(device, "ID_MODEL_FROM_DATABASE", &hardware_model) < 0)
                (void) sd_device_get_property_value(device, "ID_MODEL", &hardware_model);

        return sd_bus_message_append(reply, "s", hardware_model);
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

        Context *c = userdata;
        assert(c);

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

        _cleanup_free_ char *hn = get_default_hostname();
        if (!hn)
                return log_oom();

        return sd_bus_message_append(reply, "s", hn);
}

static int property_get_hostname_source(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Context *c = userdata;
        int r;
        assert(c);

        context_read_etc_hostname(c);

        if (c->hostname_source < 0) {
                char hostname[HOST_NAME_MAX + 1] = {};
                _cleanup_free_ char *fallback = NULL;

                (void) get_hostname_filtered(hostname);

                if (streq_ptr(hostname, c->data[PROP_STATIC_HOSTNAME]))
                        c->hostname_source = HOSTNAME_STATIC;

                else {
                        /* If the hostname was not set by us, try to figure out where it came from. If we set
                         * it to the default hostname, the file will tell us. We compare the string because
                         * it is possible that the hostname was set by an older version that had a different
                         * fallback, in the initramfs or before we reexecuted. */

                        r = read_one_line_file("/run/systemd/default-hostname", &fallback);
                        if (r < 0 && r != -ENOENT)
                                log_warning_errno(r, "Failed to read /run/systemd/default-hostname, ignoring: %m");

                        if (streq_ptr(fallback, hostname))
                                c->hostname_source = HOSTNAME_DEFAULT;
                        else
                                c->hostname_source = HOSTNAME_TRANSIENT;
                }
        }

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

        Context *c = userdata;
        const char *name;

        context_read_machine_info(c);

        if (isempty(c->data[PROP_CHASSIS]))
                name = fallback_chassis();
        else
                name = c->data[PROP_CHASSIS];

        return sd_bus_message_append(reply, "s", name);
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

static int method_set_hostname(sd_bus_message *m, void *userdata, sd_bus_error *error) {
        Context *c = userdata;
        const char *name;
        int interactive, r;

        assert(m);
        assert(c);

        r = sd_bus_message_read(m, "sb", &name, &interactive);
        if (r < 0)
                return r;

        name = empty_to_null(name);

        /* We always go through with the procedure below without comparing to the current hostname, because
         * we might want to adjust hostname source information even if the actual hostname is unchanged. */

        if (name && !hostname_is_valid(name, 0))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid hostname '%s'", name);

        context_read_etc_hostname(c);

        r = bus_verify_polkit_async(
                        m,
                        CAP_SYS_ADMIN,
                        "org.freedesktop.hostname1.set-hostname",
                        NULL,
                        interactive,
                        UID_INVALID,
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
        Context *c = userdata;
        const char *name;
        int interactive;
        int r;

        assert(m);
        assert(c);

        r = sd_bus_message_read(m, "sb", &name, &interactive);
        if (r < 0)
                return r;

        name = empty_to_null(name);

        context_read_etc_hostname(c);

        if (streq_ptr(name, c->data[PROP_STATIC_HOSTNAME]))
                return sd_bus_reply_method_return(m, NULL);

        if (name && !hostname_is_valid(name, 0))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid static hostname '%s'", name);

        r = bus_verify_polkit_async(
                        m,
                        CAP_SYS_ADMIN,
                        "org.freedesktop.hostname1.set-static-hostname",
                        NULL,
                        interactive,
                        UID_INVALID,
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

        /* Since the pretty hostname should always be changed at the
         * same time as the static one, use the same policy action for
         * both... */

        r = bus_verify_polkit_async(
                        m,
                        CAP_SYS_ADMIN,
                        prop == PROP_PRETTY_HOSTNAME ? "org.freedesktop.hostname1.set-static-hostname" : "org.freedesktop.hostname1.set-machine-info",
                        NULL,
                        interactive,
                        UID_INVALID,
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
        Context *c = userdata;
        bool has_uuid = false;
        int interactive, r;
        sd_id128_t uuid;

        assert(m);
        assert(c);

        r = id128_read("/sys/class/dmi/id/product_uuid", ID128_UUID, &uuid);
        if (r == -ENOENT)
                r = id128_read("/sys/firmware/devicetree/base/vm,uuid", ID128_UUID, &uuid);
        if (r < 0)
                log_full_errno(r == -ENOENT ? LOG_DEBUG : LOG_WARNING, r,
                               "Failed to read product UUID, ignoring: %m");
        else if (sd_id128_is_null(uuid) || sd_id128_is_allf(uuid))
                log_debug("DMI product UUID " SD_ID128_FORMAT_STR " is all 0x00 or all 0xFF, ignoring.", SD_ID128_FORMAT_VAL(uuid));
        else
                has_uuid = true;

        if (!has_uuid)
                return sd_bus_error_set(error, BUS_ERROR_NO_PRODUCT_UUID,
                                        "Failed to read product UUID from firmware.");

        r = sd_bus_message_read(m, "b", &interactive);
        if (r < 0)
                return r;

        r = bus_verify_polkit_async(
                        m,
                        CAP_SYS_ADMIN,
                        "org.freedesktop.hostname1.get-product-uuid",
                        NULL,
                        interactive,
                        UID_INVALID,
                        &c->polkit_registry,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        r = sd_bus_message_new_method_return(m, &reply);
        if (r < 0)
                return r;

        r = sd_bus_message_append_array(reply, 'y', &uuid, sizeof(uuid));
        if (r < 0)
                return r;

        return sd_bus_send(NULL, reply, NULL);
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
        SD_BUS_PROPERTY("HomeURL", "s", property_get_os_release_field, offsetof(Context, data) + sizeof(char*) * PROP_OS_HOME_URL, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("HardwareVendor", "s", property_get_hardware_vendor, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("HardwareModel", "s", property_get_hardware_model, 0, SD_BUS_VTABLE_PROPERTY_CONST),

        SD_BUS_METHOD_WITH_NAMES("SetHostname",
                                 "sb",
                                 SD_BUS_PARAM(hostname)
                                 SD_BUS_PARAM(interactive),
                                 NULL,,
                                 method_set_hostname,
                                 SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_NAMES("SetStaticHostname",
                                 "sb",
                                 SD_BUS_PARAM(hostname)
                                 SD_BUS_PARAM(interactive),
                                 NULL,,
                                 method_set_static_hostname,
                                 SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_NAMES("SetPrettyHostname",
                                 "sb",
                                 SD_BUS_PARAM(hostname)
                                 SD_BUS_PARAM(interactive),
                                 NULL,,
                                 method_set_pretty_hostname,
                                 SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_NAMES("SetIconName",
                                 "sb",
                                 SD_BUS_PARAM(icon)
                                 SD_BUS_PARAM(interactive),
                                 NULL,,
                                 method_set_icon_name,
                                 SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_NAMES("SetChassis",
                                 "sb",
                                 SD_BUS_PARAM(chassis)
                                 SD_BUS_PARAM(interactive),
                                 NULL,,
                                 method_set_chassis,
                                 SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_NAMES("SetDeployment",
                                 "sb",
                                 SD_BUS_PARAM(deployment)
                                 SD_BUS_PARAM(interactive),
                                 NULL,,
                                 method_set_deployment,
                                 SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_NAMES("SetLocation",
                                 "sb",
                                 SD_BUS_PARAM(location)
                                 SD_BUS_PARAM(interactive),
                                 NULL,,
                                 method_set_location,
                                 SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_NAMES("GetProductUUID",
                                 "b",
                                 SD_BUS_PARAM(interactive),
                                 "ay",
                                 SD_BUS_PARAM(uuid),
                                 method_get_product_uuid,
                                 SD_BUS_VTABLE_UNPRIVILEGED),

        SD_BUS_VTABLE_END,
};

static const BusObjectImplementation manager_object = {
        "/org/freedesktop/hostname1",
        "org.freedesktop.hostname1",
        .vtables = BUS_VTABLES(hostname_vtable),
};

static int connect_bus(Context *c, sd_event *event, sd_bus **ret) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        int r;

        assert(c);
        assert(event);
        assert(ret);

        r = sd_bus_default_system(&bus);
        if (r < 0)
                return log_error_errno(r, "Failed to get system bus connection: %m");

        r = bus_add_implementation(bus, &manager_object, c);
        if (r < 0)
                return r;

        r = bus_log_control_api_register(bus);
        if (r < 0)
                return r;

        r = sd_bus_request_name_async(bus, NULL, "org.freedesktop.hostname1", 0, NULL, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to request name: %m");

        r = sd_bus_attach_event(bus, event, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to attach bus to event loop: %m");

        *ret = TAKE_PTR(bus);
        return 0;
}

static int run(int argc, char *argv[]) {
        _cleanup_(context_destroy) Context context = {
                .hostname_source = _HOSTNAME_INVALID, /* appropriate value will be set later */
        };
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
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

        r = mac_selinux_init();
        if (r < 0)
                return r;

        assert_se(sigprocmask_many(SIG_BLOCK, NULL, SIGTERM, SIGINT, -1) >= 0);

        r = sd_event_default(&event);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate event loop: %m");

        (void) sd_event_set_watchdog(event, true);

        r = sd_event_add_signal(event, NULL, SIGINT, NULL, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to install SIGINT handler: %m");

        r = sd_event_add_signal(event, NULL, SIGTERM, NULL, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to install SIGTERM handler: %m");

        r = connect_bus(&context, event, &bus);
        if (r < 0)
                return r;

        r = bus_event_loop_with_idle(event, bus, "org.freedesktop.hostname1", DEFAULT_EXIT_USEC, NULL, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to run event loop: %m");

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
