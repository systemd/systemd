/* SPDX-License-Identifier: LGPL-2.1+ */

#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "sd-device.h"

#include "alloc-util.h"
#include "device-util.h"
#include "escape.h"
#include "fileio.h"
#include "main-func.h"
#include "mkdir.h"
#include "parse-util.h"
#include "proc-cmdline.h"
#include "string-util.h"
#include "strv.h"
#include "util.h"

static int find_pci_or_platform_parent(sd_device *device, sd_device **ret) {
        const char *subsystem, *sysname, *value;
        sd_device *parent;
        int r;

        assert(device);
        assert(ret);

        r = sd_device_get_parent(device, &parent);
        if (r < 0)
                return r;

        r = sd_device_get_subsystem(parent, &subsystem);
        if (r < 0)
                return r;

        r = sd_device_get_sysname(parent, &sysname);
        if (r < 0)
                return r;

        if (streq(subsystem, "drm")) {
                const char *c;

                c = startswith(sysname, "card");
                if (!c)
                        return -ENODATA;

                c += strspn(c, DIGITS);
                if (*c == '-') {
                        /* A connector DRM device, let's ignore all but LVDS and eDP! */
                        if (!STARTSWITH_SET(c, "-LVDS-", "-Embedded DisplayPort-"))
                                return -EOPNOTSUPP;
                }

        } else if (streq(subsystem, "pci") &&
                   sd_device_get_sysattr_value(parent, "class", &value) >= 0) {
                unsigned long class = 0;

                r = safe_atolu(value, &class);
                if (r < 0)
                        return log_warning_errno(r, "Cannot parse PCI class '%s' of device %s:%s: %m",
                                                 value, subsystem, sysname);

                /* Graphics card */
                if (class == 0x30000) {
                        *ret = parent;
                        return 0;
                }

        } else if (streq(subsystem, "platform")) {
                *ret = parent;
                return 0;
        }

        return find_pci_or_platform_parent(parent, ret);
}

static int same_device(sd_device *a, sd_device *b) {
        const char *a_val, *b_val;
        int r;

        assert(a);
        assert(b);

        r = sd_device_get_subsystem(a, &a_val);
        if (r < 0)
                return r;

        r = sd_device_get_subsystem(b, &b_val);
        if (r < 0)
                return r;

        if (!streq(a_val, b_val))
                return false;

        r = sd_device_get_sysname(a, &a_val);
        if (r < 0)
                return r;

        r = sd_device_get_sysname(b, &b_val);
        if (r < 0)
                return r;

        return streq(a_val, b_val);
}

static int validate_device(sd_device *device) {
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *enumerate = NULL;
        const char *v, *subsystem;
        sd_device *parent, *other;
        int r;

        assert(device);

        /* Verify whether we should actually care for a specific
         * backlight device. For backlight devices there might be
         * multiple ways to access the same control: "firmware"
         * (i.e. ACPI), "platform" (i.e. via the machine's EC) and
         * "raw" (via the graphics card). In general we should prefer
         * "firmware" (i.e. ACPI) or "platform" access over "raw"
         * access, in order not to confuse the BIOS/EC, and
         * compatibility with possible low-level hotkey handling of
         * screen brightness. The kernel will already make sure to
         * expose only one of "firmware" and "platform" for the same
         * device to userspace. However, we still need to make sure
         * that we use "raw" only if no "firmware" or "platform"
         * device for the same device exists. */

        r = sd_device_get_subsystem(device, &subsystem);
        if (r < 0)
                return r;
        if (!streq(subsystem, "backlight"))
                return true;

        r = sd_device_get_sysattr_value(device, "type", &v);
        if (r < 0)
                return r;
        if (!streq(v, "raw"))
                return true;

        r = find_pci_or_platform_parent(device, &parent);
        if (r < 0)
                return r;

        r = sd_device_get_subsystem(parent, &subsystem);
        if (r < 0)
                return r;

        r = sd_device_enumerator_new(&enumerate);
        if (r < 0)
                return r;

        r = sd_device_enumerator_allow_uninitialized(enumerate);
        if (r < 0)
                return r;

        r = sd_device_enumerator_add_match_subsystem(enumerate, "backlight", true);
        if (r < 0)
                return r;

        FOREACH_DEVICE(enumerate, other) {
                const char *other_subsystem;
                sd_device *other_parent;

                if (same_device(device, other) > 0)
                        continue;

                if (sd_device_get_sysattr_value(other, "type", &v) < 0 ||
                    !STR_IN_SET(v, "platform", "firmware"))
                        continue;

                /* OK, so there's another backlight device, and it's a
                 * platform or firmware device, so, let's see if we
                 * can verify it belongs to the same device as ours. */
                if (find_pci_or_platform_parent(other, &other_parent) < 0)
                        continue;

                if (same_device(parent, other_parent)) {
                        const char *device_sysname = NULL, *other_sysname = NULL;

                        /* Both have the same PCI parent, that means we are out. */

                        (void) sd_device_get_sysname(device, &device_sysname);
                        (void) sd_device_get_sysname(other, &other_sysname);

                        log_debug("Skipping backlight device %s, since device %s is on same PCI device and takes precedence.",
                                  device_sysname, other_sysname);
                        return false;
                }

                if (sd_device_get_subsystem(other_parent, &other_subsystem) < 0)
                        continue;

                if (streq(other_subsystem, "platform") && streq(subsystem, "pci")) {
                        const char *device_sysname = NULL, *other_sysname = NULL;

                        /* The other is connected to the platform bus and we are a PCI device, that also means we are out. */

                        (void) sd_device_get_sysname(device, &device_sysname);
                        (void) sd_device_get_sysname(other, &other_sysname);

                        log_debug("Skipping backlight device %s, since device %s is a platform device and takes precedence.",
                                  device_sysname, other_sysname);
                        return false;
                }
        }

        return true;
}

static int get_max_brightness(sd_device *device, unsigned *ret) {
        const char *max_brightness_str;
        unsigned max_brightness;
        int r;

        assert(device);
        assert(ret);

        r = sd_device_get_sysattr_value(device, "max_brightness", &max_brightness_str);
        if (r < 0)
                return log_device_warning_errno(device, r, "Failed to read 'max_brightness' attribute: %m");

        r = safe_atou(max_brightness_str, &max_brightness);
        if (r < 0)
                return log_device_warning_errno(device, r, "Failed to parse 'max_brightness' \"%s\": %m", max_brightness_str);

        if (max_brightness <= 0) {
                log_device_warning(device, "Maximum brightness is 0, ignoring device.");
                return -EINVAL;
        }

        *ret = max_brightness;
        return 0;
}

/* Some systems turn the backlight all the way off at the lowest levels.
 * clamp_brightness clamps the saved brightness to at least 1 or 5% of
 * max_brightness in case of 'backlight' subsystem. This avoids preserving
 * an unreadably dim screen, which would otherwise force the user to
 * disable state restoration. */
static int clamp_brightness(sd_device *device, char **value, unsigned max_brightness) {
        unsigned brightness, new_brightness, min_brightness;
        const char *subsystem;
        int r;

        assert(value);
        assert(*value);

        r = safe_atou(*value, &brightness);
        if (r < 0)
                return log_device_warning_errno(device, r, "Failed to parse brightness \"%s\": %m", *value);

        r = sd_device_get_subsystem(device, &subsystem);
        if (r < 0)
                return log_device_warning_errno(device, r, "Failed to get device subsystem: %m");

        if (streq(subsystem, "backlight"))
                min_brightness = MAX(1U, max_brightness/20);
        else
                min_brightness = 0;

        new_brightness = CLAMP(brightness, min_brightness, max_brightness);
        if (new_brightness != brightness) {
                char *new_value;

                r = asprintf(&new_value, "%u", new_brightness);
                if (r < 0)
                        return log_oom();

                log_device_info(device, "Saved brightness %s %s to %s.", *value,
                                new_brightness > brightness ?
                                "too low; increasing" : "too high; decreasing",
                                new_value);

                free_and_replace(*value, new_value);
        }

        return 0;
}

static bool shall_clamp(sd_device *d) {
        const char *s;
        int r;

        assert(d);

        r = sd_device_get_property_value(d, "ID_BACKLIGHT_CLAMP", &s);
        if (r < 0) {
                log_device_debug_errno(d, r, "Failed to get ID_BACKLIGHT_CLAMP property, ignoring: %m");
                return true;
        }

        r = parse_boolean(s);
        if (r < 0) {
                log_device_debug_errno(d, r, "Failed to parse ID_BACKLIGHT_CLAMP property, ignoring: %m");
                return true;
        }

        return r;
}

static int run(int argc, char *argv[]) {
        _cleanup_(sd_device_unrefp) sd_device *device = NULL;
        _cleanup_free_ char *escaped_ss = NULL, *escaped_sysname = NULL, *escaped_path_id = NULL;
        const char *sysname, *path_id, *ss, *saved;
        unsigned max_brightness;
        int r;

        if (argc != 3) {
                log_error("This program requires two arguments.");
                return -EINVAL;
        }

        log_setup_service();

        umask(0022);

        r = mkdir_p("/var/lib/systemd/backlight", 0755);
        if (r < 0)
                return log_error_errno(r, "Failed to create backlight directory /var/lib/systemd/backlight: %m");

        sysname = strchr(argv[2], ':');
        if (!sysname) {
                log_error("Requires a subsystem and sysname pair specifying a backlight device.");
                return -EINVAL;
        }

        ss = strndupa(argv[2], sysname - argv[2]);

        sysname++;

        if (!STR_IN_SET(ss, "backlight", "leds")) {
                log_error("Not a backlight or LED device: '%s:%s'", ss, sysname);
                return -EINVAL;
        }

        r = sd_device_new_from_subsystem_sysname(&device, ss, sysname);
        if (r < 0)
                return log_error_errno(r, "Failed to get backlight or LED device '%s:%s': %m", ss, sysname);

        /* If max_brightness is 0, then there is no actual backlight
         * device. This happens on desktops with Asus mainboards
         * that load the eeepc-wmi module. */
        if (get_max_brightness(device, &max_brightness) < 0)
                return 0;

        escaped_ss = cescape(ss);
        if (!escaped_ss)
                return log_oom();

        escaped_sysname = cescape(sysname);
        if (!escaped_sysname)
                return log_oom();

        if (sd_device_get_property_value(device, "ID_PATH", &path_id) >= 0) {
                escaped_path_id = cescape(path_id);
                if (!escaped_path_id)
                        return log_oom();

                saved = strjoina("/var/lib/systemd/backlight/", escaped_path_id, ":", escaped_ss, ":", escaped_sysname);
        } else
                saved = strjoina("/var/lib/systemd/backlight/", escaped_ss, ":", escaped_sysname);

        /* If there are multiple conflicting backlight devices, then
         * their probing at boot-time might happen in any order. This
         * means the validity checking of the device then is not
         * reliable, since it might not see other devices conflicting
         * with a specific backlight. To deal with this, we will
         * actively delete backlight state files at shutdown (where
         * device probing should be complete), so that the validity
         * check at boot time doesn't have to be reliable. */

        if (streq(argv[1], "load")) {
                _cleanup_free_ char *value = NULL;
                bool clamp;

                if (shall_restore_state() == 0)
                        return 0;

                if (validate_device(device) == 0)
                        return 0;

                clamp = shall_clamp(device);

                r = read_one_line_file(saved, &value);
                if (IN_SET(r, -ENOENT, 0)) {
                        const char *curval;

                        /* Fallback to clamping current brightness or exit early if
                         * clamping is not supported/enabled. */
                        if (!clamp)
                                return 0;

                        r = sd_device_get_sysattr_value(device, "brightness", &curval);
                        if (r < 0)
                                return log_device_warning_errno(device, r, "Failed to read 'brightness' attribute: %m");

                        value = strdup(curval);
                        if (!value)
                                return log_oom();
                } else if (r < 0)
                        return log_error_errno(r, "Failed to read %s: %m", saved);

                if (clamp)
                        (void) clamp_brightness(device, &value, max_brightness);

                r = sd_device_set_sysattr_value(device, "brightness", value);
                if (r < 0)
                        return log_device_error_errno(device, r, "Failed to write system 'brightness' attribute: %m");

        } else if (streq(argv[1], "save")) {
                const char *value;

                if (validate_device(device) == 0) {
                        (void) unlink(saved);
                        return 0;
                }

                r = sd_device_get_sysattr_value(device, "brightness", &value);
                if (r < 0)
                        return log_device_error_errno(device, r, "Failed to read system 'brightness' attribute: %m");

                r = write_string_file(saved, value, WRITE_STRING_FILE_CREATE);
                if (r < 0)
                        return log_device_error_errno(device, r, "Failed to write %s: %m", saved);

        } else {
                log_error("Unknown verb %s.", argv[1]);
                return -EINVAL;
        }

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
