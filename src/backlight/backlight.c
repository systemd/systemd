/* SPDX-License-Identifier: LGPL-2.1-or-later */

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
#include "percent-util.h"
#include "pretty-print.h"
#include "process-util.h"
#include "reboot-util.h"
#include "string-util.h"
#include "strv.h"
#include "terminal-util.h"

#define PCI_CLASS_GRAPHICS_CARD 0x30000

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-backlight", "8", &link);
        if (r < 0)
                return log_oom();

        printf("%s save [backlight|leds]:DEVICE\n"
               "%s load [backlight|leds]:DEVICE\n"
               "\n%sSave and restore backlight brightness at shutdown and boot.%s\n\n"
               "  save            Save current brightness\n"
               "  load            Set brightness to be the previously saved value\n"
               "\nSee the %s for details.\n",
               program_invocation_short_name,
               program_invocation_short_name,
               ansi_highlight(),
               ansi_normal(),
               link);

        return 0;
}

static int has_multiple_graphics_cards(void) {
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        bool found = false;
        int r;

        r = sd_device_enumerator_new(&e);
        if (r < 0)
                return r;

        r = sd_device_enumerator_add_match_subsystem(e, "pci", /* match = */ true);
        if (r < 0)
                return r;

        /* class is an unsigned number, let's validate the value later. */
        r = sd_device_enumerator_add_match_sysattr(e, "class", NULL, /* match = */ true);
        if (r < 0)
                return r;

        FOREACH_DEVICE(e, dev) {
                const char *s;
                unsigned long c;

                if (sd_device_get_sysattr_value(dev, "class", &s) < 0)
                        continue;

                if (safe_atolu(s, &c) < 0)
                        continue;

                if (c != PCI_CLASS_GRAPHICS_CARD)
                        continue;

                if (found)
                        return true; /* This is the second device. */

                found = true; /* Found the first device. */
        }

        return false;
}

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
                if (*c == '-' && !STARTSWITH_SET(c, "-LVDS-", "-Embedded DisplayPort-", "-eDP-"))
                        /* A connector DRM device, let's ignore all but LVDS and eDP! */
                        return -EOPNOTSUPP;

        } else if (streq(subsystem, "pci") &&
                   sd_device_get_sysattr_value(parent, "class", &value) >= 0) {
                unsigned long class;

                r = safe_atolu(value, &class);
                if (r < 0)
                        return log_warning_errno(r, "Cannot parse PCI class '%s' of device %s:%s: %m",
                                                 value, subsystem, sysname);

                /* Graphics card */
                if (class == PCI_CLASS_GRAPHICS_CARD) {
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
        const char *v, *sysname, *subsystem;
        sd_device *parent;
        int r;

        assert(device);

        /* Verify whether we should actually care for a specific backlight device. For backlight devices
         * there might be multiple ways to access the same control: "firmware" (i.e. ACPI), "platform"
         * (i.e. via the machine's EC) and "raw" (via the graphics card). In general we should prefer
         * "firmware" (i.e. ACPI) or "platform" access over "raw" access, in order not to confuse the
         * BIOS/EC, and compatibility with possible low-level hotkey handling of screen brightness. The
         * kernel will already make sure to expose only one of "firmware" and "platform" for the same
         * device to userspace. However, we still need to make sure that we use "raw" only if no
         * "firmware" or "platform" device for the same device exists. */

        r = sd_device_get_sysname(device, &sysname);
        if (r < 0)
                return log_device_debug_errno(device, r, "Failed to get sysname: %m");

        r = sd_device_get_subsystem(device, &subsystem);
        if (r < 0)
                return log_device_debug_errno(device, r, "Failed to get subsystem: %m");
        if (!streq(subsystem, "backlight"))
                return true;

        r = sd_device_get_sysattr_value(device, "type", &v);
        if (r < 0)
                return log_device_debug_errno(device, r, "Failed to read 'type' sysattr: %m");
        if (!streq(v, "raw"))
                return true;

        r = find_pci_or_platform_parent(device, &parent);
        if (r < 0)
                return log_device_debug_errno(device, r, "Failed to find PCI or platform parent: %m");

        r = sd_device_get_subsystem(parent, &subsystem);
        if (r < 0)
                return log_device_debug_errno(parent, r, "Failed to get subsystem: %m");

        if (DEBUG_LOGGING) {
                const char *s = NULL;

                (void) sd_device_get_syspath(parent, &s);
                log_device_debug(device, "Found %s parent device: %s", subsystem, strna(s));
        }

        r = sd_device_enumerator_new(&enumerate);
        if (r < 0)
                return log_oom_debug();

        r = sd_device_enumerator_allow_uninitialized(enumerate);
        if (r < 0)
                return log_debug_errno(r, "Failed to allow uninitialized devices: %m");

        r = sd_device_enumerator_add_match_subsystem(enumerate, "backlight", /* match = */ true);
        if (r < 0)
                return log_debug_errno(r, "Failed to add subsystem match: %m");

        r = sd_device_enumerator_add_nomatch_sysname(enumerate, sysname);
        if (r < 0)
                return log_debug_errno(r, "Failed to add sysname unmatch: %m");

        r = sd_device_enumerator_add_match_sysattr(enumerate, "type", "platform", /* match = */ true);
        if (r < 0)
                return log_debug_errno(r, "Failed to add sysattr match: %m");

        r = sd_device_enumerator_add_match_sysattr(enumerate, "type", "firmware", /* match = */ true);
        if (r < 0)
                return log_debug_errno(r, "Failed to add sysattr match: %m");

        if (streq(subsystem, "pci")) {
                r = has_multiple_graphics_cards();
                if (r < 0)
                        return log_debug_errno(r, "Failed to check if the system has multiple graphics cards: %m");
                if (r > 0) {
                        /* If the system has multiple graphics cards, then we cannot associate platform
                         * devices on non-PCI bus (especially WMI bus) with PCI devices. Let's ignore all
                         * backlight devices that do not have the same parent PCI device. */
                        log_debug("Found multiple graphics cards on PCI bus. "
                                  "Skipping to associate platform backlight devices on non-PCI bus.");

                        r = sd_device_enumerator_add_match_parent(enumerate, parent);
                        if (r < 0)
                                return log_debug_errno(r, "Failed to add parent match: %m");
                }
        }

        FOREACH_DEVICE(enumerate, other) {
                const char *other_subsystem;
                sd_device *other_parent;

                /* OK, so there's another backlight device, and it's a platform or firmware device.
                 * Let's see if we can verify it belongs to the same device as ours. */
                r = find_pci_or_platform_parent(other, &other_parent);
                if (r < 0) {
                        log_device_debug_errno(other, r, "Failed to get PCI or platform parent, ignoring: %m");
                        continue;
                }

                if (same_device(parent, other_parent) > 0) {
                        /* Both have the same PCI parent, that means we are out. */
                        if (DEBUG_LOGGING) {
                                const char *other_sysname = NULL, *other_type = NULL;

                                (void) sd_device_get_sysname(other, &other_sysname);
                                (void) sd_device_get_sysattr_value(other, "type", &other_type);
                                log_device_debug(device,
                                                 "Found another %s backlight device %s on the same PCI, skipping.",
                                                 strna(other_type), strna(other_sysname));
                        }
                        return false;
                }

                r = sd_device_get_subsystem(other_parent, &other_subsystem);
                if (r < 0) {
                        log_device_debug_errno(other_parent, r, "Failed to get subsystem, ignoring: %m");
                        continue;
                }

                if (streq(other_subsystem, "platform") && streq(subsystem, "pci")) {
                        /* The other is connected to the platform bus and we are a PCI device, that also means we are out. */
                        if (DEBUG_LOGGING) {
                                const char *other_sysname = NULL, *other_type = NULL;

                                (void) sd_device_get_sysname(other, &other_sysname);
                                (void) sd_device_get_sysattr_value(other, "type", &other_type);
                                log_device_debug(device,
                                                 "Found another %s backlight device %s, which has higher precedence, skipping.",
                                                 strna(other_type), strna(other_sysname));
                        }
                        return false;
                }
        }

        return true;
}

static int read_max_brightness(sd_device *device, unsigned *ret) {
        unsigned max_brightness;
        const char *s;
        int r;

        assert(device);
        assert(ret);

        r = sd_device_get_sysattr_value(device, "max_brightness", &s);
        if (r < 0)
                return log_device_warning_errno(device, r, "Failed to read 'max_brightness' attribute: %m");

        r = safe_atou(s, &max_brightness);
        if (r < 0)
                return log_device_warning_errno(device, r, "Failed to parse 'max_brightness' \"%s\": %m", s);

        /* If max_brightness is 0, then there is no actual backlight device. This happens on desktops
         * with Asus mainboards that load the eeepc-wmi module. */
        if (max_brightness == 0) {
                log_device_warning(device, "Maximum brightness is 0, ignoring device.");
                *ret = 0;
                return 0;
        }

        log_device_debug(device, "Maximum brightness is %u", max_brightness);

        *ret = max_brightness;
        return 1; /* valid max brightness */
}

static int clamp_brightness(
                sd_device *device,
                unsigned percent,
                bool saved,
                unsigned max_brightness,
                unsigned *brightness) {

        unsigned new_brightness, min_brightness;
        const char *subsystem;
        int r;

        assert(device);
        assert(brightness);

        /* Some systems turn the backlight all the way off at the lowest levels. This clamps the saved
         * brightness to at least 1 or 5% of max_brightness in case of 'backlight' subsystem. This
         * avoids preserving an unreadably dim screen, which would otherwise force the user to disable
         * state restoration. */

        r = sd_device_get_subsystem(device, &subsystem);
        if (r < 0)
                return log_device_warning_errno(device, r, "Failed to get device subsystem: %m");

        if (streq(subsystem, "backlight"))
                min_brightness = MAX(1U, (unsigned) ((double) max_brightness * percent / 100));
        else
                min_brightness = 0;

        new_brightness = CLAMP(*brightness, min_brightness, max_brightness);
        if (new_brightness != *brightness)
                log_device_info(device, "%s brightness %u is %s to %u.",
                                saved ? "Saved" : "Current",
                                *brightness,
                                new_brightness > *brightness ?
                                "too low; increasing" : "too high; decreasing",
                                new_brightness);

        *brightness = new_brightness;
        return 0;
}

static bool shall_clamp(sd_device *d, unsigned *ret) {
        const char *s;
        int r;

        assert(d);
        assert(ret);

        r = sd_device_get_property_value(d, "ID_BACKLIGHT_CLAMP", &s);
        if (r < 0) {
                if (r != -ENOENT)
                        log_device_debug_errno(d, r, "Failed to get ID_BACKLIGHT_CLAMP property, ignoring: %m");
                *ret = 5; /* defaults to 5% */
                return true;
        }

        r = parse_boolean(s);
        if (r >= 0) {
                *ret = r ? 5 : 0;
                return r;
        }

        r = parse_percent(s);
        if (r < 0) {
                log_device_debug_errno(d, r, "Failed to parse ID_BACKLIGHT_CLAMP property, ignoring: %m");
                *ret = 5;
                return true;
        }

        *ret = r;
        return true;
}

static int read_brightness(sd_device *device, unsigned max_brightness, unsigned *ret_brightness) {
        const char *subsystem, *value;
        unsigned brightness;
        int r;

        assert(device);
        assert(ret_brightness);

        r = sd_device_get_subsystem(device, &subsystem);
        if (r < 0)
                return log_device_debug_errno(device, r, "Failed to get subsystem: %m");

        if (streq(subsystem, "backlight")) {
                r = sd_device_get_sysattr_value(device, "actual_brightness", &value);
                if (r == -ENOENT) {
                        log_device_debug_errno(device, r, "Failed to read 'actual_brightness' attribute, "
                                               "fall back to use 'brightness' attribute: %m");
                        goto use_brightness;
                }
                if (r < 0)
                        return log_device_debug_errno(device, r, "Failed to read 'actual_brightness' attribute: %m");

                r = safe_atou(value, &brightness);
                if (r < 0) {
                        log_device_debug_errno(device, r, "Failed to parse 'actual_brightness' attribute, "
                                               "fall back to use 'brightness' attribute: %s", value);
                        goto use_brightness;
                }

                if (brightness > max_brightness) {
                        log_device_debug(device, "actual_brightness=%u is larger than max_brightness=%u, "
                                         "fall back to use 'brightness' attribute", brightness, max_brightness);
                        goto use_brightness;
                }

                log_device_debug(device, "Current actual_brightness is %u", brightness);
                *ret_brightness = brightness;
                return 0;
        }

use_brightness:
        r = sd_device_get_sysattr_value(device, "brightness", &value);
        if (r < 0)
                return log_device_debug_errno(device, r, "Failed to read 'brightness' attribute: %m");

        r = safe_atou(value, &brightness);
        if (r < 0)
                return log_device_debug_errno(device, r, "Failed to parse 'brightness' attribute: %s", value);

        if (brightness > max_brightness)
                return log_device_debug_errno(device, SYNTHETIC_ERRNO(EINVAL),
                                              "brightness=%u is larger than max_brightness=%u",
                                              brightness, max_brightness);

        log_device_debug(device, "Current brightness is %u", brightness);
        *ret_brightness = brightness;
        return 0;
}

static int build_save_file_path(sd_device *device, char **ret) {
        _cleanup_free_ char *escaped_subsystem = NULL, *escaped_sysname = NULL, *path = NULL;
        const char *s;
        int r;

        assert(device);
        assert(ret);

        r = sd_device_get_subsystem(device, &s);
        if (r < 0)
                return log_device_error_errno(device, r, "Failed to get subsystem: %m");

        escaped_subsystem = cescape(s);
        if (!escaped_subsystem)
                return log_oom();

        r = sd_device_get_sysname(device, &s);
        if (r < 0)
                return log_device_error_errno(device, r, "Failed to get sysname: %m");

        escaped_sysname = cescape(s);
        if (!escaped_sysname)
                return log_oom();

        if (sd_device_get_property_value(device, "ID_PATH", &s) >= 0) {
                _cleanup_free_ char *escaped_path_id = cescape(s);
                if (!escaped_path_id)
                        return log_oom();

                path = strjoin("/var/lib/systemd/backlight/", escaped_path_id, ":", escaped_subsystem, ":", escaped_sysname);
        } else
                path = strjoin("/var/lib/systemd/backlight/", escaped_subsystem, ":", escaped_sysname);
        if (!path)
                return log_oom();

        *ret = TAKE_PTR(path);
        return 0;
}

static int run(int argc, char *argv[]) {
        _cleanup_(sd_device_unrefp) sd_device *device = NULL;
        _cleanup_free_ char *saved = NULL;
        const char *sysname, *ss;
        unsigned max_brightness, brightness;
        int r;

        log_setup();

        if (argv_looks_like_help(argc, argv))
                return help();

        if (argc != 3)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "This program requires two arguments.");

        if (!STR_IN_SET(argv[1], "load", "save"))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Unknown verb %s.", argv[1]);

        umask(0022);

        r = mkdir_p("/var/lib/systemd/backlight", 0755);
        if (r < 0)
                return log_error_errno(r, "Failed to create backlight directory /var/lib/systemd/backlight: %m");

        sysname = strchr(argv[2], ':');
        if (!sysname)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Requires a subsystem and sysname pair specifying a backlight device.");

        ss = strndupa_safe(argv[2], sysname - argv[2]);

        sysname++;

        if (!STR_IN_SET(ss, "backlight", "leds"))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Not a backlight or LED device: '%s:%s'", ss, sysname);

        r = sd_device_new_from_subsystem_sysname(&device, ss, sysname);
        if (r < 0) {
                bool ignore = r == -ENODEV;

                /* Some drivers, e.g. for AMD GPU, removes acpi backlight device soon after it is added.
                 * See issue #21997. */
                log_full_errno(ignore ? LOG_DEBUG : LOG_ERR, r,
                               "Failed to get backlight or LED device '%s:%s'%s: %m",
                               ss, sysname, ignore ? ", ignoring" : "");
                return ignore ? 0 : r;
        }

        r = read_max_brightness(device, &max_brightness);
        if (r <= 0)
                return r;

        r = build_save_file_path(device, &saved);
        if (r < 0)
                return r;

        /* If there are multiple conflicting backlight devices, then their probing at boot-time might
         * happen in any order. This means the validity checking of the device then is not reliable,
         * since it might not see other devices conflicting with a specific backlight. To deal with
         * this, we will actively delete backlight state files at shutdown (where device probing should
         * be complete), so that the validity check at boot time doesn't have to be reliable. */

        if (streq(argv[1], "load")) {
                _cleanup_free_ char *value = NULL;
                unsigned percent;
                bool clamp;

                if (!shall_restore_state())
                        return 0;

                if (validate_device(device) == 0)
                        return 0;

                clamp = shall_clamp(device, &percent);

                r = read_one_line_file(saved, &value);
                if (r < 0 && r != -ENOENT)
                        return log_error_errno(r, "Failed to read %s: %m", saved);
                if (r > 0) {
                        r = safe_atou(value, &brightness);
                        if (r < 0) {
                                log_warning_errno(r, "Failed to parse saved brightness '%s', removing %s.",
                                                  value, saved);
                                (void) unlink(saved);
                        } else {
                                log_debug("Using saved brightness %u.", brightness);
                                if (clamp)
                                        (void) clamp_brightness(device, percent, /* saved = */ true, max_brightness, &brightness);

                                /* Do not fall back to read current brightness below. */
                                r = 1;
                        }
                }
                if (r <= 0) {
                        /* Fallback to clamping current brightness or exit early if clamping is not
                         * supported/enabled. */
                        if (!clamp)
                                return 0;

                        r = read_brightness(device, max_brightness, &brightness);
                        if (r < 0)
                                return log_device_error_errno(device, r, "Failed to read current brightness: %m");

                        (void) clamp_brightness(device, percent, /* saved = */ false, max_brightness, &brightness);
                }

                r = sd_device_set_sysattr_valuef(device, "brightness", "%u", brightness);
                if (r < 0)
                        return log_device_error_errno(device, r, "Failed to write system 'brightness' attribute: %m");

        } else if (streq(argv[1], "save")) {
                if (validate_device(device) == 0) {
                        (void) unlink(saved);
                        return 0;
                }

                r = read_brightness(device, max_brightness, &brightness);
                if (r < 0)
                        return log_device_error_errno(device, r, "Failed to read current brightness: %m");

                r = write_string_filef(saved, WRITE_STRING_FILE_CREATE, "%u", brightness);
                if (r < 0)
                        return log_device_error_errno(device, r, "Failed to write %s: %m", saved);

        } else
                assert_not_reached();

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
