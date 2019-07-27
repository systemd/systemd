/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <linux/input.h>

#include "device-util.h"
#include "fd-util.h"
#include "parse-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "strxcpyx.h"
#include "udev-builtin.h"

static const struct key_name *keyboard_lookup_key(const char *str, GPERF_LEN_TYPE len);
#include "keyboard-keys-from-name.h"

static int install_force_release(sd_device *dev, const unsigned *release, unsigned release_count) {
        sd_device *atkbd;
        const char *cur;
        char codes[4096];
        char *s;
        size_t l;
        unsigned i;
        int r;

        assert(dev);
        assert(release);

        r = sd_device_get_parent_with_subsystem_devtype(dev, "serio", NULL, &atkbd);
        if (r < 0)
                return log_device_error_errno(dev, r, "Failed to get serio parent: %m");

        r = sd_device_get_sysattr_value(atkbd, "force_release", &cur);
        if (r < 0)
                return log_device_error_errno(atkbd, r, "Failed to get force-release attribute: %m");

        s = codes;
        l = sizeof(codes);

        /* copy current content */
        l = strpcpy(&s, l, cur);

        /* append new codes */
        for (i = 0; i < release_count; i++)
                l = strpcpyf(&s, l, ",%u", release[i]);

        log_device_debug(atkbd, "keyboard: updating force-release list with '%s'", codes);
        r = sd_device_set_sysattr_value(atkbd, "force_release", codes);
        if (r < 0)
                return log_device_error_errno(atkbd, r, "Failed to set force-release attribute: %m");

        return 0;
}

static int map_keycode(sd_device *dev, int fd, int scancode, const char *keycode) {
        struct {
                unsigned scan;
                unsigned key;
        } map;
        char *endptr;
        const struct key_name *k;
        unsigned keycode_num;

        /* translate identifier to key code */
        k = keyboard_lookup_key(keycode, strlen(keycode));
        if (k) {
                keycode_num = k->id;
        } else {
                /* check if it's a numeric code already */
                keycode_num = strtoul(keycode, &endptr, 0);
                if (endptr[0] !='\0')
                        return log_device_error_errno(dev, SYNTHETIC_ERRNO(EINVAL), "Failed to parse key identifier '%s'", keycode);
        }

        map.scan = scancode;
        map.key = keycode_num;

        log_device_debug(dev, "keyboard: mapping scan code %d (0x%x) to key code %d (0x%x)",
                         map.scan, map.scan, map.key, map.key);

        if (ioctl(fd, EVIOCSKEYCODE, &map) < 0)
                return log_device_error_errno(dev, errno, "Failed to call EVIOCSKEYCODE with scan code 0x%x, and key code %d: %m", map.scan, map.key);

        return 0;
}

static char* parse_token(const char *current, int32_t *val_out) {
        char *next;
        int32_t val;

        if (!current)
                return NULL;

        val = strtol(current, &next, 0);
        if (*next && *next != ':')
                return NULL;

        if (next != current)
                *val_out = val;

        if (*next)
                next++;

        return next;
}

static int override_abs(sd_device *dev, int fd, unsigned evcode, const char *value) {
        struct input_absinfo absinfo;
        char *next;
        int r;

        r = ioctl(fd, EVIOCGABS(evcode), &absinfo);
        if (r < 0)
                return log_device_error_errno(dev, errno, "Failed to call EVIOCGABS");

        next = parse_token(value, &absinfo.minimum);
        next = parse_token(next, &absinfo.maximum);
        next = parse_token(next, &absinfo.resolution);
        next = parse_token(next, &absinfo.fuzz);
        next = parse_token(next, &absinfo.flat);
        if (!next)
                return log_device_error(dev, "Failed to parse EV_ABS override '%s'", value);

        log_device_debug(dev, "keyboard: %x overridden with %"PRIi32"/%"PRIi32"/%"PRIi32"/%"PRIi32"/%"PRIi32,
                         evcode, absinfo.minimum, absinfo.maximum, absinfo.resolution, absinfo.fuzz, absinfo.flat);
        r = ioctl(fd, EVIOCSABS(evcode), &absinfo);
        if (r < 0)
                return log_device_error_errno(dev, errno, "Failed to call EVIOCSABS");

        return 0;
}

static int set_trackpoint_sensitivity(sd_device *dev, const char *value) {
        sd_device *pdev;
        char val_s[DECIMAL_STR_MAX(int)];
        int r, val_i;

        assert(dev);
        assert(value);

        /* The sensitivity sysfs attr belongs to the serio parent device */
        r = sd_device_get_parent_with_subsystem_devtype(dev, "serio", NULL, &pdev);
        if (r < 0)
                return log_device_error_errno(dev, r, "Failed to get serio parent: %m");

        r = safe_atoi(value, &val_i);
        if (r < 0)
                return log_device_error_errno(dev, r, "Failed to parse POINTINGSTICK_SENSITIVITY '%s': %m", value);
        else if (val_i < 0 || val_i > 255)
                return log_device_error_errno(dev, SYNTHETIC_ERRNO(ERANGE), "POINTINGSTICK_SENSITIVITY %d outside range [0..255]", val_i);

        xsprintf(val_s, "%d", val_i);

        r = sd_device_set_sysattr_value(pdev, "sensitivity", val_s);
        if (r < 0)
                return log_device_error_errno(dev, r, "Failed to write 'sensitivity' attribute: %m");

        return 0;
}

static int builtin_keyboard(sd_device *dev, int argc, char *argv[], bool test) {
        unsigned release[1024];
        unsigned release_count = 0;
        _cleanup_close_ int fd = -1;
        const char *node, *key, *value;
        int has_abs = -1, r;

        r = sd_device_get_devname(dev, &node);
        if (r < 0)
                return log_device_error_errno(dev, r, "Failed to get device name: %m");

        FOREACH_DEVICE_PROPERTY(dev, key, value) {
                char *endptr;

                if (startswith(key, "KEYBOARD_KEY_")) {
                        const char *keycode = value;
                        unsigned scancode;

                        /* KEYBOARD_KEY_<hex scan code>=<key identifier string> */
                        scancode = strtoul(key + 13, &endptr, 16);
                        if (endptr[0] != '\0') {
                                log_device_warning(dev, "Failed to parse scan code from \"%s\", ignoring", key);
                                continue;
                        }

                        /* a leading '!' needs a force-release entry */
                        if (keycode[0] == '!') {
                                keycode++;

                                release[release_count] = scancode;
                                if (release_count < ELEMENTSOF(release)-1)
                                        release_count++;

                                if (keycode[0] == '\0')
                                        continue;
                        }

                        if (fd < 0) {
                                fd = open(node, O_RDWR|O_CLOEXEC|O_NONBLOCK|O_NOCTTY);
                                if (fd < 0)
                                        return log_device_error_errno(dev, errno, "Failed to open device '%s': %m", node);
                        }

                        (void) map_keycode(dev, fd, scancode, keycode);
                } else if (startswith(key, "EVDEV_ABS_")) {
                        unsigned evcode;

                        /* EVDEV_ABS_<EV_ABS code>=<min>:<max>:<res>:<fuzz>:<flat> */
                        evcode = strtoul(key + 10, &endptr, 16);
                        if (endptr[0] != '\0') {
                                log_device_warning(dev, "Failed to parse EV_ABS code from \"%s\", ignoring", key);
                                continue;
                        }

                        if (fd < 0) {
                                fd = open(node, O_RDWR|O_CLOEXEC|O_NONBLOCK|O_NOCTTY);
                                if (fd < 0)
                                        return log_device_error_errno(dev, errno, "Failed to open device '%s': %m", node);
                        }

                        if (has_abs == -1) {
                                unsigned long bits;
                                int rc;

                                rc = ioctl(fd, EVIOCGBIT(0, sizeof(bits)), &bits);
                                if (rc < 0)
                                        return log_device_error_errno(dev, errno, "Failed to set EVIOCGBIT");

                                has_abs = !!(bits & (1 << EV_ABS));
                                if (!has_abs)
                                        log_device_warning(dev, "EVDEV_ABS override set but no EV_ABS present on device");
                        }

                        if (!has_abs)
                                continue;

                        (void) override_abs(dev, fd, evcode, value);
                } else if (streq(key, "POINTINGSTICK_SENSITIVITY"))
                        (void) set_trackpoint_sensitivity(dev, value);
        }

        /* install list of force-release codes */
        if (release_count > 0)
                (void) install_force_release(dev, release, release_count);

        return 0;
}

const UdevBuiltin udev_builtin_keyboard = {
        .name = "keyboard",
        .cmd = builtin_keyboard,
        .help = "Keyboard scan code to key mapping",
};
