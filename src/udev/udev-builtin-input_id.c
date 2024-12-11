/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * expose input properties via udev
 *
 * Portions Copyright © 2004 David Zeuthen, <david@fubar.dk>
 * Copyright © 2014 Carlos Garnacho <carlosg@gnome.org>
 */

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <unistd.h>
#include <linux/limits.h>

#include "device-util.h"
#include "fd-util.h"
#include "missing_input.h"
#include "parse-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "udev-builtin.h"

/* we must use this kernel-compatible implementation */
#define BITS_PER_LONG (sizeof(unsigned long) * 8)
#define NBITS(x) ((((x)-1)/BITS_PER_LONG)+1)
#define OFF(x)  ((x)%BITS_PER_LONG)
#define BIT(x)  (1UL<<OFF(x))
#define LONG(x) ((x)/BITS_PER_LONG)
#define test_bit(bit, array)    ((array[LONG(bit)] >> OFF(bit)) & 1)

struct range {
        unsigned start;
        unsigned end;
};

/* key code ranges above BTN_MISC (start is inclusive, stop is exclusive) */
static const struct range high_key_blocks[] = {
        { KEY_OK, BTN_DPAD_UP },
        { KEY_ALS_TOGGLE, BTN_TRIGGER_HAPPY }
};

static int abs_size_mm(const struct input_absinfo *absinfo) {
        /* Resolution is defined to be in units/mm for ABS_X/Y */
        return (absinfo->maximum - absinfo->minimum) / absinfo->resolution;
}

static void extract_info(UdevEvent *event) {
        char width[DECIMAL_STR_MAX(int)], height[DECIMAL_STR_MAX(int)];
        struct input_absinfo xabsinfo = {}, yabsinfo = {};
        _cleanup_close_ int fd = -EBADF;

        assert(event);
        assert(event->dev);

        fd = sd_device_open(event->dev, O_RDONLY|O_CLOEXEC|O_NONBLOCK|O_NOCTTY);
        if (fd < 0)
                return;

        if (ioctl(fd, EVIOCGABS(ABS_X), &xabsinfo) < 0 ||
            ioctl(fd, EVIOCGABS(ABS_Y), &yabsinfo) < 0)
                return;

        if (xabsinfo.resolution <= 0 || yabsinfo.resolution <= 0)
                return;

        xsprintf(width, "%d", abs_size_mm(&xabsinfo));
        xsprintf(height, "%d", abs_size_mm(&yabsinfo));

        udev_builtin_add_property(event, "ID_INPUT_WIDTH_MM", width);
        udev_builtin_add_property(event, "ID_INPUT_HEIGHT_MM", height);
}

/*
 * Read a capability attribute and return bitmask.
 * @param dev sd_device
 * @param attr sysfs attribute name (e. g. "capabilities/key")
 * @param bitmask: Output array which has a sizeof of bitmask_size
 */
static void get_cap_mask(
                sd_device *pdev,
                const char *attr,
                unsigned long *bitmask,
                size_t bitmask_size,
                EventMode mode) {

        const char *v;
        char text[4096], *word;
        unsigned i;
        unsigned long val;
        int r;

        if (sd_device_get_sysattr_value(pdev, attr, &v) < 0)
                v = "";

        xsprintf(text, "%s", v);
        log_device_debug(pdev, "%s raw kernel attribute: %s", attr, text);

        memzero(bitmask, bitmask_size);
        i = 0;
        while ((word = strrchr(text, ' '))) {
                r = safe_atolu_full(word+1, 16, &val);
                if (r < 0)
                        log_device_debug_errno(pdev, r, "Ignoring %s block which failed to parse: %m", attr);
                else if (i < bitmask_size / sizeof(unsigned long))
                        bitmask[i] = val;
                else
                        log_device_debug(pdev, "Ignoring %s block %lX which is larger than maximum size", attr, val);
                *word = '\0';
                i++;
        }
        r = safe_atolu_full(text, 16, &val);
        if (r < 0)
                log_device_debug_errno(pdev, r, "Ignoring %s block which failed to parse: %m", attr);
        else if (i < bitmask_size / sizeof(unsigned long))
                bitmask[i] = val;
        else
                log_device_debug(pdev, "Ignoring %s block %lX which is larger than maximum size", attr, val);

        if (mode == EVENT_UDEVADM_TEST_BUILTIN && DEBUG_LOGGING) {
                log_device_debug(pdev, "%s decoded bit map:", attr);

                val = bitmask_size / sizeof (unsigned long);
                /* skip trailing zeros */
                while (bitmask[val-1] == 0 && val > 0)
                        --val;

                /* IN_SET() cannot be used in assert_cc(). */
                assert_cc(sizeof(unsigned long) == 4 || sizeof(unsigned long) == 8);
                for (unsigned long j = 0; j < val; j++)
                        log_device_debug(pdev,
                                         sizeof(unsigned long) == 4 ? "  bit %4lu: %08lX\n" : "  bit %4lu: %016lX\n",
                                         j * BITS_PER_LONG, bitmask[j]);
        }
}

static struct input_id get_input_id(sd_device *dev) {
        const char *v;
        struct input_id id = {};

        if (sd_device_get_sysattr_value(dev, "id/bustype", &v) >= 0)
                (void) safe_atoux16(v, &id.bustype);
        if (sd_device_get_sysattr_value(dev, "id/vendor", &v) >= 0)
                (void) safe_atoux16(v, &id.vendor);
        if (sd_device_get_sysattr_value(dev, "id/product", &v) >= 0)
                (void) safe_atoux16(v, &id.product);
        if (sd_device_get_sysattr_value(dev, "id/version", &v) >= 0)
                (void) safe_atoux16(v, &id.version);

        return id;
}

/* pointer devices */
static bool test_pointers(
                UdevEvent *event,
                const struct input_id *id,
                const unsigned long *bitmask_ev,
                const unsigned long *bitmask_abs,
                const unsigned long *bitmask_key,
                const unsigned long *bitmask_rel,
                const unsigned long *bitmask_props) {

        sd_device *dev = ASSERT_PTR(ASSERT_PTR(event)->dev);
        size_t num_joystick_axes = 0, num_joystick_buttons = 0;
        bool has_abs_coordinates = false,
                has_rel_coordinates = false,
                has_mt_coordinates = false,
                has_pad_buttons = false,
                is_direct = false,
                has_touch = false,
                has_3d_coordinates = false,
                has_keys = false,
                has_stylus = false,
                has_pen = false,
                finger_but_no_pen = false,
                has_mouse_button = false,
                is_mouse = false,
                is_abs_mouse = false,
                is_touchpad = false,
                is_touchscreen = false,
                is_tablet = false,
                is_tablet_pad = false,
                is_joystick = false,
                is_accelerometer = false,
                is_pointing_stick = false,
                has_wheel = false;

        has_keys = test_bit(EV_KEY, bitmask_ev);
        has_abs_coordinates = test_bit(ABS_X, bitmask_abs) && test_bit(ABS_Y, bitmask_abs);
        has_3d_coordinates = has_abs_coordinates && test_bit(ABS_Z, bitmask_abs);
        is_accelerometer = test_bit(INPUT_PROP_ACCELEROMETER, bitmask_props);

        if (!has_keys && has_3d_coordinates)
                is_accelerometer = true;

        if (is_accelerometer) {
                udev_builtin_add_property(event, "ID_INPUT_ACCELEROMETER", "1");
                return true;
        }

        is_pointing_stick = test_bit(INPUT_PROP_POINTING_STICK, bitmask_props);
        has_stylus = test_bit(BTN_STYLUS, bitmask_key);
        has_pen = test_bit(BTN_TOOL_PEN, bitmask_key);
        finger_but_no_pen = test_bit(BTN_TOOL_FINGER, bitmask_key) && !test_bit(BTN_TOOL_PEN, bitmask_key);
        for (int button = BTN_MOUSE; button < BTN_JOYSTICK && !has_mouse_button; button++)
                has_mouse_button = test_bit(button, bitmask_key);
        has_rel_coordinates = test_bit(EV_REL, bitmask_ev) && test_bit(REL_X, bitmask_rel) && test_bit(REL_Y, bitmask_rel);
        has_mt_coordinates = test_bit(ABS_MT_POSITION_X, bitmask_abs) && test_bit(ABS_MT_POSITION_Y, bitmask_abs);

        /* unset has_mt_coordinates if devices claims to have all abs axis */
        if (has_mt_coordinates && test_bit(ABS_MT_SLOT, bitmask_abs) && test_bit(ABS_MT_SLOT - 1, bitmask_abs))
                has_mt_coordinates = false;
        is_direct = test_bit(INPUT_PROP_DIRECT, bitmask_props);
        has_touch = test_bit(BTN_TOUCH, bitmask_key);
        has_pad_buttons = test_bit(BTN_0, bitmask_key) && test_bit(BTN_1, bitmask_key) && !has_pen;
        has_wheel = test_bit(EV_REL, bitmask_ev) && (test_bit(REL_WHEEL, bitmask_rel) || test_bit(REL_HWHEEL, bitmask_rel));

        /* joysticks don't necessarily have buttons; e. g.
         * rudders/pedals are joystick-like, but buttonless; they have
         * other fancy axes. Others have buttons only but no axes.
         *
         * The BTN_JOYSTICK range starts after the mouse range, so a mouse
         * with more than 16 buttons runs into the joystick range (e.g. Mad
         * Catz Mad Catz M.M.O.TE). Skip those.
         */
        if (!test_bit(BTN_JOYSTICK - 1, bitmask_key)) {
                for (int button = BTN_JOYSTICK; button < BTN_DIGI; button++)
                        if (test_bit(button, bitmask_key))
                                num_joystick_buttons++;
                for (int button = BTN_TRIGGER_HAPPY1; button <= BTN_TRIGGER_HAPPY40; button++)
                        if (test_bit(button, bitmask_key))
                                num_joystick_buttons++;
                for (int button = BTN_DPAD_UP; button <= BTN_DPAD_RIGHT; button++)
                        if (test_bit(button, bitmask_key))
                                num_joystick_buttons++;
        }
        for (int axis = ABS_RX; axis < ABS_PRESSURE; axis++)
                if (test_bit(axis, bitmask_abs))
                        num_joystick_axes++;

        if (has_abs_coordinates) {
                if (has_stylus || has_pen)
                        is_tablet = true;
                else if (finger_but_no_pen && !is_direct)
                        is_touchpad = true;
                else if (has_mouse_button)
                        /* This path is taken by VMware's USB mouse, which has
                         * absolute axes, but no touch/pressure button. */
                        is_abs_mouse = true;
                else if (has_touch || is_direct)
                        is_touchscreen = true;
                else if (num_joystick_buttons > 0 || num_joystick_axes > 0)
                        is_joystick = true;
        } else if (num_joystick_buttons > 0 || num_joystick_axes > 0)
                is_joystick = true;

        if (has_mt_coordinates) {
                if (has_stylus || has_pen)
                        is_tablet = true;
                else if (finger_but_no_pen && !is_direct)
                        is_touchpad = true;
                else if (has_touch || is_direct)
                        is_touchscreen = true;
        }

        if (is_tablet && has_pad_buttons)
                is_tablet_pad = true;

        if (has_pad_buttons && has_wheel && !has_rel_coordinates) {
                is_tablet = true;
                is_tablet_pad = true;
        }

        if (!is_tablet && !is_touchpad && !is_joystick &&
            has_mouse_button &&
            (has_rel_coordinates ||
            !has_abs_coordinates)) /* mouse buttons and no axis */
                is_mouse = true;

        /* There is no such thing as an i2c mouse */
        if (is_mouse && id->bustype == BUS_I2C)
                is_pointing_stick = true;

        /* Joystick un-detection. Some keyboards have random joystick buttons
         * set. Avoid those being labeled as ID_INPUT_JOYSTICK with some heuristics.
         * The well-known keys represent a (randomly picked) set of key groups.
         * A joystick may have one of those but probably not several. And a joystick with less than 2 buttons
         * or axes is not a joystick either.
         * libinput uses similar heuristics, any changes here should be added to libinput too.
         */
        if (is_joystick) {
                static const unsigned int well_known_keyboard_keys[] = {
                        KEY_LEFTCTRL, KEY_CAPSLOCK, KEY_NUMLOCK, KEY_INSERT,
                        KEY_MUTE, KEY_CALC, KEY_FILE, KEY_MAIL, KEY_PLAYPAUSE,
                        KEY_BRIGHTNESSDOWN,
                };
                size_t num_well_known_keys = 0;

                if (has_keys)
                        FOREACH_ELEMENT(key, well_known_keyboard_keys)
                                if (test_bit(*key, bitmask_key))
                                        num_well_known_keys++;

                if (num_well_known_keys >= 4 || num_joystick_buttons + num_joystick_axes < 2) {
                        log_device_debug(dev, "Input device has %zu joystick buttons and %zu axes but also %zu keyboard key sets, "
                                         "assuming this is a keyboard, not a joystick.",
                                         num_joystick_buttons, num_joystick_axes, num_well_known_keys);
                        is_joystick = false;
                }

                if (has_wheel && has_pad_buttons) {
                        log_device_debug(dev, "Input device has %zu joystick buttons as well as tablet pad buttons, "
                                        "assuming this is a tablet pad, not a joystick.", num_joystick_buttons);

                        is_joystick = false;
                }
        }

        if (is_pointing_stick)
                udev_builtin_add_property(event, "ID_INPUT_POINTINGSTICK", "1");
        if (is_mouse || is_abs_mouse)
                udev_builtin_add_property(event, "ID_INPUT_MOUSE", "1");
        if (is_touchpad)
                udev_builtin_add_property(event, "ID_INPUT_TOUCHPAD", "1");
        if (is_touchscreen)
                udev_builtin_add_property(event, "ID_INPUT_TOUCHSCREEN", "1");
        if (is_joystick)
                udev_builtin_add_property(event, "ID_INPUT_JOYSTICK", "1");
        if (is_tablet)
                udev_builtin_add_property(event, "ID_INPUT_TABLET", "1");
        if (is_tablet_pad)
                udev_builtin_add_property(event, "ID_INPUT_TABLET_PAD", "1");

        return is_tablet || is_mouse || is_abs_mouse || is_touchpad || is_touchscreen || is_joystick || is_pointing_stick;
}

/* key like devices */
static bool test_key(
                UdevEvent *event,
                const unsigned long *bitmask_ev,
                const unsigned long *bitmask_key) {

        sd_device *dev = ASSERT_PTR(ASSERT_PTR(event)->dev);
        bool found = false;

        /* do we have any KEY_* capability? */
        if (!test_bit(EV_KEY, bitmask_ev)) {
                log_device_debug(dev, "test_key: no EV_KEY capability");
                return false;
        }

        /* only consider KEY_* here, not BTN_* */
        for (size_t i = 0; i < BTN_MISC/BITS_PER_LONG && !found; i++) {
                if (bitmask_key[i])
                        found = true;

                log_device_debug(dev, "test_key: checking bit block %zu for any keys; found=%s",
                                 i * BITS_PER_LONG, yes_no(found));
        }
        /* If there are no keys in the lower block, check the higher blocks */
        for (size_t block = 0; block < ELEMENTSOF(high_key_blocks) && !found; block++)
                for (unsigned i = high_key_blocks[block].start; i < high_key_blocks[block].end && !found; i++)
                        if (test_bit(i, bitmask_key)) {
                                log_device_debug(dev, "test_key: Found key %x in high block", i);
                                found = true;
                        }

        if (found)
                udev_builtin_add_property(event, "ID_INPUT_KEY", "1");

        /* the first 32 bits are ESC, numbers, and Q to D; if we have all of
         * those, consider it a full keyboard; do not test KEY_RESERVED, though */
        if (FLAGS_SET(bitmask_key[0], 0xFFFFFFFE)) {
                udev_builtin_add_property(event, "ID_INPUT_KEYBOARD", "1");
                return true;
        }

        return found;
}

static int builtin_input_id(UdevEvent *event, int argc, char *argv[]) {
        sd_device *pdev, *dev = ASSERT_PTR(ASSERT_PTR(event)->dev);
        unsigned long bitmask_ev[NBITS(EV_MAX)],
                bitmask_abs[NBITS(ABS_MAX)],
                bitmask_key[NBITS(KEY_MAX)],
                bitmask_rel[NBITS(REL_MAX)],
                bitmask_props[NBITS(INPUT_PROP_MAX)];
        const char *sysname;
        bool is_pointer, is_key;

        /* walk up the parental chain until we find the real input device; the
         * argument is very likely a subdevice of this, like eventN */
        for (pdev = dev; pdev; ) {
                const char *s;

                if (sd_device_get_sysattr_value(pdev, "capabilities/ev", &s) >= 0)
                        break;

                if (sd_device_get_parent_with_subsystem_devtype(pdev, "input", NULL, &pdev) >= 0)
                        continue;

                pdev = NULL;
                break;
        }

        if (pdev) {
                struct input_id id = get_input_id(pdev);

                /* Use this as a flag that input devices were detected, so that this
                 * program doesn't need to be called more than once per device */
                udev_builtin_add_property(event, "ID_INPUT", "1");
                get_cap_mask(pdev, "capabilities/ev", bitmask_ev, sizeof(bitmask_ev), event->event_mode);
                get_cap_mask(pdev, "capabilities/abs", bitmask_abs, sizeof(bitmask_abs), event->event_mode);
                get_cap_mask(pdev, "capabilities/rel", bitmask_rel, sizeof(bitmask_rel), event->event_mode);
                get_cap_mask(pdev, "capabilities/key", bitmask_key, sizeof(bitmask_key), event->event_mode);
                get_cap_mask(pdev, "properties", bitmask_props, sizeof(bitmask_props), event->event_mode);
                is_pointer = test_pointers(event, &id, bitmask_ev, bitmask_abs,
                                           bitmask_key, bitmask_rel,
                                           bitmask_props);
                is_key = test_key(event, bitmask_ev, bitmask_key);
                /* Some evdev nodes have only a scrollwheel */
                if (!is_pointer && !is_key && test_bit(EV_REL, bitmask_ev) &&
                    (test_bit(REL_WHEEL, bitmask_rel) || test_bit(REL_HWHEEL, bitmask_rel)))
                        udev_builtin_add_property(event, "ID_INPUT_KEY", "1");
                if (test_bit(EV_SW, bitmask_ev))
                        udev_builtin_add_property(event, "ID_INPUT_SWITCH", "1");
        }

        if (sd_device_get_sysname(dev, &sysname) >= 0 &&
            startswith(sysname, "event"))
                extract_info(event);

        return 0;
}

const UdevBuiltin udev_builtin_input_id = {
        .name = "input_id",
        .cmd = builtin_input_id,
        .help = "Input device properties",
};
