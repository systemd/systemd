/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "device-util.h"
#include "dissect-image.h"
#include "fd-util.h"
#include "image-policy.h"
#include "loop-util.h"
#include "proc-cmdline.h"
#include "udev-builtin.h"

static int acquire_image_policy(ImagePolicy **ret) {
        int r;

        assert(ret);

        _cleanup_free_ char *value = NULL;
        r = proc_cmdline_get_key("systemd.image_policy", /* flags= */ 0, &value);
        if (r < 0)
                return log_debug_errno(r, "Failed to read systemd.image_policy= kernel command line switch: %m");
        if (r == 0) {
                *ret = NULL;
                return 0;
        }

        r = image_policy_from_string(value, ret);
        if (r < 0)
                return log_debug_errno(r, "Failed to parse image policy '%s': %m", value);

        if (DEBUG_LOGGING) {
                _cleanup_free_ char *s = NULL;

                image_policy_to_string(*ret, /* simplify= */ true, &s);
                log_debug("Loaded image policy: %s", strna(s));
        }

        return 1;
}

static int verb_probe(UdevEvent *event, sd_device *dev) {
        int r;

        assert(event);
        assert(dev);

        /* This is invoked on 'main' block devices to probe the partition table. We will generate some
         * properties with general image information, and then a bunch of properties for each partition, with
         * the partition index in the variable name. These fields will be copied into partition block devices
         * when the dissect_image builtin is later called with the "copy" verb, i.e. in verb_copy() below. */

        const char *devnode;
        r = sd_device_get_devname(dev, &devnode);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to get device node: %m");

        if (!device_in_subsystem(dev, "block"))
                return log_device_debug_errno(dev, SYNTHETIC_ERRNO(EINVAL), "Invoked on non-block device '%s', refusing: %m", devnode);
        if (!device_is_devtype(dev, "disk"))
                return log_device_debug_errno(dev, SYNTHETIC_ERRNO(EINVAL), "Invoked on partition block device '%s', refusing: %m", devnode);

        _cleanup_(loop_device_unrefp) LoopDevice *loop = NULL;
        r = loop_device_open(dev, O_RDONLY, LOCK_SH, &loop);
        if (ERRNO_IS_NEG_DEVICE_ABSENT(r)) {
                log_device_debug_errno(dev, r, "Device absent while opening block device '%s', ignoring: %m", devnode);
                return 0;
        }
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to open block device '%s: %m", devnode);

        /* Load image policy from kernel command line, similar to what systemd-gpt-auto-generator does */
        _cleanup_(image_policy_freep) ImagePolicy *image_policy = NULL;
        (void) acquire_image_policy(&image_policy);

        _cleanup_(dissected_image_unrefp) DissectedImage *image = NULL;
        r = dissect_loop_device(
                        loop,
                        /* verity= */ NULL,
                        /* mount_options= */ NULL,
                        image_policy ?: &image_policy_host,
                        DISSECT_IMAGE_READ_ONLY|
                        DISSECT_IMAGE_GPT_ONLY|
                        DISSECT_IMAGE_USR_NO_ROOT|
                        DISSECT_IMAGE_ALLOW_EMPTY,
                        &image);
        if (IN_SET(r, -ENOPKG, -ENOMSG)) {
                log_device_debug_errno(dev, r, "Device does not carry a GPT disk label with suitable partitions, skipping.");
                return 0;
        }
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to dissect disk image: %m");

        /* Marker that we determined this to be a suitable image */
        (void) udev_builtin_add_property(event, "ID_DISSECT_IMAGE", "1");

       /* Output the primary architecture this image is intended for */
        Architecture a = dissected_image_architecture(image);
        if (a >= 0)
                (void) udev_builtin_add_property(event, "ID_DISSECT_IMAGE_ARCHITECTURE", architecture_to_string(a));

        /* And now output the intended designator and architecture (if it applies) for all partitions we
         * found and think belong to this system */
        for (PartitionDesignator i = 0; i < _PARTITION_DESIGNATOR_MAX; i++) {
                const DissectedPartition *p = image->partitions + i;

                if (!p->found)
                        continue;

                assert(p->partno > 0);

                _cleanup_free_ char *df = NULL;
                if (asprintf(&df, "ID_DISSECT_PART%i_DESIGNATOR", p->partno) < 0)
                        return log_oom_debug();

                (void) udev_builtin_add_property(event, df, partition_designator_to_string(i));

                if (p->architecture >= 0) {
                        _cleanup_free_ char *af = NULL;
                        if (asprintf(&af, "ID_DISSECT_PART%i_ARCHITECTURE", p->partno) < 0)
                                return log_oom_debug();

                        (void) udev_builtin_add_property(event, af, architecture_to_string(p->architecture));
                }
        }

        return 0;
}

static int verb_copy(UdevEvent *event, sd_device *dev) {
        int r;

        assert(event);
        assert(dev);

        /* This is called for the partition block devices, and will copy the per-partition properties we
         * probed on the main block device into the partition device */

        const char *devnode;
        r = sd_device_get_devname(dev, &devnode);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to get device node: %m");

        if (!device_in_subsystem(dev, "block"))
                return log_device_debug_errno(dev, SYNTHETIC_ERRNO(EINVAL), "Invoked on non-block device '%s', refusing: %m", devnode);
        if (!device_is_devtype(dev, "partition"))
                return log_device_debug_errno(dev, SYNTHETIC_ERRNO(EINVAL), "Invoked on non-partition block device '%s', refusing: %m", devnode);

        sd_device *parent;
        r = sd_device_get_parent(dev, &parent);
        if (r < 0)
                return log_error_errno(r, "Failed to get parent of device '%s': %m", devnode);

        if (!device_in_subsystem(parent, "block"))
                return log_device_debug_errno(dev, SYNTHETIC_ERRNO(EINVAL), "Parent of block device '%s' is not a block device, refusing: %m", devnode);
        if (!device_is_devtype(parent, "disk"))
                return log_device_debug_errno(dev, SYNTHETIC_ERRNO(EINVAL), "Parent of block device '%s' is not a whole block device, refusing: %m", devnode);

        const char *sysnum;
        r = sd_device_get_sysnum(dev, &sysnum);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to get partition number of partition block device '%s': %m", devnode);

        FOREACH_STRING(f, "_DESIGNATOR", "_ARCHITECTURE") {
                /* The property on the parent device contains the partition number */
                _cleanup_free_ char *p = strjoin("ID_DISSECT_PART", sysnum, f);
                if (!p)
                        return log_oom_debug();

                const char *v;
                r = sd_device_get_property_value(parent, p, &v);
                if (r == -ENOENT)
                        continue;
                if (r < 0)
                        return log_device_debug_errno(dev, r, "Failed to get '%s' property of parent of '%s': %m", p, devnode);

                /* When we copy this property to the partition we drop the partition number, so that we have
                 * a constant field name */
                _cleanup_free_ char *c = strjoin("ID_DISSECT_PART", f);
                if (!c)
                        return log_oom_debug();

                (void) udev_builtin_add_property(event, c, v);
        }

        return 0;
}

static int builtin_dissect_image(UdevEvent *event, int argc, char *argv[]) {
        sd_device *dev = ASSERT_PTR(ASSERT_PTR(event)->dev);

        if (argc != 2)
                return log_device_warning_errno(
                                dev, SYNTHETIC_ERRNO(EINVAL), "%s: expected 'probe' or 'copy', got '%s'.", argv[0], argv[1]);

        if (streq(argv[1], "probe"))
                return verb_probe(event, dev);
        if (streq(argv[1], "copy"))
                return verb_copy(event, dev);

        return log_device_warning_errno(
                        dev, SYNTHETIC_ERRNO(EINVAL), "%s: unknown vern '%s'", argv[0], argv[1]);
}

const UdevBuiltin udev_builtin_dissect_image = {
        .name = "dissect_image",
        .cmd = builtin_dissect_image,
        .help = "Dissect Disk Images",
        .run_once = true,
};
