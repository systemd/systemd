/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <sys/file.h>

#include "alloc-util.h"
#include "blockdev-util.h"
#include "device-util.h"
#include "dissect-image.h"
#include "errno-util.h"
#include "hexdecoct.h"
#include "image-policy.h"
#include "initrd-util.h"
#include "loop-util.h"
#include "proc-cmdline.h"
#include "string-util.h"
#include "strv.h"
#include "udev-builtin.h"

static ImagePolicy *arg_image_policy = NULL;
static VeritySettings arg_verity_settings = VERITY_SETTINGS_DEFAULT;
static ImageFilter *arg_image_filter = NULL;

static int acquire_image_policy(ImagePolicy **ret) {
        int r;

        assert(ret);

        _cleanup_free_ char *value = NULL;
        r = proc_cmdline_get_key("systemd.image_policy", /* flags= */ 0, &value);
        if (r < 0)
                return log_error_errno(r, "Failed to read systemd.image_policy= kernel command line switch: %m");
        if (r == 0) {
                *ret = NULL;
                return 0;
        }

        r = image_policy_from_string(value, /* graceful= */ false, ret);
        if (r < 0)
                return log_error_errno(r, "Failed to parse image policy '%s': %m", value);

        if (DEBUG_LOGGING) {
                _cleanup_free_ char *s = NULL;

                (void) image_policy_to_string(*ret, /* simplify= */ true, &s);
                log_debug("Loaded image policy: %s", strna(s));
        }

        return 1;
}

static int acquire_verity_settings(VeritySettings *ret) {
        _cleanup_(verity_settings_done) VeritySettings verity = VERITY_SETTINGS_DEFAULT;
        int r;

        assert(ret);

        _cleanup_free_ char *h = NULL;
        r = proc_cmdline_get_key("roothash", /* flags= */ 0, &h);
        if (r < 0)
                return log_error_errno(r, "Failed to read roothash= kernel command line switch: %m");
        if (r > 0)
                verity.designator = PARTITION_ROOT;

        _cleanup_free_ char *uh = NULL;
        r = proc_cmdline_get_key("usrhash", /* flags= */ 0, &uh);
        if (r < 0)
                return log_error_errno(r, "Failed to read usrhash= kernel command line switch: %m");
        if (r > 0) {
                if (h)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Both roothash= and usrhash= specified, refusing.");

                h = TAKE_PTR(uh);
                verity.designator = PARTITION_USR;
        }

        if (h) {
                r = unhexmem(h, &verity.root_hash, &verity.root_hash_size);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse root hash from kernel command line switch: %m");
        }

        *ret = TAKE_GENERIC(verity, VeritySettings, VERITY_SETTINGS_DEFAULT);
        return 0;
}

static int acquire_image_filter(ImageFilter **ret) {
        int r;

        assert(ret);

        _cleanup_free_ char *value = NULL;
        r = proc_cmdline_get_key("systemd.image_filter", /* flags= */ 0, &value);
        if (r < 0)
                return log_error_errno(r, "Failed to read systemd.image_filter= kernel command line switch: %m");
        if (r == 0) {
                *ret = NULL;
                return 0;
        }

        r = image_filter_parse(value, ret);
        if (r < 0)
                return log_error_errno(r, "Failed to parse image filter '%s': %m", value);

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
        if (block_device_is_whole_disk(dev) <= 0) {
                log_device_debug(dev, "Must be invoked on whole block device (was invoked in '%s), ignoring.", devnode);
                return 0;
        }

        uint64_t diskseq;
        r = sd_device_get_diskseq(dev, &diskseq);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to get diskseq of '%s': %m", devnode);

        r = blockdev_partscan_enabled(dev);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to determine if block device '%s' supports partitions: %m", devnode);
        if (r == 0) {
                log_device_debug(dev, "Invoked on block device '%s' that lacks partition scanning, ignoring.", devnode);
                return 0;
        }

        _cleanup_(loop_device_unrefp) LoopDevice *loop = NULL;
        r = loop_device_open(dev, O_RDONLY, LOCK_SH, &loop);
        if (ERRNO_IS_NEG_DEVICE_ABSENT(r)) {
                log_device_debug(dev, "Device absent while opening block device '%s', ignoring.", devnode);
                return 0;
        }
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to open block device '%s: %m", devnode);

        const ImagePolicy *image_policy = arg_image_policy ?: &image_policy_host;
        _cleanup_(dissected_image_unrefp) DissectedImage *image = NULL;
        r = dissect_loop_device(
                        loop,
                        &arg_verity_settings,
                        /* mount_options= */ NULL,
                        image_policy,
                        arg_image_filter,
                        DISSECT_IMAGE_READ_ONLY|
                        DISSECT_IMAGE_GPT_ONLY|
                        DISSECT_IMAGE_USR_NO_ROOT|
                        DISSECT_IMAGE_ALLOW_EMPTY,
                        &image);
        if (r == -ERFKILL && !in_initrd()) {
                /* If we transitioned into the main system and we couldn't dissect the image with the full
                 * policy, let's see if it works if we set the policies for /usr/ and the root fs out of the
                 * policy. After all, we already made our choices, there's no point in insisting on the
                 * policy here. */

                static const PartitionDesignator ignore_designators[] = {
                        PARTITION_ROOT,
                        PARTITION_ROOT_VERITY,
                        PARTITION_ROOT_VERITY_SIG,
                        PARTITION_USR,
                        PARTITION_USR_VERITY,
                        PARTITION_USR_VERITY_SIG,
                };

                _cleanup_(image_policy_freep) ImagePolicy *image_policy_mangled = NULL;
                r = image_policy_ignore_designators(
                                image_policy,
                                ignore_designators,
                                ELEMENTSOF(ignore_designators),
                                &image_policy_mangled);
                if (r < 0)
                        return log_device_debug_errno(dev, r, "Failed to remove root/usr partitions from image policy: %m");

                if (image_policy_equal(image_policy, image_policy_mangled))
                        r = -ERFKILL; /* restore original error, if this didn't change anything */
                else {
                        if (DEBUG_LOGGING) {
                                _cleanup_free_ char *a = NULL, *b = NULL;

                                (void) image_policy_to_string(image_policy, /* simplify= */ false, &a);
                                (void) image_policy_to_string(image_policy_mangled, /* simplify= */ false, &b);

                                log_device_debug_errno(dev, ERFKILL, "Couldn't dissect block device with regular policy '%s', retrying with policy where root/usr are set to ignore '%s'.", a, b);
                        }

                        r = dissect_loop_device(
                                        loop,
                                        &arg_verity_settings,
                                        /* mount_options= */ NULL,
                                        image_policy_mangled,
                                        arg_image_filter,
                                        DISSECT_IMAGE_READ_ONLY|
                                        DISSECT_IMAGE_GPT_ONLY|
                                        DISSECT_IMAGE_USR_NO_ROOT|
                                        DISSECT_IMAGE_ALLOW_EMPTY,
                                        &image);
                }
        }
        if (IN_SET(r, -ENOPKG, -ENOMSG, -ENXIO, -ENOTUNIQ)) {
                log_device_debug_errno(dev, r, "Device does not carry a GPT disk label with suitable partitions, ignoring.");
                return 0;
        }
        if (r == -ERFKILL) {
                log_device_debug_errno(dev, r, "Device carries GPT disk label that doesn't match our image policy, ignoring.");
                return 0;
        }
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to dissect disk image: %m");

        /* Let's try to load verity data from the image now, so that we can attach it to the device via udev
         * properties */
        _cleanup_(verity_settings_done) VeritySettings verity = VERITY_SETTINGS_DEFAULT;
        r = verity_settings_copy(&verity, &arg_verity_settings);
        if (r < 0)
                return r;

        r = dissected_image_load_verity_sig_partition(image, loop->fd, &verity);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to load verity signature data from image: %m");

        r = dissected_image_guess_verity_roothash(image, &verity);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to guess root hash from image: %m");

        /* Marker that we determined this to be a suitable image */
        (void) udev_builtin_add_property(event, "ID_DISSECT_IMAGE", "1");

        /* Output the primary architecture this image is intended for */
        Architecture a = dissected_image_architecture(image);
        if (a >= 0)
                (void) udev_builtin_add_property(event, "ID_DISSECT_IMAGE_ARCHITECTURE", architecture_to_string(a));

        /* And now output the intended designator and architecture (if it applies) for all partitions we
         * found and think belong to this system */
        FOREACH_ELEMENT(p, image->partitions) {
                PartitionDesignator d = p - image->partitions;
                if (!p->found)
                        continue;

                assert(p->partno > 0);

                /* Indicate designator for partition */
                _cleanup_free_ char *df = NULL;
                if (asprintf(&df, "ID_DISSECT_PART%i_DESIGNATOR", p->partno) < 0)
                        return log_oom_debug();
                (void) udev_builtin_add_property(event, df, partition_designator_to_string(d));

                if (p->architecture >= 0) {
                        _cleanup_free_ char *f = NULL;
                        if (asprintf(&f, "ID_DISSECT_PART%i_ARCHITECTURE", p->partno) < 0)
                                return log_oom_debug();
                        (void) udev_builtin_add_property(event, f, architecture_to_string(p->architecture));
                }

                /* Indicate whether this partition has verity protection */
                PartitionDesignator dv = partition_verity_of(d);
                if (dv >= 0 && image->partitions[dv].found) {
                        /* Add one property that indicates as a boolean whether Verity is available at all for this */
                        _cleanup_free_ char *f = NULL;
                        if (asprintf(&f, "ID_DISSECT_PART%i_HAS_VERITY", p->partno) < 0)
                                return log_oom_debug();

                        (void) udev_builtin_add_property(event, f, "1");

                        /* Add a second property that indicates where the block device is found with the
                         * Verity data. We maintain this in an independent property, since Verity data might
                         * be available from other sources too, not just block devices, and we'd like to keep
                         * the props somewhat open for that. */
                        f = mfree(f);
                        if (asprintf(&f, "ID_DISSECT_PART%i_VERITY_DEVICE", p->partno) < 0)
                                return log_oom_debug();

                        (void) udev_builtin_add_propertyf(event, f, "/dev/disk/by-diskseq/%" PRIu64 "-part%i", diskseq, image->partitions[dv].partno);
                }

                dv = partition_verity_sig_of(d);
                if (dv >= 0 && image->partitions[dv].found) {
                        _cleanup_free_ char *f = NULL;
                        if (asprintf(&f, "ID_DISSECT_PART%i_HAS_VERITY_SIG", p->partno) < 0)
                                return log_oom_debug();

                        (void) udev_builtin_add_property(event, f, "1");

                        f = mfree(f);
                        if (asprintf(&f, "ID_DISSECT_PART%i_VERITY_SIG_DEVICE", p->partno) < 0)
                                return log_oom_debug();

                        (void) udev_builtin_add_propertyf(event, f, "/dev/disk/by-diskseq/%" PRIu64 "-part%i", diskseq, image->partitions[dv].partno);
                }

                if (d == verity.designator) {
                        if (verity.root_hash_size > 0) {
                                _cleanup_free_ char *f = NULL;
                                if (asprintf(&f, "ID_DISSECT_PART%i_ROOTHASH", p->partno) < 0)
                                        return log_oom_debug();

                                _cleanup_free_ char *h = hexmem(verity.root_hash, verity.root_hash_size);
                                if (!h)
                                        return log_oom_debug();

                                (void) udev_builtin_add_property(event, f, h);
                        }

                        if (verity.root_hash_sig_size > 0) {
                                _cleanup_free_ char *f = NULL;
                                if (asprintf(&f, "ID_DISSECT_PART%i_ROOTHASH_SIG", p->partno) < 0)
                                        return log_oom_debug();

                                _cleanup_free_ char *h = NULL;
                                if (base64mem(verity.root_hash_sig, verity.root_hash_sig_size, &h) < 0)
                                        return log_oom_debug();

                                (void) udev_builtin_add_property(event, f, h);
                        }
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

        r = device_is_subsystem_devtype(dev, "block", "partition");
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to check if the device '%s' is a partition, refusing: %m", devnode);
        if (r == 0)
                return log_device_debug_errno(dev, SYNTHETIC_ERRNO(EINVAL), "Invoked on non-partition device '%s', refusing.", devnode);

        sd_device *parent;
        r = sd_device_get_parent(dev, &parent);
        if (r < 0)
                return log_error_errno(r, "Failed to get parent of device '%s': %m", devnode);

        r = device_is_subsystem_devtype(parent, "block", "disk");
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to check if the parent of block device '%s' is a whole block device, refusing: %m", devnode);
        if (r == 0)
                return log_device_debug_errno(dev, SYNTHETIC_ERRNO(EINVAL), "Parent of block device '%s' is not a whole block device, refusing.", devnode);

        const char *partn;
        r = sd_device_get_property_value(dev, "PARTN", &partn);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to get partition number of partition block device '%s': %m", devnode);

        FOREACH_STRING(f,
                       "_DESIGNATOR", "_ARCHITECTURE",
                       "_HAS_VERITY", "_HAS_VERITY_SIG",
                       "_ROOTHASH", "_ROOTHASH_SIG",
                       "_VERITY_DEVICE", "_VERITY_SIG_DEVICE") {

                /* The property on the parent device contains the partition number */
                _cleanup_free_ char *p = strjoin("ID_DISSECT_PART", partn, f);
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
                                dev, SYNTHETIC_ERRNO(EINVAL), "%s: expected single argument.", argv[0]);

        if (streq(argv[1], "probe"))
                return verb_probe(event, dev);
        if (streq(argv[1], "copy"))
                return verb_copy(event, dev);

        return log_device_warning_errno(
                        dev, SYNTHETIC_ERRNO(EINVAL), "%s: unknown verb '%s'", argv[0], argv[1]);
}

static int builtin_dissect_image_init(void) {
        int r;

        r = acquire_image_policy(&arg_image_policy);
        if (r < 0)
                return r;

        r = acquire_verity_settings(&arg_verity_settings);
        if (r < 0)
                return r;

        r = acquire_image_filter(&arg_image_filter);
        if (r < 0)
                return r;

        return 0;
}

static void builtin_dissect_image_exit(void) {
        arg_image_policy = image_policy_free(arg_image_policy);
        verity_settings_done(&arg_verity_settings);
        arg_image_filter = image_filter_free(arg_image_filter);
}

const UdevBuiltin udev_builtin_dissect_image = {
        .name = "dissect_image",
        .cmd = builtin_dissect_image,
        .init = builtin_dissect_image_init,
        .exit = builtin_dissect_image_exit,
        .help = "Dissect Disk Images",
        .run_once = true,
};
