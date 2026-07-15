/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <linux/dm-ioctl.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#include "sd-device.h"

#include "clonesetup-ioctl.h"
#include "device-private.h"
#include "errno-util.h"
#include "fd-util.h"
#include "log.h"
#include "memory-util.h"
#include "string-util.h"

/* Returns the size in bytes of the block device at dev_path.
 * Loading the dm-clone table needs the source device size in sectors; sysfs
 * reports size in 512-byte sectors. This reads sysfs and returns bytes so the
 * caller can divide by 512 and pass the sector count to dm_clone_load_table(). */
static int get_size(const char *dev_path, uint64_t *ret_size) {
        _cleanup_(sd_device_unrefp) sd_device *dev = NULL;
        uint64_t size, temp_size;
        int r;

        assert(dev_path);
        assert(ret_size);

        r = sd_device_new_from_devname(&dev, dev_path);
        if (r < 0)
                return log_error_errno(r, "Failed to create device from '%s': %m", dev_path);

        r = device_get_sysattr_u64(dev, "size", &size);
        if (r < 0)
                return log_error_errno(r, "Failed to get device size for '%s': %m", dev_path);

        /* sysfs 'size' is in 512-byte sectors */
        temp_size = u64_multiply_safe(size, 512);
        if (temp_size == 0 && size != 0)
                return log_error_errno(SYNTHETIC_ERRNO(EOVERFLOW),
                               "Device size overflow for '%s'", dev_path);

        *ret_size = temp_size;
        return 0;
}

/* Common helper used to run dm ioctls. */
static int dm_ioctl_run(const char *name, uint32_t cmd, struct dm_ioctl *data, size_t data_size) {
        _cleanup_close_ int fd = -EBADF;
        struct dm_ioctl *dm = data;
        int r;

        assert(name);
        assert(data);
        assert(data_size >= sizeof(struct dm_ioctl));

        dm->version[0] = DM_VERSION_MAJOR;
        dm->version[1] = DM_VERSION_MINOR;
        dm->version[2] = DM_VERSION_PATCHLEVEL;
        dm->data_size = data_size;

        if (strlen(name) >= sizeof_field(struct dm_ioctl, name))
                return log_error_errno(SYNTHETIC_ERRNO(ENAMETOOLONG),
                               "DM device name too long: %s", name);
        strncpy_exact(dm->name, name, sizeof(dm->name));

        fd = open("/dev/mapper/control", O_RDWR | O_CLOEXEC);
        if (fd < 0)
                return log_error_errno(errno, "Failed to open /dev/mapper/control: %m");

        r = RET_NERRNO(ioctl(fd, cmd, dm));
        if (r < 0) {
                if (r == -ENXIO && cmd == DM_DEV_REMOVE) {
                        log_full_errno(LOG_DEBUG, r, "Device \"%s\" is already inactive, ignoring: %m", dm->name);
                        return 0;
                }
                return log_error_errno(r, "DM ioctl failed: %m");
        }
        return 0;
}

/* First dm ioctl needed to create a device. */
static int dm_clone_create(const char *name) {
        int r;
        assert(name);

        struct dm_ioctl dm = {};
        r = dm_ioctl_run(name, DM_DEV_CREATE, &dm, sizeof(dm));
        if (r < 0) {
                if (r == -EEXIST)
                        return log_error_errno(r, "Device '/dev/mapper/%s' already exists.", name);
                return log_error_errno(r, "Failed to create DM device '%s': %m", name);
        }
        return 0;
}

/* Second dm ioctl needed to create a device. */
static int dm_clone_load_table(const char *name, uint64_t size_sectors, const char *target_params) {
        char *params_buf;
        size_t params_len, target_size, dm_size;
        _cleanup_free_ struct dm_ioctl *dm = NULL;
        struct dm_target_spec *tgt;

        assert(name);
        assert(target_params);

        params_len = strlen(target_params);
        target_size = sizeof(struct dm_target_spec);
        if (!ADD_SAFE(&params_len, params_len, 1) ||
            !ADD_SAFE(&target_size, target_size, params_len))
                return log_error_errno(SYNTHETIC_ERRNO(EOVERFLOW), "DM target parameters too long.");

        /* ensure that dm_size is always aligned, so it makes the buffer actually match what .next claims */
        target_size = ALIGN8(target_size);
        dm_size = ALIGN8(sizeof(struct dm_ioctl));
        if (target_size == SIZE_MAX ||
            !ADD_SAFE(&dm_size, dm_size, target_size) ||
            dm_size > UINT32_MAX)
                return log_error_errno(SYNTHETIC_ERRNO(EOVERFLOW), "DM target parameters too long.");

        dm = malloc0(dm_size);
        if (!dm)
                return log_oom();
        *dm = (struct dm_ioctl) {
                .data_start = ALIGN8(sizeof(struct dm_ioctl)),
                .target_count = 1,
        };

        tgt = CAST_ALIGN_PTR(struct dm_target_spec, (uint8_t *) dm + dm->data_start);
        *tgt = (struct dm_target_spec) {
                .length = size_sectors,
                /* Per linux/dm-ioctl.h: next is the byte offset from this dm_target_spec to the next one,
                 * rounded up to 8-byte alignment. With target_count == 1 next == 0 works, but set it
                 * correctly to avoid silent breakage if a second target is ever added. */
                .next = target_size,
        };
        strncpy(tgt->target_type, "clone", sizeof(tgt->target_type));

        params_buf = (char *) tgt + ALIGN8(sizeof(struct dm_target_spec));
        memcpy(params_buf, target_params, params_len);

        return dm_ioctl_run(name, DM_TABLE_LOAD, dm, dm_size);
}

/* Third and final dm ioctl needed to create a device. */
static int dm_clone_activate(const char *name) {
        assert(name);

        struct dm_ioctl dm = {};

        return dm_ioctl_run(name, DM_DEV_SUSPEND, &dm, sizeof(dm));
}

/* Calls multiple dm ioctls to create device. */
int dm_clone_create_device(
                const char *name,
                const char *source_dev,
                const char *dest_dev,
                const char *metadata_dev,
                uint64_t region_size_bytes) {

        _cleanup_free_ char *target_params = NULL;
        uint64_t src_dev_size_sectors, src_dev_size, region_size_sectors;
        int r;

        assert(name);
        assert(source_dev);
        assert(dest_dev);
        assert(metadata_dev);

        r = get_size(source_dev, &src_dev_size);
        if (r < 0)
                return r;

        /* The device mapper kernel API always uses 512-byte sectors, regardless of the
         * physical block size of the device (all DM targets use sector_t which is 512B).
         *
         * get_size internally uses sysfs i.e. /sys/block/<disk>/size which also reports device size in
         * 512-byte sectors. Before returning, get_size multiplies the size returned by sysfs to bytes. So we
         * divide the received byte size by 512 to get the sector count for the DM table. */
        assert(src_dev_size % 512 == 0);
        src_dev_size_sectors = src_dev_size / 512;

        assert(region_size_bytes % 512 == 0);
        region_size_sectors = region_size_bytes / 512;

        /* dm-clone target params: <metadata_dev> <dest_dev> <source_dev> <region_size> <hydration_threshold> [options]
         *   region_size = region size in sectors, configurable via clonetab (default 8 = 4KB regions with
         *   512-byte sectors) 1 = hydration threshold (regions to hydrate per batch) no_hydration = don't
         *   start automatic background hydration
         *
         * The DM table "target_params" string is passed directly to the kernel via ioctl(fd, DM_TABLE_LOAD,
         * ...) in dm_clone_load_table as a raw byte buffer. The kernel's DM table parser
         * (drivers/md/dm-table.c) simply splits the params string on whitespace, so the only constraint is
         * that the paths in params - metadata_dev, dest_dev, source_dev, and region_size must not contain
         * spaces, which standard /dev/ paths never do, so the below args do NOT require shell escaping */
        if (asprintf(&target_params, "%s %s %s %" PRIu64 " 1 no_hydration",
                                metadata_dev, dest_dev, source_dev, region_size_sectors) < 0)
                return log_oom();

        r = dm_clone_create(name);
        if (r < 0)
                return r;

        r = dm_clone_load_table(name, src_dev_size_sectors, target_params);
        if (r < 0)
                goto fail;

        r = dm_clone_activate(name);
        if (r < 0)
                goto fail;

        log_info("Device %s active.", name);
        return 0;

fail:
        (void) dm_clone_remove_device_deferred(name);
        return r;
}

/* Calls dm ioctl to send a message to the device. dm_ioctl is the kernel's generic device mapper envelope —
 * every ioctl needs it. dm_target_msg is specific to the "send a message" operation
 * */
int dm_clone_send_message(const char *name, const char *message) {
        _cleanup_free_ struct dm_ioctl *dm = NULL;
        struct dm_target_msg *msg;
        size_t dm_size, msg_len;

        assert(name);
        assert(message);

        msg_len = strlen(message);
        /* need to take into account both headers in size calculation */
        dm_size = ALIGN8(sizeof(struct dm_ioctl));
        if (!ADD_SAFE(&msg_len, msg_len, 1) ||
            !ADD_SAFE(&dm_size, dm_size, sizeof(struct dm_target_msg)) ||
            !ADD_SAFE(&dm_size, dm_size, msg_len))
                return log_error_errno(SYNTHETIC_ERRNO(EOVERFLOW), "DM target message too long.");

        dm = malloc0(dm_size);
        if (!dm)
                return log_oom();
        *dm = (struct dm_ioctl) {
                /* with ALIGN8 call below, dm_target_msg starts at ALIGN8(sizeof(struct dm_ioctl)) which is
                 * already aligned, so the dm_target_msg struct lands correctly */
                .data_start = ALIGN8(sizeof(struct dm_ioctl)),
        };

        msg = CAST_ALIGN_PTR(struct dm_target_msg, (uint8_t *) dm + dm->data_start);
        memcpy(msg->message, message, msg_len);

        return dm_ioctl_run(name, DM_TARGET_MSG, dm, dm_size);
}

/* Calls dm ioctl to remove a device. flags if set can be used
 * for deferred remove - e.g. DM_DEFERRED_REMOVE */
static int dm_clone_remove_device_full(const char *name, uint32_t flags) {
        struct dm_ioctl dm = {
                .flags = flags,
        };

        assert(name);

        return dm_ioctl_run(name, DM_DEV_REMOVE, &dm, sizeof(dm));
}

/* Calls dm ioctl to remove a device. */
int dm_clone_remove_device(const char *name) {
        int r;

        assert(name);
        r = dm_clone_remove_device_full(name, 0);
        if (r < 0)
                return r;

        log_info("Device %s inactive.", name);
        return 0;
}

/* Calls dm ioctl for deferred removal i.e. DM_DEFERRED_REMOVE */
int dm_clone_remove_device_deferred(const char *name) {
        int r;

        assert(name);
        r = dm_clone_remove_device_full(name, DM_DEFERRED_REMOVE);
        if (r < 0)
                return r;

        log_info("Device %s marked for deferred removal.", name);
        return 0;
}
