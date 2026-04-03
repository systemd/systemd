/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <linux/dm-ioctl.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#include "clone-ioctl.h"
#include "device-private.h"
#include "fd-util.h"
#include "log.h"
#include "memory-util.h"         /* memzero() */
#include "sd-device.h"
#include "stdio-util.h"          /* xsprintf() */
#include "string-util.h"

static int get_size(const char *dev_path, uint64_t *ret_size) {
        _cleanup_(sd_device_unrefp) sd_device *dev = NULL;
        uint64_t size;
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
        *ret_size = size * 512;
        return 0;
}

static int dm_ioctl_run(const char *name, uint32_t cmd, struct dm_ioctl *data, size_t data_size) {
        _cleanup_close_ int fd = -EBADF;
        struct dm_ioctl *dm = data;

        assert(name);
        assert(data);
        assert(data_size >= sizeof(struct dm_ioctl));

        dm->version[0] = DM_VERSION_MAJOR;
        dm->version[1] = DM_VERSION_MINOR;
        dm->version[2] = DM_VERSION_PATCHLEVEL;
        dm->data_size = data_size;

        assert(strlen(name) < sizeof_field(struct dm_ioctl, name));
        strncpy_exact(dm->name, name, sizeof(dm->name));

        fd = open("/dev/mapper/control", O_RDWR|O_CLOEXEC);
        if (fd < 0)
                return log_error_errno(errno, "Failed to open /dev/mapper/control: %m");

        if (ioctl(fd, cmd, dm) < 0)
                return log_error_errno(errno, "DM ioctl failed: %m");

        return 0;
}

static int dm_clone_create(const char *name) {
        assert(name);

        struct dm_ioctl dm = {};
        return dm_ioctl_run(name, DM_DEV_CREATE, &dm, sizeof(struct dm_ioctl));
}

static int dm_clone_load_table(const char *name, uint64_t size_sectors, const char *target_params) {
        char *params_buf;
        size_t params_len, dm_size;
        struct dm_ioctl *dm;
        struct dm_target_spec *tgt;

        assert(name);
        assert(target_params);

        params_len = strlen(target_params) + 1;
        dm_size = sizeof(struct dm_ioctl) + sizeof(struct dm_target_spec) + params_len;
        dm = alloca0(dm_size);

        dm->data_start = sizeof(struct dm_ioctl);
        dm->target_count = 1;

        tgt = (struct dm_target_spec *) ((uint8_t *) dm + dm->data_start);
        tgt->sector_start = 0;
        tgt->length = size_sectors;
        strncpy(tgt->target_type, "clone", sizeof(tgt->target_type));
        tgt->next = 0;

        params_buf = (char *) tgt + sizeof(struct dm_target_spec);
        strcpy(params_buf, target_params);
        tgt->status = 0;

        return dm_ioctl_run(name, DM_TABLE_LOAD, dm, dm_size);
}

static int dm_clone_activate(const char *name) {
        assert(name);

        struct dm_ioctl dm = {};

        return dm_ioctl_run(name, DM_DEV_SUSPEND, &dm, sizeof(struct dm_ioctl));
}

int dm_clone_create_device(
                const char *name,
                const char *source_dev,
                const char *dest_dev,
                const char *metadata_dev) {

        uint64_t src_dev_size_sectors, src_dev_size;
        char target_params[256];
        int r;

        assert(name);
        assert(source_dev);
        assert(dest_dev);
        assert(metadata_dev);

        r = get_size(source_dev, &src_dev_size);
        if (r < 0)
                return r;

        src_dev_size_sectors = src_dev_size / 512;

        /* dm-clone target params: <metadata_dev> <dest_dev> <source_dev> <region_size> <hydration_threshold> [options]
         *   8 = region size in sectors (4KB regions with 512-byte sectors)
         *   1 = hydration threshold (regions to hydrate per batch)
         *   no_hydration = don't start automatic background hydration */
        xsprintf(target_params, "%s %s %s 8 1 no_hydration", metadata_dev, dest_dev, source_dev);

        r = dm_clone_create(name);
        if (r < 0)
                return r;

        r = dm_clone_load_table(name, src_dev_size_sectors, target_params);
        if (r < 0)
                return r;

        r = dm_clone_activate(name);
        if (r < 0)
                return r;

        return 0;
}

int dm_clone_send_message(const char *name, const char *message) {
        struct dm_ioctl *dm;
        struct dm_target_msg *msg;
        size_t dm_size, msg_len;

        assert(name);
        assert(message);

        msg_len = strlen(message) + 1;
        dm_size = sizeof(struct dm_ioctl) + sizeof(struct dm_target_msg) + msg_len;
        dm = alloca0(dm_size);

        dm->data_start = sizeof(struct dm_ioctl);

        msg = (struct dm_target_msg *) ((char *) dm + dm->data_start);
        strcpy(msg->message, message);

        return dm_ioctl_run(name, DM_TARGET_MSG, dm, dm_size);
}
