/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <linux/dm-ioctl.h>
#include <linux/fs.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#include "dm-clone-ioctl.h"
#include "fd-util.h"
#include "log.h"
#include "memory-util.h"         /* memzero() */
#include "stdio-util.h"          /* xsprintf() */
#include "string-util.h"
#include "time-util.h"
#include "udev-util.h"

static int get_size(const char *dev_path, uint64_t *ret_size) {
        _cleanup_close_ int fd = -EBADF;
        uint64_t block_size_bytes;

        assert(dev_path);
        assert(ret_size);

        fd = open(dev_path, O_RDONLY|O_CLOEXEC);
        if (fd < 0)
                return log_error_errno(errno, "Failed to open device '%s': %m", dev_path);

        if (ioctl(fd, BLKGETSIZE64, &block_size_bytes) < 0)
                return log_error_errno(errno, "Failed to get device size for '%s': %m", dev_path);

        *ret_size = block_size_bytes / 512;
        return 0;
}

static int dm_ioctl_run(const char *name, uint32_t cmd, void *data, size_t data_size) {
        _cleanup_close_ int fd = -EBADF;
        struct dm_ioctl *dm = data;

        assert(name);
        assert(data);

        fd = open("/dev/mapper/control", O_RDWR|O_CLOEXEC);
        if (fd < 0)
                return log_error_errno(errno, "Failed to open /dev/mapper/control: %m");

        dm->version[0] = DM_VERSION_MAJOR;
        dm->version[1] = DM_VERSION_MINOR;
        dm->version[2] = DM_VERSION_PATCHLEVEL;
        dm->data_size = data_size;

        if (strlen(name) >= sizeof(dm->name))
                return log_error_errno(SYNTHETIC_ERRNO(ENAMETOOLONG), "Device name too long");
        strncpy_exact(dm->name, name, sizeof(dm->name));

        if (ioctl(fd, cmd, dm) < 0)
                return log_error_errno(errno, "DM ioctl failed: %m");

        return 0;
}

static int dm_clone_create(const char *name) {
        struct dm_ioctl *dm;
        size_t dm_size;

        assert(name);

        dm_size = sizeof(struct dm_ioctl);
        dm = alloca(dm_size);
        memzero(dm, dm_size);
        dm->dev = 0;

        return dm_ioctl_run(name, DM_DEV_CREATE, dm, dm_size);
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
        dm = alloca(dm_size);
        memzero(dm, dm_size);

        dm->data_start = sizeof(struct dm_ioctl);
        dm->target_count = 1;

        tgt = (struct dm_target_spec *) ((char *) dm + dm->data_start);
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
        struct dm_ioctl *dm;
        size_t dm_size;

        assert(name);

        dm_size = sizeof(struct dm_ioctl);
        dm = alloca(dm_size);
        memzero(dm, dm_size);
        dm->flags = 0;

        return dm_ioctl_run(name, DM_DEV_SUSPEND, dm, dm_size);
}

int dm_clone_create_device(
                const char *name,
                const char *source_dev,
                const char *dest_dev,
                const char *metadata_dev) {

        uint64_t device_size_sectors;
        char target_params[256], devlink[PATH_MAX];
        int r;

        assert(name);
        assert(source_dev);
        assert(dest_dev);
        assert(metadata_dev);

        r = get_size(source_dev, &device_size_sectors);
        if (r < 0)
                return r;

        xsprintf(target_params, "%s %s %s 8 1 no_hydration", metadata_dev, dest_dev, source_dev);

        r = dm_clone_create(name);
        if (r < 0)
                return r;

        r = dm_clone_load_table(name, device_size_sectors, target_params);
        if (r < 0)
                return r;

        r = dm_clone_activate(name);
        if (r < 0)
                return r;

        /* Wait for udev to create /dev/mapper/<name> */
        xsprintf(devlink, "/dev/mapper/%s", name);
        r = device_wait_for_devlink(devlink, "block", 10 * USEC_PER_SEC, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to wait for device %s: %m", devlink);

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
        dm = alloca(dm_size);
        memzero(dm, dm_size);

        dm->data_start = sizeof(struct dm_ioctl);

        msg = (struct dm_target_msg *) ((char *) dm + dm->data_start);
        msg->sector = 0;
        strcpy(msg->message, message);

        return dm_ioctl_run(name, DM_TARGET_MSG, dm, dm_size);
}

