/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <inttypes.h>
#include <linux/dm-ioctl.h>
#include <sys/ioctl.h>
#include <sys/sysmacros.h>

#include "alloc-util.h"
#include "dm-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "memory-util.h"
#include "string-util.h"

/* The upper half of dm_ioctl.event_nr carries udev flags. Keep this in sync with
 * DM_UDEV_PRIMARY_SOURCE_FLAG and DM_UDEV_FLAGS_SHIFT from libdevmapper.h. We use the raw kernel API
 * here, hence libdevmapper cannot add the flag for us. */
#define DM_UDEV_PRIMARY_SOURCE_EVENT UINT32_C(0x00400000)

static int dm_ioctl_run(int fd, unsigned long request, struct dm_ioctl *dm, size_t size) {
        assert(fd >= 0);
        assert(dm);
        assert(size >= sizeof(*dm));
        assert(size <= UINT32_MAX);

        dm->version[0] = DM_VERSION_MAJOR;
        dm->version[1] = DM_VERSION_MINOR;
        dm->version[2] = DM_VERSION_PATCHLEVEL;
        dm->data_size = size;

        return RET_NERRNO(ioctl(fd, request, dm));
}

static int dm_remove_device_fd(int fd, const char *name) {
        struct dm_ioctl dm = {};
        int r;

        assert(fd >= 0);
        assert(name);

        if (strlen(name) >= sizeof(dm.name))
                return -ENAMETOOLONG;

        strncpy_exact(dm.name, name, sizeof(dm.name));

        r = dm_ioctl_run(fd, DM_DEV_REMOVE, &dm, sizeof(dm));
        if (r == -ENXIO)
                return 0;

        return r;
}

int dm_deferred_remove_cancel(const char *name) {
        _cleanup_close_ int fd = -EBADF;

        struct combined {
                struct dm_ioctl dm_ioctl;
                struct dm_target_msg dm_target_msg;
        } _packed_;

        union message {
                struct combined combined;
                struct {
                        uint8_t space[offsetof(struct combined, dm_target_msg.message)];
                        char text[STRLEN("@cancel_deferred_remove") + 1];
                } _packed_;
        } message = {
                .combined.dm_ioctl = {
                        .version = {
                                DM_VERSION_MAJOR,
                                DM_VERSION_MINOR,
                                DM_VERSION_PATCHLEVEL
                        },
                        .data_size = sizeof(union message),
                        .data_start = offsetof(union message, combined.dm_target_msg),
                },
        };

        assert(name);

        if (strlen(name) >= sizeof(message.combined.dm_ioctl.name))
                return -ENODEV; /* A device with a name longer than this cannot possibly exist */

        strncpy_exact(message.combined.dm_ioctl.name, name, sizeof(message.combined.dm_ioctl.name));
        strncpy_exact(message.text, "@cancel_deferred_remove", sizeof(message.text));

        fd = open("/dev/mapper/control", O_RDWR|O_CLOEXEC);
        if (fd < 0)
                return -errno;

        if (ioctl(fd, DM_TARGET_MSG, &message))
                return -errno;

        return 0;
}

int dm_create_linear(
                const char *name,
                const char *uuid,
                dev_t devnum,
                uint64_t offset,
                uint64_t size) {

        _cleanup_close_ int fd = -EBADF;
        _cleanup_free_ struct dm_ioctl *table = NULL;
        _cleanup_free_ char *params = NULL;
        size_t params_size, table_size, target_size;
        struct dm_target_spec *target;
        struct dm_ioctl create = {};
        int r;

        assert(name);
        assert(uuid);
        assert(major(devnum) > 0);
        assert(offset % 512U == 0);
        assert(size > 0 && size % 512U == 0);

        if (strlen(name) >= sizeof(create.name) || strlen(uuid) >= sizeof(create.uuid))
                return -ENAMETOOLONG;

        fd = open("/dev/mapper/control", O_RDWR|O_CLOEXEC);
        if (fd < 0)
                return -errno;

        strncpy_exact(create.name, name, sizeof(create.name));
        strncpy_exact(create.uuid, uuid, sizeof(create.uuid));

        r = dm_ioctl_run(fd, DM_DEV_CREATE, &create, sizeof(create));
        if (r < 0)
                return r;

        if (asprintf(&params,
                     "%u:%u %" PRIu64,
                     major(devnum),
                     minor(devnum),
                     offset / 512U) < 0) {
                r = -ENOMEM;
                goto fail;
        }

        params_size = strlen(params) + 1;
        target_size = sizeof(struct dm_target_spec);
        if (!ADD_SAFE(&target_size, target_size, params_size)) {
                r = -EOVERFLOW;
                goto fail;
        }
        target_size = ALIGN8(target_size);

        table_size = ALIGN8(sizeof(struct dm_ioctl));
        if (target_size == SIZE_MAX ||
            !ADD_SAFE(&table_size, table_size, target_size) ||
            table_size > UINT32_MAX) {
                r = -EOVERFLOW;
                goto fail;
        }

        table = malloc0(table_size);
        if (!table) {
                r = -ENOMEM;
                goto fail;
        }

        *table = (struct dm_ioctl) {
                .data_start = ALIGN8(sizeof(struct dm_ioctl)),
                .target_count = 1,
        };
        strncpy_exact(table->name, name, sizeof(table->name));

        target = CAST_ALIGN_PTR(struct dm_target_spec, (uint8_t*) table + table->data_start);
        *target = (struct dm_target_spec) {
                .length = size / 512U,
                .next = target_size,
        };
        strncpy_exact(target->target_type, "linear", sizeof(target->target_type));
        memcpy((uint8_t*) target + sizeof(*target), params, params_size);

        r = dm_ioctl_run(fd, DM_TABLE_LOAD, table, table_size);
        if (r < 0)
                goto fail;

        struct dm_ioctl resume = {
                .event_nr = DM_UDEV_PRIMARY_SOURCE_EVENT,
        };
        strncpy_exact(resume.name, name, sizeof(resume.name));

        r = dm_ioctl_run(fd, DM_DEV_SUSPEND, &resume, sizeof(resume));
        if (r < 0)
                goto fail;

        return 0;

fail:
        (void) dm_remove_device_fd(fd, name);
        return r;
}

int dm_remove_device(const char *name) {
        _cleanup_close_ int fd = -EBADF;

        assert(name);

        fd = open("/dev/mapper/control", O_RDWR|O_CLOEXEC);
        if (fd < 0)
                return -errno;

        return dm_remove_device_fd(fd, name);
}
