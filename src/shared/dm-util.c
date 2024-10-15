/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <linux/dm-ioctl.h>
#include <sys/ioctl.h>

#include "dm-util.h"
#include "fd-util.h"
#include "string-util.h"

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
