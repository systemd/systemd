/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <linux/dm-ioctl.h>
#include <sys/ioctl.h>

#include "dm-util.h"
#include "fd-util.h"
#include "string-util.h"

int dm_deferred_remove_cancel(const char *name) {
        _cleanup_close_ int fd = -1;
        struct message {
                struct dm_ioctl dm_ioctl;
                struct dm_target_msg dm_target_msg;
                char msg_text[STRLEN("@cancel_deferred_remove") + 1];
        } _packed_ message = {
                .dm_ioctl = {
                        .version = {
                                DM_VERSION_MAJOR,
                                DM_VERSION_MINOR,
                                DM_VERSION_PATCHLEVEL
                        },
                        .data_size = sizeof(struct message),
                        .data_start = sizeof(struct dm_ioctl),
                },
                .msg_text = "@cancel_deferred_remove",
        };

        assert(name);

        if (strlen(name) >= sizeof(message.dm_ioctl.name))
                return -ENODEV; /* A device with a name longer than this cannot possibly exist */

        strncpy_exact(message.dm_ioctl.name, name, sizeof(message.dm_ioctl.name));

        fd = open("/dev/mapper/control", O_RDWR|O_CLOEXEC);
        if (fd < 0)
                return -errno;

        if (ioctl(fd, DM_TARGET_MSG, &message))
                return -errno;

        return 0;
}
