/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <linux/dm-ioctl.h>
#include <sys/ioctl.h>

#include "dm-util.h"
#include "fd-util.h"
#include "string-util.h"
#include "log.h"
#include "dlfcn-util.h" /* ELF_NOTE_DLOPEN */

#if HAVE_LIBDEVMAPPER
static void *devmapper_dl = NULL;
DLSYM_PROTOTYPE(dm_task_set_name) = NULL;
DLSYM_PROTOTYPE(dm_task_create) = NULL;
#endif
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

#if HAVE_LIBDEVMAPPER
int dlopen_libdevmapper(void) {
        int r;

        ELF_NOTE_DLOPEN("devmapper",
                        "Support for device mapper",
                        ELF_NOTE_DLOPEN_PRIORITY_SUGGESTED,
                        "libdevmapper.so.1.02");

        r = dlopen_many_sym_or_warn(
                        &devmapper_dl, "libdevmapper.so.1.02", LOG_DEBUG,
                        DLSYM_ARG(dm_task_set_name),
                        DLSYM_ARG(dm_task_create));
        if (r <= 0)
                return r;
        return 0;
}
#endif
