#include <fcntl.h>
#include <linux/dm-ioctl.h>
#include <string.h>
#include <sys/ioctl.h>

#include "dm-util.h"
#include "fd-util.h"
#include "string-util.h"

int dm_deferred_remove(const char *name) {

        struct dm_ioctl dm = {
                .version = {
                        DM_VERSION_MAJOR,
                        DM_VERSION_MINOR,
                        DM_VERSION_PATCHLEVEL
                },
                .data_size = sizeof(dm),
                .flags = DM_DEFERRED_REMOVE,
        };

        _cleanup_close_ int fd = -1;

        assert(name);

        /* Unfortunately, libcryptsetup doesn't provide a proper API for this, hence call the ioctl()
         * directly. */

        if (strlen(name) >= sizeof(dm.name))
                return -ENODEV; /* A device with a name longer than this cannot possibly exist */

        fd = open("/dev/mapper/control", O_RDWR|O_CLOEXEC);
        if (fd < 0)
                return -errno;

        strncpy_exact(dm.name, name, sizeof(dm.name));

        if (ioctl(fd, DM_DEV_REMOVE, &dm))
                return -errno;

        return 0;
}
