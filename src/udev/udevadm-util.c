/* SPDX-License-Identifier: GPL-2.0+ */

#include "path-util.h"
#include "string-util.h"
#include "udevadm-util.h"

struct udev_device *find_device(struct udev *udev,
                                const char *id,
                                const char *prefix) {

        assert(udev);
        assert(id);

        if (prefix && !startswith(id, prefix))
                id = strjoina(prefix, id);

        if (path_startswith(id, "/dev/")) {
                struct stat statbuf;
                char type;

                if (stat(id, &statbuf) < 0)
                        return NULL;

                if (S_ISBLK(statbuf.st_mode))
                        type = 'b';
                else if (S_ISCHR(statbuf.st_mode))
                        type = 'c';
                else
                        return NULL;

                return udev_device_new_from_devnum(udev, type, statbuf.st_rdev);
        } else if (path_startswith(id, "/sys/"))
                return udev_device_new_from_syspath(udev, id);
        else
                return NULL;
}
