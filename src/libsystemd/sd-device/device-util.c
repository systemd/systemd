/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "device-private.h"
#include "device-util.h"
#include "devnum-util.h"
#include "fd-util.h"
#include "string-util.h"

int devname_from_devnum(mode_t mode, dev_t devnum, char **ret) {
        _cleanup_(sd_device_unrefp) sd_device *dev = NULL;
        _cleanup_free_ char *s = NULL;
        const char *devname;
        int r;

        assert(ret);

        if (major(devnum) == 0 && minor(devnum) == 0)
                return device_path_make_inaccessible(mode, ret);

        r = device_new_from_mode_and_devnum(&dev, mode, devnum);
        if (r < 0)
                return r;

        r = sd_device_get_devname(dev, &devname);
        if (r < 0)
                return r;

        s = strdup(devname);
        if (!s)
                return -ENOMEM;

        *ret = TAKE_PTR(s);
        return 0;
}

int device_open_from_devnum(mode_t mode, dev_t devnum, int flags, char **ret) {
        _cleanup_(sd_device_unrefp) sd_device *dev = NULL;
        _cleanup_close_ int fd = -1;
        int r;

        r = device_new_from_mode_and_devnum(&dev, mode, devnum);
        if (r < 0)
                return r;

        fd = sd_device_open(dev, flags);
        if (fd < 0)
                return fd;

        if (ret) {
                const char *devname;
                char *s;

                r = sd_device_get_devname(dev, &devname);
                if (r < 0)
                        return r;

                s = strdup(devname);
                if (!s)
                        return -ENOMEM;

                *ret = s;
        }

        return TAKE_FD(fd);
}
