/*
 * Copyright (C) 2008-2009 Kay Sievers <kay@vrfy.org>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "udevadm-util.h"

struct udev_device *find_device(struct udev *udev,
                                const char *id,
                                const char *prefix) {

        assert(udev);
        assert(id);

        if (prefix && !startswith(id, prefix))
                id = strjoina(prefix, id);

        if (startswith(id, "/dev/")) {
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
        } else if (startswith(id, "/sys/"))
                return udev_device_new_from_syspath(udev, id);
        else
                return NULL;
}
