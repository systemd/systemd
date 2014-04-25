/***
  This file is part of systemd.

  Copyright 2008-2012 Kay Sievers <kay@vrfy.org>

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "libudev.h"
#include "libudev-private.h"

static void udev_device_tag(struct udev_device *dev, const char *tag, bool add)
{
        const char *id;
        char filename[UTIL_PATH_SIZE];

        id = udev_device_get_id_filename(dev);
        if (id == NULL)
                return;
        strscpyl(filename, sizeof(filename), "/run/udev/tags/", tag, "/", id, NULL);

        if (add) {
                int fd;

                mkdir_parents(filename, 0755);
                fd = open(filename, O_WRONLY|O_CREAT|O_CLOEXEC|O_TRUNC|O_NOFOLLOW, 0444);
                if (fd >= 0)
                        close(fd);
        } else {
                unlink(filename);
        }
}

int udev_device_tag_index(struct udev_device *dev, struct udev_device *dev_old, bool add)
{
        struct udev_list_entry *list_entry;
        bool found;

        if (add && dev_old != NULL) {
                /* delete possible left-over tags */
                udev_list_entry_foreach(list_entry, udev_device_get_tags_list_entry(dev_old)) {
                        const char *tag_old = udev_list_entry_get_name(list_entry);
                        struct udev_list_entry *list_entry_current;

                        found = false;
                        udev_list_entry_foreach(list_entry_current, udev_device_get_tags_list_entry(dev)) {
                                const char *tag = udev_list_entry_get_name(list_entry_current);

                                if (streq(tag, tag_old)) {
                                        found = true;
                                        break;
                                }
                        }
                        if (!found)
                                udev_device_tag(dev_old, tag_old, false);
                }
        }

        udev_list_entry_foreach(list_entry, udev_device_get_tags_list_entry(dev))
                udev_device_tag(dev, udev_list_entry_get_name(list_entry), add);

        return 0;
}

static bool device_has_info(struct udev_device *udev_device)
{
        struct udev_list_entry *list_entry;

        if (udev_device_get_devlinks_list_entry(udev_device) != NULL)
                return true;
        if (udev_device_get_devlink_priority(udev_device) != 0)
                return true;
        udev_list_entry_foreach(list_entry, udev_device_get_properties_list_entry(udev_device))
                if (udev_list_entry_get_num(list_entry))
                        return true;
        if (udev_device_get_tags_list_entry(udev_device) != NULL)
                return true;
        if (udev_device_get_watch_handle(udev_device) >= 0)
                return true;
        return false;
}

int udev_device_update_db(struct udev_device *udev_device)
{
        struct udev *udev = udev_device_get_udev(udev_device);
        bool has_info;
        const char *id;
        char filename[UTIL_PATH_SIZE];
        char filename_tmp[UTIL_PATH_SIZE];
        FILE *f;
        int r;

        id = udev_device_get_id_filename(udev_device);
        if (id == NULL)
                return -1;

        has_info = device_has_info(udev_device);
        strscpyl(filename, sizeof(filename), "/run/udev/data/", id, NULL);

        /* do not store anything for otherwise empty devices */
        if (!has_info &&
            major(udev_device_get_devnum(udev_device)) == 0 &&
            udev_device_get_ifindex(udev_device) == 0) {
                unlink(filename);
                return 0;
        }

        /* write a database file */
        strscpyl(filename_tmp, sizeof(filename_tmp), filename, ".tmp", NULL);
        mkdir_parents(filename_tmp, 0755);
        f = fopen(filename_tmp, "we");
        if (f == NULL) {
                udev_err(udev, "unable to create temporary db file '%s': %m\n", filename_tmp);
                return -1;
        }

        /*
         * set 'sticky' bit to indicate that we should not clean the
         * database when we transition from initramfs to the real root
         */
        if (udev_device_get_db_persist(udev_device))
                fchmod(fileno(f), 01644);

        if (has_info) {
                struct udev_list_entry *list_entry;

                if (major(udev_device_get_devnum(udev_device)) > 0) {
                        udev_list_entry_foreach(list_entry, udev_device_get_devlinks_list_entry(udev_device))
                                fprintf(f, "S:%s\n", udev_list_entry_get_name(list_entry) + strlen("/dev/"));
                        if (udev_device_get_devlink_priority(udev_device) != 0)
                                fprintf(f, "L:%i\n", udev_device_get_devlink_priority(udev_device));
                        if (udev_device_get_watch_handle(udev_device) >= 0)
                                fprintf(f, "W:%i\n", udev_device_get_watch_handle(udev_device));
                }

                if (udev_device_get_usec_initialized(udev_device) > 0)
                        fprintf(f, "I:"USEC_FMT"\n", udev_device_get_usec_initialized(udev_device));

                udev_list_entry_foreach(list_entry, udev_device_get_properties_list_entry(udev_device)) {
                        if (!udev_list_entry_get_num(list_entry))
                                continue;
                        fprintf(f, "E:%s=%s\n",
                                udev_list_entry_get_name(list_entry),
                                udev_list_entry_get_value(list_entry));
                }

                udev_list_entry_foreach(list_entry, udev_device_get_tags_list_entry(udev_device))
                        fprintf(f, "G:%s\n", udev_list_entry_get_name(list_entry));
        }

        fclose(f);
        r = rename(filename_tmp, filename);
        if (r < 0)
                return -1;
        udev_dbg(udev, "created %s file '%s' for '%s'\n", has_info ? "db" : "empty",
             filename, udev_device_get_devpath(udev_device));
        return 0;
}

int udev_device_delete_db(struct udev_device *udev_device)
{
        const char *id;
        char filename[UTIL_PATH_SIZE];

        id = udev_device_get_id_filename(udev_device);
        if (id == NULL)
                return -1;
        strscpyl(filename, sizeof(filename), "/run/udev/data/", id, NULL);
        unlink(filename);
        return 0;
}
