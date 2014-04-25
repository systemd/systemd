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

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>
#include <fcntl.h>
#include <ctype.h>
#include <net/if.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/sockios.h>

#include "libudev.h"
#include "libudev-private.h"

static int udev_device_set_devnode(struct udev_device *udev_device, const char *devnode);

/**
 * SECTION:libudev-device
 * @short_description: kernel sys devices
 *
 * Representation of kernel sys devices. Devices are uniquely identified
 * by their syspath, every device has exactly one path in the kernel sys
 * filesystem. Devices usually belong to a kernel subsystem, and have
 * a unique name inside that subsystem.
 */

/**
 * udev_device:
 *
 * Opaque object representing one kernel sys device.
 */
struct udev_device {
        struct udev *udev;
        struct udev_device *parent_device;
        char *syspath;
        const char *devpath;
        char *sysname;
        const char *sysnum;
        char *devnode;
        mode_t devnode_mode;
        uid_t devnode_uid;
        gid_t devnode_gid;
        char *subsystem;
        char *devtype;
        char *driver;
        char *action;
        char *devpath_old;
        char *id_filename;
        char **envp;
        char *monitor_buf;
        size_t monitor_buf_len;
        struct udev_list devlinks_list;
        struct udev_list properties_list;
        struct udev_list sysattr_value_list;
        struct udev_list sysattr_list;
        struct udev_list tags_list;
        unsigned long long int seqnum;
        usec_t usec_initialized;
        int devlink_priority;
        int refcount;
        dev_t devnum;
        int ifindex;
        int watch_handle;
        int maj, min;
        bool parent_set;
        bool subsystem_set;
        bool devtype_set;
        bool devlinks_uptodate;
        bool envp_uptodate;
        bool tags_uptodate;
        bool driver_set;
        bool info_loaded;
        bool db_loaded;
        bool uevent_loaded;
        bool is_initialized;
        bool sysattr_list_read;
        bool db_persist;
};

/**
 * udev_device_get_seqnum:
 * @udev_device: udev device
 *
 * This is only valid if the device was received through a monitor. Devices read from
 * sys do not have a sequence number.
 *
 * Returns: the kernel event sequence number, or 0 if there is no sequence number available.
 **/
_public_ unsigned long long int udev_device_get_seqnum(struct udev_device *udev_device)
{
        if (udev_device == NULL)
                return 0;
        return udev_device->seqnum;
}

static int udev_device_set_seqnum(struct udev_device *udev_device, unsigned long long int seqnum)
{
        char num[32];

        udev_device->seqnum = seqnum;
        snprintf(num, sizeof(num), "%llu", seqnum);
        udev_device_add_property(udev_device, "SEQNUM", num);
        return 0;
}

int udev_device_get_ifindex(struct udev_device *udev_device)
{
        if (!udev_device->info_loaded)
                udev_device_read_uevent_file(udev_device);
        return udev_device->ifindex;
}

static int udev_device_set_ifindex(struct udev_device *udev_device, int ifindex)
{
        char num[32];

        udev_device->ifindex = ifindex;
        snprintf(num, sizeof(num), "%u", ifindex);
        udev_device_add_property(udev_device, "IFINDEX", num);
        return 0;
}

/**
 * udev_device_get_devnum:
 * @udev_device: udev device
 *
 * Get the device major/minor number.
 *
 * Returns: the dev_t number.
 **/
_public_ dev_t udev_device_get_devnum(struct udev_device *udev_device)
{
        if (udev_device == NULL)
                return makedev(0, 0);
        if (!udev_device->info_loaded)
                udev_device_read_uevent_file(udev_device);
        return udev_device->devnum;
}

static int udev_device_set_devnum(struct udev_device *udev_device, dev_t devnum)
{
        char num[32];

        udev_device->devnum = devnum;

        snprintf(num, sizeof(num), "%u", major(devnum));
        udev_device_add_property(udev_device, "MAJOR", num);
        snprintf(num, sizeof(num), "%u", minor(devnum));
        udev_device_add_property(udev_device, "MINOR", num);
        return 0;
}

const char *udev_device_get_devpath_old(struct udev_device *udev_device)
{
        return udev_device->devpath_old;
}

static int udev_device_set_devpath_old(struct udev_device *udev_device, const char *devpath_old)
{
        const char *pos;

        free(udev_device->devpath_old);
        udev_device->devpath_old = strdup(devpath_old);
        if (udev_device->devpath_old == NULL)
                return -ENOMEM;
        udev_device_add_property(udev_device, "DEVPATH_OLD", udev_device->devpath_old);

        pos = strrchr(udev_device->devpath_old, '/');
        if (pos == NULL)
                return -EINVAL;
        return 0;
}

/**
 * udev_device_get_driver:
 * @udev_device: udev device
 *
 * Get the kernel driver name.
 *
 * Returns: the driver name string, or #NULL if there is no driver attached.
 **/
_public_ const char *udev_device_get_driver(struct udev_device *udev_device)
{
        char driver[UTIL_NAME_SIZE];

        if (udev_device == NULL)
                return NULL;
        if (!udev_device->driver_set) {
                udev_device->driver_set = true;
                if (util_get_sys_core_link_value(udev_device->udev, "driver", udev_device->syspath, driver, sizeof(driver)) > 0)
                        udev_device->driver = strdup(driver);
        }
        return udev_device->driver;
}

static int udev_device_set_driver(struct udev_device *udev_device, const char *driver)
{
        free(udev_device->driver);
        udev_device->driver = strdup(driver);
        if (udev_device->driver == NULL)
                return -ENOMEM;
        udev_device->driver_set = true;
        udev_device_add_property(udev_device, "DRIVER", udev_device->driver);
        return 0;
}

/**
 * udev_device_get_devtype:
 * @udev_device: udev device
 *
 * Retrieve the devtype string of the udev device.
 *
 * Returns: the devtype name of the udev device, or #NULL if it can not be determined
 **/
_public_ const char *udev_device_get_devtype(struct udev_device *udev_device)
{
        if (udev_device == NULL)
                return NULL;
        if (!udev_device->devtype_set) {
                udev_device->devtype_set = true;
                udev_device_read_uevent_file(udev_device);
        }
        return udev_device->devtype;
}

static int udev_device_set_devtype(struct udev_device *udev_device, const char *devtype)
{
        free(udev_device->devtype);
        udev_device->devtype = strdup(devtype);
        if (udev_device->devtype == NULL)
                return -ENOMEM;
        udev_device->devtype_set = true;
        udev_device_add_property(udev_device, "DEVTYPE", udev_device->devtype);
        return 0;
}

int udev_device_set_subsystem(struct udev_device *udev_device, const char *subsystem)
{
        free(udev_device->subsystem);
        udev_device->subsystem = strdup(subsystem);
        if (udev_device->subsystem == NULL)
                return -ENOMEM;
        udev_device->subsystem_set = true;
        udev_device_add_property(udev_device, "SUBSYSTEM", udev_device->subsystem);
        return 0;
}

/**
 * udev_device_get_subsystem:
 * @udev_device: udev device
 *
 * Retrieve the subsystem string of the udev device. The string does not
 * contain any "/".
 *
 * Returns: the subsystem name of the udev device, or #NULL if it can not be determined
 **/
_public_ const char *udev_device_get_subsystem(struct udev_device *udev_device)
{
        char subsystem[UTIL_NAME_SIZE];

        if (udev_device == NULL)
                return NULL;
        if (!udev_device->subsystem_set) {
                udev_device->subsystem_set = true;
                /* read "subsystem" link */
                if (util_get_sys_core_link_value(udev_device->udev, "subsystem", udev_device->syspath, subsystem, sizeof(subsystem)) > 0) {
                        udev_device_set_subsystem(udev_device, subsystem);
                        return udev_device->subsystem;
                }
                /* implicit names */
                if (startswith(udev_device->devpath, "/module/")) {
                        udev_device_set_subsystem(udev_device, "module");
                        return udev_device->subsystem;
                }
                if (strstr(udev_device->devpath, "/drivers/") != NULL) {
                        udev_device_set_subsystem(udev_device, "drivers");
                        return udev_device->subsystem;
                }
                if (startswith(udev_device->devpath, "/subsystem/") ||
                    startswith(udev_device->devpath, "/class/") ||
                    startswith(udev_device->devpath, "/bus/")) {
                        udev_device_set_subsystem(udev_device, "subsystem");
                        return udev_device->subsystem;
                }
        }
        return udev_device->subsystem;
}

mode_t udev_device_get_devnode_mode(struct udev_device *udev_device)
{
        if (!udev_device->info_loaded)
                udev_device_read_uevent_file(udev_device);
        return udev_device->devnode_mode;
}

static int udev_device_set_devnode_mode(struct udev_device *udev_device, mode_t mode)
{
        char num[32];

        udev_device->devnode_mode = mode;
        snprintf(num, sizeof(num), "%#o", mode);
        udev_device_add_property(udev_device, "DEVMODE", num);
        return 0;
}

uid_t udev_device_get_devnode_uid(struct udev_device *udev_device)
{
        if (!udev_device->info_loaded)
                udev_device_read_uevent_file(udev_device);
        return udev_device->devnode_uid;
}

static int udev_device_set_devnode_uid(struct udev_device *udev_device, uid_t uid)
{
        char num[32];

        udev_device->devnode_uid = uid;
        snprintf(num, sizeof(num), "%u", uid);
        udev_device_add_property(udev_device, "DEVUID", num);
        return 0;
}

gid_t udev_device_get_devnode_gid(struct udev_device *udev_device)
{
        if (!udev_device->info_loaded)
                udev_device_read_uevent_file(udev_device);
        return udev_device->devnode_gid;
}

static int udev_device_set_devnode_gid(struct udev_device *udev_device, gid_t gid)
{
        char num[32];

        udev_device->devnode_gid = gid;
        snprintf(num, sizeof(num), "%u", gid);
        udev_device_add_property(udev_device, "DEVGID", num);
        return 0;
}

struct udev_list_entry *udev_device_add_property(struct udev_device *udev_device, const char *key, const char *value)
{
        udev_device->envp_uptodate = false;
        if (value == NULL) {
                struct udev_list_entry *list_entry;

                list_entry = udev_device_get_properties_list_entry(udev_device);
                list_entry = udev_list_entry_get_by_name(list_entry, key);
                if (list_entry != NULL)
                        udev_list_entry_delete(list_entry);
                return NULL;
        }
        return udev_list_entry_add(&udev_device->properties_list, key, value);
}

static struct udev_list_entry *udev_device_add_property_from_string(struct udev_device *udev_device, const char *property)
{
        char name[UTIL_LINE_SIZE];
        char *val;

        strscpy(name, sizeof(name), property);
        val = strchr(name, '=');
        if (val == NULL)
                return NULL;
        val[0] = '\0';
        val = &val[1];
        if (val[0] == '\0')
                val = NULL;
        return udev_device_add_property(udev_device, name, val);
}

/*
 * parse property string, and if needed, update internal values accordingly
 *
 * udev_device_add_property_from_string_parse_finish() needs to be
 * called after adding properties, and its return value checked
 *
 * udev_device_set_info_loaded() needs to be set, to avoid trying
 * to use a device without a DEVPATH set
 */
void udev_device_add_property_from_string_parse(struct udev_device *udev_device, const char *property)
{
        if (startswith(property, "DEVPATH=")) {
                char path[UTIL_PATH_SIZE];

                strscpyl(path, sizeof(path), "/sys", &property[8], NULL);
                udev_device_set_syspath(udev_device, path);
        } else if (startswith(property, "SUBSYSTEM=")) {
                udev_device_set_subsystem(udev_device, &property[10]);
        } else if (startswith(property, "DEVTYPE=")) {
                udev_device_set_devtype(udev_device, &property[8]);
        } else if (startswith(property, "DEVNAME=")) {
                udev_device_set_devnode(udev_device, &property[8]);
        } else if (startswith(property, "DEVLINKS=")) {
                char devlinks[UTIL_PATH_SIZE];
                char *slink;
                char *next;

                strscpy(devlinks, sizeof(devlinks), &property[9]);
                slink = devlinks;
                next = strchr(slink, ' ');
                while (next != NULL) {
                        next[0] = '\0';
                        udev_device_add_devlink(udev_device, slink);
                        slink = &next[1];
                        next = strchr(slink, ' ');
                }
                if (slink[0] != '\0')
                        udev_device_add_devlink(udev_device, slink);
        } else if (startswith(property, "TAGS=")) {
                char tags[UTIL_PATH_SIZE];
                char *next;

                strscpy(tags, sizeof(tags), &property[5]);
                next = strchr(tags, ':');
                if (next != NULL) {
                        next++;
                        while (next[0] != '\0') {
                                char *tag;

                                tag = next;
                                next = strchr(tag, ':');
                                if (next == NULL)
                                        break;
                                next[0] = '\0';
                                next++;
                                udev_device_add_tag(udev_device, tag);
                        }
                }
        } else if (startswith(property, "USEC_INITIALIZED=")) {
                udev_device_set_usec_initialized(udev_device, strtoull(&property[19], NULL, 10));
        } else if (startswith(property, "DRIVER=")) {
                udev_device_set_driver(udev_device, &property[7]);
        } else if (startswith(property, "ACTION=")) {
                udev_device_set_action(udev_device, &property[7]);
        } else if (startswith(property, "MAJOR=")) {
                udev_device->maj = strtoull(&property[6], NULL, 10);
        } else if (startswith(property, "MINOR=")) {
                udev_device->min = strtoull(&property[6], NULL, 10);
        } else if (startswith(property, "DEVPATH_OLD=")) {
                udev_device_set_devpath_old(udev_device, &property[12]);
        } else if (startswith(property, "SEQNUM=")) {
                udev_device_set_seqnum(udev_device, strtoull(&property[7], NULL, 10));
        } else if (startswith(property, "IFINDEX=")) {
                udev_device_set_ifindex(udev_device, strtoull(&property[8], NULL, 10));
        } else if (startswith(property, "DEVMODE=")) {
                udev_device_set_devnode_mode(udev_device, strtoul(&property[8], NULL, 8));
        } else if (startswith(property, "DEVUID=")) {
                udev_device_set_devnode_uid(udev_device, strtoul(&property[7], NULL, 10));
        } else if (startswith(property, "DEVGID=")) {
                udev_device_set_devnode_gid(udev_device, strtoul(&property[7], NULL, 10));
        } else {
                udev_device_add_property_from_string(udev_device, property);
        }
}

int udev_device_add_property_from_string_parse_finish(struct udev_device *udev_device)
{
        if (udev_device->maj > 0)
                udev_device_set_devnum(udev_device, makedev(udev_device->maj, udev_device->min));
        udev_device->maj = 0;
        udev_device->min = 0;

        if (udev_device->devpath == NULL || udev_device->subsystem == NULL)
                return -EINVAL;
        return 0;
}

/**
 * udev_device_get_property_value:
 * @udev_device: udev device
 * @key: property name
 *
 * Get the value of a given property.
 *
 * Returns: the property string, or #NULL if there is no such property.
 **/
_public_ const char *udev_device_get_property_value(struct udev_device *udev_device, const char *key)
{
        struct udev_list_entry *list_entry;

        if (udev_device == NULL)
                return NULL;
        if (key == NULL)
                return NULL;

        list_entry = udev_device_get_properties_list_entry(udev_device);
        list_entry = udev_list_entry_get_by_name(list_entry, key);
        return udev_list_entry_get_value(list_entry);
}

int udev_device_read_db(struct udev_device *udev_device, const char *dbfile)
{
        char filename[UTIL_PATH_SIZE];
        char line[UTIL_LINE_SIZE];
        FILE *f;

        /* providing a database file will always force-load it */
        if (dbfile == NULL) {
                const char *id;

                if (udev_device->db_loaded)
                        return 0;
                udev_device->db_loaded = true;

                id = udev_device_get_id_filename(udev_device);
                if (id == NULL)
                        return -1;
                strscpyl(filename, sizeof(filename), "/run/udev/data/", id, NULL);
                dbfile = filename;
        }

        f = fopen(dbfile, "re");
        if (f == NULL) {
                udev_dbg(udev_device->udev, "no db file to read %s: %m\n", dbfile);
                return -errno;
        }

        /* devices with a database entry are initialized */
        udev_device->is_initialized = true;

        while (fgets(line, sizeof(line), f)) {
                ssize_t len;
                const char *val;
                struct udev_list_entry *entry;

                len = strlen(line);
                if (len < 4)
                        break;
                line[len-1] = '\0';
                val = &line[2];
                switch(line[0]) {
                case 'S':
                        strscpyl(filename, sizeof(filename), "/dev/", val, NULL);
                        udev_device_add_devlink(udev_device, filename);
                        break;
                case 'L':
                        udev_device_set_devlink_priority(udev_device, atoi(val));
                        break;
                case 'E':
                        entry = udev_device_add_property_from_string(udev_device, val);
                        udev_list_entry_set_num(entry, true);
                        break;
                case 'G':
                        udev_device_add_tag(udev_device, val);
                        break;
                case 'W':
                        udev_device_set_watch_handle(udev_device, atoi(val));
                        break;
                case 'I':
                        udev_device_set_usec_initialized(udev_device, strtoull(val, NULL, 10));
                        break;
                }
        }
        fclose(f);

        udev_dbg(udev_device->udev, "device %p filled with db file data\n", udev_device);
        return 0;
}

int udev_device_read_uevent_file(struct udev_device *udev_device)
{
        char filename[UTIL_PATH_SIZE];
        FILE *f;
        char line[UTIL_LINE_SIZE];
        int maj = 0;
        int min = 0;

        if (udev_device->uevent_loaded)
                return 0;

        strscpyl(filename, sizeof(filename), udev_device->syspath, "/uevent", NULL);
        f = fopen(filename, "re");
        if (f == NULL)
                return -errno;
        udev_device->uevent_loaded = true;

        while (fgets(line, sizeof(line), f)) {
                char *pos;

                pos = strchr(line, '\n');
                if (pos == NULL)
                        continue;
                pos[0] = '\0';

                if (startswith(line, "DEVTYPE=")) {
                        udev_device_set_devtype(udev_device, &line[8]);
                        continue;
                }
                if (startswith(line, "IFINDEX=")) {
                        udev_device_set_ifindex(udev_device, strtoull(&line[8], NULL, 10));
                        continue;
                }
                if (startswith(line, "DEVNAME=")) {
                        udev_device_set_devnode(udev_device, &line[8]);
                        continue;
                }

                if (startswith(line, "MAJOR="))
                        maj = strtoull(&line[6], NULL, 10);
                else if (startswith(line, "MINOR="))
                        min = strtoull(&line[6], NULL, 10);
                else if (startswith(line, "DEVMODE="))
                        udev_device->devnode_mode = strtoul(&line[8], NULL, 8);

                udev_device_add_property_from_string(udev_device, line);
        }

        udev_device->devnum = makedev(maj, min);
        fclose(f);
        return 0;
}

void udev_device_set_info_loaded(struct udev_device *device)
{
        device->info_loaded = true;
}

struct udev_device *udev_device_new(struct udev *udev)
{
        struct udev_device *udev_device;
        struct udev_list_entry *list_entry;

        if (udev == NULL)
                return NULL;

        udev_device = new0(struct udev_device, 1);
        if (udev_device == NULL)
                return NULL;
        udev_device->refcount = 1;
        udev_device->udev = udev;
        udev_list_init(udev, &udev_device->devlinks_list, true);
        udev_list_init(udev, &udev_device->properties_list, true);
        udev_list_init(udev, &udev_device->sysattr_value_list, true);
        udev_list_init(udev, &udev_device->sysattr_list, false);
        udev_list_init(udev, &udev_device->tags_list, true);
        udev_device->watch_handle = -1;
        /* copy global properties */
        udev_list_entry_foreach(list_entry, udev_get_properties_list_entry(udev))
                udev_device_add_property(udev_device,
                                         udev_list_entry_get_name(list_entry),
                                         udev_list_entry_get_value(list_entry));
        return udev_device;
}

/**
 * udev_device_new_from_syspath:
 * @udev: udev library context
 * @syspath: sys device path including sys directory
 *
 * Create new udev device, and fill in information from the sys
 * device and the udev database entry. The syspath is the absolute
 * path to the device, including the sys mount point.
 *
 * The initial refcount is 1, and needs to be decremented to
 * release the resources of the udev device.
 *
 * Returns: a new udev device, or #NULL, if it does not exist
 **/
_public_ struct udev_device *udev_device_new_from_syspath(struct udev *udev, const char *syspath)
{
        const char *subdir;
        char path[UTIL_PATH_SIZE];
        char *pos;
        struct stat statbuf;
        struct udev_device *udev_device;

        if (udev == NULL)
                return NULL;
        if (syspath == NULL)
                return NULL;

        /* path starts in sys */
        if (!startswith(syspath, "/sys")) {
                udev_dbg(udev, "not in sys :%s\n", syspath);
                return NULL;
        }

        /* path is not a root directory */
        subdir = syspath + strlen("/sys");
        pos = strrchr(subdir, '/');
        if (pos == NULL || pos[1] == '\0' || pos < &subdir[2])
                return NULL;

        /* resolve possible symlink to real path */
        strscpy(path, sizeof(path), syspath);
        util_resolve_sys_link(udev, path, sizeof(path));

        if (startswith(path + strlen("/sys"), "/devices/")) {
                char file[UTIL_PATH_SIZE];

                /* all "devices" require a "uevent" file */
                strscpyl(file, sizeof(file), path, "/uevent", NULL);
                if (stat(file, &statbuf) != 0)
                        return NULL;
        } else {
                /* everything else just needs to be a directory */
                if (stat(path, &statbuf) != 0 || !S_ISDIR(statbuf.st_mode))
                        return NULL;
        }

        udev_device = udev_device_new(udev);
        if (udev_device == NULL)
                return NULL;

        udev_device_set_syspath(udev_device, path);
        udev_dbg(udev, "device %p has devpath '%s'\n", udev_device, udev_device_get_devpath(udev_device));

        return udev_device;
}

/**
 * udev_device_new_from_devnum:
 * @udev: udev library context
 * @type: char or block device
 * @devnum: device major/minor number
 *
 * Create new udev device, and fill in information from the sys
 * device and the udev database entry. The device is looked-up
 * by its major/minor number and type. Character and block device
 * numbers are not unique across the two types.
 *
 * The initial refcount is 1, and needs to be decremented to
 * release the resources of the udev device.
 *
 * Returns: a new udev device, or #NULL, if it does not exist
 **/
_public_ struct udev_device *udev_device_new_from_devnum(struct udev *udev, char type, dev_t devnum)
{
        char path[UTIL_PATH_SIZE];
        const char *type_str;

        if (type == 'b')
                type_str = "block";
        else if (type == 'c')
                type_str = "char";
        else
                return NULL;

        /* use /sys/dev/{block,char}/<maj>:<min> link */
        snprintf(path, sizeof(path), "/sys/dev/%s/%u:%u",
                 type_str, major(devnum), minor(devnum));
        return udev_device_new_from_syspath(udev, path);
}

/**
 * udev_device_new_from_device_id:
 * @udev: udev library context
 * @id: text string identifying a kernel device
 *
 * Create new udev device, and fill in information from the sys
 * device and the udev database entry. The device is looked-up
 * by a special string:
 *   b8:2          - block device major:minor
 *   c128:1        - char device major:minor
 *   n3            - network device ifindex
 *   +sound:card29 - kernel driver core subsystem:device name
 *
 * The initial refcount is 1, and needs to be decremented to
 * release the resources of the udev device.
 *
 * Returns: a new udev device, or #NULL, if it does not exist
 **/
_public_ struct udev_device *udev_device_new_from_device_id(struct udev *udev, const char *id)
{
        char type;
        int maj, min;
        char subsys[UTIL_PATH_SIZE];
        char *sysname;

        switch(id[0]) {
        case 'b':
        case 'c':
                if (sscanf(id, "%c%i:%i", &type, &maj, &min) != 3)
                        return NULL;
                return udev_device_new_from_devnum(udev, type, makedev(maj, min));
        case 'n': {
                int sk;
                struct ifreq ifr;
                struct udev_device *dev;
                int ifindex;

                ifindex = strtoul(&id[1], NULL, 10);
                if (ifindex <= 0)
                        return NULL;

                sk = socket(PF_INET, SOCK_DGRAM, 0);
                if (sk < 0)
                        return NULL;
                memzero(&ifr, sizeof(struct ifreq));
                ifr.ifr_ifindex = ifindex;
                if (ioctl(sk, SIOCGIFNAME, &ifr) != 0) {
                        close(sk);
                        return NULL;
                }
                close(sk);

                dev = udev_device_new_from_subsystem_sysname(udev, "net", ifr.ifr_name);
                if (dev == NULL)
                        return NULL;
                if (udev_device_get_ifindex(dev) == ifindex)
                        return dev;
                udev_device_unref(dev);
                return NULL;
        }
        case '+':
                strscpy(subsys, sizeof(subsys), &id[1]);
                sysname = strchr(subsys, ':');
                if (sysname == NULL)
                        return NULL;
                sysname[0] = '\0';
                sysname = &sysname[1];
                return udev_device_new_from_subsystem_sysname(udev, subsys, sysname);
        default:
                return NULL;
        }
}

/**
 * udev_device_new_from_subsystem_sysname:
 * @udev: udev library context
 * @subsystem: the subsystem of the device
 * @sysname: the name of the device
 *
 * Create new udev device, and fill in information from the sys device
 * and the udev database entry. The device is looked up by the subsystem
 * and name string of the device, like "mem" / "zero", or "block" / "sda".
 *
 * The initial refcount is 1, and needs to be decremented to
 * release the resources of the udev device.
 *
 * Returns: a new udev device, or #NULL, if it does not exist
 **/
_public_ struct udev_device *udev_device_new_from_subsystem_sysname(struct udev *udev, const char *subsystem, const char *sysname)
{
        char path[UTIL_PATH_SIZE];
        struct stat statbuf;

        if (streq(subsystem, "subsystem")) {
                strscpyl(path, sizeof(path), "/sys/subsystem/", sysname, NULL);
                if (stat(path, &statbuf) == 0)
                        goto found;

                strscpyl(path, sizeof(path), "/sys/bus/", sysname, NULL);
                if (stat(path, &statbuf) == 0)
                        goto found;

                strscpyl(path, sizeof(path), "/sys/class/", sysname, NULL);
                if (stat(path, &statbuf) == 0)
                        goto found;
                goto out;
        }

        if (streq(subsystem, "module")) {
                strscpyl(path, sizeof(path), "/sys/module/", sysname, NULL);
                if (stat(path, &statbuf) == 0)
                        goto found;
                goto out;
        }

        if (streq(subsystem, "drivers")) {
                char subsys[UTIL_NAME_SIZE];
                char *driver;

                strscpy(subsys, sizeof(subsys), sysname);
                driver = strchr(subsys, ':');
                if (driver != NULL) {
                        driver[0] = '\0';
                        driver = &driver[1];

                        strscpyl(path, sizeof(path), "/sys/subsystem/", subsys, "/drivers/", driver, NULL);
                        if (stat(path, &statbuf) == 0)
                                goto found;

                        strscpyl(path, sizeof(path), "/sys/bus/", subsys, "/drivers/", driver, NULL);
                        if (stat(path, &statbuf) == 0)
                                goto found;
                }
                goto out;
        }

        strscpyl(path, sizeof(path), "/sys/subsystem/", subsystem, "/devices/", sysname, NULL);
        if (stat(path, &statbuf) == 0)
                goto found;

        strscpyl(path, sizeof(path), "/sys/bus/", subsystem, "/devices/", sysname, NULL);
        if (stat(path, &statbuf) == 0)
                goto found;

        strscpyl(path, sizeof(path), "/sys/class/", subsystem, "/", sysname, NULL);
        if (stat(path, &statbuf) == 0)
                goto found;
out:
        return NULL;
found:
        return udev_device_new_from_syspath(udev, path);
}

/**
 * udev_device_new_from_environment
 * @udev: udev library context
 *
 * Create new udev device, and fill in information from the
 * current process environment. This only works reliable if
 * the process is called from a udev rule. It is usually used
 * for tools executed from IMPORT= rules.
 *
 * The initial refcount is 1, and needs to be decremented to
 * release the resources of the udev device.
 *
 * Returns: a new udev device, or #NULL, if it does not exist
 **/
_public_ struct udev_device *udev_device_new_from_environment(struct udev *udev)
{
        int i;
        struct udev_device *udev_device;

        udev_device = udev_device_new(udev);
        if (udev_device == NULL)
                return NULL;
        udev_device_set_info_loaded(udev_device);

        for (i = 0; environ[i] != NULL; i++)
                udev_device_add_property_from_string_parse(udev_device, environ[i]);

        if (udev_device_add_property_from_string_parse_finish(udev_device) < 0) {
                udev_dbg(udev, "missing values, invalid device\n");
                udev_device_unref(udev_device);
                udev_device = NULL;
        }

        return udev_device;
}

static struct udev_device *device_new_from_parent(struct udev_device *udev_device)
{
        struct udev_device *udev_device_parent = NULL;
        char path[UTIL_PATH_SIZE];
        const char *subdir;

        strscpy(path, sizeof(path), udev_device->syspath);
        subdir = path + strlen("/sys/");
        for (;;) {
                char *pos;

                pos = strrchr(subdir, '/');
                if (pos == NULL || pos < &subdir[2])
                        break;
                pos[0] = '\0';
                udev_device_parent = udev_device_new_from_syspath(udev_device->udev, path);
                if (udev_device_parent != NULL)
                        return udev_device_parent;
        }
        return NULL;
}

/**
 * udev_device_get_parent:
 * @udev_device: the device to start searching from
 *
 * Find the next parent device, and fill in information from the sys
 * device and the udev database entry.
 *
 * Returned device is not referenced. It is attached to the child
 * device, and will be cleaned up when the child device is cleaned up.
 *
 * It is not necessarily just the upper level directory, empty or not
 * recognized sys directories are ignored.
 *
 * It can be called as many times as needed, without caring about
 * references.
 *
 * Returns: a new udev device, or #NULL, if it no parent exist.
 **/
_public_ struct udev_device *udev_device_get_parent(struct udev_device *udev_device)
{
        if (udev_device == NULL)
                return NULL;
        if (!udev_device->parent_set) {
                udev_device->parent_set = true;
                udev_device->parent_device = device_new_from_parent(udev_device);
        }
        return udev_device->parent_device;
}

/**
 * udev_device_get_parent_with_subsystem_devtype:
 * @udev_device: udev device to start searching from
 * @subsystem: the subsystem of the device
 * @devtype: the type (DEVTYPE) of the device
 *
 * Find the next parent device, with a matching subsystem and devtype
 * value, and fill in information from the sys device and the udev
 * database entry.
 *
 * If devtype is #NULL, only subsystem is checked, and any devtype will
 * match.
 *
 * Returned device is not referenced. It is attached to the child
 * device, and will be cleaned up when the child device is cleaned up.
 *
 * It can be called as many times as needed, without caring about
 * references.
 *
 * Returns: a new udev device, or #NULL if no matching parent exists.
 **/
_public_ struct udev_device *udev_device_get_parent_with_subsystem_devtype(struct udev_device *udev_device, const char *subsystem, const char *devtype)
{
        struct udev_device *parent;

        if (subsystem == NULL)
                return NULL;

        parent = udev_device_get_parent(udev_device);
        while (parent != NULL) {
                const char *parent_subsystem;
                const char *parent_devtype;

                parent_subsystem = udev_device_get_subsystem(parent);
                if (parent_subsystem != NULL && streq(parent_subsystem, subsystem)) {
                        if (devtype == NULL)
                                break;
                        parent_devtype = udev_device_get_devtype(parent);
                        if (parent_devtype != NULL && streq(parent_devtype, devtype))
                                break;
                }
                parent = udev_device_get_parent(parent);
        }
        return parent;
}

/**
 * udev_device_get_udev:
 * @udev_device: udev device
 *
 * Retrieve the udev library context the device was created with.
 *
 * Returns: the udev library context
 **/
_public_ struct udev *udev_device_get_udev(struct udev_device *udev_device)
{
        if (udev_device == NULL)
                return NULL;
        return udev_device->udev;
}

/**
 * udev_device_ref:
 * @udev_device: udev device
 *
 * Take a reference of a udev device.
 *
 * Returns: the passed udev device
 **/
_public_ struct udev_device *udev_device_ref(struct udev_device *udev_device)
{
        if (udev_device == NULL)
                return NULL;
        udev_device->refcount++;
        return udev_device;
}

/**
 * udev_device_unref:
 * @udev_device: udev device
 *
 * Drop a reference of a udev device. If the refcount reaches zero,
 * the resources of the device will be released.
 *
 * Returns: #NULL
 **/
_public_ struct udev_device *udev_device_unref(struct udev_device *udev_device)
{
        if (udev_device == NULL)
                return NULL;
        udev_device->refcount--;
        if (udev_device->refcount > 0)
                return NULL;
        if (udev_device->parent_device != NULL)
                udev_device_unref(udev_device->parent_device);
        free(udev_device->syspath);
        free(udev_device->sysname);
        free(udev_device->devnode);
        free(udev_device->subsystem);
        free(udev_device->devtype);
        udev_list_cleanup(&udev_device->devlinks_list);
        udev_list_cleanup(&udev_device->properties_list);
        udev_list_cleanup(&udev_device->sysattr_value_list);
        udev_list_cleanup(&udev_device->sysattr_list);
        udev_list_cleanup(&udev_device->tags_list);
        free(udev_device->action);
        free(udev_device->driver);
        free(udev_device->devpath_old);
        free(udev_device->id_filename);
        free(udev_device->envp);
        free(udev_device->monitor_buf);
        free(udev_device);
        return NULL;
}

/**
 * udev_device_get_devpath:
 * @udev_device: udev device
 *
 * Retrieve the kernel devpath value of the udev device. The path
 * does not contain the sys mount point, and starts with a '/'.
 *
 * Returns: the devpath of the udev device
 **/
_public_ const char *udev_device_get_devpath(struct udev_device *udev_device)
{
        if (udev_device == NULL)
                return NULL;
        return udev_device->devpath;
}

/**
 * udev_device_get_syspath:
 * @udev_device: udev device
 *
 * Retrieve the sys path of the udev device. The path is an
 * absolute path and starts with the sys mount point.
 *
 * Returns: the sys path of the udev device
 **/
_public_ const char *udev_device_get_syspath(struct udev_device *udev_device)
{
        if (udev_device == NULL)
                return NULL;
        return udev_device->syspath;
}

/**
 * udev_device_get_sysname:
 * @udev_device: udev device
 *
 * Get the kernel device name in /sys.
 *
 * Returns: the name string of the device device
 **/
_public_ const char *udev_device_get_sysname(struct udev_device *udev_device)
{
        if (udev_device == NULL)
                return NULL;
        return udev_device->sysname;
}

/**
 * udev_device_get_sysnum:
 * @udev_device: udev device
 *
 * Get the instance number of the device.
 *
 * Returns: the trailing number string of the device name
 **/
_public_ const char *udev_device_get_sysnum(struct udev_device *udev_device)
{
        if (udev_device == NULL)
                return NULL;
        return udev_device->sysnum;
}

/**
 * udev_device_get_devnode:
 * @udev_device: udev device
 *
 * Retrieve the device node file name belonging to the udev device.
 * The path is an absolute path, and starts with the device directory.
 *
 * Returns: the device node file name of the udev device, or #NULL if no device node exists
 **/
_public_ const char *udev_device_get_devnode(struct udev_device *udev_device)
{
        if (udev_device == NULL)
                return NULL;
        if (udev_device->devnode != NULL)
                return udev_device->devnode;
        if (!udev_device->info_loaded)
                udev_device_read_uevent_file(udev_device);
        return udev_device->devnode;
}

/**
 * udev_device_get_devlinks_list_entry:
 * @udev_device: udev device
 *
 * Retrieve the list of device links pointing to the device file of
 * the udev device. The next list entry can be retrieved with
 * udev_list_entry_get_next(), which returns #NULL if no more entries exist.
 * The devlink path can be retrieved from the list entry by
 * udev_list_entry_get_name(). The path is an absolute path, and starts with
 * the device directory.
 *
 * Returns: the first entry of the device node link list
 **/
_public_ struct udev_list_entry *udev_device_get_devlinks_list_entry(struct udev_device *udev_device)
{
        if (udev_device == NULL)
                return NULL;
        if (!udev_device->info_loaded)
                udev_device_read_db(udev_device, NULL);
        return udev_list_get_entry(&udev_device->devlinks_list);
}

void udev_device_cleanup_devlinks_list(struct udev_device *udev_device)
{
        udev_device->devlinks_uptodate = false;
        udev_list_cleanup(&udev_device->devlinks_list);
}

/**
 * udev_device_get_properties_list_entry:
 * @udev_device: udev device
 *
 * Retrieve the list of key/value device properties of the udev
 * device. The next list entry can be retrieved with udev_list_entry_get_next(),
 * which returns #NULL if no more entries exist. The property name
 * can be retrieved from the list entry by udev_list_entry_get_name(),
 * the property value by udev_list_entry_get_value().
 *
 * Returns: the first entry of the property list
 **/
_public_ struct udev_list_entry *udev_device_get_properties_list_entry(struct udev_device *udev_device)
{
        if (udev_device == NULL)
                return NULL;
        if (!udev_device->info_loaded) {
                udev_device_read_uevent_file(udev_device);
                udev_device_read_db(udev_device, NULL);
        }
        if (!udev_device->devlinks_uptodate) {
                char symlinks[UTIL_PATH_SIZE];
                struct udev_list_entry *list_entry;

                udev_device->devlinks_uptodate = true;
                list_entry = udev_device_get_devlinks_list_entry(udev_device);
                if (list_entry != NULL) {
                        char *s;
                        size_t l;

                        s = symlinks;
                        l = strpcpyl(&s, sizeof(symlinks), udev_list_entry_get_name(list_entry), NULL);
                        udev_list_entry_foreach(list_entry, udev_list_entry_get_next(list_entry))
                                l = strpcpyl(&s, l, " ", udev_list_entry_get_name(list_entry), NULL);
                        udev_device_add_property(udev_device, "DEVLINKS", symlinks);
                }
        }
        if (!udev_device->tags_uptodate) {
                udev_device->tags_uptodate = true;
                if (udev_device_get_tags_list_entry(udev_device) != NULL) {
                        char tags[UTIL_PATH_SIZE];
                        struct udev_list_entry *list_entry;
                        char *s;
                        size_t l;

                        s = tags;
                        l = strpcpyl(&s, sizeof(tags), ":", NULL);
                        udev_list_entry_foreach(list_entry, udev_device_get_tags_list_entry(udev_device))
                                l = strpcpyl(&s, l, udev_list_entry_get_name(list_entry), ":", NULL);
                        udev_device_add_property(udev_device, "TAGS", tags);
                }
        }
        return udev_list_get_entry(&udev_device->properties_list);
}

/**
 * udev_device_get_action:
 * @udev_device: udev device
 *
 * This is only valid if the device was received through a monitor. Devices read from
 * sys do not have an action string. Usual actions are: add, remove, change, online,
 * offline.
 *
 * Returns: the kernel action value, or #NULL if there is no action value available.
 **/
_public_ const char *udev_device_get_action(struct udev_device *udev_device)
{
        if (udev_device == NULL)
                return NULL;
        return udev_device->action;
}

/**
 * udev_device_get_usec_since_initialized:
 * @udev_device: udev device
 *
 * Return the number of microseconds passed since udev set up the
 * device for the first time.
 *
 * This is only implemented for devices with need to store properties
 * in the udev database. All other devices return 0 here.
 *
 * Returns: the number of microseconds since the device was first seen.
 **/
_public_ unsigned long long int udev_device_get_usec_since_initialized(struct udev_device *udev_device)
{
        usec_t now_ts;

        if (udev_device == NULL)
                return 0;
        if (!udev_device->info_loaded)
                udev_device_read_db(udev_device, NULL);
        if (udev_device->usec_initialized == 0)
                return 0;
        now_ts = now(CLOCK_MONOTONIC);
        if (now_ts == 0)
                return 0;
        return now_ts - udev_device->usec_initialized;
}

usec_t udev_device_get_usec_initialized(struct udev_device *udev_device)
{
        return udev_device->usec_initialized;
}

void udev_device_set_usec_initialized(struct udev_device *udev_device, usec_t usec_initialized)
{
        char num[32];

        udev_device->usec_initialized = usec_initialized;
        snprintf(num, sizeof(num), USEC_FMT, usec_initialized);
        udev_device_add_property(udev_device, "USEC_INITIALIZED", num);
}

/**
 * udev_device_get_sysattr_value:
 * @udev_device: udev device
 * @sysattr: attribute name
 *
 * The retrieved value is cached in the device. Repeated calls will return the same
 * value and not open the attribute again.
 *
 * Returns: the content of a sys attribute file, or #NULL if there is no sys attribute value.
 **/
_public_ const char *udev_device_get_sysattr_value(struct udev_device *udev_device, const char *sysattr)
{
        struct udev_list_entry *list_entry;
        char path[UTIL_PATH_SIZE];
        char value[4096];
        struct stat statbuf;
        int fd;
        ssize_t size;
        const char *val = NULL;

        if (udev_device == NULL)
                return NULL;
        if (sysattr == NULL)
                return NULL;

        /* look for possibly already cached result */
        list_entry = udev_list_get_entry(&udev_device->sysattr_value_list);
        list_entry = udev_list_entry_get_by_name(list_entry, sysattr);
        if (list_entry != NULL)
                return udev_list_entry_get_value(list_entry);

        strscpyl(path, sizeof(path), udev_device_get_syspath(udev_device), "/", sysattr, NULL);
        if (lstat(path, &statbuf) != 0) {
                udev_list_entry_add(&udev_device->sysattr_value_list, sysattr, NULL);
                goto out;
        }

        if (S_ISLNK(statbuf.st_mode)) {
                /*
                 * Some core links return only the last element of the target path,
                 * these are just values, the paths should not be exposed.
                 */
                if (streq(sysattr, "driver") ||
                    streq(sysattr, "subsystem") ||
                    streq(sysattr, "module")) {
                        if (util_get_sys_core_link_value(udev_device->udev, sysattr,
                                                         udev_device->syspath, value, sizeof(value)) < 0)
                                return NULL;
                        list_entry = udev_list_entry_add(&udev_device->sysattr_value_list, sysattr, value);
                        val = udev_list_entry_get_value(list_entry);
                        goto out;
                }

                goto out;
        }

        /* skip directories */
        if (S_ISDIR(statbuf.st_mode))
                goto out;

        /* skip non-readable files */
        if ((statbuf.st_mode & S_IRUSR) == 0)
                goto out;

        /* read attribute value */
        fd = open(path, O_RDONLY|O_CLOEXEC);
        if (fd < 0)
                goto out;
        size = read(fd, value, sizeof(value));
        close(fd);
        if (size < 0)
                goto out;
        if (size == sizeof(value))
                goto out;

        /* got a valid value, store it in cache and return it */
        value[size] = '\0';
        util_remove_trailing_chars(value, '\n');
        list_entry = udev_list_entry_add(&udev_device->sysattr_value_list, sysattr, value);
        val = udev_list_entry_get_value(list_entry);
out:
        return val;
}

/**
 * udev_device_set_sysattr_value:
 * @udev_device: udev device
 * @sysattr: attribute name
 * @value: new value to be set
 *
 * Update the contents of the sys attribute and the cached value of the device.
 *
 * Returns: Negative error code on failure or 0 on success.
 **/
_public_ int udev_device_set_sysattr_value(struct udev_device *udev_device, const char *sysattr, char *value)
{
        struct udev_device *dev;
        char path[UTIL_PATH_SIZE];
        struct stat statbuf;
        int fd;
        ssize_t size, value_len;
        int ret = 0;

        if (udev_device == NULL)
                return -EINVAL;
        dev = udev_device;
        if (sysattr == NULL)
                return -EINVAL;
        if (value == NULL)
                value_len = 0;
        else
                value_len = strlen(value);

        strscpyl(path, sizeof(path), udev_device_get_syspath(dev), "/", sysattr, NULL);
        if (lstat(path, &statbuf) != 0) {
                udev_list_entry_add(&dev->sysattr_value_list, sysattr, NULL);
                ret = -ENXIO;
                goto out;
        }

        if (S_ISLNK(statbuf.st_mode)) {
                ret = -EINVAL;
                goto out;
        }

        /* skip directories */
        if (S_ISDIR(statbuf.st_mode)) {
                ret = -EISDIR;
                goto out;
        }

        /* skip non-readable files */
        if ((statbuf.st_mode & S_IRUSR) == 0) {
                ret = -EACCES;
                goto out;
        }

        /* Value is limited to 4k */
        if (value_len > 4096) {
                ret = -EINVAL;
                goto out;
        }
        util_remove_trailing_chars(value, '\n');

        /* write attribute value */
        fd = open(path, O_WRONLY|O_CLOEXEC);
        if (fd < 0) {
                ret = -errno;
                goto out;
        }
        size = write(fd, value, value_len);
        close(fd);
        if (size < 0) {
                ret = -errno;
                goto out;
        }
        if (size < value_len) {
                ret = -EIO;
                goto out;
        }

        /* wrote a valid value, store it in cache and return it */
        udev_list_entry_add(&dev->sysattr_value_list, sysattr, value);
out:
        if (dev != udev_device)
                udev_device_unref(dev);
        return ret;
}

static int udev_device_sysattr_list_read(struct udev_device *udev_device)
{
        struct dirent *dent;
        DIR *dir;
        int num = 0;

        if (udev_device == NULL)
                return -EINVAL;
        if (udev_device->sysattr_list_read)
                return 0;

        dir = opendir(udev_device_get_syspath(udev_device));
        if (!dir)
                return -errno;

        for (dent = readdir(dir); dent != NULL; dent = readdir(dir)) {
                char path[UTIL_PATH_SIZE];
                struct stat statbuf;

                /* only handle symlinks and regular files */
                if (dent->d_type != DT_LNK && dent->d_type != DT_REG)
                        continue;

                strscpyl(path, sizeof(path), udev_device_get_syspath(udev_device), "/", dent->d_name, NULL);
                if (lstat(path, &statbuf) != 0)
                        continue;
                if ((statbuf.st_mode & S_IRUSR) == 0)
                        continue;

                udev_list_entry_add(&udev_device->sysattr_list, dent->d_name, NULL);
                num++;
        }

        closedir(dir);
        udev_device->sysattr_list_read = true;

        return num;
}

/**
 * udev_device_get_sysattr_list_entry:
 * @udev_device: udev device
 *
 * Retrieve the list of available sysattrs, with value being empty;
 * This just return all available sysfs attributes for a particular
 * device without reading their values.
 *
 * Returns: the first entry of the property list
 **/
_public_ struct udev_list_entry *udev_device_get_sysattr_list_entry(struct udev_device *udev_device)
{
        if (!udev_device->sysattr_list_read) {
                int ret;
                ret = udev_device_sysattr_list_read(udev_device);
                if (0 > ret)
                        return NULL;
        }

        return udev_list_get_entry(&udev_device->sysattr_list);
}

int udev_device_set_syspath(struct udev_device *udev_device, const char *syspath)
{
        const char *pos;
        size_t len;

        free(udev_device->syspath);
        udev_device->syspath = strdup(syspath);
        if (udev_device->syspath ==  NULL)
                return -ENOMEM;
        udev_device->devpath = udev_device->syspath + strlen("/sys");
        udev_device_add_property(udev_device, "DEVPATH", udev_device->devpath);

        pos = strrchr(udev_device->syspath, '/');
        if (pos == NULL)
                return -EINVAL;
        udev_device->sysname = strdup(&pos[1]);
        if (udev_device->sysname == NULL)
                return -ENOMEM;

        /* some devices have '!' in their name, change that to '/' */
        len = 0;
        while (udev_device->sysname[len] != '\0') {
                if (udev_device->sysname[len] == '!')
                        udev_device->sysname[len] = '/';
                len++;
        }

        /* trailing number */
        while (len > 0 && isdigit(udev_device->sysname[--len]))
                udev_device->sysnum = &udev_device->sysname[len];

        /* sysname is completely numeric */
        if (len == 0)
                udev_device->sysnum = NULL;

        return 0;
}

static int udev_device_set_devnode(struct udev_device *udev_device, const char *devnode)
{
        free(udev_device->devnode);
        if (devnode[0] != '/') {
                if (asprintf(&udev_device->devnode, "/dev/%s", devnode) < 0)
                        udev_device->devnode = NULL;
        } else {
                udev_device->devnode = strdup(devnode);
        }
        if (udev_device->devnode == NULL)
                return -ENOMEM;
        udev_device_add_property(udev_device, "DEVNAME", udev_device->devnode);
        return 0;
}

int udev_device_add_devlink(struct udev_device *udev_device, const char *devlink)
{
        struct udev_list_entry *list_entry;

        udev_device->devlinks_uptodate = false;
        list_entry = udev_list_entry_add(&udev_device->devlinks_list, devlink, NULL);
        if (list_entry == NULL)
                return -ENOMEM;
        return 0;
}

const char *udev_device_get_id_filename(struct udev_device *udev_device)
{
        if (udev_device->id_filename == NULL) {
                if (udev_device_get_subsystem(udev_device) == NULL)
                        return NULL;

                if (major(udev_device_get_devnum(udev_device)) > 0) {
                        /* use dev_t -- b259:131072, c254:0 */
                        if (asprintf(&udev_device->id_filename, "%c%u:%u",
                                     streq(udev_device_get_subsystem(udev_device), "block") ? 'b' : 'c',
                                     major(udev_device_get_devnum(udev_device)),
                                     minor(udev_device_get_devnum(udev_device))) < 0)
                                udev_device->id_filename = NULL;
                } else if (udev_device_get_ifindex(udev_device) > 0) {
                        /* use netdev ifindex -- n3 */
                        if (asprintf(&udev_device->id_filename, "n%u", udev_device_get_ifindex(udev_device)) < 0)
                                udev_device->id_filename = NULL;
                } else {
                        /*
                         * use $subsys:$syname -- pci:0000:00:1f.2
                         * sysname() has '!' translated, get it from devpath
                         */
                        const char *sysname;
                        sysname = strrchr(udev_device->devpath, '/');
                        if (sysname == NULL)
                                return NULL;
                        sysname = &sysname[1];
                        if (asprintf(&udev_device->id_filename, "+%s:%s", udev_device_get_subsystem(udev_device), sysname) < 0)
                                udev_device->id_filename = NULL;
                }
        }
        return udev_device->id_filename;
}

/**
 * udev_device_get_is_initialized:
 * @udev_device: udev device
 *
 * Check if udev has already handled the device and has set up
 * device node permissions and context, or has renamed a network
 * device.
 *
 * This is only implemented for devices with a device node
 * or network interfaces. All other devices return 1 here.
 *
 * Returns: 1 if the device is set up. 0 otherwise.
 **/
_public_ int udev_device_get_is_initialized(struct udev_device *udev_device)
{
        if (!udev_device->info_loaded)
                udev_device_read_db(udev_device, NULL);
        return udev_device->is_initialized;
}

void udev_device_set_is_initialized(struct udev_device *udev_device)
{
        udev_device->is_initialized = true;
}

int udev_device_add_tag(struct udev_device *udev_device, const char *tag)
{
        if (strchr(tag, ':') != NULL || strchr(tag, ' ') != NULL)
                return -EINVAL;
        udev_device->tags_uptodate = false;
        if (udev_list_entry_add(&udev_device->tags_list, tag, NULL) != NULL)
                return 0;
        return -ENOMEM;
}

void udev_device_cleanup_tags_list(struct udev_device *udev_device)
{
        udev_device->tags_uptodate = false;
        udev_list_cleanup(&udev_device->tags_list);
}

/**
 * udev_device_get_tags_list_entry:
 * @udev_device: udev device
 *
 * Retrieve the list of tags attached to the udev device. The next
 * list entry can be retrieved with udev_list_entry_get_next(),
 * which returns #NULL if no more entries exist. The tag string
 * can be retrieved from the list entry by udev_list_entry_get_name().
 *
 * Returns: the first entry of the tag list
 **/
_public_ struct udev_list_entry *udev_device_get_tags_list_entry(struct udev_device *udev_device)
{
        if (udev_device == NULL)
                return NULL;
        if (!udev_device->info_loaded)
                udev_device_read_db(udev_device, NULL);
        return udev_list_get_entry(&udev_device->tags_list);
}

/**
 * udev_device_has_tag:
 * @udev_device: udev device
 * @tag: tag name
 *
 * Check if a given device has a certain tag associated.
 *
 * Returns: 1 if the tag is found. 0 otherwise.
 **/
_public_ int udev_device_has_tag(struct udev_device *udev_device, const char *tag)
{
        struct udev_list_entry *list_entry;

        if (udev_device == NULL)
                return false;
        if (!udev_device->info_loaded)
                udev_device_read_db(udev_device, NULL);
        list_entry = udev_device_get_tags_list_entry(udev_device);
        if (udev_list_entry_get_by_name(list_entry, tag) != NULL)
                return true;
        return false;
}

#define ENVP_SIZE                        128
#define MONITOR_BUF_SIZE                4096
static int update_envp_monitor_buf(struct udev_device *udev_device)
{
        struct udev_list_entry *list_entry;
        char *s;
        size_t l;
        unsigned int i;

        /* monitor buffer of property strings */
        free(udev_device->monitor_buf);
        udev_device->monitor_buf_len = 0;
        udev_device->monitor_buf = malloc(MONITOR_BUF_SIZE);
        if (udev_device->monitor_buf == NULL)
                return -ENOMEM;

        /* envp array, strings will point into monitor buffer */
        if (udev_device->envp == NULL)
                udev_device->envp = malloc(sizeof(char *) * ENVP_SIZE);
        if (udev_device->envp == NULL)
                return -ENOMEM;

        i = 0;
        s = udev_device->monitor_buf;
        l = MONITOR_BUF_SIZE;
        udev_list_entry_foreach(list_entry, udev_device_get_properties_list_entry(udev_device)) {
                const char *key;

                key = udev_list_entry_get_name(list_entry);
                /* skip private variables */
                if (key[0] == '.')
                        continue;

                /* add string to envp array */
                udev_device->envp[i++] = s;
                if (i+1 >= ENVP_SIZE)
                        return -EINVAL;

                /* add property string to monitor buffer */
                l = strpcpyl(&s, l, key, "=", udev_list_entry_get_value(list_entry), NULL);
                if (l == 0)
                        return -EINVAL;
                /* advance past the trailing '\0' that strpcpyl() guarantees */
                s++;
                l--;
        }
        udev_device->envp[i] = NULL;
        udev_device->monitor_buf_len = s - udev_device->monitor_buf;
        udev_device->envp_uptodate = true;
        return 0;
}

char **udev_device_get_properties_envp(struct udev_device *udev_device)
{
        if (!udev_device->envp_uptodate)
                if (update_envp_monitor_buf(udev_device) != 0)
                        return NULL;
        return udev_device->envp;
}

ssize_t udev_device_get_properties_monitor_buf(struct udev_device *udev_device, const char **buf)
{
        if (!udev_device->envp_uptodate)
                if (update_envp_monitor_buf(udev_device) != 0)
                        return -EINVAL;
        *buf = udev_device->monitor_buf;
        return udev_device->monitor_buf_len;
}

int udev_device_set_action(struct udev_device *udev_device, const char *action)
{
        free(udev_device->action);
        udev_device->action = strdup(action);
        if (udev_device->action == NULL)
                return -ENOMEM;
        udev_device_add_property(udev_device, "ACTION", udev_device->action);
        return 0;
}

int udev_device_get_devlink_priority(struct udev_device *udev_device)
{
        if (!udev_device->info_loaded)
                udev_device_read_db(udev_device, NULL);
        return udev_device->devlink_priority;
}

int udev_device_set_devlink_priority(struct udev_device *udev_device, int prio)
{
         udev_device->devlink_priority = prio;
        return 0;
}

int udev_device_get_watch_handle(struct udev_device *udev_device)
{
        if (!udev_device->info_loaded)
                udev_device_read_db(udev_device, NULL);
        return udev_device->watch_handle;
}

int udev_device_set_watch_handle(struct udev_device *udev_device, int handle)
{
        udev_device->watch_handle = handle;
        return 0;
}

bool udev_device_get_db_persist(struct udev_device *udev_device)
{
        return udev_device->db_persist;
}

void udev_device_set_db_persist(struct udev_device *udev_device)
{
        udev_device->db_persist = true;
}
