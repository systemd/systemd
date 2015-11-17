/***
  This file is part of systemd.

  Copyright 2008-2012 Kay Sievers <kay@vrfy.org>
  Copyright 2015 Tom Gundersen <teg@jklm.no>

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

#include "libudev.h"

#include "device-private.h"
#include "libudev-device-internal.h"
#include "libudev-private.h"

int udev_device_tag_index(struct udev_device *udev_device, struct udev_device *udev_device_old, bool add) {
        sd_device *device_old = NULL;
        int r;

        assert(udev_device);

        if (udev_device_old)
                device_old = udev_device_old->device;

        r = device_tag_index(udev_device->device, device_old, add);
        if (r < 0)
                return r;

        return 0;
}

int udev_device_update_db(struct udev_device *udev_device) {
        int r;

        assert(udev_device);

        r = device_update_db(udev_device->device);
        if (r < 0)
                return r;

        return 0;
}

int udev_device_delete_db(struct udev_device *udev_device) {
        int r;

        assert(udev_device);

        r = device_delete_db(udev_device->device);
        if (r < 0)
                return r;

        return 0;
}

int udev_device_get_ifindex(struct udev_device *udev_device) {
        int r, ifindex;

        assert(udev_device);

        r = sd_device_get_ifindex(udev_device->device, &ifindex);
        if (r < 0)
                return r;

        return ifindex;
}

const char *udev_device_get_devpath_old(struct udev_device *udev_device) {
        const char *devpath_old = NULL;
        int r;

        assert(udev_device);

        r = sd_device_get_property_value(udev_device->device, "DEVPATH_OLD", &devpath_old);
        if (r < 0 && r != -ENOENT) {
                errno = -r;
                return NULL;
        }

        return devpath_old;
}

mode_t udev_device_get_devnode_mode(struct udev_device *udev_device) {
        mode_t mode;
        int r;

        assert(udev_device);

        r = device_get_devnode_mode(udev_device->device, &mode);
        if (r < 0) {
                errno = -r;
                return 0;
        }

        return mode;
}

uid_t udev_device_get_devnode_uid(struct udev_device *udev_device) {
        uid_t uid;
        int r;

        assert(udev_device);

        r = device_get_devnode_uid(udev_device->device, &uid);
        if (r < 0) {
                errno = -r;
                return 0;
        }

        return uid;
}

gid_t udev_device_get_devnode_gid(struct udev_device *udev_device) {
        gid_t gid;
        int r;

        assert(udev_device);

        r = device_get_devnode_gid(udev_device->device, &gid);
        if (r < 0) {
                errno = -r;
                return 0;
        }

        return gid;
}

void udev_device_ensure_usec_initialized(struct udev_device *udev_device, struct udev_device *udev_device_old) {
        sd_device *device_old = NULL;

        assert(udev_device);

        if (udev_device_old)
                device_old = udev_device_old->device;

        device_ensure_usec_initialized(udev_device->device, device_old);
}

char **udev_device_get_properties_envp(struct udev_device *udev_device) {
        char **envp;
        int r;

        assert(udev_device);

        r = device_get_properties_strv(udev_device->device, &envp);
        if (r < 0) {
                errno = -r;
                return NULL;
        }

        return envp;
}

ssize_t udev_device_get_properties_monitor_buf(struct udev_device *udev_device, const char **buf) {
        const char *nulstr;
        size_t len;
        int r;

        assert(udev_device);
        assert(buf);

        r = device_get_properties_nulstr(udev_device->device, (const uint8_t **)&nulstr, &len);
        if (r < 0)
                return r;

        *buf = nulstr;

        return len;
}

int udev_device_get_devlink_priority(struct udev_device *udev_device) {
        int priority, r;

        assert(udev_device);

        r = device_get_devlink_priority(udev_device->device, &priority);
        if (r < 0)
                return r;

        return priority;
}

int udev_device_get_watch_handle(struct udev_device *udev_device) {
        int handle, r;

        assert(udev_device);

        r = device_get_watch_handle(udev_device->device, &handle);
        if (r < 0)
                return r;

        return handle;
}

void udev_device_set_is_initialized(struct udev_device *udev_device) {
        assert(udev_device);

        device_set_is_initialized(udev_device->device);
}

int udev_device_rename(struct udev_device *udev_device, const char *name) {
        int r;

        assert(udev_device);

        r = device_rename(udev_device->device, name);
        if (r < 0)
                return r;

        return 0;
}

struct udev_device *udev_device_shallow_clone(struct udev_device *old_device) {
        struct udev_device *device;
        int r;

        assert(old_device);

        device = udev_device_new(old_device->udev);
        if (!device)
                return NULL;

        r = device_shallow_clone(old_device->device, &device->device);
        if (r < 0) {
                udev_device_unref(device);
                errno = -r;
                return NULL;
        }

        return device;
}

struct udev_device *udev_device_clone_with_db(struct udev_device *udev_device_old) {
        struct udev_device *udev_device;
        int r;

        assert(udev_device_old);

        udev_device = udev_device_new(udev_device_old->udev);
        if (!udev_device)
                return NULL;

        r = device_clone_with_db(udev_device_old->device, &udev_device->device);
        if (r < 0) {
                udev_device_unref(udev_device);
                errno = -r;
                return NULL;
        }

        return udev_device;
}

struct udev_device *udev_device_new_from_nulstr(struct udev *udev, char *nulstr, ssize_t buflen) {
        struct udev_device *device;
        int r;

        device = udev_device_new(udev);
        if (!device)
                return NULL;

        r = device_new_from_nulstr(&device->device, (uint8_t*)nulstr, buflen);
        if (r < 0) {
                udev_device_unref(device);
                errno = -r;
                return NULL;
        }

        return device;
}

struct udev_device *udev_device_new_from_synthetic_event(struct udev *udev, const char *syspath, const char *action) {
        struct udev_device *device;
        int r;

        device = udev_device_new(udev);
        if (!device)
                return NULL;

        r = device_new_from_synthetic_event(&device->device, syspath, action);
        if (r < 0) {
                udev_device_unref(device);
                errno = -r;
                return NULL;
        }

        return device;
}

int udev_device_copy_properties(struct udev_device *udev_device_dst, struct udev_device *udev_device_src) {
        int r;

        assert(udev_device_dst);
        assert(udev_device_src);

        r = device_copy_properties(udev_device_dst->device, udev_device_src->device);
        if (r < 0)
                return r;

        return 0;
}

const char *udev_device_get_id_filename(struct udev_device *udev_device) {
        const char *filename;
        int r;

        assert(udev_device);

        r = device_get_id_filename(udev_device->device, &filename);
        if (r < 0) {
                errno = -r;
                return NULL;
        }

        return filename;
}

int udev_device_set_watch_handle(struct udev_device *udev_device, int handle) {

        assert(udev_device);

        device_set_watch_handle(udev_device->device, handle);

        return 0;
}

void udev_device_set_db_persist(struct udev_device *udev_device) {
        assert(udev_device);

        device_set_db_persist(udev_device->device);
}

int udev_device_set_devlink_priority(struct udev_device *udev_device, int priority) {
        assert(udev_device);

        device_set_devlink_priority(udev_device->device, priority);

        return 0;
}

int udev_device_add_devlink(struct udev_device *udev_device, const char *devlink) {
        int r;

        assert(udev_device);

        r = device_add_devlink(udev_device->device, devlink);
        if (r < 0)
                return r;

        return 0;
}

int udev_device_add_property(struct udev_device *udev_device, const char *property, const char *value) {
        int r;

        assert(udev_device);

        r = device_add_property(udev_device->device, property, value);
        if (r < 0)
                return r;

        return 0;
}

int udev_device_add_tag(struct udev_device *udev_device, const char *tag) {
        int r;

        assert(udev_device);

        r = device_add_tag(udev_device->device, tag);
        if (r < 0)
                return r;

        return 0;
}

void udev_device_remove_tag(struct udev_device *udev_device, const char *tag) {
        assert(udev_device);

        device_remove_tag(udev_device->device, tag);
}

void udev_device_cleanup_tags_list(struct udev_device *udev_device) {
        assert(udev_device);

        device_cleanup_tags(udev_device->device);
}

void udev_device_cleanup_devlinks_list(struct udev_device *udev_device) {
        assert(udev_device);

        device_cleanup_devlinks(udev_device->device);
}

void udev_device_set_info_loaded(struct udev_device *udev_device) {
        assert(udev_device);

        device_seal(udev_device->device);
}

void udev_device_read_db(struct udev_device *udev_device) {
        assert(udev_device);

        device_read_db_force(udev_device->device);
}
