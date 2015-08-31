/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2014 Lennart Poettering

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

#include "bus-label.h"
#include "strv.h"
#include "bus-util.h"
#include "machine-image.h"
#include "image-dbus.h"

static BUS_DEFINE_PROPERTY_GET_ENUM(property_get_type, image_type, ImageType);

int bus_image_method_remove(
                sd_bus_message *message,
                void *userdata,
                sd_bus_error *error) {

        Image *image = userdata;
        Manager *m = image->userdata;
        int r;

        assert(message);
        assert(image);

        r = bus_verify_polkit_async(
                        message,
                        CAP_SYS_ADMIN,
                        "org.freedesktop.machine1.manage-images",
                        NULL,
                        false,
                        UID_INVALID,
                        &m->polkit_registry,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* Will call us back */

        r = image_remove(image);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, NULL);
}

int bus_image_method_rename(
                sd_bus_message *message,
                void *userdata,
                sd_bus_error *error) {

        Image *image = userdata;
        Manager *m = image->userdata;
        const char *new_name;
        int r;

        assert(message);
        assert(image);

        r = sd_bus_message_read(message, "s", &new_name);
        if (r < 0)
                return r;

        if (!image_name_is_valid(new_name))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Image name '%s' is invalid.", new_name);

        r = bus_verify_polkit_async(
                        message,
                        CAP_SYS_ADMIN,
                        "org.freedesktop.machine1.manage-images",
                        NULL,
                        false,
                        UID_INVALID,
                        &m->polkit_registry,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* Will call us back */

        r = image_rename(image, new_name);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, NULL);
}

int bus_image_method_clone(
                sd_bus_message *message,
                void *userdata,
                sd_bus_error *error) {

        Image *image = userdata;
        Manager *m = image->userdata;
        const char *new_name;
        int r, read_only;

        assert(message);
        assert(image);

        r = sd_bus_message_read(message, "sb", &new_name, &read_only);
        if (r < 0)
                return r;

        if (!image_name_is_valid(new_name))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Image name '%s' is invalid.", new_name);

        r = bus_verify_polkit_async(
                        message,
                        CAP_SYS_ADMIN,
                        "org.freedesktop.machine1.manage-images",
                        NULL,
                        false,
                        UID_INVALID,
                        &m->polkit_registry,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* Will call us back */

        r = image_clone(image, new_name, read_only);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, NULL);
}

int bus_image_method_mark_read_only(
                sd_bus_message *message,
                void *userdata,
                sd_bus_error *error) {

        Image *image = userdata;
        Manager *m = image->userdata;
        int r, read_only;

        assert(message);

        r = sd_bus_message_read(message, "b", &read_only);
        if (r < 0)
                return r;

        r = bus_verify_polkit_async(
                        message,
                        CAP_SYS_ADMIN,
                        "org.freedesktop.machine1.manage-images",
                        NULL,
                        false,
                        UID_INVALID,
                        &m->polkit_registry,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* Will call us back */

        r = image_read_only(image, read_only);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, NULL);
}

int bus_image_method_set_limit(
                sd_bus_message *message,
                void *userdata,
                sd_bus_error *error) {

        Image *image = userdata;
        Manager *m = image->userdata;
        uint64_t limit;
        int r;

        assert(message);

        r = sd_bus_message_read(message, "t", &limit);
        if (r < 0)
                return r;

        r = bus_verify_polkit_async(
                        message,
                        CAP_SYS_ADMIN,
                        "org.freedesktop.machine1.manage-images",
                        NULL,
                        false,
                        UID_INVALID,
                        &m->polkit_registry,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* Will call us back */

        r = image_set_limit(image, limit);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, NULL);
}

const sd_bus_vtable image_vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_PROPERTY("Name", "s", NULL, offsetof(Image, name), 0),
        SD_BUS_PROPERTY("Path", "s", NULL, offsetof(Image, path), 0),
        SD_BUS_PROPERTY("Type", "s", property_get_type,  offsetof(Image, type), 0),
        SD_BUS_PROPERTY("ReadOnly", "b", bus_property_get_bool, offsetof(Image, read_only), 0),
        SD_BUS_PROPERTY("CreationTimestamp", "t", NULL, offsetof(Image, crtime), 0),
        SD_BUS_PROPERTY("ModificationTimestamp", "t", NULL, offsetof(Image, mtime), 0),
        SD_BUS_PROPERTY("Usage", "t", NULL, offsetof(Image, usage), 0),
        SD_BUS_PROPERTY("Limit", "t", NULL, offsetof(Image, limit), 0),
        SD_BUS_PROPERTY("UsageExclusive", "t", NULL, offsetof(Image, usage_exclusive), 0),
        SD_BUS_PROPERTY("LimitExclusive", "t", NULL, offsetof(Image, limit_exclusive), 0),
        SD_BUS_METHOD("Remove", NULL, NULL, bus_image_method_remove, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("Rename", "s", NULL, bus_image_method_rename, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("Clone", "sb", NULL, bus_image_method_clone, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("MarkReadOnly", "b", NULL, bus_image_method_mark_read_only, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("SetLimit", "t", NULL, bus_image_method_set_limit, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_VTABLE_END
};

static int image_flush_cache(sd_event_source *s, void *userdata) {
        Manager *m = userdata;
        Image *i;

        assert(s);
        assert(m);

        while ((i = hashmap_steal_first(m->image_cache)))
                image_unref(i);

        return 0;
}

int image_object_find(sd_bus *bus, const char *path, const char *interface, void *userdata, void **found, sd_bus_error *error) {
        _cleanup_free_ char *e = NULL;
        Manager *m = userdata;
        Image *image = NULL;
        const char *p;
        int r;

        assert(bus);
        assert(path);
        assert(interface);
        assert(found);

        p = startswith(path, "/org/freedesktop/machine1/image/");
        if (!p)
                return 0;

        e = bus_label_unescape(p);
        if (!e)
                return -ENOMEM;

        image = hashmap_get(m->image_cache, e);
        if (image) {
                *found = image;
                return 1;
        }

        r = hashmap_ensure_allocated(&m->image_cache, &string_hash_ops);
        if (r < 0)
                return r;

        if (!m->image_cache_defer_event) {
                r = sd_event_add_defer(m->event, &m->image_cache_defer_event, image_flush_cache, m);
                if (r < 0)
                        return r;

                r = sd_event_source_set_priority(m->image_cache_defer_event, SD_EVENT_PRIORITY_IDLE);
                if (r < 0)
                        return r;
        }

        r = sd_event_source_set_enabled(m->image_cache_defer_event, SD_EVENT_ONESHOT);
        if (r < 0)
                return r;

        r = image_find(e, &image);
        if (r <= 0)
                return r;

        image->userdata = m;

        r = hashmap_put(m->image_cache, image->name, image);
        if (r < 0) {
                image_unref(image);
                return r;
        }

        *found = image;
        return 1;
}

char *image_bus_path(const char *name) {
        _cleanup_free_ char *e = NULL;

        assert(name);

        e = bus_label_escape(name);
        if (!e)
                return NULL;

        return strappend("/org/freedesktop/machine1/image/", e);
}

int image_node_enumerator(sd_bus *bus, const char *path, void *userdata, char ***nodes, sd_bus_error *error) {
        _cleanup_(image_hashmap_freep) Hashmap *images = NULL;
        _cleanup_strv_free_ char **l = NULL;
        Image *image;
        Iterator i;
        int r;

        assert(bus);
        assert(path);
        assert(nodes);

        images = hashmap_new(&string_hash_ops);
        if (!images)
                return -ENOMEM;

        r = image_discover(images);
        if (r < 0)
                return r;

        HASHMAP_FOREACH(image, images, i) {
                char *p;

                p = image_bus_path(image->name);
                if (!p)
                        return -ENOMEM;

                r = strv_consume(&l, p);
                if (r < 0)
                        return r;
        }

        *nodes = l;
        l = NULL;

        return 1;
}
