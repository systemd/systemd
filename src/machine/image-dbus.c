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
#include "bus-common-errors.h"
#include "strv.h"
#include "machine-image.h"
#include "image-dbus.h"

static int image_find_by_bus_path(const char *path, Image **ret) {
        _cleanup_free_ char *e = NULL;
        const char *p;

        assert(path);

        p = startswith(path, "/org/freedesktop/machine1/image/");
        if (!p)
                return 0;

        e = bus_label_unescape(p);
        if (!e)
                return -ENOMEM;

        return image_find(e, ret);
}

static int image_find_by_bus_path_with_error(const char *path, Image **ret, sd_bus_error *error) {
        int r;

        assert(path);

        r = image_find_by_bus_path(path, ret);
        if (r == 0)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_IMAGE, "Image doesn't exist.");

        return r;
}

static int property_get_name(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        _cleanup_(image_unrefp) Image *image = NULL;
        int r;

        assert(bus);
        assert(reply);

        r = image_find_by_bus_path_with_error(path, &image, error);
        if (r < 0)
                return r;

        r = sd_bus_message_append(reply, "s", image->name);
        if (r < 0)
                return r;

        return 1;
}

static int property_get_path(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        _cleanup_(image_unrefp) Image *image = NULL;
        int r;

        assert(bus);
        assert(reply);

        r = image_find_by_bus_path_with_error(path, &image, error);
        if (r < 0)
                return r;

        r = sd_bus_message_append(reply, "s", image->path);
        if (r < 0)
                return r;

        return 1;
}

static int property_get_type(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {


        _cleanup_(image_unrefp) Image *image = NULL;
        int r;

        assert(bus);
        assert(reply);

        r = image_find_by_bus_path_with_error(path, &image, error);
        if (r < 0)
                return r;

        r = sd_bus_message_append(reply, "s", image_type_to_string(image->type));
        if (r < 0)
                return r;

        return 1;
}

static int property_get_read_only(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {


        _cleanup_(image_unrefp) Image *image = NULL;
        int r;

        assert(bus);
        assert(reply);

        r = image_find_by_bus_path_with_error(path, &image, error);
        if (r < 0)
                return r;

        r = sd_bus_message_append(reply, "b", image->read_only);
        if (r < 0)
                return r;

        return 1;
}

static int property_get_crtime(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {


        _cleanup_(image_unrefp) Image *image = NULL;
        int r;

        assert(bus);
        assert(reply);

        r = image_find_by_bus_path_with_error(path, &image, error);
        if (r < 0)
                return r;

        r = sd_bus_message_append(reply, "t", image->crtime);
        if (r < 0)
                return r;

        return 1;
}

static int property_get_mtime(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {


        _cleanup_(image_unrefp) Image *image = NULL;
        int r;

        assert(bus);
        assert(reply);

        r = image_find_by_bus_path_with_error(path, &image, error);
        if (r < 0)
                return r;

        r = sd_bus_message_append(reply, "t", image->mtime);
        if (r < 0)
                return r;

        return 1;
}

const sd_bus_vtable image_vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_PROPERTY("Name",                  "s", property_get_name,      0, 0),
        SD_BUS_PROPERTY("Path",                  "s", property_get_path,      0, 0),
        SD_BUS_PROPERTY("Type",                  "s", property_get_type,      0, 0),
        SD_BUS_PROPERTY("ReadOnly",              "b", property_get_read_only, 0, 0),
        SD_BUS_PROPERTY("CreationTimestamp",     "t", property_get_crtime,    0, 0),
        SD_BUS_PROPERTY("ModificationTimestamp", "t", property_get_mtime,     0, 0),
        SD_BUS_VTABLE_END
};

int image_object_find(sd_bus *bus, const char *path, const char *interface, void *userdata, void **found, sd_bus_error *error) {
        int r;

        assert(bus);
        assert(path);
        assert(interface);
        assert(found);

        r = image_find_by_bus_path(path, NULL);
        if (r <= 0)
                return r;

        *found = NULL;
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
