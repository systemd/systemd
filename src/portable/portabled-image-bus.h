/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-bus.h"

#include "discover-image.h"
#include "portabled.h"

int bus_image_common_get_os_release(Manager *m, sd_bus_message *message, const char *name_or_path, Image *image, sd_bus_error *error);
int bus_image_common_get_metadata(Manager *m, sd_bus_message *message, const char *name_or_path, Image *image, sd_bus_error *error);
int bus_image_common_attach(Manager *m, sd_bus_message *message, const char *name_or_path, Image *image, sd_bus_error *error);
int bus_image_common_remove(Manager *m, sd_bus_message *message, const char *name_or_path, Image *image, sd_bus_error *error);
int bus_image_common_reattach(Manager *m, sd_bus_message *message, const char *name_or_path, Image *image, sd_bus_error *error);
int bus_image_common_mark_read_only(Manager *m, sd_bus_message *message, const char *name_or_path, Image *image, sd_bus_error *error);
int bus_image_common_set_limit(Manager *m, sd_bus_message *message, const char *name_or_path, Image *image, sd_bus_error *error);

extern const sd_bus_vtable image_vtable[];
extern const BusObjectImplementation image_object;

int bus_image_path(Image *image, char **ret);

/* So here's some complexity: some of operations can either take an image name, or a fully qualified file system path
 * to an image. We need to authenticate differently when processing these two: images referenced via simple image names
 * mean the images are located in the image search path and thus safe for limited read access for unprivileged
 * clients. For operations on images located anywhere else we need explicit authentication however, so that
 * unprivileged clients can't make us open arbitrary files in the file system.
 *
 * The "Image" bus objects directly represent images in the image search path, but do not exist for path-referenced
 * images. Hence, when requesting a bus object we need to refuse references by file system path, but still allow
 * references by image name. Depending on the operation to execute potentially we need to authenticate in all cases. */

typedef enum ImageAcquireMode {
        BUS_IMAGE_REFUSE_BY_PATH,            /* allow by name  + prohibit by path */
        BUS_IMAGE_AUTHENTICATE_BY_PATH,      /* allow by name  + polkit by path */
        BUS_IMAGE_AUTHENTICATE_ALL,          /* polkit by name + polkit by path */
        _BUS_IMAGE_ACQUIRE_MODE_MAX,
        _BUS_IMAGE_ACQUIRE_MODE_INVALID = -EINVAL,
} ImageAcquireMode;

int bus_image_acquire(Manager *m, sd_bus_message *message, const char *name_or_path, Image *image, ImageAcquireMode mode, const char *polkit_action, Image **ret, sd_bus_error *error);

int bus_image_object_find(sd_bus *bus, const char *path, const char *interface, void *userdata, void **found, sd_bus_error *error);
int bus_image_node_enumerator(sd_bus *bus, const char *path, void *userdata, char ***nodes, sd_bus_error *error);
