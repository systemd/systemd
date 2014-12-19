/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

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

#include "time-util.h"
#include "hashmap.h"
#include "machined.h"

typedef enum ImageType {
        IMAGE_DIRECTORY,
        IMAGE_SUBVOLUME,
        IMAGE_GPT,
        _IMAGE_TYPE_MAX,
        _IMAGE_TYPE_INVALID = -1
} ImageType;

typedef struct Image {
        ImageType type;
        char *name;
        char *path;
        bool read_only;

        usec_t mtime;
        usec_t btime;
} Image;

Image *image_unref(Image *i);
void image_hashmap_free(Hashmap *map);

DEFINE_TRIVIAL_CLEANUP_FUNC(Image*, image_unref);
DEFINE_TRIVIAL_CLEANUP_FUNC(Hashmap*, image_hashmap_free);

int image_find(const char *name, Image **ret);
int image_discover(Hashmap *map);

extern const sd_bus_vtable image_vtable[];

char *image_bus_path(const char *name);

int image_object_find(sd_bus *bus, const char *path, const char *interface, void *userdata, void **found, sd_bus_error *error);
int image_node_enumerator(sd_bus *bus, const char *path, void *userdata, char ***nodes, sd_bus_error *error);

const char* image_type_to_string(ImageType t) _const_;
ImageType image_type_from_string(const char *s) _pure_;
