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
#include "lockfile-util.h"
#include "hashmap.h"

typedef enum ImageType {
        IMAGE_DIRECTORY,
        IMAGE_SUBVOLUME,
        IMAGE_RAW,
        _IMAGE_TYPE_MAX,
        _IMAGE_TYPE_INVALID = -1
} ImageType;

typedef struct Image {
        ImageType type;
        char *name;
        char *path;
        bool read_only;

        usec_t crtime;
        usec_t mtime;

        uint64_t usage;
        uint64_t usage_exclusive;
        uint64_t limit;
        uint64_t limit_exclusive;

        void *userdata;
} Image;

Image *image_unref(Image *i);
void image_hashmap_free(Hashmap *map);

DEFINE_TRIVIAL_CLEANUP_FUNC(Image*, image_unref);
DEFINE_TRIVIAL_CLEANUP_FUNC(Hashmap*, image_hashmap_free);

int image_find(const char *name, Image **ret);
int image_discover(Hashmap *map);

int image_remove(Image *i);
int image_rename(Image *i, const char *new_name);
int image_clone(Image *i, const char *new_name, bool read_only);
int image_read_only(Image *i, bool b);

const char* image_type_to_string(ImageType t) _const_;
ImageType image_type_from_string(const char *s) _pure_;

bool image_name_is_valid(const char *s) _pure_;

int image_path_lock(const char *path, int operation, LockFile *global, LockFile *local);
int image_name_lock(const char *name, int operation, LockFile *ret);

int image_set_limit(Image *i, uint64_t referenced_max);
