#pragma once

/***
  This file is part of systemd.

  Copyright 2016 Lennart Poettering

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

#include <stdbool.h>

#include "macro.h"

typedef struct DissectedImage DissectedImage;
typedef struct DissectedPartition DissectedPartition;

struct DissectedPartition {
        bool found:1;
        bool rw:1;
        int partno;        /* -1 if there was no partition and the images contains a file system directly */
        int architecture;  /* Intended architecture: either native, secondary or unset (-1). */
        char *fstype;
        char *node;
};

enum  {
        PARTITION_ROOT,
        PARTITION_ROOT_SECONDARY,  /* Secondary architecture */
        PARTITION_HOME,
        PARTITION_SRV,
        PARTITION_ESP,
        PARTITION_SWAP,
        _PARTITION_DESIGNATOR_MAX,
        _PARTITION_DESIGNATOR_INVALID = -1
};

typedef enum DissectedImageMountFlags {
        DISSECTED_IMAGE_READ_ONLY = 1,
        DISSECTED_IMAGE_DISCARD_ON_LOOP = 2, /* Turn on "discard" if on loop device and file system supports it */
} DissectedImageMountFlags;

struct DissectedImage {
        DissectedPartition partitions[_PARTITION_DESIGNATOR_MAX];
};

int dissect_image(int fd, DissectedImage **ret);

DissectedImage* dissected_image_unref(DissectedImage *m);
DEFINE_TRIVIAL_CLEANUP_FUNC(DissectedImage*, dissected_image_unref);

int dissected_image_mount(DissectedImage *m, const char *dest, DissectedImageMountFlags flags);

const char* partition_designator_to_string(int i) _const_;
int partition_designator_from_string(const char *name) _pure_;
