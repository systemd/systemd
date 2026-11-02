/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

/* Manipulates FAT file systems without mounting them. The file system lives in the block device or image
 * file 'path', at byte offset 'offset' into it, for a file system in a partition of a larger image. Currently
 * implemented by shelling out to mtools. */

/* Copies the whole directory tree 'root' into the file system, in deterministic order */
int vfat_copy_tree(const char *path, uint64_t offset, const char *root);

/* Creates the specified directory in the file system, and its parents, if they don't exist yet */
int vfat_mkdir(const char *path, uint64_t offset, const char *dir);

/* Copies a single file into the file system, replacing a file of the same name */
int vfat_copy_file(const char *path, uint64_t offset, const char *source, const char *dest);
