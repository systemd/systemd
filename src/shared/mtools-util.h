/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

/* Wrappers around the mtools commands, for manipulating FAT file systems without mounting them. The 'node'
 * parameter is what mtools' -i switch takes: a block device or image file, optionally followed by "@@" and a
 * byte offset into it, for a file system that lives in a partition of a larger image. */

/* Copies the whole directory tree 'root' into the file system, in deterministic order */
int mtools_copy_tree(const char *node, const char *root);

/* Creates the specified directory in the file system, and its parents, if they don't exist yet */
int mtools_mkdir(const char *node, const char *path);

/* Copies a single file into the file system, replacing a file of the same name */
int mtools_copy_file(const char *node, const char *source, const char *dest);
