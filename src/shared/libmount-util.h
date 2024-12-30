/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* This needs to be after sys/mount.h */
#include <libmount/libmount.h>

#include "macro.h"

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(struct libmnt_table*, mnt_free_table, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(struct libmnt_iter*, mnt_free_iter, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(struct libmnt_cache*, mnt_unref_cache, NULL);

int libmount_parse(
                const char *path,
                FILE *source,
                struct libmnt_table **ret_table,
                struct libmnt_iter **ret_iter);

/* If /proc/self/mountinfo contains an entry like /dev/root, then libmount will
 * try to resolve it to the real device by guesssing; it will check the kernel
 * cmdline. If the cmdline contains an entry like root=<TAG>=<VALUE>, then
 * libmount will probe and scan all block devices in order to find the tag. The
 * tag_cache here can be used so that if this function is called more than
 * once, then tag can be cached and we need to probe and scan only once */
int libmount_parse_cached(
                const char *path,
                FILE *source,
                struct libmnt_table **ret_table,
                struct libmnt_iter **ret_iter,
                struct libmnt_cache *tag_cache);

int libmount_is_leaf(
                struct libmnt_table *table,
                struct libmnt_fs *fs);
