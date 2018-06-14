/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <stdio.h>

int generator_open_unit_file(
        const char *dest,
        const char *source,
        const char *name,
        FILE **file);

int generator_add_symlink(const char *root, const char *dst, const char *dep_type, const char *src);

int generator_write_fsck_deps(
        FILE *f,
        const char *dir,
        const char *what,
        const char *where,
        const char *type);

int generator_write_timeouts(
        const char *dir,
        const char *what,
        const char *where,
        const char *opts,
        char **filtered);

int generator_write_device_deps(
        const char *dir,
        const char *what,
        const char *where,
        const char *opts);

int generator_write_initrd_root_device_deps(
        const char *dir,
        const char *what);

int generator_hook_up_mkswap(
        const char *dir,
        const char *what);
int generator_hook_up_mkfs(
        const char *dir,
        const char *what,
        const char *where,
        const char *type);
int generator_hook_up_growfs(
        const char *dir,
        const char *where,
        const char *target);
