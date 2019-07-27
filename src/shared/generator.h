/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <stdio.h>

#include "main-func.h"

int generator_open_unit_file(
        const char *dest,
        const char *source,
        const char *name,
        FILE **file);

int generator_add_symlink(const char *dir, const char *dst, const char *dep_type, const char *src);

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

int generator_enable_remount_fs_service(const char *dir);

void log_setup_generator(void);

/* Similar to DEFINE_MAIN_FUNCTION, but initializes logging and assigns positional arguments. */
#define DEFINE_MAIN_GENERATOR_FUNCTION(impl)                            \
        _DEFINE_MAIN_FUNCTION(                                          \
                ({                                                      \
                        log_setup_generator();                          \
                        if (argc > 1 && argc != 4)                      \
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), \
                                                       "This program takes zero or three arguments."); \
                }),                                                     \
                impl(argc > 1 ? argv[1] : "/tmp",                       \
                     argc > 1 ? argv[2] : "/tmp",                       \
                     argc > 1 ? argv[3] : "/tmp"),                      \
                r < 0 ? EXIT_FAILURE : EXIT_SUCCESS)
