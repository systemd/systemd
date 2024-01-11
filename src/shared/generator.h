/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdio.h>

#include "macro.h"
#include "main-func.h"

int generator_open_unit_file_full(const char *dest, const char *source, const char *name, FILE **ret_file, char **ret_final_path, char **ret_temp_path);

static inline int generator_open_unit_file(const char *dest, const char *source, const char *name, FILE **ret_file) {
        return generator_open_unit_file_full(dest, source, name, ret_file, NULL, NULL);
}

int generator_add_symlink_full(const char *dir, const char *dst, const char *dep_type, const char *src, const char *instance);

static inline int generator_add_symlink(const char *dir, const char *dst, const char *dep_type, const char *src) {
        return generator_add_symlink_full(dir, dst, dep_type, src, NULL);
}

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

int generator_write_blockdev_dependency(
                FILE *f,
                const char *what);

int generator_write_cryptsetup_unit_section(
                FILE *f,
                const char *source);

int generator_write_cryptsetup_service_section(
                FILE *f,
                const char *name,
                const char *what,
                const char *password,
                const char *options);

int generator_write_veritysetup_unit_section(
                FILE *f,
                const char *source);

int generator_write_veritysetup_service_section(
                FILE *f,
                const char *name,
                const char *data_what,
                const char *hash_what,
                const char *roothash,
                const char *options);

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
int generator_hook_up_pcrfs(
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
                        if (!IN_SET(argc, 2, 4))                        \
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), \
                                                       "This program takes one or three arguments."); \
                }),                                                     \
                impl(argv[1],                                           \
                     argv[argc == 4 ? 2 : 1],                           \
                     argv[argc == 4 ? 3 : 1]),                          \
                r < 0 ? EXIT_FAILURE : EXIT_SUCCESS)
