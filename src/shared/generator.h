/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"
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
        const char *type,
        const char *options);

int generator_write_device_timeout(
        const char *dir,
        const char *what,
        const char *opts,
        char **filtered);

int generator_write_unit_timeout(
                FILE *f,
                const char *where,
                const char *opts,
                const char *filter,
                const char *unit_setting);
static inline int generator_write_mount_timeout(FILE *f, const char *where, const char *opts) {
        return generator_write_unit_timeout(f, where, opts,
                                            "x-systemd.mount-timeout\0", "TimeoutSec");
}

int generator_write_blockdev_dependency(FILE *f, const char *what);

int generator_write_network_device_deps(
        const char *dir,
        const char *what,
        const char *where,
        const char *opts);

int generator_write_initrd_root_device_deps(const char *dir, const char *what);

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
int generator_hook_up_validatefs(
        const char *dir,
        const char *where,
        const char *target);
int generator_hook_up_quotacheck(
        const char *dir,
        const char *what,
        const char *where,
        const char *target,
        const char *fstype);
int generator_hook_up_quotaon(
        const char *dir,
        const char *where,
        const char *target);

int generator_write_cryptsetup_unit_section(FILE *f, const char *source);
int generator_write_cryptsetup_service_section(
                FILE *f,
                const char *name,
                const char *what,
                const char *key_file,
                const char *options);

int generator_write_veritysetup_unit_section(FILE *f, const char *source);
int generator_write_veritysetup_service_section(
                FILE *f,
                const char *name,
                const char *data_what,
                const char *hash_what,
                const char *roothash,
                const char *options);

int generator_enable_remount_fs_service(const char *dir);

void log_setup_generator(void);

bool generator_soft_rebooted(void);

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
                exit_failure_if_negative,                               \
                exit_failure_if_negative)

typedef enum GptAutoRoot {
        GPT_AUTO_ROOT_OFF = 0,       /* root= set to something else */
        GPT_AUTO_ROOT_ON,            /* root= set explicitly to "gpt-auto" */
        GPT_AUTO_ROOT_FORCE,         /* root= set explicitly to "gpt-auto-force" → ignores factory reset mode */
        GPT_AUTO_ROOT_DISSECT,       /* root= set to "dissect" */
        GPT_AUTO_ROOT_DISSECT_FORCE, /* root= set to "dissect-force" → ignores factory reset mode */
        _GPT_AUTO_ROOT_MAX,
        _GPT_AUTO_ROOT_INVALID = -EINVAL,
} GptAutoRoot;

GptAutoRoot parse_gpt_auto_root(const char *switch_name, const char *value);
