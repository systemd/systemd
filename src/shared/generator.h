/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"
#include "main-func.h"
#include "verbs.h"

int generator_open_unit_file_full(const char *dir, const char *source, const char *filename, FILE **ret_file, char **ret_final_path, char **ret_temp_path);
static inline int generator_open_unit_file(const char *dir, const char *source, const char *filename, FILE **ret_file) {
        return generator_open_unit_file_full(dir, source, filename, ret_file, NULL, NULL);
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

/* Every generator takes either one directory, used for all three outputs, or the three directories
 * described in systemd.generator(7). */
#define GENERATOR_ARGSPEC "NORMAL-DIR [EARLY-DIR LATE-DIR]\0"

typedef int (*generator_main_func_t)(const char *dest, const char *dest_early, const char *dest_late);

/* Parse the common options with _common_parse_argv(), check that one or three directories were
 * given, and call impl with them (the single directory is passed for all three). The generator must
 * define a COMMAND() with .argspec = GENERATOR_ARGSPEC and .option_namespace = "common". Returns the
 * result of impl, 0 if --help, --version, or --introspect-cli was handled, and a negative errno on
 * error. */
int _generator_main(
                const Verb verbs[],
                const Verb verbs_end[],
                const Option options[],
                const Option options_end[],
                int argc, char *argv[],
                generator_main_func_t impl);

/* The macro inserts the calling binary's verb section, where its COMMAND is found, and its option
 * section, see common_parse_argv(). */
#define generator_main(argc, argv, impl)                                \
        _generator_main(                                                \
                __start_SYSTEMD_VERBS, __stop_SYSTEMD_VERBS,            \
                __start_SYSTEMD_OPTIONS, __stop_SYSTEMD_OPTIONS,        \
                argc, argv, impl)

/* Similar to DEFINE_MAIN_FUNCTION, but initializes logging for a generator, parses the common
 * options, and passes the output directories to impl. */
#define DEFINE_MAIN_GENERATOR_FUNCTION(impl)                            \
        _DEFINE_MAIN_FUNCTION(                                          \
                log_setup_generator(),                                  \
                generator_main(argc, argv, impl),                       \
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
