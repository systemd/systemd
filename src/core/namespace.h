/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/***
  Copyright © 2016 Djalal Harouni
***/

typedef struct NamespaceInfo NamespaceInfo;
typedef struct BindMount BindMount;
typedef struct TemporaryFileSystem TemporaryFileSystem;
typedef struct MountImage MountImage;

#include <stdbool.h>

#include "dissect-image.h"
#include "fs-util.h"
#include "macro.h"
#include "namespace-util.h"
#include "string-util.h"

typedef enum ProtectHome {
        PROTECT_HOME_NO,
        PROTECT_HOME_YES,
        PROTECT_HOME_READ_ONLY,
        PROTECT_HOME_TMPFS,
        _PROTECT_HOME_MAX,
        _PROTECT_HOME_INVALID = -EINVAL,
} ProtectHome;

typedef enum ProtectSystem {
        PROTECT_SYSTEM_NO,
        PROTECT_SYSTEM_YES,
        PROTECT_SYSTEM_FULL,
        PROTECT_SYSTEM_STRICT,
        _PROTECT_SYSTEM_MAX,
        _PROTECT_SYSTEM_INVALID = -EINVAL,
} ProtectSystem;

typedef enum ProtectProc {
        PROTECT_PROC_DEFAULT,
        PROTECT_PROC_NOACCESS,   /* hidepid=noaccess */
        PROTECT_PROC_INVISIBLE,  /* hidepid=invisible */
        PROTECT_PROC_PTRACEABLE, /* hidepid=ptraceable */
        _PROTECT_PROC_MAX,
        _PROTECT_PROC_INVALID = -EINVAL,
} ProtectProc;

typedef enum ProcSubset {
        PROC_SUBSET_ALL,
        PROC_SUBSET_PID, /* subset=pid */
        _PROC_SUBSET_MAX,
        _PROC_SUBSET_INVALID = -EINVAL,
} ProcSubset;

struct NamespaceInfo {
        bool ignore_protect_paths;
        bool private_dev;
        bool private_mounts;
        bool protect_control_groups;
        bool protect_kernel_tunables;
        bool protect_kernel_modules;
        bool protect_kernel_logs;
        bool mount_apivfs;
        bool protect_hostname;
        bool private_ipc;
        bool mount_nosuid;
        ProtectHome protect_home;
        ProtectSystem protect_system;
        ProtectProc protect_proc;
        ProcSubset proc_subset;
};

struct BindMount {
        char *source;
        char *destination;
        bool read_only;
        bool nosuid;
        bool recursive;
        bool ignore_enoent;
};

struct TemporaryFileSystem {
        char *path;
        char *options;
};

typedef enum MountImageType {
        MOUNT_IMAGE_DISCRETE,
        MOUNT_IMAGE_EXTENSION,
        _MOUNT_IMAGE_TYPE_MAX,
        _MOUNT_IMAGE_TYPE_INVALID = -EINVAL,
} MountImageType;

struct MountImage {
        char *source;
        char *destination; /* Unused if MountImageType == MOUNT_IMAGE_EXTENSION */
        LIST_HEAD(MountOptions, mount_options);
        bool ignore_enoent;
        MountImageType type;
};

int setup_namespace(
                const char *root_directory,
                const char *root_image,
                const MountOptions *root_image_options,
                const NamespaceInfo *ns_info,
                char **read_write_paths,
                char **read_only_paths,
                char **inaccessible_paths,
                char **exec_paths,
                char **no_exec_paths,
                char **empty_directories,
                char **exec_dir_symlinks,
                const BindMount *bind_mounts,
                size_t n_bind_mounts,
                const TemporaryFileSystem *temporary_filesystems,
                size_t n_temporary_filesystems,
                const MountImage *mount_images,
                size_t n_mount_images,
                const char *tmp_dir,
                const char *var_tmp_dir,
                const char *creds_path,
                const char *log_namespace,
                unsigned long mount_flags,
                const void *root_hash,
                size_t root_hash_size,
                const char *root_hash_path,
                const void *root_hash_sig,
                size_t root_hash_sig_size,
                const char *root_hash_sig_path,
                const char *root_verity,
                const MountImage *extension_images,
                size_t n_extension_images,
                char **extension_directories,
                const char *propagate_dir,
                const char *incoming_dir,
                const char *extension_dir,
                const char *notify_socket,
                char **error_path);

#define RUN_SYSTEMD_EMPTY "/run/systemd/empty"

static inline char* namespace_cleanup_tmpdir(char *p) {
        PROTECT_ERRNO;
        if (!streq_ptr(p, RUN_SYSTEMD_EMPTY))
                (void) rmdir(p);
        return mfree(p);
}
DEFINE_TRIVIAL_CLEANUP_FUNC(char*, namespace_cleanup_tmpdir);

int setup_tmp_dirs(
                const char *id,
                char **tmp_dir,
                char **var_tmp_dir);

int setup_shareable_ns(const int ns_storage_socket[static 2], unsigned long nsflag);
int open_shareable_ns_path(const int netns_storage_socket[static 2], const char *path, unsigned long nsflag);

const char* protect_home_to_string(ProtectHome p) _const_;
ProtectHome protect_home_from_string(const char *s) _pure_;

const char* protect_system_to_string(ProtectSystem p) _const_;
ProtectSystem protect_system_from_string(const char *s) _pure_;

const char* protect_proc_to_string(ProtectProc i) _const_;
ProtectProc protect_proc_from_string(const char *s) _pure_;

const char* proc_subset_to_string(ProcSubset i) _const_;
ProcSubset proc_subset_from_string(const char *s) _pure_;

void bind_mount_free_many(BindMount *b, size_t n);
int bind_mount_add(BindMount **b, size_t *n, const BindMount *item);

void temporary_filesystem_free_many(TemporaryFileSystem *t, size_t n);
int temporary_filesystem_add(TemporaryFileSystem **t, size_t *n,
                             const char *path, const char *options);

MountImage* mount_image_free_many(MountImage *m, size_t *n);
int mount_image_add(MountImage **m, size_t *n, const MountImage *item);

const char* namespace_type_to_string(NamespaceType t) _const_;
NamespaceType namespace_type_from_string(const char *s) _pure_;

bool ns_type_supported(NamespaceType type);
