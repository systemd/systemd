/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  Copyright © 2016 Djalal Harouni
***/

typedef struct NamespaceInfo NamespaceInfo;
typedef struct BindMount BindMount;
typedef struct TemporaryFileSystem TemporaryFileSystem;

#include <stdbool.h>

#include "dissect-image.h"
#include "macro.h"

typedef enum ProtectHome {
        PROTECT_HOME_NO,
        PROTECT_HOME_YES,
        PROTECT_HOME_READ_ONLY,
        PROTECT_HOME_TMPFS,
        _PROTECT_HOME_MAX,
        _PROTECT_HOME_INVALID = -1
} ProtectHome;

typedef enum NamespaceType {
        NAMESPACE_MOUNT,
        NAMESPACE_CGROUP,
        NAMESPACE_UTS,
        NAMESPACE_IPC,
        NAMESPACE_USER,
        NAMESPACE_PID,
        NAMESPACE_NET,
        _NAMESPACE_TYPE_MAX,
        _NAMESPACE_TYPE_INVALID = -1,
} NamespaceType;

typedef enum ProtectSystem {
        PROTECT_SYSTEM_NO,
        PROTECT_SYSTEM_YES,
        PROTECT_SYSTEM_FULL,
        PROTECT_SYSTEM_STRICT,
        _PROTECT_SYSTEM_MAX,
        _PROTECT_SYSTEM_INVALID = -1
} ProtectSystem;

struct NamespaceInfo {
        bool ignore_protect_paths:1;
        bool private_dev:1;
        bool private_mounts:1;
        bool protect_control_groups:1;
        bool protect_kernel_tunables:1;
        bool protect_kernel_modules:1;
        bool mount_apivfs:1;
        bool protect_hostname:1;
};

struct BindMount {
        char *source;
        char *destination;
        bool read_only:1;
        bool nosuid:1;
        bool recursive:1;
        bool ignore_enoent:1;
};

struct TemporaryFileSystem {
        char *path;
        char *options;
};

int setup_namespace(
                const char *root_directory,
                const char *root_image,
                const NamespaceInfo *ns_info,
                char **read_write_paths,
                char **read_only_paths,
                char **inaccessible_paths,
                char **empty_directories,
                const BindMount *bind_mounts,
                size_t n_bind_mounts,
                const TemporaryFileSystem *temporary_filesystems,
                size_t n_temporary_filesystems,
                const char *tmp_dir,
                const char *var_tmp_dir,
                ProtectHome protect_home,
                ProtectSystem protect_system,
                unsigned long mount_flags,
                DissectImageFlags dissected_image_flags,
                char **error_path);

int setup_tmp_dirs(
                const char *id,
                char **tmp_dir,
                char **var_tmp_dir);

int setup_netns(const int netns_storage_socket[static 2]);
int open_netns_path(const int netns_storage_socket[static 2], const char *path);

const char* protect_home_to_string(ProtectHome p) _const_;
ProtectHome protect_home_from_string(const char *s) _pure_;

const char* protect_system_to_string(ProtectSystem p) _const_;
ProtectSystem protect_system_from_string(const char *s) _pure_;

void bind_mount_free_many(BindMount *b, size_t n);
int bind_mount_add(BindMount **b, size_t *n, const BindMount *item);

void temporary_filesystem_free_many(TemporaryFileSystem *t, size_t n);
int temporary_filesystem_add(TemporaryFileSystem **t, size_t *n,
                             const char *path, const char *options);

const char* namespace_type_to_string(NamespaceType t) _const_;
NamespaceType namespace_type_from_string(const char *s) _pure_;

bool ns_type_supported(NamespaceType type);
