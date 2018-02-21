/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering
  Copyright 2016 Djalal Harouni

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
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
        bool protect_control_groups:1;
        bool protect_kernel_tunables:1;
        bool protect_kernel_modules:1;
        bool mount_apivfs:1;
};

struct BindMount {
        char *source;
        char *destination;
        bool read_only:1;
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
                unsigned n_bind_mounts,
                const TemporaryFileSystem *temporary_filesystems,
                unsigned n_temporary_filesystems,
                const char *tmp_dir,
                const char *var_tmp_dir,
                ProtectHome protect_home,
                ProtectSystem protect_system,
                unsigned long mount_flags,
                DissectImageFlags dissected_image_flags);

int setup_tmp_dirs(
                const char *id,
                char **tmp_dir,
                char **var_tmp_dir);

int setup_netns(int netns_storage_socket[2]);

const char* protect_home_to_string(ProtectHome p) _const_;
ProtectHome protect_home_from_string(const char *s) _pure_;
ProtectHome parse_protect_home_or_bool(const char *s);

const char* protect_system_to_string(ProtectSystem p) _const_;
ProtectSystem protect_system_from_string(const char *s) _pure_;
ProtectSystem parse_protect_system_or_bool(const char *s);

void bind_mount_free_many(BindMount *b, unsigned n);
int bind_mount_add(BindMount **b, unsigned *n, const BindMount *item);

void temporary_filesystem_free_many(TemporaryFileSystem *t, unsigned n);
int temporary_filesystem_add(TemporaryFileSystem **t, unsigned *n,
                             const char *path, const char *options);

const char* namespace_type_to_string(NamespaceType t) _const_;
NamespaceType namespace_type_from_string(const char *s) _pure_;

bool ns_type_supported(NamespaceType type);
