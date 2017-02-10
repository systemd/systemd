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

typedef struct NameSpaceInfo NameSpaceInfo;
typedef struct BindMount BindMount;

#include <stdbool.h>

#include "dissect-image.h"
#include "macro.h"

typedef enum ProtectHome {
        PROTECT_HOME_NO,
        PROTECT_HOME_YES,
        PROTECT_HOME_READ_ONLY,
        _PROTECT_HOME_MAX,
        _PROTECT_HOME_INVALID = -1
} ProtectHome;

typedef enum ProtectSystem {
        PROTECT_SYSTEM_NO,
        PROTECT_SYSTEM_YES,
        PROTECT_SYSTEM_FULL,
        PROTECT_SYSTEM_STRICT,
        _PROTECT_SYSTEM_MAX,
        _PROTECT_SYSTEM_INVALID = -1
} ProtectSystem;

struct NameSpaceInfo {
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

int setup_namespace(
                const char *root_directory,
                const char *root_image,
                const NameSpaceInfo *ns_info,
                char **read_write_paths,
                char **read_only_paths,
                char **inaccessible_paths,
                const BindMount *bind_mounts,
                unsigned n_bind_mounts,
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

const char* protect_system_to_string(ProtectSystem p) _const_;
ProtectSystem protect_system_from_string(const char *s) _pure_;

void bind_mount_free_many(BindMount *b, unsigned n);
int bind_mount_add(BindMount **b, unsigned *n, const BindMount *item);
