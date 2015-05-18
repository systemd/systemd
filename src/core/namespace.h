/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

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

#include <stdbool.h>

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
        _PROTECT_SYSTEM_MAX,
        _PROTECT_SYSTEM_INVALID = -1
} ProtectSystem;

int setup_namespace(const char *chroot,
                    char **read_write_dirs,
                    char **read_only_dirs,
                    char **inaccessible_dirs,
                    const char *tmp_dir,
                    const char *var_tmp_dir,
                    const char *endpoint_path,
                    bool private_dev,
                    ProtectHome protect_home,
                    ProtectSystem protect_system,
                    unsigned long mount_flags);

int setup_tmp_dirs(const char *id,
                  char **tmp_dir,
                  char **var_tmp_dir);

int setup_netns(int netns_storage_socket[2]);

const char* protect_home_to_string(ProtectHome p) _const_;
ProtectHome protect_home_from_string(const char *s) _pure_;

const char* protect_system_to_string(ProtectSystem p) _const_;
ProtectSystem protect_system_from_string(const char *s) _pure_;
