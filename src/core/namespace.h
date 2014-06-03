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

typedef enum ProtectedHome {
        PROTECTED_HOME_NO,
        PROTECTED_HOME_YES,
        PROTECTED_HOME_READ_ONLY,
        _PROTECTED_HOME_MAX,
        _PROTECTED_HOME_INVALID = -1
} ProtectedHome;

int setup_namespace(char **read_write_dirs,
                    char **read_only_dirs,
                    char **inaccessible_dirs,
                    char *tmp_dir,
                    char *var_tmp_dir,
                    bool private_dev,
                    ProtectedHome protected_home,
                    bool read_only_system,
                    unsigned mount_flags);

int setup_tmp_dirs(const char *id,
                  char **tmp_dir,
                  char **var_tmp_dir);

int setup_netns(int netns_storage_socket[2]);

const char* protected_home_to_string(ProtectedHome p) _const_;
ProtectedHome protected_home_from_string(const char *s) _pure_;
