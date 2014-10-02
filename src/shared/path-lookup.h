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

#include "macro.h"

typedef struct LookupPaths {
        char **unit_path;
#ifdef HAVE_SYSV_COMPAT
        char **sysvinit_path;
        char **sysvrcnd_path;
#endif
} LookupPaths;

typedef enum SystemdRunningAs {
        SYSTEMD_SYSTEM,
        SYSTEMD_USER,
        _SYSTEMD_RUNNING_AS_MAX,
        _SYSTEMD_RUNNING_AS_INVALID = -1
} SystemdRunningAs;

int user_config_home(char **config_home);
int user_runtime_dir(char **runtime_dir);

int lookup_paths_init(LookupPaths *p,
                      SystemdRunningAs running_as,
                      bool personal,
                      const char *root_dir,
                      const char *generator,
                      const char *generator_early,
                      const char *generator_late);
void lookup_paths_free(LookupPaths *p);

#define _cleanup_lookup_paths_free_ _cleanup_(lookup_paths_free)
