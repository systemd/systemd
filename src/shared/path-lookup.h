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

typedef struct LookupPaths LookupPaths;

#include "install.h"
#include "macro.h"

struct LookupPaths {
        char **search_path;

        /* Where we shall create or remove our installation symlinks, aka "configuration". */
        char *persistent_config;
        char *runtime_config;

        /* Where to place generated unit files */
        char *generator;
        char *generator_early;
        char *generator_late;

        /* Where to place transient unit files */
        char *transient;

        /* The root directory prepended to all items above, or NULL */
        char *root_dir;
};

char **generator_paths(UnitFileScope scope);

int lookup_paths_init(LookupPaths *p, UnitFileScope scope, const char *root_dir);

int lookup_paths_reduce(LookupPaths *p);

int lookup_paths_mkdir_generator(LookupPaths *p);
void lookup_paths_trim_generator(LookupPaths *p);
void lookup_paths_flush_generator(LookupPaths *p);

void lookup_paths_free(LookupPaths *p);
#define _cleanup_lookup_paths_free_ _cleanup_(lookup_paths_free)
