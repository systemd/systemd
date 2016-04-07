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
        /* Where we look for unit files. This includes the individual special paths below, but also any vendor
         * supplied, static unit file paths. */
        char **search_path;

        /* Where we shall create or remove our installation symlinks, aka "configuration", and where the user/admin
         * shall place his own unit files. */
        char *persistent_config;
        char *runtime_config;

        /* Where to place generated unit files (i.e. those a "generator" tool generated). Note the special semantics of
         * this directory: the generators are flushed each time a "systemctl daemon-reload" is issued. The user should
         * not alter these directories directly. */
        char *generator;
        char *generator_early;
        char *generator_late;

        /* Where to place transient unit files (i.e. those created dynamically via the bus API). Note the special
         * semantics of this directory: all units created transiently have their unit files removed as the transient
         * unit is unloaded. The user should not alter this directory directly. */
        char *transient;

        /* Where the snippets created by "systemctl set-property" are placed. Note that for transient units, the
         * snippets are placed in the transient directory though (see above). The user should not alter this directory
         * directly. */
        char *persistent_control;
        char *runtime_control;

        /* The root directory prepended to all items above, or NULL */
        char *root_dir;
};

int lookup_paths_init(LookupPaths *p, UnitFileScope scope, const char *root_dir);

int lookup_paths_reduce(LookupPaths *p);

int lookup_paths_mkdir_generator(LookupPaths *p);
void lookup_paths_trim_generator(LookupPaths *p);
void lookup_paths_flush_generator(LookupPaths *p);

void lookup_paths_free(LookupPaths *p);
#define _cleanup_lookup_paths_free_ _cleanup_(lookup_paths_free)

char **generator_binary_paths(UnitFileScope scope);
