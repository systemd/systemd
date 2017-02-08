#pragma once

/***
  This file is part of systemd.

  Copyright 2014 Zbigniew Jędrzejewski-Szmek

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

#include "hashmap.h"
#include "macro.h"
#include "set.h"
#include "unit-name.h"

int drop_in_file(const char *dir, const char *unit, unsigned level,
                 const char *name, char **_p, char **_q);

int write_drop_in(const char *dir, const char *unit, unsigned level,
                  const char *name, const char *data);

int write_drop_in_format(const char *dir, const char *unit, unsigned level,
                         const char *name, const char *format, ...) _printf_(5, 6);

int unit_file_find_dropin_paths(
                const char *original_root,
                char **lookup_path,
                Set *unit_path_cache,
                const char *dir_suffix,
                const char *file_suffix,
                Set *names,
                char ***paths);

static inline int unit_file_find_dropin_conf_paths(
                const char *original_root,
                char **lookup_path,
                Set *unit_path_cache,
                Set *names,
                char ***paths) {
        return unit_file_find_dropin_paths(original_root,
                                           lookup_path,
                                           unit_path_cache,
                                           ".d", ".conf",
                                           names, paths);
}
