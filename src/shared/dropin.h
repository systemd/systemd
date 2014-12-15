/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

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

#include "macro.h"
#include "set.h"
#include "unit-name.h"

int drop_in_file(const char *dir, const char *unit, unsigned level,
                 const char *name, char **_p, char **_q);

int write_drop_in(const char *dir, const char *unit, unsigned level,
                  const char *name, const char *data);

int write_drop_in_format(const char *dir, const char *unit, unsigned level,
                         const char *name, const char *format, ...) _printf_(5, 6);

/**
 * This callback will be called for each directory entry @entry,
 * with @filepath being the full path to the entry.
 *
 * If return value is negative, loop will be aborted.
 */
typedef int (*dependency_consumer_t)(UnitDependency dependency,
                                     const char *entry,
                                     const char* filepath,
                                     void *arg);

int unit_file_process_dir(
                Set * unit_path_cache,
                const char *unit_path,
                const char *name,
                const char *suffix,
                UnitDependency dependency,
                dependency_consumer_t consumer,
                void *arg,
                char ***strv);

int unit_file_find_dropin_paths(
                char **lookup_path,
                Set *unit_path_cache,
                Set *names,
                char ***paths);
