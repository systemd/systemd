/* SPDX-License-Identifier: LGPL-2.1+ */
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
#include "unit-def.h"

#define UNIT_NAME_MAX 256

typedef enum UnitNameFlags {
        UNIT_NAME_PLAIN = 1,      /* Allow foo.service */
        UNIT_NAME_INSTANCE = 2,   /* Allow foo@bar.service */
        UNIT_NAME_TEMPLATE = 4,   /* Allow foo@.service */
        UNIT_NAME_ANY = UNIT_NAME_PLAIN|UNIT_NAME_INSTANCE|UNIT_NAME_TEMPLATE,
} UnitNameFlags;

bool unit_name_is_valid(const char *n, UnitNameFlags flags) _pure_;
bool unit_prefix_is_valid(const char *p) _pure_;
bool unit_instance_is_valid(const char *i) _pure_;
bool unit_suffix_is_valid(const char *s) _pure_;

static inline int unit_prefix_and_instance_is_valid(const char *p) {
        /* For prefix+instance and instance the same rules apply */
        return unit_instance_is_valid(p);
}

int unit_name_to_prefix(const char *n, char **prefix);
int unit_name_to_instance(const char *n, char **instance);
int unit_name_to_prefix_and_instance(const char *n, char **ret);

UnitType unit_name_to_type(const char *n) _pure_;

int unit_name_change_suffix(const char *n, const char *suffix, char **ret);

int unit_name_build(const char *prefix, const char *instance, const char *suffix, char **ret);

char *unit_name_escape(const char *f);
int unit_name_unescape(const char *f, char **ret);
int unit_name_path_escape(const char *f, char **ret);
int unit_name_path_unescape(const char *f, char **ret);

int unit_name_replace_instance(const char *f, const char *i, char **ret);

int unit_name_template(const char *f, char **ret);

int unit_name_from_path(const char *path, const char *suffix, char **ret);
int unit_name_from_path_instance(const char *prefix, const char *path, const char *suffix, char **ret);
int unit_name_to_path(const char *name, char **ret);

typedef enum UnitNameMangle {
        UNIT_NAME_NOGLOB,
        UNIT_NAME_GLOB,
} UnitNameMangle;

int unit_name_mangle_with_suffix(const char *name, UnitNameMangle allow_globs, const char *suffix, char **ret);

static inline int unit_name_mangle(const char *name, UnitNameMangle allow_globs, char **ret) {
        return unit_name_mangle_with_suffix(name, allow_globs, ".service", ret);
}

int slice_build_parent_slice(const char *slice, char **ret);
int slice_build_subslice(const char *slice, const char*name, char **subslice);
bool slice_name_is_valid(const char *name);
