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

#define UNIT_NAME_MAX 256

typedef enum UnitType UnitType;
typedef enum UnitLoadState UnitLoadState;
typedef enum UnitDependency UnitDependency;

enum UnitType {
        UNIT_SERVICE = 0,
        UNIT_SOCKET,
        UNIT_BUSNAME,
        UNIT_TARGET,
        UNIT_SNAPSHOT,
        UNIT_DEVICE,
        UNIT_MOUNT,
        UNIT_AUTOMOUNT,
        UNIT_SWAP,
        UNIT_TIMER,
        UNIT_PATH,
        UNIT_SLICE,
        UNIT_SCOPE,
        _UNIT_TYPE_MAX,
        _UNIT_TYPE_INVALID = -1
};

enum UnitLoadState {
        UNIT_STUB = 0,
        UNIT_LOADED,
        UNIT_NOT_FOUND,
        UNIT_ERROR,
        UNIT_MERGED,
        UNIT_MASKED,
        _UNIT_LOAD_STATE_MAX,
        _UNIT_LOAD_STATE_INVALID = -1
};

enum UnitDependency {
        /* Positive dependencies */
        UNIT_REQUIRES,
        UNIT_REQUIRES_OVERRIDABLE,
        UNIT_REQUISITE,
        UNIT_REQUISITE_OVERRIDABLE,
        UNIT_WANTS,
        UNIT_BINDS_TO,
        UNIT_PART_OF,

        /* Inverse of the above */
        UNIT_REQUIRED_BY,             /* inverse of 'requires' and 'requisite' is 'required_by' */
        UNIT_REQUIRED_BY_OVERRIDABLE, /* inverse of 'requires_overridable' and 'requisite_overridable' is 'soft_required_by' */
        UNIT_WANTED_BY,               /* inverse of 'wants' */
        UNIT_BOUND_BY,                /* inverse of 'binds_to' */
        UNIT_CONSISTS_OF,             /* inverse of 'part_of' */

        /* Negative dependencies */
        UNIT_CONFLICTS,               /* inverse of 'conflicts' is 'conflicted_by' */
        UNIT_CONFLICTED_BY,

        /* Order */
        UNIT_BEFORE,                  /* inverse of 'before' is 'after' and vice versa */
        UNIT_AFTER,

        /* On Failure */
        UNIT_ON_FAILURE,

        /* Triggers (i.e. a socket triggers a service) */
        UNIT_TRIGGERS,
        UNIT_TRIGGERED_BY,

        /* Propagate reloads */
        UNIT_PROPAGATES_RELOAD_TO,
        UNIT_RELOAD_PROPAGATED_FROM,

        /* Joins namespace of */
        UNIT_JOINS_NAMESPACE_OF,

        /* Reference information for GC logic */
        UNIT_REFERENCES,              /* Inverse of 'references' is 'referenced_by' */
        UNIT_REFERENCED_BY,

        _UNIT_DEPENDENCY_MAX,
        _UNIT_DEPENDENCY_INVALID = -1
};

const char *unit_type_to_string(UnitType i) _const_;
UnitType unit_type_from_string(const char *s) _pure_;

const char *unit_load_state_to_string(UnitLoadState i) _const_;
UnitLoadState unit_load_state_from_string(const char *s) _pure_;

int unit_name_to_instance(const char *n, char **instance);
char* unit_name_to_prefix(const char *n);
char* unit_name_to_prefix_and_instance(const char *n);

enum template_valid {
        TEMPLATE_INVALID,
        TEMPLATE_VALID,
};

bool unit_name_is_valid(const char *n, enum template_valid template_ok) _pure_;
bool unit_prefix_is_valid(const char *p) _pure_;
bool unit_instance_is_valid(const char *i) _pure_;

UnitType unit_name_to_type(const char *n) _pure_;

char *unit_name_change_suffix(const char *n, const char *suffix);

char *unit_name_build(const char *prefix, const char *instance, const char *suffix);

char *unit_name_escape(const char *f);
char *unit_name_unescape(const char *f);
char *unit_name_path_escape(const char *f);
char *unit_name_path_unescape(const char *f);

bool unit_name_is_template(const char *n) _pure_;
bool unit_name_is_instance(const char *n) _pure_;

char *unit_name_replace_instance(const char *f, const char *i);

char *unit_name_template(const char *f);

char *unit_name_from_path(const char *path, const char *suffix);
char *unit_name_from_path_instance(const char *prefix, const char *path, const char *suffix);
char *unit_name_to_path(const char *name);

char *unit_dbus_path_from_name(const char *name);
int unit_name_from_dbus_path(const char *path, char **name);

enum unit_name_mangle {
        MANGLE_NOGLOB,
        MANGLE_GLOB,
};

char *unit_name_mangle(const char *name, enum unit_name_mangle allow_globs);
char *unit_name_mangle_with_suffix(const char *name, enum unit_name_mangle allow_globs, const char *suffix);

int build_subslice(const char *slice, const char*name, char **subslice);

const char *unit_dependency_to_string(UnitDependency i) _const_;
UnitDependency unit_dependency_from_string(const char *s) _pure_;
