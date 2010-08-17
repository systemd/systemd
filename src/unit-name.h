/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#ifndef foounitnamehfoo
#define foounitnamehfoo

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include "unit.h"

UnitType unit_name_to_type(const char *n);

int unit_name_to_instance(const char *n, char **instance);
char* unit_name_to_prefix(const char *n);
char* unit_name_to_prefix_and_instance(const char *n);

bool unit_name_is_valid(const char *n);
bool unit_prefix_is_valid(const char *p);
bool unit_instance_is_valid(const char *i);

char *unit_name_change_suffix(const char *n, const char *suffix);

char *unit_name_build(const char *prefix, const char *instance, const char *suffix);
char *unit_name_build_escape(const char *prefix, const char *instance, const char *suffix);

char *unit_name_escape(const char *f);
char *unit_name_unescape(const char *f);

bool unit_name_is_template(const char *n);

char *unit_name_replace_instance(const char *f, const char *i);

char *unit_name_template(const char *f);

char *unit_name_from_path(const char *path, const char *suffix);
char *unit_name_to_path(const char *name);

#endif
