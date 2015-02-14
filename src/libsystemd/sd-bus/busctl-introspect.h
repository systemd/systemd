/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2014 Lennart Poettering

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

typedef struct XMLIntrospectOps {
        int (*on_path)(const char *path, void *userdata);
        int (*on_interface)(const char *name, uint64_t flags, void *userdata);
        int (*on_method)(const char *interface, const char *name, const char *signature, const char *result, uint64_t flags, void *userdata);
        int (*on_signal)(const char *interface, const char *name, const char *signature, uint64_t flags, void *userdata);
        int (*on_property)(const char *interface, const char *name, const char *signature, bool writable, uint64_t flags, void *userdata);
} XMLIntrospectOps;

int parse_xml_introspect(const char *prefix, const char *xml, const XMLIntrospectOps *ops, void *userdata);
