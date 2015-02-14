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

enum {
        JSON_END,
        JSON_COLON,
        JSON_COMMA,
        JSON_OBJECT_OPEN,
        JSON_OBJECT_CLOSE,
        JSON_ARRAY_OPEN,
        JSON_ARRAY_CLOSE,
        JSON_STRING,
        JSON_REAL,
        JSON_INTEGER,
        JSON_BOOLEAN,
        JSON_NULL,
};

union json_value {
        bool boolean;
        double real;
        intmax_t integer;
};

#define JSON_VALUE_NULL ((union json_value) {})

int json_tokenize(const char **p, char **ret_string, union json_value *ret_value, void **state, unsigned *line);
