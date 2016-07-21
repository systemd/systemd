#pragma once

/***
  This file is part of systemd.

  Copyright 2016 Lennart Poettering

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

#include "sd-id128.h"
#include "macro.h"

char *id128_to_uuid_string(sd_id128_t id, char s[37]);

/* Like SD_ID128_FORMAT_STR, but formats as UUID, not in plain format */
#define ID128_UUID_FORMAT_STR "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x"

bool id128_is_valid(const char *s) _pure_;

typedef enum Id128Format {
        ID128_ANY,
        ID128_PLAIN,  /* formatted as 32 hex chars as-is */
        ID128_UUID,   /* formatted as 36 character uuid string */
        _ID128_FORMAT_MAX,
} Id128Format;

int id128_read_fd(int fd, Id128Format f, sd_id128_t *ret);
int id128_read(const char *p, Id128Format f, sd_id128_t *ret);

int id128_write_fd(int fd, Id128Format f, sd_id128_t id, bool do_sync);
int id128_write(const char *p, Id128Format f, sd_id128_t id, bool do_sync);
