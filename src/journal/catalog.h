/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2012 Lennart Poettering

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
#include "hashmap.h"
#include "strbuf.h"

int catalog_import_file(Hashmap *h, struct strbuf *sb, const char *path);
int catalog_update(const char* database, const char* root, const char* const* dirs);
int catalog_get(const char* database, sd_id128_t id, char **data);
int catalog_list(FILE *f, const char* database, bool oneline);
int catalog_list_items(FILE *f, const char* database, bool oneline, char **items);
int catalog_file_lang(const char *filename, char **lang);
extern const char * const catalog_file_dirs[];
extern const struct hash_ops catalog_hash_ops;
