/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2015 Lennart Poettering

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

typedef enum ImportVerify {
        IMPORT_VERIFY_NO,
        IMPORT_VERIFY_CHECKSUM,
        IMPORT_VERIFY_SIGNATURE,
        _IMPORT_VERIFY_MAX,
        _IMPORT_VERIFY_INVALID = -1,
} ImportVerify;

int import_url_last_component(const char *url, char **ret);
int import_url_change_last_component(const char *url, const char *suffix, char **ret);

const char* import_verify_to_string(ImportVerify v) _const_;
ImportVerify import_verify_from_string(const char *s) _pure_;

int tar_strip_suffixes(const char *name, char **ret);
int raw_strip_suffixes(const char *name, char **ret);

bool dkr_name_is_valid(const char *name);
bool dkr_id_is_valid(const char *id);
bool dkr_ref_is_valid(const char *ref);
bool dkr_digest_is_valid(const char *digest);
#define dkr_tag_is_valid(tag) filename_is_valid(tag)
