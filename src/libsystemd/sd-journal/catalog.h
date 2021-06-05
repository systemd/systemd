/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <stdio.h>

#include "sd-id128.h"

#include "hashmap.h"
#include "strbuf.h"

int catalog_import_file(OrderedHashmap *h, const char *path);
int catalog_update(const char* database, const char* root, const char* const* dirs);
int catalog_get(const char* database, sd_id128_t id, char **data);
int catalog_list(FILE *f, const char* database, bool oneline);
int catalog_list_items(FILE *f, const char* database, bool oneline, char **items);
int catalog_file_lang(const char *filename, char **lang);
extern const char * const catalog_file_dirs[];
extern const struct hash_ops catalog_hash_ops;
