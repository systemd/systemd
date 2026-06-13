/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-id128.h"

#include "sd-forward.h"
#include "sparse-endian.h"

#define CATALOG_SIGNATURE { 'R', 'H', 'H', 'H', 'K', 'S', 'L', 'P' }

typedef struct CatalogHeader {
        uint8_t signature[8];  /* "RHHHKSLP" */
        le32_t compatible_flags;
        le32_t incompatible_flags;
        le64_t header_size;
        le64_t n_items;
        le64_t catalog_item_size;
} CatalogHeader;

typedef struct CatalogItem {
        sd_id128_t id;
        char language[32]; /* One byte is used for termination, so the maximum allowed
                            * length of the string is actually 31 bytes. */
        le64_t offset;
} CatalogItem;

int catalog_import_file(OrderedHashmap **h, int fd, const char *path);
int catalog_update(const char *database, const char *root, const char* const *dirs);
int catalog_get(const char *database, sd_id128_t id, char **ret_text);
int catalog_list(FILE *f, const char *database, bool oneline);
int catalog_list_items(FILE *f, const char *database, bool oneline, char **items);
int catalog_file_lang(const char *filename, char **ret);
