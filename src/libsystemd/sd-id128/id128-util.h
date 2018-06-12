/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
***/

#include <stdbool.h>

#include "sd-id128.h"

#include "hash-funcs.h"
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

void id128_hash_func(const void *p, struct siphash *state);
int id128_compare_func(const void *a, const void *b) _pure_;
extern const struct hash_ops id128_hash_ops;
