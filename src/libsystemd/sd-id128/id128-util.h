/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

#include "sd-id128.h"

#include "hash-funcs.h"
#include "macro.h"

bool id128_is_valid(const char *s) _pure_;

typedef enum Id128FormatFlag {
        ID128_FORMAT_PLAIN = 1 << 0,  /* formatted as 32 hex chars as-is */
        ID128_FORMAT_UUID  = 1 << 1,  /* formatted as 36 character uuid string */
        ID128_FORMAT_ANY   = ID128_FORMAT_PLAIN | ID128_FORMAT_UUID,

        ID128_SYNC_ON_WRITE = 1 << 2, /* Sync the file after write. Used only when writing an ID. */
} Id128FormatFlag;

int id128_read_fd(int fd, Id128FormatFlag f, sd_id128_t *ret);
int id128_read(const char *root, const char *p, Id128FormatFlag f, sd_id128_t *ret);

int id128_write_fd(int fd, Id128FormatFlag f, sd_id128_t id);
int id128_write(const char *p, Id128FormatFlag f, sd_id128_t id);

int id128_get_machine_impl(const char *root, sd_id128_t *ret);
static inline int id128_get_machine(const char *root, sd_id128_t *ret) {
        return root ? id128_get_machine_impl(root, ret) : sd_id128_get_machine(ret);
}

void id128_hash_func(const sd_id128_t *p, struct siphash *state);
int id128_compare_func(const sd_id128_t *a, const sd_id128_t *b) _pure_;
extern const struct hash_ops id128_hash_ops;
extern const struct hash_ops id128_hash_ops_free;

sd_id128_t id128_make_v4_uuid(sd_id128_t id);

int id128_get_product(sd_id128_t *ret);

/* A helper to check for the three relevant cases of "machine ID not initialized" */
#define ERRNO_IS_MACHINE_ID_UNSET(r)            \
        IN_SET(abs(r),                          \
               ENOENT,                          \
               ENOMEDIUM,                       \
               ENOPKG)
