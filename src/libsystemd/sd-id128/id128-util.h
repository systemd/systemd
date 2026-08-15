/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-id128.h"

#include "errno-util.h"
#include "forward.h"

bool id128_is_valid(const char *s) _pure_;

typedef enum Id128Flag {
        ID128_FORMAT_PLAIN  = 1 << 0,  /* formatted as 32 hex chars as-is */
        ID128_FORMAT_UUID   = 1 << 1,  /* formatted as 36 character uuid string */
        ID128_FORMAT_ANY    = ID128_FORMAT_PLAIN | ID128_FORMAT_UUID,

        ID128_SYNC_ON_WRITE = 1 << 2, /* Sync the file after write. Used only when writing an ID. */
        ID128_REFUSE_NULL   = 1 << 3, /* Refuse all zero ID with -ENOMEDIUM. */
} Id128Flag;

int id128_from_string_nonzero(const char *s, sd_id128_t *ret);

int id128_read_fd(int fd, Id128Flag f, sd_id128_t *ret);
int id128_read_at(int dir_fd, const char *path, Id128Flag f, sd_id128_t *ret);
static inline int id128_read(const char *path, Id128Flag f, sd_id128_t *ret) {
        return id128_read_at(AT_FDCWD, path, f, ret);
}

int id128_write_fd(int fd, Id128Flag f, sd_id128_t id);
int id128_write_at(int dir_fd, const char *path, Id128Flag f, sd_id128_t id);
static inline int id128_write(const char *path, Id128Flag f, sd_id128_t id) {
        return id128_write_at(AT_FDCWD, path, f, id);
}

int id128_get_machine(const char *root, sd_id128_t *ret);
int id128_get_machine_at(int rfd, sd_id128_t *ret);

void id128_hash_func(const sd_id128_t *p, struct siphash *state);
int id128_compare_func(const sd_id128_t *a, const sd_id128_t *b) _pure_;
extern const struct hash_ops id128_hash_ops;
extern const struct hash_ops id128_hash_ops_free;

sd_id128_t id128_make_v4_uuid(sd_id128_t id);

int id128_get_product(sd_id128_t *ret);

sd_id128_t id128_digest(const void *data, size_t size);

int id128_get_boot(sd_id128_t *ret);
int id128_get_boot_for_machine(const char *machine, sd_id128_t *ret);

/* A helper to check for the three relevant cases of "machine ID not initialized" */
#define ERRNO_IS_NEG_MACHINE_ID_UNSET(r)        \
        IN_SET(r,                               \
               -ENOENT,                         \
               -ENOMEDIUM,                      \
               -ENOPKG)
_DEFINE_ABS_WRAPPER(MACHINE_ID_UNSET);
