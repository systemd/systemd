/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

int memfd_create_wrapper(const char *name, unsigned mode);

int memfd_new_full(const char *name, unsigned extra_flags);
static inline int memfd_new(const char *name) {
        return memfd_new_full(name, 0);
}

int memfd_new_and_seal(const char *name, const void *data, size_t sz);
static inline int memfd_new_and_seal_string(const char *name, const char *s) {
        return memfd_new_and_seal(name, s, SIZE_MAX);
}

int memfd_add_seals(int fd, unsigned seals);
int memfd_get_seals(int fd, unsigned *ret_seals);

int memfd_set_sealed(int fd);
int memfd_get_sealed(int fd);

int memfd_get_size(int fd, uint64_t *ret);
int memfd_set_size(int fd, uint64_t sz);
