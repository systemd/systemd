/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

int memfd_create_wrapper(const char *name, unsigned mode);

int memfd_new(const char *name);
int memfd_new_and_map(const char *name, size_t sz, void **p);
int memfd_new_and_seal(const char *name, const void *data, size_t sz);

int memfd_map(int fd, uint64_t offset, size_t size, void **p);

int memfd_set_sealed(int fd);
int memfd_get_sealed(int fd);

int memfd_get_size(int fd, uint64_t *sz);
int memfd_set_size(int fd, uint64_t sz);
