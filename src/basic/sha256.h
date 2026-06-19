/* SPDX-License-Identifier: LGPL-2.1-or-later */

#pragma once

#include "basic-forward.h"

#include "../fundamental/sha256.h" /* IWYU pragma: export */

int sha256_fd(int fd, uint64_t max_size, uint8_t ret[static SHA256_DIGEST_SIZE]);

int parse_sha256(const char *s, uint8_t ret[static SHA256_DIGEST_SIZE]);

bool sha256_is_valid(const char *s) _pure_;

char *sha256_direct_hex(const void *buffer, size_t sz);
