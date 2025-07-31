/* SPDX-License-Identifier: LGPL-2.1-or-later */

#pragma once

#include "forward.h"
#include "sha256-fundamental.h" /* IWYU pragma: export */

int sha256_fd(int fd, uint64_t max_size, uint8_t ret[static SHA256_DIGEST_SIZE]);

int parse_sha256(const char *s, uint8_t res[static SHA256_DIGEST_SIZE]);

bool sha256_is_valid(const char *s) _pure_;
