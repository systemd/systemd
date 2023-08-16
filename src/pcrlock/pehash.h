/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/types.h>

#include "openssl-util.h"
#include "uki.h"

int pe_hash(int fd, const EVP_MD *md, void **ret_hash, size_t *ret_hash_size);

int uki_hash(int fd, const EVP_MD *md, void *ret_hashes[static _UNIFIED_SECTION_MAX], size_t *ret_hash_size);
