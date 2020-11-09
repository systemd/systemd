/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <inttypes.h>
#include <sys/types.h>

int load_key_file(
                const char *key_file,
                char **search_path,
                size_t key_file_size,
                uint64_t key_file_offset,
                void **ret_key,
                size_t *ret_key_size);
