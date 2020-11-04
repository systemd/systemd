/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <inttypes.h>
#include <sys/types.h>

int find_key_file(
                const char *key_file,
                char **search_path,
                const char *bindname,
                void **ret_key,
                size_t *ret_key_size);
