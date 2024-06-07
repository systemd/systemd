/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stddef.h>
#include <stdint.h>

int fido2_generate_salt(void **ret_salt, size_t *ret_size);
int fido2_read_salt_file(const char *filename, uint64_t offset, size_t size, const char *client, const char *node, void **ret_salt, size_t *ret_size);
