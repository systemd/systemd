/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <inttypes.h>
#include <stdbool.h>
#include <sys/types.h>

bool credential_name_valid(const char *s);

int get_credentials_dir(const char **ret);

int read_credential(const char *name, void **ret, size_t *ret_size);
