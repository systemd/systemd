/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <inttypes.h>
#include <sys/types.h>

#include "iovec-util.h"

int find_key_file(const char *key_file, char **search_path, const char *bindname, struct iovec *ret_key);
