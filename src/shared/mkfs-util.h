/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

#include "sd-id128.h"

int mkfs_exists(const char *fstype);

int make_filesystem(const char *node, const char *fstype, const char *label, sd_id128_t uuid, bool discard);
