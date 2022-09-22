/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

#include "sd-id128.h"

#include "strv.h"

int mkfs_exists(const char *fstype);

int make_filesystem(const char *node, const char *fstype, const char *label, const char *root, sd_id128_t uuid, bool discard);
