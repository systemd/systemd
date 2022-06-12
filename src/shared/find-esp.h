/* SPDX-License-Identifier: LGPL-2.1-or-later */

#pragma once

#include <inttypes.h>
#include <stdbool.h>
#include <sys/types.h>

#include "sd-id128.h"

int find_esp_and_warn(const char *root, const char *path, bool unprivileged_mode, char **ret_path, uint32_t *ret_part, uint64_t *ret_pstart, uint64_t *ret_psize, sd_id128_t *ret_uuid, dev_t *ret_devid);
int find_xbootldr_and_warn(const char *root, const char *path, bool unprivileged_mode, char **ret_path, sd_id128_t *ret_uuid, dev_t *ret_devid);
