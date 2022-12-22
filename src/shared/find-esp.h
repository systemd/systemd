/* SPDX-License-Identifier: LGPL-2.1-or-later */

#pragma once

#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <sys/types.h>

#include "fd-util.h"
#include "sd-id128.h"

int find_esp_at_and_warn(int dir_fd, const char *path, bool unprivileged_mode, char **ret_path, int *ret_fd, uint32_t *ret_part, uint64_t *ret_pstart, uint64_t *ret_psize, sd_id128_t *ret_uuid, dev_t *ret_devid);
int find_esp_and_warn(const char *root, const char *path, bool unprivileged_mode, char **ret_path, int *ret_fd, uint32_t *ret_part, uint64_t *ret_pstart, uint64_t *ret_psize, sd_id128_t *ret_uuid, dev_t *ret_devid);

int find_xbootldr_at_and_warn(int dir_fd, const char *path, bool unprivileged_mode, char **ret_path, int *ret_fd, sd_id128_t *ret_uuid, dev_t *ret_devid);
int find_xbootldr_and_warn(const char *root, const char *path, bool unprivileged_mode, char **ret_path, int *ret_fd, sd_id128_t *ret_uuid, dev_t *ret_devid);
