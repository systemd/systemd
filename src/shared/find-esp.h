/* SPDX-License-Identifier: LGPL-2.1-or-later */

#pragma once

#include "forward.h"

int find_esp_and_warn_at(int rfd, const char *path, int unprivileged_mode, char **ret_path, uint32_t *ret_part, uint64_t *ret_pstart, uint64_t *ret_psize, sd_id128_t *ret_uuid, dev_t *ret_devid);
int find_esp_and_warn(const char *root, const char *path, int unprivileged_mode, char **ret_path, uint32_t *ret_part, uint64_t *ret_pstart, uint64_t *ret_psize, sd_id128_t *ret_uuid, dev_t *ret_devid);

int find_xbootldr_and_warn_at(int rfd, const char *path, int unprivileged_mode, char **ret_path, sd_id128_t *ret_uuid, dev_t *ret_devid);
int find_xbootldr_and_warn(const char *root, const char *path, int unprivileged_mode, char **ret_path, sd_id128_t *ret_uuid, dev_t *ret_devid);
