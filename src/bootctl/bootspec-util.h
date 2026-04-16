/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "bootspec.h"

int boot_config_load_and_select(BootConfig *config, const char *esp_path, dev_t esp_devid, const char *xbootldr_path, dev_t xbootldr_devid);

static inline bool entry_commit_valid(uint64_t commit) {
        return commit > 0 && commit < UINT64_MAX;
}

int boot_entry_make_commit_filename(const char *entry_token, uint64_t entry_commit, const char *version, unsigned profile_nr, unsigned tries_left, char **ret);

int boot_entry_parse_commit_filename(const char *filename, char **ret_entry_token, uint64_t *ret_entry_commit);

int boot_entry_parse_commit(BootEntry *entry, char **ret_entry_token, uint64_t *ret_entry_commit);

int boot_config_find_oldest_commit(BootConfig *config, const char *entry_token, char ***ret_ids);
