/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "bootspec.h"
#include "shared-forward.h"

int verb_unlink(int argc, char *argv[], uintptr_t _data, void *userdata);

int vl_method_unlink(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata);

int boot_config_count_known_files(const BootConfig *config, BootEntrySource source, Hashmap **ret_known_files);

int boot_entry_unlink(const BootEntry *e, const char *root, int root_fd, Hashmap *known_files, bool dry_run);
