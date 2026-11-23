/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

#include "sysupdate-update-set-flags.h"

int reboot_now(void);
bool sysupdate_version_is_pending(const char *installed_version, const char *booted_version);
bool sysupdate_update_set_has_partial_or_pending(UpdateSetFlags flags);

#define SD_SYSUPDATE_OFFLINE   (UINT64_C(1) << 0)
#define SD_SYSUPDATE_FLAGS_ALL (SD_SYSUPDATE_OFFLINE)

bool feature_name_valid(const char *c);

bool component_name_valid(const char *c);
int get_component_list(const char *root, char ***ret);
