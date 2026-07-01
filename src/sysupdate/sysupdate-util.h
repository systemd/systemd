/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

int reboot_now(void);

#define SD_SYSUPDATE_OFFLINE   (UINT64_C(1) << 0)
#define SD_SYSUPDATE_FLAGS_ALL (SD_SYSUPDATE_OFFLINE)

bool component_name_valid(const char *c);
bool feature_name_valid(const char *c);

int get_component_list(const char *root, char ***ret);
