/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

int identity_add_recovery_key(sd_json_variant **v, char **ret_recovery_key);
void show_recovery_key(const char *recovery_key);
int recovery_key_file_write(const char *path, const char *recovery_key);
