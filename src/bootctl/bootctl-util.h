/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

bool touch_variables(void);
int verify_touch_variables_allowed(const char *command);

int sync_everything(void);

const char* get_efi_arch(void);

int get_file_version(int fd, char **ret);

int settle_entry_token(void);
