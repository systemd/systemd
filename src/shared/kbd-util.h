/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

int keymap_directories(char ***ret);
int get_keymaps(char ***ret);
bool keymap_is_valid(const char *name);
int keymap_exists(const char *name);
