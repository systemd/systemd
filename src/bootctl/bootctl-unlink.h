/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "shared-forward.h"

int verb_unlink(int argc, char *argv[], void *userdata);

int boot_config_count_known_files(const BootConfig *config, const char* root, Hashmap **ret_known_files);
