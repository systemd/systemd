/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "shared-forward.h"

int install_random_seed(const char *esp, int esp_fd);

int verb_random_seed(int argc, char *argv[], uintptr_t _data, void *userdata);
