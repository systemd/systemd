/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

extern const char* const systemd_features;

int version(void);
int version_only(void);

#define EXPERIMENTAL_DISABLED 0
#define EXPERIMENTAL_ENVVAR 1
#define EXPERIMENTAL_ENABLED 2

bool experimental_enabled(void);
