/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "macro.h"
#include "version.h"

extern const char* const systemd_features;

#define PROJECT_VERSION_STR STRINGIFY(PROJECT_VERSION)

int version(void);
