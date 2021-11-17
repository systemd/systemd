/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "json.h"

int parse_core(int fd, const char *executable, char **ret, JsonVariant **ret_package_metadata);
