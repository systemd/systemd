/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

bool header_is_valid(const char *e);
int strv_header_replace_consume(char ***l, char *p);
