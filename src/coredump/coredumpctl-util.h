/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

int resolve_filename(const char *root, char **p);

int retrieve(const void *data, size_t len, const char *name, char **var);
