/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

void hexdump(FILE *f, const void *p, size_t s) _nonnull_if_nonzero_(2, 3);
