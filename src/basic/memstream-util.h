/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdio.h>

#include "macro.h"

typedef struct MemStream MemStream;

MemStream* memstream_free(MemStream *m);
DEFINE_TRIVIAL_CLEANUP_FUNC(MemStream*, memstream_free);
FILE* memstream_open(MemStream **ret);
int memstream_finalize(MemStream *m, char **ret_buf, size_t *ret_size);
