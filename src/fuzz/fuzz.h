/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stddef.h>
#include <stdint.h>

#include "fileio.h"

/* The entry point into the fuzzer */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static inline FILE* data_to_file(const uint8_t *data, size_t size) {
        if (size == 0)
                return fopen("/dev/null", "re");
        else
                return fmemopen_unlocked((char*) data, size, "re");
}
