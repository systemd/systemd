/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stddef.h>
#include <stdint.h>

/* The entry point into the fuzzer */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
